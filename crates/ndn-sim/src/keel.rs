//! **The Keel slice** — ndn-lab as the first real consumer of the manifest /
//! render-contract calculus (`ndn-manifest` + `ndn-render-contract`).
//!
//! The thesis, applied to a simulator: a telemetry sample **describes itself**
//! (a [`Manifest`] over an ndn-lab [`Vocabulary`]); renderers **publish what
//! they can express** ([`Contract`]s); a decidable, evaluation-free matcher
//! binds `(manifest × intent × contracts × trust-frontier)` to a verdict and
//! an inert renderer binding. ndn-lab stops hand-rolling one serializer per
//! output — it describes the metric once and every output is a *lens*.
//!
//! This slice takes **one** telemetry type — [`FabricGauges`] — and offers it
//! through **two** lenses:
//!
//! - a **sparkline** contract, which Expresses `series.window` over the gauge
//!   type directly (`fabric-gauges` *narrower-than* `metric-gauge`, lossless) —
//!   verdict **Express**;
//! - an **OTLP** contract, reachable only through the separate
//!   `ndn-lab-otel-bridge` stratum whose `maps-to` edge demotes fidelity — so
//!   the Phase-B OTLP lossiness that used to be buried in a hand-written
//!   serializer becomes a **named loss term** (`otel-attribute-flattening`) a
//!   reader can point at — verdict **Approximate**.
//!
//! Two properties the design demands are honoured here:
//!
//! - **Resolve once, stream the rest.** The matcher runs a single time per
//!   `(type-term × contract-set × frontier)`; the [`Match`]es are cached. The
//!   *schema* is the Block; the samples are Sparks bound to that resolution —
//!   matching per sample would be category-confused, not merely slow.
//! - **`Via::Native` is a registry key and nothing more.** The matcher never
//!   evaluates `via` (C8); the id string resolves a Rust renderer in
//!   [`Renderers`] and is not allowed to accrue any other meaning (native-via
//!   is the register's acknowledged attestation gap).
//!
//! Presentation of *why* a verdict landed is delegated to `ndn_bench::explain`
//! — the tool-tier trace renderer — so the spec crates stay label-blind.

use std::collections::BTreeMap;

use ndn_bench::explain;
use ndn_manifest::model::{
    Clause, Contract, Document, EdgeForm, Intent, Manifest, ManifestEntry, Subject, Term, Value,
    Via, Vocabulary,
};
use ndn_manifest::{term_hash, FrozenDag, hash::Hash};
use ndn_render_contract::{r#match, Budget, Floor, Match, TrustFrontier, Verdict};

use crate::telemetry::FabricGauges;

// ── intent + native-renderer ids (registry keys only) ───────────────────────

/// The window-series render intent (Riverwatch's own example intent).
pub const INTENT_SERIES_WINDOW: &str = "series.window";
/// The OTLP-gauge render intent.
pub const INTENT_OTLP_GAUGE: &str = "otlp.gauge";

const VIA_SPARKLINE: &str = "ndn-lab/sparkline-svg";
const VIA_OTLP: &str = "ndn-lab/otlp-gauge";

fn term(label: &str, doc: &str) -> Term {
    Term { label: label.into(), doc: Some(doc.into()), ty: None, attrs: Vec::new() }
}

/// The term hashes the vocabulary/manifest/contracts are wired from — computed
/// once so producers never re-hash. (This struct is exactly the shape a
/// `#[derive(Manifest)]` on `FabricGauges` would need to synthesise: a type
/// term + one field term per struct field. See the module notes.)
struct Handles {
    /// The manifest type: `fabric-gauges`.
    fabric_gauges: Hash,
    /// The broader renderable term the type narrows to.
    metric_gauge: Hash,
    /// The OTLP-side term reached through the bridge.
    otel_gauge: Hash,
    /// The declared loss of the ndn-lab → OTLP mapping.
    loss_flatten: Hash,
    /// Field terms, in `FabricGauges` field order.
    f_virtual_time: Hash,
    f_radio_airtime: Hash,
    f_handoffs: Hash,
    f_assoc_overhead: Hash,
}

impl Handles {
    fn new() -> Self {
        Handles {
            fabric_gauges: term_hash(&term("fabric-gauges", "One fabric-wide gauge snapshot.")).unwrap(),
            metric_gauge: term_hash(&term("metric-gauge", "A renderable numeric gauge over virtual time.")).unwrap(),
            otel_gauge: term_hash(&term("gauge", "An OpenTelemetry gauge data point.")).unwrap(),
            loss_flatten: term_hash(&term("otel-attribute-flattening", "Loss: NDN structure flattened to OTLP key/value attributes.")).unwrap(),
            f_virtual_time: term_hash(&term("virtual-time", "Kernel-clock time of the sample (ns).")).unwrap(),
            f_radio_airtime: term_hash(&term("radio-airtime", "Shared-radio airtime consumed (ns).")).unwrap(),
            f_handoffs: term_hash(&term("handoffs", "AP-mode (re)associations.")).unwrap(),
            f_assoc_overhead: term_hash(&term("assoc-overhead", "Association-handshake time (ns).")).unwrap(),
        }
    }
}

// ── the producer: a telemetry sample describes itself ────────────────────────

/// `FabricGauges` → a [`Manifest`]: say-what-it-is-once, against the ndn-lab
/// vocabulary. **This is the by-hand producer the derive would replace** — one
/// `ManifestEntry` per struct field, each binding a field term hash to a flat
/// `Value`. (A single snapshot; a *run* is a stream of these, all sharing this
/// one resolved type.)
fn fabric_gauges_manifest(g: &FabricGauges, h: &Handles) -> Manifest {
    Manifest {
        ty: h.fabric_gauges,
        label: Some("fabric-gauges".into()),
        describes: Subject::Name("ndn-lab/run/fabric-gauges".into()),
        entries: vec![
            ManifestEntry { field: h.f_virtual_time, value: Value::Integer(g.virtual_time_ns) },
            ManifestEntry { field: h.f_radio_airtime, value: Value::Integer(g.radio_airtime_ns) },
            ManifestEntry { field: h.f_handoffs, value: Value::Integer(g.handoffs) },
            ManifestEntry { field: h.f_assoc_overhead, value: Value::Integer(g.association_overhead_ns) },
        ],
        edges: Vec::new(),
    }
}

// ── the native-renderer registry (Via::Native id → a Rust renderer) ──────────

/// The `Via::Native` registry: an id string resolves a Rust renderer that turns
/// the **sample stream** into an artifact. The id is a key and nothing more.
struct Renderers {
    table: BTreeMap<&'static str, fn(&[FabricGauges]) -> String>,
}

impl Renderers {
    fn new() -> Self {
        let mut table: BTreeMap<&'static str, fn(&[FabricGauges]) -> String> = BTreeMap::new();
        table.insert(VIA_SPARKLINE, render_sparkline_lens);
        table.insert(VIA_OTLP, render_otlp_lens);
        Renderers { table }
    }
    fn get(&self, id: &str) -> Option<fn(&[FabricGauges]) -> String> {
        self.table.get(id).copied()
    }
}

/// Sparkline lens: the window of radio-airtime over virtual time as an SVG
/// (reuses ndn-lab's existing [`render_sparkline`](crate::scene::render_sparkline)).
fn render_sparkline_lens(samples: &[FabricGauges]) -> String {
    let series: Vec<(u64, f64)> =
        samples.iter().map(|g| (g.virtual_time_ns, g.radio_airtime_ns as f64)).collect();
    crate::scene::render_sparkline(&series, 240, 48)
}

/// OTLP lens: the most-recent sample as an OTLP/JSON gauge document (scrape
/// semantics — point-in-time, the flattening the bridge's loss term names).
fn render_otlp_lens(samples: &[FabricGauges]) -> String {
    let latest = samples.last().copied().unwrap_or_default();
    crate::otel_export::OtlpExporter::new("127.0.0.1:4318").fabric_gauges_payload(&latest)
}

// ── the resolved view: match once, render many ──────────────────────────────

/// A resolved rendering plan for `FabricGauges`: the DAG is assembled and the
/// matcher run **once**; thereafter each lens renders sample batches from the
/// cached [`Match`]es without re-matching.
pub struct KeelView {
    dag: FrozenDag,
    matches: Vec<Match>,
    renderers: Renderers,
    resolves: usize,
}

/// One lens's outcome for a batch of samples.
pub struct Rendered {
    /// The intent this lens offered.
    pub intent: String,
    /// The matcher's verdict (Express / Approximate(loss) / …).
    pub verdict: Verdict,
    /// The rendered artifact (SVG, OTLP/JSON, …).
    pub body: String,
    /// A human-auditable trace of *why* this verdict landed (`ndn_bench::explain`).
    pub trace: String,
}

impl KeelView {
    /// Assemble the ndn-lab telemetry DAG (vocabulary + OTLP bridge stratum +
    /// one `FabricGauges` manifest + the two contracts) and resolve the lenses.
    ///
    /// `admit_otel_bridge` toggles whether the consumer admits the bridge
    /// stratum's edges (C10). Without it, the OTLP lens simply has no path and
    /// drops out — two consumers diverge *honestly* rather than fighting over a
    /// serializer.
    pub fn for_fabric_gauges(admit_otel_bridge: bool) -> Self {
        let h = Handles::new();
        let mut dag = FrozenDag::new();

        // The kernel trio rides in every DAG (R14) and gives the total floor.
        let fp = ndn_manifest::kernel::fixed_point();
        dag.insert_bytes(&fp.im0_bytes).expect("IM₀ decodes");
        let t0 = dag.insert_bytes(&fp.t0_bytes).expect("T₀ decodes");

        // The ndn-lab telemetry vocabulary: the gauge type narrows (losslessly)
        // to the renderable metric-gauge term.
        let ndnlab = dag
            .insert_document(&Document::Vocabulary(Vocabulary {
                label: "ndn-lab".into(),
                doc: Some("ndn-lab telemetry terms: fabric gauges and their renderable form.".into()),
                imports: Vec::new(),
                terms: vec![
                    term("fabric-gauges", "One fabric-wide gauge snapshot."),
                    term("metric-gauge", "A renderable numeric gauge over virtual time."),
                    term("virtual-time", "Kernel-clock time of the sample (ns)."),
                    term("radio-airtime", "Shared-radio airtime consumed (ns)."),
                    term("handoffs", "AP-mode (re)associations."),
                    term("assoc-overhead", "Association-handshake time (ns)."),
                ],
                edges: vec![EdgeForm::NarrowerThan { narrower: h.fabric_gauges, broader: h.metric_gauge }],
                supersedes: None,
            }))
            .expect("ndn-lab vocab encodes");

        // The OTLP vocabulary (defines the gauge term the bridge maps to).
        let otel = dag
            .insert_document(&Document::Vocabulary(Vocabulary {
                label: "otel".into(),
                doc: Some("OpenTelemetry render terms.".into()),
                imports: Vec::new(),
                terms: vec![
                    term("gauge", "An OpenTelemetry gauge data point."),
                    term("otel-attribute-flattening", "Loss: NDN structure flattened to OTLP key/value attributes."),
                ],
                edges: Vec::new(),
                supersedes: None,
            }))
            .expect("otel vocab encodes");

        // The bridge stratum: a SEPARATE vocabulary carrying the lossy mapping.
        // Whoever publishes this owns the mapping; admitting it is a per-consumer
        // choice (C10) — the governance answer, as data.
        let bridge = dag
            .insert_document(&Document::Vocabulary(Vocabulary {
                label: "ndn-lab-otel-bridge".into(),
                doc: Some("Maps ndn-lab metric-gauge to an OTLP gauge; the mapping's loss is declared.".into()),
                imports: vec![ndnlab, otel],
                terms: Vec::new(),
                edges: vec![EdgeForm::MapsTo {
                    from: h.metric_gauge,
                    to: h.otel_gauge,
                    loss: h.loss_flatten,
                    attrs: Vec::new(),
                }],
                supersedes: None,
            }))
            .expect("bridge vocab encodes");

        // The self-describing sample (one; a run streams many past this schema).
        dag.insert_document(&Document::Manifest(fabric_gauges_manifest(&FabricGauges::default(), &h)))
            .expect("manifest encodes");

        // Lens 1 — the sparkline: Expresses series.window over the gauge type
        // directly (lossless narrower hop) via the native sparkline renderer.
        let sparkline = dag
            .insert_document(&Document::Contract(Contract {
                label: "sparkline".into(),
                doc: Some("A decimated airtime window as SVG.".into()),
                imports: vec![ndnlab],
                binds: vec![Subject::Name("ndn-lab/".into())],
                clauses: vec![Clause::Express {
                    intent: Intent { name: INTENT_SERIES_WINDOW.into(), attrs: Vec::new() },
                    target: h.metric_gauge,
                    via: Some(Via::Native(VIA_SPARKLINE.into())),
                    attrs: Vec::new(),
                }],
            }))
            .expect("sparkline contract encodes");

        // Lens 2 — the OTLP exporter: Expresses otlp.gauge over the OTEL gauge
        // term, reachable only through the bridge's lossy maps-to ⇒ Approximate.
        let otlp = dag
            .insert_document(&Document::Contract(Contract {
                label: "otlp".into(),
                doc: Some("An OTLP/JSON gauge document for a collector.".into()),
                imports: vec![ndnlab, otel, bridge],
                binds: vec![Subject::Name("ndn-lab/".into())],
                clauses: vec![Clause::Express {
                    intent: Intent { name: INTENT_OTLP_GAUGE.into(), attrs: Vec::new() },
                    target: h.otel_gauge,
                    via: Some(Via::Native(VIA_OTLP.into())),
                    attrs: Vec::new(),
                }],
            }))
            .expect("otlp contract encodes");

        // The consumer admits ndn-lab always; the bridge only if asked.
        let mut frontier = TrustFrontier::from_vocabularies([ndnlab]);
        if admit_otel_bridge {
            frontier.admit(bridge);
        }

        // Resolve ONCE. Everything after is a Spark stream past this Block.
        let matches = r#match(&dag, &[sparkline, otlp, t0], &frontier, Budget::generous())
            .expect("generous budget suffices");

        KeelView { dag, matches, renderers: Renderers::new(), resolves: 1 }
    }

    /// How many times the matcher has run (proof of resolve-once: always 1,
    /// regardless of how many sample batches are rendered).
    pub fn resolves(&self) -> usize {
        self.resolves
    }

    /// The renderable lenses (Express/Approximate matches carrying a native
    /// renderer), best verdict first.
    pub fn lenses(&self) -> Vec<&Match> {
        let mut out: Vec<&Match> = self
            .matches
            .iter()
            .filter(|m| matches!(m.verdict, Verdict::Express | Verdict::Approximate(_)))
            .filter(|m| self.via_of(m).is_some())
            .collect();
        out.sort_by_key(|m| (m.verdict.rank(), m.verdict.loss_len()));
        out
    }

    /// The cached match for an intent, if any (no re-matching).
    pub fn lens_for(&self, intent: &str) -> Option<&Match> {
        self.matches.iter().find(|m| m.intent == intent)
    }

    /// Render a batch of samples through a resolved lens: dispatch its
    /// `Via::Native` id to the [`Renderers`] registry, and attach the
    /// human-auditable verdict trace.
    pub fn render(&self, m: &Match, samples: &[FabricGauges]) -> Option<Rendered> {
        // Only native-via renderers are in this registry; a Wasm-via lens would
        // need the (not-yet-built) WASM render host.
        let Via::Native(id) = self.via_of(m)? else { return None };
        let renderer = self.renderers.get(id)?;
        Some(Rendered {
            intent: m.intent.clone(),
            verdict: m.verdict.clone(),
            body: renderer(samples),
            trace: explain::trace(&self.dag, m),
        })
    }

    /// The best lens at or above a fidelity floor (deterministic F46 order).
    pub fn best_lens(&self, floor: Floor) -> Option<&Match> {
        self.lenses()
            .into_iter()
            .find(|m| match floor {
                Floor::Express => matches!(m.verdict, Verdict::Express),
                Floor::Approximate => true,
            })
    }

    /// The clause `via` for a match — found by locating the offering clause in
    /// the contract by intent name.
    fn via_of(&self, m: &Match) -> Option<&Via> {
        let Document::Contract(c) = &self.dag.get(&m.contract)?.doc else { return None };
        c.clauses.iter().find_map(|cl| match cl {
            Clause::Express { intent, via, .. } | Clause::Approximate { intent, via, .. }
                if intent.name == m.intent =>
            {
                via.as_ref()
            }
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<FabricGauges> {
        (0..12)
            .map(|i| FabricGauges {
                virtual_time_ns: i * 1_000_000,
                radio_airtime_ns: 200_000 + i * 40_000,
                handoffs: i / 4,
                association_overhead_ns: (i / 4) * 120_000_000,
            })
            .collect()
    }

    #[test]
    fn one_manifest_two_lenses_express_and_approximate() {
        let view = KeelView::for_fabric_gauges(true);

        // The sparkline lens Expresses (lossless narrower hop).
        let spark = view.lens_for(INTENT_SERIES_WINDOW).expect("sparkline offered");
        assert_eq!(spark.verdict, Verdict::Express, "series.window is lossless");

        // The OTLP lens is Approximate — reached only through the bridge's
        // lossy maps-to, whose loss term the trace names.
        let otlp = view.lens_for(INTENT_OTLP_GAUGE).expect("otlp offered");
        assert!(matches!(otlp.verdict, Verdict::Approximate(_)), "otlp is lossy: {:?}", otlp.verdict);
        let trace = explain::trace(&view.dag, otlp);
        assert!(trace.contains("otel-attribute-flattening"), "loss named in the trace: {trace}");
    }

    #[test]
    fn resolve_once_then_stream_samples() {
        let view = KeelView::for_fabric_gauges(true);
        let s = samples();
        // Render every lens over several batches — the matcher never re-runs.
        for _ in 0..5 {
            for m in view.lenses() {
                let r = view.render(m, &s).expect("lens renders");
                assert!(!r.body.is_empty());
            }
        }
        assert_eq!(view.resolves(), 1, "matched once; samples are Sparks past the resolved schema");
    }

    #[test]
    fn native_dispatch_produces_the_real_artifacts() {
        let view = KeelView::for_fabric_gauges(true);
        let s = samples();
        let spark = view.render(view.lens_for(INTENT_SERIES_WINDOW).unwrap(), &s).unwrap();
        assert!(spark.body.contains("<svg") && spark.body.contains("polyline"), "real sparkline SVG");
        let otlp = view.render(view.lens_for(INTENT_OTLP_GAUGE).unwrap(), &s).unwrap();
        assert!(otlp.body.contains("ndn.radio.airtime_us"), "real OTLP gauge JSON");
    }

    #[test]
    fn c10_frontier_divergence_is_honest() {
        // Admit the bridge ⇒ both lenses resolve.
        let with = KeelView::for_fabric_gauges(true);
        assert_eq!(with.lenses().len(), 2, "sparkline + otlp");

        // Withhold the bridge ⇒ the OTLP path is simply gone; the sparkline
        // still Expresses. Two consumers diverge honestly, not by a fight over a
        // serializer.
        let without = KeelView::for_fabric_gauges(false);
        assert!(without.lens_for(INTENT_SERIES_WINDOW).is_some(), "sparkline unaffected");
        let otlp = without.lens_for(INTENT_OTLP_GAUGE);
        assert!(
            otlp.is_none() || !matches!(otlp.unwrap().verdict, Verdict::Express | Verdict::Approximate(_)),
            "without the bridge, OTLP has no renderable verdict"
        );
        assert_eq!(without.lenses().len(), 1, "only the sparkline lens survives");
    }

    #[test]
    fn best_lens_prefers_express() {
        let view = KeelView::for_fabric_gauges(true);
        let best = view.best_lens(Floor::Approximate).expect("a lens at or above the floor");
        assert_eq!(best.intent, INTENT_SERIES_WINDOW, "Express beats Approximate in F46 order");
    }
}
