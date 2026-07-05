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

use ndn_manifest::model::{
    Clause, Contract, Document, EdgeForm, Intent, Subject, Term, Vocabulary,
};
use ndn_manifest::{term_hash, FrozenDag};
use ndn_render_contract::{
    contract_via, r#match, Budget, Floor, Match, TrustFrontier, Verdict, Via,
};

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
        let mut dag = FrozenDag::new();

        // The kernel trio rides in every DAG (R14) and gives the total floor.
        let fp = ndn_manifest::kernel::fixed_point();
        dag.insert_bytes(&fp.im0_bytes).expect("IM₀ decodes");
        let t0 = dag.insert_bytes(&fp.t0_bytes).expect("T₀ decodes");

        // Render-side terms (NOT the producer's self-description — these are the
        // lens's concern, so they stay hand-authored per Law #1).
        let metric_gauge = term_hash(&term("metric-gauge", "A renderable numeric gauge over virtual time.")).unwrap();
        let otel_gauge = term_hash(&term("gauge", "An OpenTelemetry gauge data point.")).unwrap();
        let loss_flatten = term_hash(&term("otel-attribute-flattening", "Loss: NDN structure flattened to OTLP key/value attributes.")).unwrap();

        // The ndn-lab telemetry vocabulary: the DESCRIBE terms come from the
        // derive (`FabricGauges::manifest_terms()` — retired the hand-built list),
        // plus the render target it narrows to.
        let mut ndnlab_terms = FabricGauges::manifest_terms();
        ndnlab_terms.push(term("metric-gauge", "A renderable numeric gauge over virtual time."));
        let ndnlab = dag
            .insert_document(&Document::Vocabulary(Vocabulary {
                label: "ndn-lab".into(),
                doc: Some("ndn-lab telemetry: derived fabric-gauge terms + their renderable form.".into()),
                imports: Vec::new(),
                terms: ndnlab_terms,
                edges: vec![EdgeForm::NarrowerThan { narrower: FabricGauges::schema(), broader: metric_gauge }],
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
                    from: metric_gauge,
                    to: otel_gauge,
                    loss: loss_flatten,
                    attrs: Vec::new(),
                }],
                supersedes: None,
            }))
            .expect("bridge vocab encodes");

        // The self-describing sample, straight from the derive (one; a run streams
        // many past this schema).
        dag.insert_document(&Document::Manifest(
            FabricGauges::default().to_manifest_default().expect("all-integer gauges never refuse"),
        ))
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
                    target: metric_gauge,
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
                    target: otel_gauge,
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
            .filter(|m| contract_via(&self.dag, m).is_some())
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
        // `contract_via` (F54) owns the walk back to the emitting clause,
        // including path-final-hop disambiguation. Only native-via renderers are
        // in this registry; a Wasm-via lens needs the (unbuilt) WASM host.
        let Via::Native(id) = contract_via(&self.dag, m)? else { return None };
        let renderer = self.renderers.get(id)?;
        Some(Rendered {
            intent: m.intent.clone(),
            verdict: m.verdict.clone(),
            body: renderer(samples),
            trace: ndn_explain::trace(&self.dag, m),
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
}

// ═════════════════════════════════════════════════════════════════════════════
// The topology slice — the nested producer, now DERIVED.
//
// SceneView's hand-woven vocabulary (the scene-node/scene-link record terms, the
// field terms, the whole nested manifest) is retired onto `#[derive(Manifest)]`
// on the real scene types: SceneSnapshot::manifest_terms()/schema()/
// to_manifest_default() (see crate::scene). Only the render-side term
// (topology-map) and the narrower edge stay hand-authored — that's the lens's
// concern, not the producer's self-description (Law #1).
// ═════════════════════════════════════════════════════════════════════════════

use ndn_manifest_describe::DescribeError;

use crate::scene::SceneSnapshot;

const VIA_TOPOLOGY: &str = "ndn-lab/topology-svg";
/// The topology-map render intent.
pub const INTENT_TOPOLOGY_MAP: &str = "topology.map";

/// A resolved topology lens over a scene snapshot — the nested-manifest twin of
/// [`KeelView`], kept separate because its renderer consumes a `SceneSnapshot`,
/// not a gauge stream (unifying the two registries is a decision for *after* the
/// derive is designed against both, not before).
pub struct SceneView {
    dag: FrozenDag,
    matches: Vec<Match>,
    /// The encoded manifest bytes — proof the nested Values canonically encode.
    manifest_bytes: Vec<u8>,
    render: fn(&SceneSnapshot) -> String,
}

impl SceneView {
    /// Assemble the scene DAG (the derived scene vocabulary + the topology render
    /// term + the scene manifest + the contract) and resolve the lens once.
    pub fn for_scene(scene: &SceneSnapshot) -> Result<Self, DescribeError> {
        // Render-side (Law #1): the renderable target the scene type narrows to.
        let map = term_hash(&term("topology-map", "A renderable network map.")).unwrap();

        let mut dag = FrozenDag::new();
        let fp = ndn_manifest::kernel::fixed_point();
        dag.insert_bytes(&fp.im0_bytes).expect("IM₀");
        let t0 = dag.insert_bytes(&fp.t0_bytes).expect("T₀");

        // The DESCRIBE terms (scene marker, field terms, nested scene-node /
        // scene-link / radio-link / scene-bounds records) come from the derive;
        // only the render target is hand-added.
        let mut terms = SceneSnapshot::manifest_terms();
        terms.push(term("topology-map", "A renderable network map."));
        let vocab = dag
            .insert_document(&Document::Vocabulary(Vocabulary {
                label: "ndn-lab-scene".into(),
                doc: Some("Derived scene terms + their renderable map.".into()),
                imports: Vec::new(),
                terms,
                edges: vec![EdgeForm::NarrowerThan { narrower: SceneSnapshot::schema(), broader: map }],
                supersedes: None,
            }))
            .expect("scene vocab encodes");

        // The self-describing manifest, straight from the derive.
        let manifest = scene.to_manifest_default()?;
        let manifest_bytes = ndn_manifest::canon::encode_document(&Document::Manifest(manifest.clone()))
            .expect("nested manifest encodes canonically");
        dag.insert_document(&Document::Manifest(manifest)).expect("manifest inserts");

        let topo = dag
            .insert_document(&Document::Contract(Contract {
                label: "topology-svg".into(),
                doc: Some("The scene as an SVG network map.".into()),
                imports: vec![vocab],
                binds: vec![Subject::Name("ndn-lab/".into())],
                clauses: vec![Clause::Express {
                    intent: Intent { name: INTENT_TOPOLOGY_MAP.into(), attrs: Vec::new() },
                    target: map,
                    via: Some(Via::Native(VIA_TOPOLOGY.into())),
                    attrs: Vec::new(),
                }],
            }))
            .expect("topology contract encodes");

        let frontier = TrustFrontier::from_vocabularies([vocab]);
        let matches = r#match(&dag, &[topo, t0], &frontier, Budget::generous()).expect("budget");
        Ok(SceneView { dag, matches, manifest_bytes, render: render_topology_lens })
    }

    /// The resolved topology lens, if the matcher admitted it.
    pub fn topology_lens(&self) -> Option<&Match> {
        self.matches.iter().find(|m| m.intent == INTENT_TOPOLOGY_MAP)
    }

    /// Render a scene through the resolved lens (native dispatch + explain trace).
    pub fn render(&self, m: &Match, scene: &SceneSnapshot) -> Option<Rendered> {
        let Via::Native(_) = contract_via(&self.dag, m)? else { return None };
        Some(Rendered {
            intent: m.intent.clone(),
            verdict: m.verdict.clone(),
            body: (self.render)(scene),
            trace: ndn_explain::trace(&self.dag, m),
        })
    }

    /// The canonically-encoded nested manifest bytes (round-trip proof).
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
}

fn render_topology_lens(scene: &SceneSnapshot) -> String {
    crate::scene::render_topology_svg(scene, 480, 320)
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
        let trace = ndn_explain::trace(&view.dag, otlp);
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

    // ── the nested topology slice ────────────────────────────────────────────

    fn scene() -> SceneSnapshot {
        use crate::scene::{SceneBounds, SceneLink, SceneNode};
        SceneSnapshot {
            virtual_time_ns: 5_000_000,
            nodes: vec![
                SceneNode { id: 0, label: "consumer".into(), x: 0.0, y: 0.0, faces: 1, pit_depth: 2, cs_hit_rate: 0.5, in_interests: 3, out_data: 1 },
                SceneNode { id: 1, label: "producer".into(), x: 10.0, y: 5.0, faces: 2, pit_depth: 0, cs_hit_rate: 0.0, in_interests: 1, out_data: 3 },
            ],
            links: vec![
                SceneLink { from: 0, to: 1, distance_m: Some(11.18) }, // Some ⇒ 1-element list
                SceneLink { from: 1, to: 0, distance_m: None },        // None ⇒ empty list
            ],
            radio_links: Vec::new(),
            bounds: SceneBounds { min_x: 0.0, min_y: 0.0, max_x: 10.0, max_y: 5.0 },
        }
    }

    #[test]
    fn nested_scene_manifest_expresses_topology_and_renders_svg() {
        let s = scene();
        let view = SceneView::for_scene(&s).expect("finite scene describes");
        let m = view.topology_lens().expect("topology.map offered");
        assert_eq!(m.verdict, Verdict::Express, "scene narrows to topology-map losslessly");
        let r = view.render(m, &s).expect("renders");
        assert!(r.body.contains("<svg") && r.body.contains("</svg>"), "real topology SVG");
    }

    #[test]
    fn non_finite_coordinate_is_refused_not_zeroed() {
        // F55-B: a NaN position has no honest decimal — describing it must fail,
        // not silently encode 0 (which would poison a downstream aggregate).
        let mut s = scene();
        s.nodes[0].x = f64::NAN;
        match SceneView::for_scene(&s) {
            Err(e) => assert_eq!(e, DescribeError::NonFinite { field: "x" }, "NaN refused, never a guess"),
            Ok(_) => panic!("a NaN coordinate must not describe"),
        }
    }

    #[test]
    fn nested_manifest_encodes_canonically_and_round_trips() {
        // The lists-of-records + optional-as-list encode to canonical bytes and
        // decode∘encode is byte identity — the discipline the flat gauge skipped.
        let s = scene();
        let view = SceneView::for_scene(&s).expect("finite scene describes");
        let bytes = view.manifest_bytes();
        assert!(!bytes.is_empty(), "nested manifest encoded");
        let decoded = ndn_manifest::canon::decode_document(bytes).expect("decodes");
        let reencoded = ndn_manifest::canon::encode_decoded(&decoded).expect("re-encodes");
        assert_eq!(bytes, reencoded.as_slice(), "decode ∘ encode is byte identity (R13)");
    }

    // ── the retirement: producers derive; the schema is frozen by a pin ──────
    //
    // The hand-built vocabularies are gone — the real FabricGauges / SceneSnapshot
    // now describe themselves via #[derive(Manifest)]. The byte-identity gate is
    // replaced by the freeze pattern: pin the derived schema hashes, so a field
    // reorder or a doc edit (which silently mints a NEW term — the L-07 fork)
    // turns red and demands a deliberate version, not an accident.
    use crate::scene::{RadioLink, SceneBounds, SceneLink, SceneNode};

    fn hex(h: &ndn_manifest::hash::Hash) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn derived_schema_is_deterministic_and_frozen() {
        // Determinism: the same annotated struct always hashes the same.
        assert_eq!(FabricGauges::schema(), FabricGauges::schema());
        assert_eq!(SceneSnapshot::schema(), SceneSnapshot::schema());

        // Freeze pins (regenerate deliberately if a schema is intentionally versioned).
        assert_eq!(hex(&FabricGauges::schema()), "d58bdcdc5bd70f4e662d6996178e308d0f46e5becdc48bd7219aff72ec894570");
        assert_eq!(hex(&SceneSnapshot::schema()), "badb3407d302e2ec2ab56b43f52846ad720f35194445f51467e2f1ea766d902e");
        assert_eq!(hex(&SceneNode::record_schema()), "fbc93f3a1528f6910cbda5c70d8f5f5cc2ed2400df6b20a3c6b1d07717bee949");
        assert_eq!(hex(&SceneLink::record_schema()), "d3253e38b57e0a409cbdff01dbf2cbcfef875fa5fc39c3e3960c2a6fa1f7a46b");
        assert_eq!(hex(&RadioLink::record_schema()), "b709ea9594f6893f1d4bcaa18ec6ba03da51683806133328d405d2f4049390ba");
        assert_eq!(hex(&SceneBounds::record_schema()), "bccb0b687f58b7e3cebdfa312e02d1c38203e5d9eb71d2a7f83af20fbdf64ec7");
    }

    #[test]
    fn derived_producers_encode_canonically() {
        // Flat (FabricGauges) and nested (SceneSnapshot) both derive a manifest
        // that canonically round-trips — decode ∘ encode is byte identity (R13).
        let g = FabricGauges { virtual_time_ns: 5_000_000, radio_airtime_ns: 7_405_000, handoffs: 2, association_overhead_ns: 240_000_000 };
        for m in [g.to_manifest_default().expect("gauges never refuse"), scene().to_manifest_default().expect("finite scene")] {
            let bytes = ndn_manifest::canon::encode_document(&Document::Manifest(m)).unwrap();
            let decoded = ndn_manifest::canon::decode_document(&bytes).unwrap();
            let re = ndn_manifest::canon::encode_decoded(&decoded).unwrap();
            assert_eq!(bytes, re, "derived manifest canonically round-trips");
        }
        // The derive walks the whole struct: scene describes all five fields.
        assert_eq!(SceneSnapshot::field_terms().len(), 5);
        assert_eq!(FabricGauges::field_terms().len(), 4);
    }
}
