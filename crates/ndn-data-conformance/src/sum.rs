//! The cases' evaluators for answers (`ndn_data::answer`): `/conformance/eval/sum/v=1` and
//! `/conformance/eval/sum/v=2`.
//!
//! The definition is a version of a collection whose field `inputs` lists collection names
//! (comma separated). The evaluator reads the newest version of each, sums their integer field
//! `n` — `v=2` adds one per input — and answers the sum as decimal text. A hostile program
//! ([`Sum::lax`]) registers the name of `v=1` and answers one too many.
//!
//! Every evaluation of a sum is counted ([`evaluations`]), and [`slow`] takes its time to plan
//! its first answer ([`overlaps`] counts plans that began while another was in progress): the
//! cases that ask a device for an answer read these to see what the asked device did. The
//! counters are the process's: a case runs alone in it, and reads the difference between two
//! looks.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_data::{
    AnswerConfig, AnswerPolicy, Definition, EvalError, Evaluator, Evaluators, Got, Name, Payload,
    PlanError, ReadView, Reads, Signers,
};

use crate::provider::Program;

/// Evaluations made so far, by any device.
static EVALUATIONS: AtomicU64 = AtomicU64::new(0);
/// Plans of [`slow`] begun while another was in progress.
static OVERLAPS: AtomicU64 = AtomicU64::new(0);
/// Plans of [`slow`] in progress now.
static PLANNING: AtomicU64 = AtomicU64::new(0);

/// How long [`slow`] takes to plan, until it has evaluated once: longer than a device takes to
/// receive a second ask sent at the same moment, shorter than the pause a refusal asks for.
const SLOW: Duration = Duration::from_millis(300);

/// How many times a sum has been evaluated, on any device, in this process.
pub fn evaluations() -> u64 {
    EVALUATIONS.load(Ordering::SeqCst)
}

/// How many plans of [`slow`] began while another was in progress, on any device, in this
/// process: nonzero once a device works on two asks for its answer at the same time.
pub fn overlaps() -> u64 {
    OVERLAPS.load(Ordering::SeqCst)
}

/// The name of the evaluator `v`: `/conformance/eval/sum/v=<v>`.
pub fn name(v: u64) -> Name {
    format!("/conformance/eval/sum/v={v}")
        .parse()
        .expect("a valid name")
}

/// The function name of the cases' provider: `/conformance/fn/summarize/v=<v>`.
pub fn function(v: u64) -> Name {
    format!("/conformance/fn/summarize/v={v}")
        .parse()
        .expect("a valid name")
}

/// The name of the evaluator whose result is 200 KiB: `/conformance/eval/big/v=1`.
pub fn big() -> Name {
    "/conformance/eval/big/v=1".parse().expect("a valid name")
}

/// The name of the evaluator that plans slowly: `/conformance/eval/slow/v=1`.
pub fn slow() -> Name {
    "/conformance/eval/slow/v=1".parse().expect("a valid name")
}

/// An evaluator that reads nothing but its definition and answers 200 KiB, so an answer travels
/// in pieces.
struct Big(Name);

#[async_trait::async_trait]
impl Evaluator for Big {
    fn evaluator(&self) -> &Name {
        &self.0
    }

    async fn plan(&self, _: &Definition, _: &mut dyn Reads) -> Result<(), PlanError> {
        Ok(())
    }

    fn evaluate(&self, _: &Definition, _: &dyn ReadView) -> Result<Bytes, EvalError> {
        Ok(Bytes::from(vec![0x5A; 200 * 1024]))
    }
}

/// One version of the evaluator.
pub struct Sum {
    name: Name,
    plus: i64,
    lax: i64,
}

impl Sum {
    /// `/conformance/eval/sum/v=<v>` as written.
    pub fn version(v: u64) -> Arc<dyn Evaluator> {
        Arc::new(Sum {
            name: name(v),
            plus: i64::from(v == 2),
            lax: 0,
        })
    }

    /// The name of `v=1`, a result one too high.
    pub fn lax() -> Arc<dyn Evaluator> {
        Arc::new(Sum {
            name: name(1),
            plus: 0,
            lax: 1,
        })
    }
}

fn inputs(def: &Definition) -> Result<Vec<Name>, EvalError> {
    let Got::Version(v) = &def.got else {
        return Err(EvalError::Refused("the definition is a version".into()));
    };
    let Payload::Entry(c) = &v.payload else {
        return Err(EvalError::Refused("the definition is one entry".into()));
    };
    let list = c
        .get("inputs")
        .ok_or_else(|| EvalError::Refused("the definition has no field inputs".into()))?;
    Ok(String::from_utf8_lossy(list)
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect())
}

#[async_trait::async_trait]
impl Evaluator for Sum {
    fn evaluator(&self) -> &Name {
        &self.name
    }

    async fn plan(&self, def: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError> {
        for c in inputs(def)? {
            let (r, _) = reads.current(&c).await?;
            reads.read(&r).await?;
        }
        Ok(())
    }

    fn evaluate(&self, def: &Definition, view: &dyn ReadView) -> Result<Bytes, EvalError> {
        EVALUATIONS.fetch_add(1, Ordering::SeqCst);
        let mut total = self.lax;
        for c in inputs(def)? {
            let r = view.current(&c)?;
            let Got::Version(v) = view.read(r)? else {
                return Err(EvalError::Refused("an input is a version".into()));
            };
            let Payload::Entry(content) = &v.payload else {
                return Err(EvalError::Refused("an input is one entry".into()));
            };
            let n: i64 = content
                .get("n")
                .and_then(|b| String::from_utf8_lossy(b).parse().ok())
                .ok_or_else(|| EvalError::Refused("an input has an integer n".into()))?;
            total += n + self.plus;
        }
        Ok(Bytes::from(total.to_string()))
    }
}

/// `/conformance/eval/slow/v=1`: the sum of `v=1` that takes [`SLOW`] to plan, in the time the
/// network runs on, until it has evaluated once — so that a device asked for its answer is
/// working on the first ask while others arrive. Once it has evaluated, planning is as quick as
/// the sum's.
struct Slow {
    sum: Sum,
    name: Name,
    evaluated: AtomicBool,
}

impl Slow {
    fn fresh() -> Arc<dyn Evaluator> {
        Arc::new(Slow {
            sum: Sum {
                name: slow(),
                plus: 0,
                lax: 0,
            },
            name: slow(),
            evaluated: AtomicBool::new(false),
        })
    }
}

/// One more plan in progress, counted until dropped.
struct Planning;

impl Planning {
    fn begin() -> Planning {
        if PLANNING.fetch_add(1, Ordering::SeqCst) > 0 {
            OVERLAPS.fetch_add(1, Ordering::SeqCst);
        }
        Planning
    }
}

impl Drop for Planning {
    fn drop(&mut self) {
        PLANNING.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Evaluator for Slow {
    fn evaluator(&self) -> &Name {
        &self.name
    }

    async fn plan(&self, def: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError> {
        let _planning = Planning::begin();
        if !self.evaluated.load(Ordering::SeqCst) {
            tokio::time::sleep(SLOW).await;
        }
        self.sum.plan(def, reads).await
    }

    fn evaluate(&self, def: &Definition, view: &dyn ReadView) -> Result<Bytes, EvalError> {
        let result = self.sum.evaluate(def, view);
        self.evaluated.store(true, Ordering::SeqCst);
        result
    }
}

/// What a device running `program` knows of evaluators, and its answer policy. The cases'
/// provider is Alice's laptop.
pub fn host(program: Program) -> (Evaluators, AnswerConfig) {
    let providers = vec![(
        function(1),
        Signers::Devices(vec![
            "/alice/laptop".parse().expect("a valid name"),
            "/summarizer/service".parse().expect("a valid name"),
        ]),
    )];
    let known = |evaluators: Vec<Arc<dyn Evaluator>>| {
        evaluators
            .into_iter()
            .fold(Evaluators::none(), |e, x| e.with(x))
    };
    let config = |policy: AnswerPolicy| AnswerConfig {
        policy,
        ..AnswerConfig::default()
    };
    let default = AnswerPolicy {
        providers: providers.clone(),
        ..AnswerPolicy::default()
    };
    let wary = AnswerPolicy {
        pure: Signers::None,
        providers: providers.clone(),
        ..AnswerPolicy::default()
    };
    match program {
        Program::Evaluating => (
            known(vec![
                Sum::version(1),
                Sum::version(2),
                Arc::new(Big(big())),
                Slow::fresh(),
            ]),
            config(default),
        ),
        Program::EvaluatingV2 => (known(vec![Sum::version(2)]), config(wary)),
        Program::Hostile => (known(vec![Sum::lax()]), config(default)),
        Program::Wary => (known(vec![]), config(wary)),
        Program::Element | Program::Standard | Program::LaxElement => {
            (Evaluators::none(), config(AnswerPolicy::default()))
        }
    }
}
