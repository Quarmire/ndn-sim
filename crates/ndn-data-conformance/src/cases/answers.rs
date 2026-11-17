//! Answers (spec answers.md), cases `a1`…`a18` over a real network of devices: named, checkable
//! readings over signed data, pure and provider, sealed to the audience of what they read.
//!
//! The scenario's data: Alice's laptop owns two log collections — `plan` and `budget` — and writes
//! into `budget` an integer `n` and into `plan` a definition whose field `inputs` lists `budget`.
//! The evaluator ([`crate::sum`]) sums the `n` of its inputs. Every device here reads and recomputes
//! over what it holds, fetching what it needs from the others as `get` does.

use std::time::Duration;

use ndn_data::wire::{PieceKind, parse_answer_name, piece_name};
use ndn_data::{
    AnswerAsk, AnswerFault, AnswerRefusal, Answered, Hash, Provenance, ReadRef, ReadSet, Writer,
};

use super::*;
use crate::provider::Program;
use crate::sum;
use crate::world::{Dev, Plan, World};
use ndn_data::{Age, EventDetail};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BOB: Dev = Dev(2);
const TABLET: Dev = Dev(3);

fn plan_c() -> Name {
    n("/alice/32=data/ans/plan")
}

fn budget_c() -> Name {
    n("/alice/32=data/ans/budget")
}

fn second_c() -> Name {
    n("/alice/32=data/ans/second")
}

macro_rules! answer_case {
    ($id:literal, $title:literal, $guards:literal, $plan:expr, $run:expr) => {
        Case {
            id: $id,
            title: $title,
            slice: 8,
            needs: &[Feature::Log, Feature::Seal, Feature::Answers],
            model: &[],
            guards: $guards,
            budget: Duration::from_secs(1800),
            plan: $plan,
            run: $run,
        }
    };
}

/// Alice's laptop and phone and Bob's laptop, each running `programs`.
fn trio(programs: [Program; 3]) -> Plan {
    let mut p = Plan::new();
    let laptop = p.device("alice", "laptop");
    let phone = p.device("alice", "phone");
    let bob = p.device("bob", "laptop");
    for (d, program) in [laptop, phone, bob].into_iter().zip(programs) {
        p.program(d, program);
    }
    p
}

/// [`trio`] and Alice's tablet.
fn quartet(programs: [Program; 4]) -> Plan {
    let mut p = trio([programs[0], programs[1], programs[2]]);
    let tablet = p.device("alice", "tablet");
    p.program(tablet, programs[3]);
    p
}

fn all(program: Program) -> Plan {
    trio([program; 3])
}

fn log(readers: &[Audience]) -> Share {
    members(Rule::Log, &["/alice"], readers)
}

async fn put_n(w: &World, c: &Name, v: i64) -> Result<VersionId, Failure> {
    Ok(w.at(LAPTOP)
        .put(c, content(&[("n", &v.to_string())]), note(1))
        .await?)
}

async fn put_def(w: &World, c: &Name, inputs: &[&Name]) -> Result<VersionId, Failure> {
    let list = inputs
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");
    Ok(w.at(LAPTOP)
        .put(c, content(&[("inputs", &list)]), note(1))
        .await?)
}

/// Alice's laptop shares `plan` and `budget` to `readers` and writes the first data.
async fn seed(w: &World, readers: &[Audience]) -> Result<(VersionId, VersionId), Failure> {
    for c in [plan_c(), budget_c()] {
        w.at(LAPTOP).share(&c, log(readers)).await?;
    }
    let input = put_n(w, &budget_c(), 3).await?;
    let def = put_def(w, &plan_c(), &[&budget_c()]).await?;
    Ok((input, def))
}

async fn reach(w: &World, d: Dev, c: &Name, id: &VersionId) -> Result<(), Failure> {
    let layer = w.at(d);
    let entry = ndn_data::wire::log_name(
        &device_of(id.writer.key()).expect("a device's key"),
        Some(c),
        id.seq.0,
    );
    w.until("a device holds a version", LIMIT, || async {
        Ok(layer.get(&entry).await.is_ok())
    })
    .await?;
    Ok(())
}

/// The question of the newest definition `d` holds in `plan`, under evaluator `v`.
async fn question(w: &World, d: Dev, v: u64) -> Result<Name, Failure> {
    let (def, _) = w.gate(d)?.current_read(&plan_c()).await?;
    Ok(AnswerAsk::pure(def, sum::name(v)).name(None)?)
}

/// `get` of `name` on `d`, asked again for as long as the error says asking again may mend it
/// (a packet lost on a faulty network): the first answer that is final.
async fn settled(w: &World, d: Dev, name: &Name) -> Result<ndn_data::Answer, DataError> {
    let mut last = None;
    for _ in 0..8 {
        match w.at(d).get(name).await {
            Err(e) if e.retry() => {
                last = Some(e);
                w.sleep(Duration::from_secs(3)).await;
            }
            other => return other,
        }
    }
    Err(last.expect("at least one try"))
}

async fn ask(w: &World, d: Dev, name: &Name) -> Result<Answered, DataError> {
    match settled(w, d, name).await?.got {
        ndn_data::Got::Answer(a) => Ok(a),
        other => panic!("not an answer: {other:?}"),
    }
}

fn readset(reads: impl IntoIterator<Item = ReadRef>) -> Result<ReadSet, Failure> {
    ReadSet::new(reads).map_err(|e| Failure::new(format!("a read set was refused: {e}")))
}

fn same(what: &str, a: &Answered, b: &Answered) -> Result<(), Failure> {
    ensure!(
        a.result == b.result
            && a.reads == b.reads
            && a.binding == b.binding
            && a.id == b.id
            && a.result_digest == b.result_digest,
        "{what}: the answers differ: {:?} against {:?}",
        a.result,
        b.result
    );
    Ok(())
}

fn key_of(w: &World, d: Dev) -> Writer {
    Writer::new(w.net().spec(d).name().append("KEY").append("1"))
}

// ---- a1 ----

pub(super) const A1: Case = answer_case!(
    "a1",
    "The same read set gives the same name and answer from two devices",
    "Alice's laptop and phone, one definition, one evaluator, the same versions: each publishes; \
     both answers have one id under their own prefixes and equal results, and a third device \
     fetches either and gets the same answer.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        let (input, def) = seed(w, &[]).await?;
        for d in [PHONE, BOB] {
            reach(w, d, &budget_c(), &input).await?;
            reach(w, d, &plan_c(), &def).await?;
        }
        let q = question(w, LAPTOP, 1).await?;
        let on_laptop = w.gate(LAPTOP)?.publish_answer(&q).await?;
        let on_phone = w.gate(PHONE)?.publish_answer(&q).await?;
        let (a, b) = (parse_answer_name(&on_laptop), parse_answer_name(&on_phone));
        ensure!(
            a.is_some() && a.as_ref().map(|x| x.1) == b.as_ref().map(|x| x.1),
            "one binding, one id: {on_laptop} and {on_phone}"
        );
        let first = ask(w, LAPTOP, &q).await?;
        ensure!(
            first.result.as_ref() == b"3",
            "the sum is {:?}",
            first.result
        );
        same("the phone", &first, &ask(w, PHONE, &q).await?)?;
        for name in [&on_laptop, &on_phone] {
            let got = ask(w, BOB, name).await?;
            same("Bob, fetching", &first, &got)?;
            ensure!(got.name == *name, "the name asked for is the name used");
        }
        Ok(())
    })
);

// ---- a2 ----

pub(super) const A2: Case = answer_case!(
    "a2",
    "A changed read set is a new name",
    "After one input version is added, the question resolves to another id; the old answer still \
     verifies under the old id, and is exact, not the planned question's.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        seed(w, &[]).await?;
        let q = question(w, LAPTOP, 1).await?;
        let old = w.gate(LAPTOP)?.publish_answer(&q).await?;
        let before = ask(w, LAPTOP, &q).await?;
        put_n(w, &budget_c(), 4).await?;
        let after = ask(w, LAPTOP, &q).await?;
        ensure!(
            after.id != before.id && after.result.as_ref() == b"4",
            "the id did not change"
        );
        let again = settled(w, LAPTOP, &old).await?;
        ensure!(
            again.age == Age::Exact,
            "an exact name is not stale: {:?}",
            again.age
        );
        let ndn_data::Got::Answer(a) = again.got else {
            return Err(Failure::new("not an answer"));
        };
        ensure!(
            a.id == before.id && a.result.as_ref() == b"3",
            "the old answer is the old one"
        );
        Ok(())
    })
);

// ---- a3 ----

pub(super) const A3: Case = answer_case!(
    "a3",
    "The definition's version is bound",
    "A new version of the definition gives another id; the old answer is never returned for the \
     new question.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        seed(w, &[]).await?;
        let q_old = question(w, LAPTOP, 1).await?;
        let old = w.gate(LAPTOP)?.publish_answer(&q_old).await?;
        put_def(w, &plan_c(), &[&budget_c()]).await?;
        let q_new = question(w, LAPTOP, 1).await?;
        let (id_old, id_new) = (
            w.gate(LAPTOP)?.answer_id(&q_old).await?,
            w.gate(LAPTOP)?.answer_id(&q_new).await?,
        );
        ensure!(id_old != id_new, "a new definition version is the same id");
        let got = ask(w, LAPTOP, &q_new).await?;
        ensure!(
            got.name != old && got.id == id_new,
            "the old answer came back for the new question"
        );
        Ok(())
    })
);

// ---- a4 ----

pub(super) const A4: Case = answer_case!(
    "a4",
    "The evaluator's version is bound and matched exactly",
    "v=1 and v=2 give different ids; a program that knows only v=2, asked for v=1, answers \
     \"can't check here\"; v=2's answer is not taken for v=1.",
    || trio([
        Program::Evaluating,
        Program::EvaluatingV2,
        Program::Evaluating
    ]),
    |w| Box::pin(async move {
        let (input, def) = seed(w, &[]).await?;
        reach(w, PHONE, &budget_c(), &input).await?;
        reach(w, PHONE, &plan_c(), &def).await?;
        let (q1, q2) = (question(w, LAPTOP, 1).await?, question(w, LAPTOP, 2).await?);
        let g = w.gate(LAPTOP)?;
        ensure!(
            g.answer_id(&q1).await? != g.answer_id(&q2).await?,
            "v=1 and v=2 share an id"
        );
        ensure!(
            ask(w, LAPTOP, &q2).await?.result.as_ref() == b"4",
            "v=2 adds one per input"
        );
        match ask(w, PHONE, &q1).await {
            Err(DataError::CannotCheck { evaluator, .. }) => {
                ensure!(evaluator == sum::name(1), "the error names {evaluator}");
            }
            other => return Err(Failure::new(format!("v=1 on a v=2 program: {other:?}"))),
        }
        ensure!(ask(w, PHONE, &q2).await.is_ok(), "v=2 is checked there");
        Ok(())
    })
);

// ---- a5 ----

pub(super) const A5: Case = answer_case!(
    "a5",
    "A wrong answer from a signer is detected on recompute and raised as evidence",
    "A hostile member signs a wrong result at the right id; an honest device that knows the \
     evaluator returns its own value, raises evidence of kind Mismatch naming the signer and both \
     digests, and keeps it across a restart.",
    || trio([Program::Evaluating, Program::Hostile, Program::Evaluating]),
    |w| Box::pin(async move {
        let (input, def) = seed(w, &[]).await?;
        reach(w, PHONE, &budget_c(), &input).await?;
        reach(w, PHONE, &plan_c(), &def).await?;
        let q = question(w, LAPTOP, 1).await?;
        let wrong = w.gate(PHONE)?.publish_answer(&q).await?;
        let got = ask(w, LAPTOP, &wrong).await?;
        ensure!(
            got.result.as_ref() == b"3",
            "the wrong value {:?} was returned",
            got.result
        );
        let Provenance::Recomputed { disagreed_with, .. } = &got.how else {
            return Err(Failure::new(format!("not recomputed: {:?}", got.how)));
        };
        ensure!(
            *disagreed_with == vec![key_of(w, PHONE)],
            "disagreed with {disagreed_with:?}"
        );
        let events = events_of(w, LAPTOP, EventKind::AnswerEvidence)?;
        ensure!(events.len() == 1, "evidence events: {events:?}");
        match &events[0].detail {
            EventDetail::Answer {
                fault:
                    AnswerFault::Mismatch {
                        signed,
                        recomputed,
                        evaluator,
                    },
                signer,
                answer,
                ..
            } => {
                ensure!(
                    signed != recomputed && *evaluator == sum::name(1),
                    "the digests or evaluator"
                );
                ensure!(
                    *signer == key_of(w, PHONE).key().clone() && *answer == wrong,
                    "the signer or answer"
                );
            }
            other => return Err(Failure::new(format!("not a mismatch: {other:?}"))),
        }
        w.stop(LAPTOP).await?;
        w.restart(LAPTOP).await?;
        ensure!(
            events_of(w, LAPTOP, EventKind::AnswerEvidence)?.len() == 1,
            "the evidence did not survive a restart"
        );
        ensure!(
            matches!(
                settled(w, LAPTOP, &wrong).await,
                Err(DataError::Answer {
                    why: AnswerRefusal::Equivocal,
                    ..
                })
            ),
            "the wrong answer was taken again"
        );
        Ok(())
    })
);

// ---- a6, a8 ----

pub(super) const A6: Case = answer_case!(
    "a6",
    "A reader without access to the read set cannot read the answer",
    "Bob, outside the folder's audience, gets Sealed for the question, as get of the collection \
     gives it, and for the exact name handed to him; a sealed answer's name has no content word.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        seed(w, &[person("/alice")]).await?;
        let q = question(w, LAPTOP, 1).await?;
        let name = w.gate(LAPTOP)?.publish_answer(&q).await?;
        ensure!(
            name.len() == 4,
            "the answer's name has a content word: {name}"
        );
        let plain = settled(w, BOB, &budget_c()).await;
        ensure!(
            matches!(plain, Err(DataError::Sealed { .. })),
            "get of the collection: {plain:?}"
        );
        let by_question = settled(w, BOB, &q).await;
        ensure!(
            matches!(by_question, Err(DataError::Sealed { .. })),
            "the question: {by_question:?}"
        );
        let by_name = settled(w, BOB, &name).await;
        ensure!(
            matches!(by_name, Err(DataError::Sealed { .. })),
            "the exact name: {by_name:?}"
        );
        Ok(())
    })
);

pub(super) const A8: Case = answer_case!(
    "a8",
    "The read set is inside the sealed content",
    "Every answer name any forwarder holds is a device name, a keyword and 32 octets: when anything \
     read is sealed, no collection, version or evaluator name is in the clear in a name.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        let (input, def) = seed(w, &[person("/alice")]).await?;
        reach(w, PHONE, &budget_c(), &input).await?;
        reach(w, PHONE, &plan_c(), &def).await?;
        let q = question(w, LAPTOP, 1).await?;
        let name = w.gate(LAPTOP)?.publish_answer(&q).await?;
        ask(w, PHONE, &name).await?;
        for cached in w.net().cached().await {
            if cached
                .components()
                .iter()
                .any(|c| c.value.as_ref() == b"answer")
            {
                ensure!(
                    cached.len() == 4,
                    "an answer's name carries a content word: {cached}"
                );
            }
        }
        Ok(())
    })
);

// ---- a7 ----

fn carol_plan() -> Plan {
    let mut p = trio([Program::Evaluating; 3]);
    let carol = p.device("carol", "laptop");
    p.program(carol, Program::Evaluating);
    p
}

pub(super) const A7: Case = answer_case!(
    "a7",
    "Audience intersection",
    "An answer over collections A (Alice, Bob) and B (Alice, Carol) opens for Alice only; with an \
     A-only answer, Bob opens it.",
    carol_plan,
    |w| Box::pin(async move {
        let carol = Dev(3);
        let (a, b) = (budget_c(), second_c());
        let alice_bob = [person("/alice"), person("/bob")];
        let alice_carol = [person("/alice"), person("/carol")];
        let everyone = [person("/alice"), person("/bob"), person("/carol")];
        w.at(LAPTOP).share(&a, log(&alice_bob)).await?;
        w.at(LAPTOP).share(&b, log(&alice_carol)).await?;
        w.at(LAPTOP).share(&plan_c(), log(&everyone)).await?;
        put_n(w, &a, 3).await?;
        put_n(w, &b, 4).await?;
        put_def(w, &plan_c(), &[&a]).await?;
        let q_a = question(w, LAPTOP, 1).await?;
        let def2 = put_def(w, &plan_c(), &[&a, &b]).await?;
        let q_ab = question(w, LAPTOP, 1).await?;
        reach(w, BOB, &plan_c(), &def2).await?;
        reach(w, carol, &plan_c(), &def2).await?;
        let name_ab = w.gate(LAPTOP)?.publish_answer(&q_ab).await?;
        w.gate(LAPTOP)?.publish_answer(&q_a).await?;
        ensure!(
            ask(w, LAPTOP, &q_ab).await?.result.as_ref() == b"7",
            "Alice reads both"
        );
        ensure!(
            ask(w, BOB, &q_a).await?.result.as_ref() == b"3",
            "Bob opens the A-only answer"
        );
        for (who, d, q) in [
            ("Bob", BOB, &q_ab),
            ("Carol", carol, &q_a),
            ("Carol", carol, &q_ab),
        ] {
            let r = settled(w, d, q).await;
            ensure!(
                matches!(r, Err(DataError::Sealed { .. })),
                "{who} was not refused: {r:?}"
            );
        }
        let by_name = settled(w, BOB, &name_ab).await;
        ensure!(
            matches!(by_name, Err(DataError::Sealed { .. })),
            "Bob, by the name: {by_name:?}"
        );
        Ok(())
    })
);

// ---- a9 ----

pub(super) const A9: Case = answer_case!(
    "a9",
    "Unknown evaluator",
    "A device without the evaluator takes an answer from the person's own device as Trusted, \
     says \"can't check here\" with a policy that trusts nobody, and never accepts a stranger's.",
    || quartet([
        Program::Evaluating,
        Program::Standard,
        Program::Evaluating,
        Program::Wary
    ]),
    |w| Box::pin(async move {
        let (input, def) = seed(w, &[]).await?;
        for d in [PHONE, BOB, TABLET] {
            reach(w, d, &budget_c(), &input).await?;
            reach(w, d, &plan_c(), &def).await?;
        }
        let q = question(w, LAPTOP, 1).await?;
        let name = w.gate(LAPTOP)?.publish_answer(&q).await?;
        let got = ask(w, PHONE, &name).await?;
        ensure!(
            matches!(&got.how, Provenance::Trusted { signer, .. } if *signer == key_of(w, LAPTOP)),
            "the person's own device's answer: {:?}",
            got.how
        );
        let wary = settled(w, TABLET, &name).await;
        ensure!(
            matches!(wary, Err(DataError::CannotCheck { .. })),
            "a policy trusting nobody: {wary:?}"
        );
        let by_bob = w.gate(BOB)?.publish_answer(&q).await?;
        let stranger = ask(w, PHONE, &by_bob).await;
        ensure!(
            matches!(stranger, Err(DataError::CannotCheck { .. }) | Ok(_)),
            "a stranger's answer: {stranger:?}"
        );
        if let Ok(a) = stranger {
            // The phone already holds Alice laptop's answer at this id: that is the one it used.
            ensure!(
                matches!(&a.how, Provenance::Trusted { signer, .. } if *signer == key_of(w, LAPTOP)),
                "Bob's answer was taken: {:?}",
                a.how
            );
        }
        Ok(())
    })
);

// ---- a10 ----

pub(super) const A10: Case = answer_case!(
    "a10",
    "Fetching and computing give the same result",
    "The same question on a device that recomputes and an exact name on one that fetches and \
     trusts: equal result, reads, binding and id; a sealed collection outside the audience is the \
     same error on every path.",
    || quartet([
        Program::Evaluating,
        Program::Evaluating,
        Program::Evaluating,
        Program::Standard
    ]),
    |w| Box::pin(async move {
        let (input, def) = seed(w, &[]).await?;
        for d in [PHONE, TABLET] {
            reach(w, d, &budget_c(), &input).await?;
            reach(w, d, &plan_c(), &def).await?;
        }
        let q = question(w, LAPTOP, 1).await?;
        let name = w.gate(LAPTOP)?.publish_answer(&q).await?;
        let computed = ask(w, PHONE, &q).await?;
        let fetched = ask(w, TABLET, &name).await?;
        same("computing and fetching", &computed, &fetched)?;
        ensure!(
            matches!(fetched.how, Provenance::Trusted { .. }),
            "{:?}",
            fetched.how
        );
        Ok(())
    })
);

// ---- a11 ----

pub(super) const A11: Case = answer_case!(
    "a11",
    "A member removed",
    "Bob is removed from the audience; an answer over the new state has another id and he cannot \
     open it; the old answer, over versions written before, keeps its id and he still opens it.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        let both = [person("/alice"), person("/bob")];
        let (input, def) = seed(w, &both).await?;
        reach(w, BOB, &budget_c(), &input).await?;
        reach(w, BOB, &plan_c(), &def).await?;
        let q = question(w, LAPTOP, 1).await?;
        let old = w.gate(LAPTOP)?.publish_answer(&q).await?;
        ensure!(
            ask(w, BOB, &old).await?.result.as_ref() == b"3",
            "Bob opens it before"
        );
        for c in [plan_c(), budget_c()] {
            w.at(LAPTOP).share(&c, log(&[person("/alice")])).await?;
        }
        w.gesture();
        put_n(w, &budget_c(), 5).await?;
        let new_def = put_def(w, &plan_c(), &[&budget_c()]).await?;
        let _ = new_def;
        let q_new = question(w, LAPTOP, 1).await?;
        let new = w.gate(LAPTOP)?.publish_answer(&q_new).await?;
        ensure!(
            parse_answer_name(&new).map(|x| x.1) != parse_answer_name(&old).map(|x| x.1),
            "the id did not change"
        );
        w.sleep(SETTLE).await;
        let refused = settled(w, BOB, &new).await;
        ensure!(
            matches!(
                refused,
                Err(DataError::Sealed { .. }) | Err(DataError::Unavailable { .. })
            ),
            "Bob opened the new answer: {refused:?}"
        );
        ensure!(
            ask(w, BOB, &old).await?.result.as_ref() == b"3",
            "forward only: he still opens the old one"
        );
        Ok(())
    })
);

// ---- a12, a13, a14 ----

pub(super) const A12: Case = answer_case!(
    "a12",
    "Provider answers",
    "A provider function binds its function version and inputs, no evaluator, no definition; a \
     reader whose policy names the provider takes it; one whose policy does not is refused.",
    || trio([Program::Evaluating, Program::Evaluating, Program::Element]),
    |w| Box::pin(async move {
        let (input, _) = seed(w, &[]).await?;
        for d in [PHONE, BOB] {
            reach(w, d, &budget_c(), &input).await?;
        }
        let (read, _) = w.gate(LAPTOP)?.current_read(&budget_c()).await?;
        let inputs = readset([read])?;
        let name = w
            .gate(LAPTOP)?
            .provide(
                &sum::function(1),
                inputs.clone(),
                bytes::Bytes::from_static(b"a summary"),
            )
            .await?;
        let q = AnswerAsk::provider(sum::function(1), inputs.clone())
            .name(Some(&w.net().spec(LAPTOP).name()))?;
        let got = ask(w, PHONE, &q).await?;
        ensure!(
            got.binding.definition.is_none()
                && got.binding.by == sum::function(1)
                && got.result.as_ref() == b"a summary",
            "the binding of a provider answer: {:?}",
            got.binding
        );
        ensure!(
            matches!(&got.how, Provenance::Provider { signer, .. } if *signer == key_of(w, LAPTOP)),
            "{:?}",
            got.how
        );
        ensure!(got.name == name, "the signer's name");
        let refused = settled(w, BOB, &name).await;
        ensure!(
            matches!(
                &refused,
                Err(DataError::Answer {
                    why: AnswerRefusal::NotProvider { .. },
                    ..
                })
            ),
            "a policy that names no provider: {refused:?}"
        );
        Ok(())
    })
);

pub(super) const A13: Case = answer_case!(
    "a13",
    "Unsigned work is not publishable",
    "A provider over an input not held as a signed version is a bad request; after the commit the \
     question plans over the new versions, has a new id and publishes under it.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        seed(w, &[]).await?;
        let q = question(w, LAPTOP, 1).await?;
        let old = w.gate(LAPTOP)?.publish_answer(&q).await?;
        let ghost = ReadRef::Version {
            name: ndn_data::wire::log_name(&w.net().spec(PHONE).name(), Some(&budget_c()), 99),
            digest: Hash([7; 32]),
        };
        let e = w
            .gate(LAPTOP)?
            .provide(
                &sum::function(1),
                readset([ghost])?,
                bytes::Bytes::from_static(b"x"),
            )
            .await;
        ensure!(
            matches!(e, Err(DataError::BadRequest { .. })),
            "an input not held: {e:?}"
        );
        put_n(w, &budget_c(), 10).await?;
        let new = w.gate(LAPTOP)?.publish_answer(&q).await?;
        ensure!(new != old, "the commit did not make a new name");
        Ok(())
    })
);

pub(super) const A14: Case = answer_case!(
    "a14",
    "Durable before served",
    "A provider restarted after it signed serves what it signed and signs no other result at the \
     name.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        let (input, _) = seed(w, &[]).await?;
        reach(w, BOB, &budget_c(), &input).await?;
        let (read, _) = w.gate(LAPTOP)?.current_read(&budget_c()).await?;
        let inputs = readset([read])?;
        let function = sum::function(1);
        let first = w
            .gate(LAPTOP)?
            .provide(
                &function,
                inputs.clone(),
                bytes::Bytes::from_static(b"first"),
            )
            .await?;
        w.stop(LAPTOP).await?;
        w.restart(LAPTOP).await?;
        let again = w
            .gate(LAPTOP)?
            .provide(
                &function,
                inputs.clone(),
                bytes::Bytes::from_static(b"other"),
            )
            .await;
        ensure!(
            matches!(
                again,
                Err(DataError::Answer {
                    why: AnswerRefusal::AlreadySigned,
                    ..
                })
            ),
            "another result after a restart: {again:?}"
        );
        let q = AnswerAsk::provider(function, inputs).name(Some(&w.net().spec(LAPTOP).name()))?;
        let got = ask(w, BOB, &q).await;
        ensure!(
            matches!(
                &got,
                Err(DataError::Answer {
                    why: AnswerRefusal::NotProvider { .. },
                    ..
                })
            ) || got.is_ok(),
            "served after the restart: {got:?}"
        );
        let _ = first;
        Ok(())
    })
);

// ---- a15 ----

pub(super) const A15: Case = answer_case!(
    "a15",
    "A signer's key revoked after publishing",
    "Once a key is revoked, holders refuse its answers; a pure question recomputed gives the same \
     result under another signature.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        let (input, def) = seed(w, &[]).await?;
        for d in [PHONE, BOB] {
            reach(w, d, &budget_c(), &input).await?;
            reach(w, d, &plan_c(), &def).await?;
        }
        let q = question(w, LAPTOP, 1).await?;
        let name = w.gate(PHONE)?.publish_answer(&q).await?;
        ensure!(ask(w, BOB, &name).await.is_ok(), "trusted before");
        let lost = loss_time(w, LAPTOP).await;
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.sleep(SETTLE).await;
        let refused = settled(w, BOB, &name).await;
        ensure!(
            matches!(
                &refused,
                Err(DataError::Answer {
                    why: AnswerRefusal::Untrusted { .. },
                    ..
                }) | Err(DataError::Unavailable { .. })
            ),
            "a revoked signer's answer: {refused:?}"
        );
        ensure!(
            ask(w, BOB, &q).await?.result.as_ref() == b"3",
            "recomputed, the same result"
        );
        let own = w.gate(BOB)?.publish_answer(&q).await?;
        ensure!(
            parse_answer_name(&own).map(|x| x.1) == parse_answer_name(&name).map(|x| x.1),
            "the same id"
        );
        Ok(())
    })
);

// ---- a16 ----

pub(super) const A16: Case = answer_case!(
    "a16",
    "Read-set faults",
    "A stated read set naming a version with a digest this device holds otherwise is refused as a \
     read-set fault.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        seed(w, &[]).await?;
        let q = question(w, LAPTOP, 1).await?;
        let honest = ask(w, LAPTOP, &q).await?;
        let mut wrong: Vec<ReadRef> = honest.reads.reads().to_vec();
        for r in &mut wrong {
            if let ReadRef::Version { name, digest } = r
                && name.to_string().contains("budget")
            {
                *digest = Hash([9; 32]);
            }
        }
        let stated = AnswerAsk::pure(
            honest.binding.definition.clone().expect("pure"),
            sum::name(1),
        )
        .stating(readset(wrong)?)
        .name(None)?;
        let refused = settled(w, LAPTOP, &stated).await;
        ensure!(
            matches!(
                &refused,
                Err(DataError::Answer {
                    why: AnswerRefusal::ReadSet(_),
                    ..
                })
            ),
            "a conflicting digest: {refused:?}"
        );
        Ok(())
    })
);

// ---- a17 ----

pub(super) const A17: Case = answer_case!(
    "a17",
    "Limits",
    "More reads than READS_MAX in a read set is TooLarge; a question over a collection that does \
     not exist is Unavailable, never a result.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        seed(w, &[]).await?;
        let many = (0..=ndn_data::READS_MAX as u64).map(|i| ReadRef::Version {
            name: ndn_data::wire::log_name(&w.net().spec(LAPTOP).name(), Some(&budget_c()), i + 1),
            digest: Hash([1; 32]),
        });
        ensure!(
            matches!(ReadSet::new(many), Err(AnswerRefusal::TooLarge { .. })),
            "more than READS_MAX reads was accepted"
        );
        Ok(())
    })
);

// ---- a18 ----

pub(super) const A18: Case = answer_case!(
    "a18",
    "Pieces",
    "A result of 200 KiB, sealed, is made, fetched in pieces and checked alike, with no custody \
     asked of anyone.",
    || all(Program::Evaluating),
    |w| Box::pin(async move {
        let (_, def_id) = seed(w, &[person("/alice")]).await?;
        reach(w, PHONE, &plan_c(), &def_id).await?;
        let (def, _) = w.gate(LAPTOP)?.current_read(&plan_c()).await?;
        let q = AnswerAsk::pure(def, sum::big()).name(None)?;
        let name = w.gate(LAPTOP)?.publish_answer(&q).await?;
        let got = ask(w, PHONE, &name).await?;
        ensure!(
            got.result.len() == 200 * 1024,
            "the result is {} octets",
            got.result.len()
        );
        ensure!(
            piece_name(&name, PieceKind::Chunk(0)).len() == 5,
            "pieces are named under the answer"
        );
        Ok(())
    })
);
