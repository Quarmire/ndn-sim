//! Answers (spec answers.md), cases `a1`…`a22` over a real network of devices: named, checkable
//! readings over signed data, pure and provider, sealed to the audience of what they read, and
//! asked of another device (`a19`…`a22`).
//!
//! The scenario's data: Alice's laptop owns two log collections — `plan` and `budget` — and writes
//! into `budget` an integer `n` and into `plan` a definition whose field `inputs` lists `budget`.
//! The evaluator ([`crate::sum`]) sums the `n` of its inputs. Every device here reads and recomputes
//! over what it holds, fetching what it needs from the others as `get` does.

use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_data::wire::{PieceKind, parse_answer_name, parse_seal_key_name, piece_name};
use ndn_data::{
    AnswerAsk, AnswerAskBody, AnswerAskEnvelope, AnswerFault, AnswerRefusal, Answered, AskRefusal,
    Device, Hash, Provenance, ReadRef, ReadSet, Writer, answer_ask_prefix,
};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_security::Signer;
use ndn_security::confidentiality::{ContentKey, wrap_ck_to};
use tokio_util::sync::CancellationToken;

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

/// [`trio`] for the cases whose phone asks the laptop for an answer, with Alice's devices named
/// as `ndn-fwd init` names them: the reference context lists every role in DataRequiresCut, so a
/// device with no role in its name is no device of it and is not served as the person's own
/// (answers.md §15.7). The phone is a member (`/alice/member/phone`); the laptop signs, whatever
/// its name.
fn askers(programs: [Program; 3]) -> Plan {
    let mut p = Plan::new();
    let laptop = p.device("alice", "laptop");
    let phone = p.member("alice", "phone");
    let bob = p.device("bob", "laptop");
    for (d, program) in [laptop, phone, bob].into_iter().zip(programs) {
        p.program(d, program);
    }
    p
}

/// [`askers`] and Alice's tablet, a member too.
fn askers_and_tablet(programs: [Program; 4]) -> Plan {
    let mut p = askers([programs[0], programs[1], programs[2]]);
    let tablet = p.member("alice", "tablet");
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
    || askers([Program::Evaluating, Program::Evaluating, Program::Element]),
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
        // Bob is another person's device: where his fetch reaches nothing published (a network
        // that drops packets), the laptop is asked and, serving asks from its own person's
        // devices only, does not reply to his. Anything but a refusal, that silence (told as
        // not ready) or the answer is a second result.
        ensure!(
            matches!(
                &got,
                Err(DataError::Answer {
                    why: AnswerRefusal::NotProvider { .. }
                        | AnswerRefusal::AskRefused {
                            why: AskRefusal::NotServed,
                            ..
                        },
                    ..
                }) | Err(DataError::NotReady { .. })
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

// ---- a19 … a22: asking another device for the answer ----

/// The question of the newest definition of `plan` the laptop holds, under evaluator `evaluator`.
async fn question_of(w: &World, evaluator: Name) -> Result<Name, Failure> {
    let (def, _) = w.gate(LAPTOP)?.current_read(&plan_c()).await?;
    Ok(AnswerAsk::pure(def, evaluator).name(None)?)
}

/// What `signer` answers `gate`'s `ask_answer` of `question`, asked again as [`settled`] does for
/// as long as the error says asking again may mend it (the verb's own loop has already asked a
/// busy signer up to three times): the answer, and how many times the case had to ask again.
async fn asked(
    w: &World,
    gate: &Device,
    signer: &Name,
    question: &Name,
) -> Result<(Answered, usize), DataError> {
    let mut last = None;
    for again in 0..8 {
        match gate.ask_answer(signer, question).await {
            Ok(ndn_data::Got::Answer(a)) => return Ok((a, again)),
            Ok(other) => panic!("not an answer: {other:?}"),
            Err(e) if e.retry() => {
                last = Some(e);
                w.sleep(Duration::from_secs(3)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.expect("at least one try"))
}

/// `get` of `name` on `d`, asked again for as long as asking again may mend it, as [`settled`]
/// does, and while no signer is known or reached to ask (`CannotCheck`: a device that has not
/// yet heard of its person's other devices, or a network that lost its asks): the answer.
async fn get_asking(w: &World, d: Dev, name: &Name) -> Result<Answered, DataError> {
    let mut last = None;
    for _ in 0..8 {
        match w.at(d).get(name).await {
            Ok(answer) => match answer.got {
                ndn_data::Got::Answer(a) => return Ok(a),
                other => panic!("not an answer: {other:?}"),
            },
            Err(e) if e.retry() || matches!(e, DataError::CannotCheck { .. }) => {
                last = Some(e);
                w.sleep(Duration::from_secs(3)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.expect("at least one try"))
}

/// `a` was taken on trust from the laptop's key.
fn trusted_from_laptop(w: &World, what: &str, a: &Answered) -> Result<(), Failure> {
    ensure!(
        matches!(&a.how, Provenance::Trusted { signer, .. } if *signer == key_of(w, LAPTOP)),
        "{what}: not taken on trust from the laptop: {:?}",
        a.how
    );
    Ok(())
}

// ---- a19 ----

pub(super) const A19: Case = answer_case!(
    "a19",
    "A device that cannot compute asks another of its person",
    "Alice's phone, which has no evaluator, asks her laptop for an answer nobody published: the \
     laptop computes it for the ask, and the phone returns Got::Answer, Provenance::Trusted by \
     its policy; her tablet, which knows the evaluator and holds the inputs, asks too, \
     recomputes, and agrees.",
    || askers_and_tablet([
        Program::Evaluating,
        Program::Standard,
        Program::Standard,
        Program::Evaluating
    ]),
    |w| Box::pin(async move {
        let (input, def) = seed(w, &[]).await?;
        reach(w, TABLET, &budget_c(), &input).await?;
        reach(w, TABLET, &plan_c(), &def).await?;
        // The phone knows the laptop as a device of its person once it holds a version the
        // laptop signed: it can then ask it, having no evaluator to plan the reads with.
        reach(w, PHONE, &plan_c(), &def).await?;
        let q = question(w, LAPTOP, 1).await?;
        let laptop = w.net().spec(LAPTOP).name();

        // The tablet is out of reach while the phone asks, so that the signer the phone's policy
        // finds is the laptop: the tablet would answer as willingly, and be trusted as much.
        w.net().offline(TABLET);
        let before = sum::evaluations();
        let trusted = get_asking(w, PHONE, &q).await?;
        w.net().online(TABLET);
        ensure!(
            trusted.result.as_ref() == b"3",
            "the sum is {:?}",
            trusted.result
        );
        trusted_from_laptop(w, "the phone", &trusted)?;
        ensure!(
            sum::evaluations() == before + 1,
            "the laptop evaluated {} times for the phone's ask; once, only for the ask",
            sum::evaluations() - before
        );

        let (recomputed, _) = asked(w, &w.gate(TABLET)?, &laptop, &q).await?;
        match &recomputed.how {
            Provenance::Recomputed { disagreed_with, .. } => ensure!(
                disagreed_with.is_empty(),
                "the tablet's own value differs from the laptop's: {disagreed_with:?}"
            ),
            other => {
                return Err(Failure::new(format!(
                    "the tablet knows the evaluator and must recompute: {other:?}"
                )));
            }
        }
        same("the tablet, asking", &trusted, &recomputed)?;
        ensure!(
            events_of(w, TABLET, EventKind::AnswerEvidence)?.is_empty(),
            "the tablet raised evidence against an honest laptop"
        );
        Ok(())
    })
);

// ---- a20 ----

pub(super) const A20: Case = answer_case!(
    "a20",
    "A device outside the audience of one read is refused",
    "The question reads two sealed collections, one open to Alice's devices and one to her \
     laptop alone: her phone's ask is refused NotAudience, naming the read it may not read, \
     and the laptop evaluated nothing and signed no answer; a question over the first alone, \
     asked the same way, is answered.",
    || askers([Program::Evaluating, Program::Standard, Program::Standard]),
    |w| Box::pin(async move {
        let laptop = w.net().spec(LAPTOP).name();
        let devices = [person("/alice")];
        let laptop_only = [Audience::Device(laptop.clone())];
        w.at(LAPTOP).share(&plan_c(), log(&devices)).await?;
        w.at(LAPTOP).share(&second_c(), log(&devices)).await?;
        w.at(LAPTOP).share(&budget_c(), log(&laptop_only)).await?;
        let second = put_n(w, &second_c(), 4).await?;
        put_n(w, &budget_c(), 3).await?;
        let def = put_def(w, &plan_c(), &[&second_c(), &budget_c()]).await?;
        // The phone knows the laptop as a device of its person once it holds a version the
        // laptop signed: it can then ask it, whatever else the phone holds. It holds the
        // definition and the open input, so that it can open an answer over them; never `budget`.
        reach(w, PHONE, &plan_c(), &def).await?;
        reach(w, PHONE, &second_c(), &second).await?;
        let q = question(w, LAPTOP, 1).await?;

        // What the ask reads, in the order the signer checks it: the first it may not read.
        let gate = w.gate(LAPTOP)?;
        let mut reads = Vec::new();
        for c in [plan_c(), second_c(), budget_c()] {
            reads.push(gate.current_read(&c).await?.0);
        }
        let reads = readset(reads.clone())?;
        let budget = gate.current_read(&budget_c()).await?.0;
        let expected = reads.reads().iter().position(|r| *r == budget);

        let phone = w.gate(PHONE)?;
        let before = sum::evaluations();
        let refused = asked(w, &phone, &laptop, &q).await;
        match &refused {
            Err(
                e @ DataError::Answer {
                    why:
                        AnswerRefusal::AskRefused {
                            why: AskRefusal::NotAudience { index },
                            ..
                        },
                    ..
                },
            ) => {
                ensure!(
                    Some(*index as usize) == expected,
                    "the refusal names read {index}; the one outside the audience is {expected:?}"
                );
                ensure!(
                    e.next() == NextStep::AskOwner && !e.retry(),
                    "the refusal says {:?} (retry {})",
                    e.next(),
                    e.retry()
                );
            }
            other => {
                return Err(Failure::new(format!(
                    "the phone, outside one read's audience, was not refused NotAudience: {other:?}"
                )));
            }
        }
        ensure!(
            sum::evaluations() == before,
            "the laptop evaluated {} times for an ask it refused",
            sum::evaluations() - before
        );
        let answers = w
            .stored_names(LAPTOP)?
            .into_iter()
            .filter(|name| {
                name.components()
                    .iter()
                    .any(|c| c.value.as_ref() == b"answer")
            })
            .count();
        ensure!(
            answers == 0,
            "the laptop signed {answers} answers for an ask it refused"
        );

        // The refusal is of the read, not of the asker: over the open collection alone the same
        // phone is answered.
        put_def(w, &plan_c(), &[&second_c()]).await?;
        let open = question(w, LAPTOP, 1).await?;
        let (got, _) = asked(w, &phone, &laptop, &open).await?;
        ensure!(
            got.result.as_ref() == b"4",
            "the phone's answer over the open read is {:?}",
            got.result
        );
        Ok(())
    })
);

// ---- a21 ----

/// Eight phones' worth of asks, from one: how many the laptop is asked at once.
const ASKS: usize = 8;

pub(super) const A21: Case = answer_case!(
    "a21",
    "One ask in progress per asker",
    "Eight asks for one answer sent at once from Alice's phone to her laptop, which is slow to \
     plan it: the laptop works on one at a time (no two plans overlap) and evaluates once; the \
     rest are refused Busy, and the phone's own loop, asking again after the pause the refusal \
     names, at most three times each, has every one answered.",
    || {
        let mut p = askers([Program::Evaluating, Program::Standard, Program::Standard]);
        p.count_names(3);
        p
    },
    |w| Box::pin(async move {
        seed(w, &[]).await?;
        let q = question_of(w, sum::slow()).await?;
        let laptop = w.net().spec(LAPTOP).name();
        let phone = w.gate(PHONE)?;

        let (evaluated, overlapped) = (sum::evaluations(), sum::overlaps());
        let sent =
            futures::future::join_all((0..ASKS).map(|_| asked(w, &phone, &laptop, &q))).await;
        let mut answers = Vec::new();
        let mut again = 0;
        for (i, sent) in sent.into_iter().enumerate() {
            let (answer, case_asked_again) = sent
                .map_err(|e| Failure::new(format!("ask {i} of {ASKS} was never answered: {e}")))?;
            again += case_asked_again;
            answers.push(answer);
        }
        for a in &answers {
            ensure!(a.result.as_ref() == b"3", "the sum is {:?}", a.result);
            trusted_from_laptop(w, "an asker", a)?;
            same("two askers", &answers[0], a)?;
        }
        ensure!(
            sum::overlaps() == overlapped,
            "the laptop planned for {} asks of one device while another was in progress",
            sum::overlaps() - overlapped
        );
        ensure!(
            sum::evaluations() == evaluated + 1,
            "the laptop evaluated {} times for one answer",
            sum::evaluations() - evaluated
        );
        if w.net().faults().is_none() {
            // Every ask meets a reply, and nothing is lost to resend: the first wave of eight
            // has one in progress and seven Busy, so at least seven more asks were answered.
            let replies = w.net().received(PHONE, &answer_ask_prefix(&laptop));
            ensure!(
                replies >= (2 * ASKS - 1) as u64,
                "the phone had {replies} replies to {ASKS} asks: at most one of a wave is not Busy"
            );
            ensure!(
                again == 0,
                "{again} asks needed the case to ask again; the verb's own three asks suffice"
            );
        }
        Ok(())
    })
);

// ---- a22 ----

/// The seal key `from`'s node learns from `device`'s `<device>/32=seal` packet, asked until one
/// comes.
async fn seal_key_of(w: &World, from: Dev, device: &Name) -> Result<[u8; 32], Failure> {
    for _ in 0..8 {
        let engine = w
            .net()
            .fabric()
            .engine_of(w.net().spec(from).node)
            .expect("every device is a node");
        let mut consumer = engine.app_consumer(CancellationToken::new());
        let got = consumer
            .fetch_with(
                InterestBuilder::new(ndn_data::wire::seal_key_prefix(device))
                    .can_be_prefix()
                    .lifetime(Duration::from_secs(2)),
            )
            .await;
        if let Ok(data) = got
            && let Some((of, public)) = parse_seal_key_name(&data.name)
            && of == *device
        {
            return Ok(public);
        }
        w.sleep(Duration::from_secs(1)).await;
    }
    Err(Failure::new(format!("{device} gave no seal key packet")))
}

/// The parameters of an ask of `to` for `ask`, made by hand as a device `asker` makes one and
/// sealed to `to`'s seal key `public`; `proof` makes the proof packet of `asker` from the ask's
/// binding.
fn hand_made(
    to: &Name,
    public: &[u8; 32],
    ask: &AnswerAsk,
    asker: &Name,
    proof: impl FnOnce(&[u8; 32]) -> bytes::Bytes,
) -> Result<bytes::Bytes, Failure> {
    let aad = answer_ask_prefix(to).encode_to_tlv();
    let ck = ContentKey::generate();
    let (ephemeral, wrapped) = wrap_ck_to(public, &ck, &aad)
        .map_err(|e| Failure::new(format!("the ask could not be sealed: {e}")))?;
    let binding = AnswerAskBody::binding(to, ask, &ephemeral);
    let body = AnswerAskBody {
        ask: ask.clone(),
        asker: asker.clone(),
        proof: proof(&binding),
    };
    let sealed = ck.seal(&body.encode(), &aad);
    Ok(AnswerAskEnvelope {
        ephemeral,
        key: wrapped.to_bytes(),
        sealed: sealed.to_bytes(),
    }
    .encode())
}

/// `<asker>/32=ask/<binding>` signed by `signer`.
fn proof_by(signer: &dyn Signer, asker: &Name, binding: &[u8; 32]) -> bytes::Bytes {
    DataBuilder::new(ndn_data::wire::ask_name(asker, binding), &[])
        .freshness(Duration::ZERO)
        .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
            signer.sign_sync(region).unwrap_or_default()
        })
}

/// What came back to an ask sent from `from`'s node.
enum Heard {
    /// Something answered it: a Data packet, or one its node's forwarder refused (a network
    /// that alters packets may have altered it); what it was.
    Replied(String),
    /// No Data did within the Interest's lifetime (a Nack is no Data either).
    Nothing,
}

/// Send the ask with `params` to `to` from `from`'s node, as an Interest of lifetime 2 s, and wait
/// the lifetime out.
async fn send_ask(
    w: &World,
    from: Dev,
    to: &Name,
    params: &bytes::Bytes,
) -> Result<Heard, Failure> {
    let engine = w
        .net()
        .fabric()
        .engine_of(w.net().spec(from).node)
        .expect("every device is a node");
    let mut consumer = engine.app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new(answer_ask_prefix(to))
        .lifetime(Duration::from_secs(2))
        .app_parameters(params.to_vec());
    match consumer.fetch_with(builder).await {
        Ok(data) => Ok(Heard::Replied(format!("Data {}", data.name))),
        Err(ndn_app::AppError::Timeout | ndn_app::AppError::Nacked { .. }) => Ok(Heard::Nothing),
        Err(e @ ndn_app::AppError::Refused { .. }) => {
            Ok(Heard::Replied(format!("a Data the forwarder refused: {e}")))
        }
        Err(e) => Err(Failure::new(format!("the ask could not be sent: {e}"))),
    }
}

pub(super) const A22: Case = answer_case!(
    "a22",
    "An ask that does not prove its asker gets no reply",
    "Asks of Alice's laptop whose proof is unsigned, signed by Bob's key, or Alice's phone's own \
     signature on another ask's binding get no Data within the Interest's lifetime, not even a \
     refusal, and the laptop evaluates nothing; the same ask with the phone's real proof is \
     answered.",
    || askers([Program::Evaluating, Program::Standard, Program::Standard]),
    |w| Box::pin(async move {
        seed(w, &[]).await?;
        let (def, _) = w.gate(LAPTOP)?.current_read(&plan_c()).await?;
        let ask = AnswerAsk::pure(def, sum::name(1));
        let (laptop, phone) = (w.net().spec(LAPTOP).name(), w.net().spec(PHONE).name());
        let public = seal_key_of(w, PHONE, &laptop).await?;
        let (mine, bobs) = (w.signer(PHONE)?, w.signer(BOB)?);

        let mut forgeries: Vec<(&str, bytes::Bytes)> = Vec::new();
        forgeries.push((
            "a proof signed by a digest alone",
            hand_made(&laptop, &public, &ask, &phone, |binding| {
                DataBuilder::new(ndn_data::wire::ask_name(&phone, binding), &[])
                    .freshness(Duration::ZERO)
                    .sign_digest_sha256()
            })?,
        ));
        forgeries.push((
            "a proof of the phone signed by Bob's device key",
            hand_made(&laptop, &public, &ask, &phone, |binding| {
                proof_by(bobs.as_ref(), &phone, binding)
            })?,
        ));
        forgeries.push((
            "the phone's own proof of another ask's binding",
            hand_made(&laptop, &public, &ask, &phone, |_| {
                let other = AnswerAskBody::binding(&laptop, &ask, &[0x42; 32]);
                proof_by(mine.as_ref(), &phone, &other)
            })?,
        ));

        let before = sum::evaluations();
        for (what, params) in &forgeries {
            // Sent twice, the same ask, as an asker whose first send was lost sends it again.
            for _ in 0..2 {
                if let Heard::Replied(what_came) = send_ask(w, PHONE, &laptop, params).await? {
                    return Err(Failure::new(format!(
                        "{what}: the laptop replied to an ask that proves nothing: {what_came}"
                    )));
                }
            }
        }
        ensure!(
            sum::evaluations() == before,
            "the laptop evaluated {} times for asks that prove nothing",
            sum::evaluations() - before
        );

        // The same ask with the phone's real proof is answered: the silence above is the proof's,
        // not the path's.
        let real = hand_made(&laptop, &public, &ask, &phone, |binding| {
            proof_by(mine.as_ref(), &phone, binding)
        })?;
        let mut replied = false;
        for _ in 0..6 {
            if let Heard::Replied(_) = send_ask(w, PHONE, &laptop, &real).await? {
                replied = true;
                break;
            }
        }
        ensure!(
            replied,
            "the laptop did not reply to an ask with the phone's real proof"
        );
        Ok(())
    })
);
