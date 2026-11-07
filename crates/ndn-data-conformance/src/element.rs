//! The cases' own merge rule, shaped like ndf's element rule (its reply to the workspace, §B):
//! `/conformance/merge/element/v=1`.
//!
//! One collection is one element. Its writers build each operation themselves (`put_op`): the
//! **basis** — the content addresses (implicit digests) of the versions of this element it was made
//! over, each of which must lie in the operation's past — and an ordered list of **edits**, each
//! with a relative time in milliseconds: `Create(kind)`, `Set(setting, value)`, `Change(setting,
//! splice)`, `Place(parent, order)`, `Remove`, `Lock(setting)`, `Unlock(setting)`, or alone a
//! `Checkpoint(state)` that replaces the state of its past. An operation names its writer, and the
//! rule refuses one that claims another.
//!
//! The merged value ([`ElementValue`], [`decode`]) is the element's state, its **variants** (the
//! alternatives of one slot that concurrent versions wrote — neither in the other's past — in a
//! fixed order, each with its writer, version digest and value) and its **heads** (the versions
//! no other is made over, whose digests a writer names as the basis of its next operation).
//!
//! A version that sets or changes a setting another writer locked (the lock in the version's
//! past, nothing lifting it) does not count: it is applied, kept and shown
//! ([`Counting::NotCounted`]), and counts once an `Unlock` of that lock by its writer — or a
//! checkpoint over the lock that does not keep it — is applied.
//!
//! The value is computed from the set of applied versions and what each was made over, never from
//! the order they arrived in: the same set gives the same value on every device. The encoding is
//! JSON of ordered maps and lists, so it is deterministic too.

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use ndn_data::{
    Counting, MergeError, MergeRule, MergeState, Name, Op, OpKind, Value, VersionId, Writer,
};
use serde::{Deserialize, Serialize};

/// The rule's versioned name.
pub const NAME: &str = "/conformance/merge/element/v=1";

/// The rule's name, as a members record names it.
pub fn name() -> Name {
    NAME.parse()
        .expect("the element rule's name is a valid NDN name")
}

/// One edit of an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Edit {
    /// The element is made, of this kind.
    Create(String),
    /// A setting takes this value.
    Set(String, String),
    /// A setting's text is spliced: at a character offset, remove some, insert some.
    Change(String, Splice),
    /// The element is placed under a parent, at an order key.
    Place(Place),
    /// The element is removed.
    Remove,
    /// The writer locks a setting: another writer's later set of it does not count.
    Lock(String),
    /// The writer lifts its lock of a setting.
    Unlock(String),
    /// The element's whole state, replacing the state of the operation's past. Alone in its
    /// operation.
    Checkpoint(ElementState),
}

/// A text splice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Splice {
    /// Character offset.
    pub at: usize,
    /// Characters removed there.
    pub remove: usize,
    /// Text inserted there.
    pub insert: String,
}

/// Where an element is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Place {
    /// Its parent element.
    pub parent: String,
    /// Its order key among the parent's children.
    pub order: String,
}

/// A lock in force.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Lock {
    /// The setting.
    pub setting: String,
    /// The writer holding it, by key name.
    pub by: String,
}

/// An edit and when it was made, relative to the operation's previous edit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timed {
    /// Milliseconds since the previous edit (pauses kept).
    pub after_ms: u64,
    /// The edit.
    pub edit: Edit,
}

/// One operation, as its writer builds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    /// Its writer: a prefix of the signing key's name (the writing device).
    pub writer: String,
    /// The implicit digests (hex) of the versions of this element it was made over; empty: the
    /// writer's previous version.
    pub basis: Vec<String>,
    /// The edits, in order.
    pub edits: Vec<Timed>,
}

impl Operation {
    /// An empty operation by `writer` (the writing device's name), made over nothing named.
    pub fn by(writer: &Name) -> Self {
        Self {
            writer: writer.to_string(),
            basis: Vec::new(),
            edits: Vec::new(),
        }
    }

    /// Made over the versions with these digests.
    pub fn over<'d>(mut self, basis: impl IntoIterator<Item = &'d [u8; 32]>) -> Self {
        self.basis.extend(basis.into_iter().map(|d| hex(d)));
        self
    }

    /// Made over the heads of `value`: everything it holds.
    pub fn over_heads(self, value: &ElementValue) -> Self {
        let heads: Vec<[u8; 32]> = value.heads.iter().filter_map(|h| h.digest()).collect();
        self.over(heads.iter())
    }

    /// With `edit`, `after_ms` after the previous one.
    pub fn then(mut self, after_ms: u64, edit: Edit) -> Self {
        self.edits.push(Timed { after_ms, edit });
        self
    }

    /// With `Set(setting, value)`, a second after the previous edit.
    pub fn set(self, setting: &str, value: impl Into<String>) -> Self {
        self.then(1000, Edit::Set(setting.to_owned(), value.into()))
    }

    /// The operation's octets, as `put_op` carries them.
    pub fn encode(&self) -> Bytes {
        Bytes::from(serde_json::to_vec(self).expect("an operation serializes"))
    }

    /// The operation these octets carry.
    pub fn decode(bytes: &[u8]) -> Result<Self, MergeError> {
        serde_json::from_slice(bytes)
            .map_err(|e| MergeError(format!("not an operation of {NAME}: {e}")))
    }
}

/// An element's state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementState {
    /// Its kind, once created.
    pub kind: Option<String>,
    /// Where it is, once placed.
    pub place: Option<Place>,
    /// Its settings.
    pub settings: BTreeMap<String, String>,
    /// Whether it was removed.
    pub removed: bool,
    /// The locks in force.
    pub locks: Vec<Lock>,
}

/// What a variant is about.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Slot {
    /// The kind.
    Kind,
    /// The place.
    Place,
    /// Whether it is removed.
    Removed,
    /// A setting.
    Setting(String),
}

/// A value one version wrote into a slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Written {
    /// Text: a kind or a setting.
    Text(String),
    /// A place.
    Place(Place),
    /// Removed.
    Removed,
}

/// One alternative of a variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alternative {
    /// Its writer, by key name.
    pub writer: String,
    /// The implicit digest (hex) of the version that wrote it.
    pub version: String,
    /// What it wrote.
    pub value: Written,
}

/// Alternatives concurrent versions wrote into one slot, in a fixed order (writer, then
/// version digest); the state shows the first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variant {
    /// The slot.
    pub slot: Slot,
    /// The alternatives.
    pub alternatives: Vec<Alternative>,
}

/// A version no other applied version is made over.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Head {
    /// Its writer, by key name.
    pub writer: String,
    /// Its seq.
    pub seq: u64,
    /// Its implicit digest (hex).
    pub digest: String,
}

impl Head {
    /// The digest as octets.
    pub fn digest(&self) -> Option<[u8; 32]> {
        unhex(&self.digest)
    }
}

/// The merged value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementValue {
    /// The state.
    pub state: ElementState,
    /// Slots written concurrently.
    pub variants: Vec<Variant>,
    /// The versions no other is made over, by (writer, seq).
    pub heads: Vec<Head>,
}

/// The element value `value` carries; an error when it is no value of this rule.
pub fn decode(value: &Value) -> Result<ElementValue, String> {
    let bytes = value
        .bytes()
        .ok_or_else(|| format!("a value of fields, not of {NAME}: {value:?}"))?;
    serde_json::from_slice(bytes).map_err(|e| format!("not a value of {NAME}: {e}"))
}

/// The rule. [`Element::lax`] is a faulty writer's copy of it: same name, a check that refuses
/// nothing, so what it signs only honest readers judge.
pub struct Element {
    function: Name,
    lax: bool,
}

impl Element {
    /// The rule as written.
    pub fn new() -> Self {
        Self {
            function: name(),
            lax: false,
        }
    }

    /// The rule with a check that lets every decodable operation through.
    pub fn lax() -> Self {
        Self {
            function: name(),
            lax: true,
        }
    }
}

impl Default for Element {
    fn default() -> Self {
        Self::new()
    }
}

impl MergeRule for Element {
    fn function(&self) -> &Name {
        &self.function
    }

    fn start(&self, _local: &Writer) -> Box<dyn MergeState> {
        Box::new(Applied {
            lax: self.lax,
            nodes: Vec::new(),
            reported: BTreeSet::new(),
        })
    }
}

/// One applied version.
struct Node {
    id: VersionId,
    digest: [u8; 32],
    op: Operation,
    /// The applied versions (by index) inside its past.
    past: BTreeSet<usize>,
}

impl Node {
    fn checkpoint(&self) -> Option<&ElementState> {
        match self.op.edits.as_slice() {
            [
                Timed {
                    edit: Edit::Checkpoint(s),
                    ..
                },
            ] => Some(s),
            _ => None,
        }
    }

    /// The settings it sets or changes.
    fn writes(&self) -> impl Iterator<Item = &str> {
        self.op.edits.iter().filter_map(|t| match &t.edit {
            Edit::Set(s, _) | Edit::Change(s, _) => Some(s.as_str()),
            _ => None,
        })
    }
}

/// A lock some applied version holds: `setting`, by `by`, from node `at`.
struct Held {
    setting: String,
    by: String,
    at: usize,
}

/// The applied versions of one element.
struct Applied {
    lax: bool,
    nodes: Vec<Node>,
    /// Versions answered NotCounted, not yet reported counting.
    reported: BTreeSet<VersionId>,
}

impl Applied {
    /// Every lock an applied version took (a `Lock` edit, or a checkpoint's state).
    fn locks(&self) -> Vec<Held> {
        let mut out = Vec::new();
        for (i, n) in self.nodes.iter().enumerate() {
            if let Some(s) = n.checkpoint() {
                out.extend(s.locks.iter().map(|l| Held {
                    setting: l.setting.clone(),
                    by: l.by.clone(),
                    at: i,
                }));
                continue;
            }
            let mut taken: BTreeSet<&str> = BTreeSet::new();
            for t in &n.op.edits {
                match &t.edit {
                    Edit::Lock(s) => {
                        taken.insert(s);
                    }
                    Edit::Unlock(s) => {
                        taken.remove(s.as_str());
                    }
                    _ => {}
                }
            }
            out.extend(taken.into_iter().map(|s| Held {
                setting: s.to_owned(),
                by: n.id.writer.key().to_string(),
                at: i,
            }));
        }
        out
    }

    /// Whether an applied version lifts `lock`: an `Unlock` of it by its holder made over it, or
    /// a checkpoint made over it that does not keep it.
    fn lifted(&self, lock: &Held) -> bool {
        self.nodes.iter().any(|n| {
            if !n.past.contains(&lock.at) {
                return false;
            }
            if let Some(s) = n.checkpoint() {
                return !s
                    .locks
                    .iter()
                    .any(|l| l.setting == lock.setting && l.by == lock.by);
            }
            n.id.writer.key().to_string() == lock.by
                && n.op
                    .edits
                    .iter()
                    .any(|t| matches!(&t.edit, Edit::Unlock(s) if *s == lock.setting))
        })
    }

    /// Why node `i` does not count, if it does not: it writes a setting another writer locked in
    /// its past, and nothing applied lifts that lock.
    fn not_counted(&self, i: usize, locks: &[Held]) -> Option<String> {
        let n = &self.nodes[i];
        let me = n.id.writer.key().to_string();
        let writes: BTreeSet<&str> = n.writes().collect();
        locks
            .iter()
            .find(|l| {
                l.by != me
                    && n.past.contains(&l.at)
                    && writes.contains(l.setting.as_str())
                    && !self.lifted(l)
            })
            .map(|l| format!("setting {} locked by {}", l.setting, l.by))
    }

    /// The applied versions in one order every device computes alike from the set: each after
    /// every version in its past, ties by (writer, seq).
    fn order(&self) -> Vec<usize> {
        let mut done = vec![false; self.nodes.len()];
        let mut out = Vec::with_capacity(self.nodes.len());
        while out.len() < self.nodes.len() {
            let next = (0..self.nodes.len())
                .filter(|&i| !done[i] && self.nodes[i].past.iter().all(|&p| done[p]))
                .min_by(|&a, &b| self.nodes[a].id.cmp(&self.nodes[b].id))
                .expect("the past of applied versions is acyclic");
            done[next] = true;
            out.push(next);
        }
        out
    }

    fn merged(&self) -> ElementValue {
        let locks = self.locks();
        let mut slots: BTreeMap<Slot, Vec<(usize, Written)>> = BTreeMap::new();
        for i in self.order() {
            if self.not_counted(i, &locks).is_some() {
                continue;
            }
            let n = &self.nodes[i];
            // What this version writes replaces what its past wrote; what versions concurrent
            // with it wrote stays beside it.
            let write = |slots: &mut BTreeMap<Slot, Vec<(usize, Written)>>, slot, value| {
                let heads = slots.entry(slot).or_default();
                heads.retain(|(at, _)| *at != i && !n.past.contains(at));
                heads.push((i, value));
            };
            if let Some(s) = n.checkpoint() {
                for heads in slots.values_mut() {
                    heads.retain(|(at, _)| !n.past.contains(at));
                }
                for (slot, value) in state_slots(s) {
                    write(&mut slots, slot, value);
                }
                continue;
            }
            for t in &n.op.edits {
                match &t.edit {
                    Edit::Create(kind) => {
                        write(&mut slots, Slot::Kind, Written::Text(kind.clone()))
                    }
                    Edit::Set(s, v) => {
                        write(
                            &mut slots,
                            Slot::Setting(s.clone()),
                            Written::Text(v.clone()),
                        );
                    }
                    Edit::Change(s, splice) => {
                        let slot = Slot::Setting(s.clone());
                        let base = slots
                            .get(&slot)
                            .and_then(|h| self.first(h))
                            .and_then(|w| match w {
                                Written::Text(t) => Some(t.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        write(&mut slots, slot, Written::Text(spliced(&base, splice)));
                    }
                    Edit::Place(p) => write(&mut slots, Slot::Place, Written::Place(p.clone())),
                    Edit::Remove => write(&mut slots, Slot::Removed, Written::Removed),
                    Edit::Lock(_) | Edit::Unlock(_) | Edit::Checkpoint(_) => {}
                }
            }
        }

        let mut value = ElementValue::default();
        for (slot, heads) in &slots {
            let Some(shown) = self.first(heads) else {
                continue;
            };
            match (slot, shown) {
                (Slot::Kind, Written::Text(k)) => value.state.kind = Some(k.clone()),
                (Slot::Place, Written::Place(p)) => value.state.place = Some(p.clone()),
                (Slot::Removed, _) => value.state.removed = true,
                (Slot::Setting(s), Written::Text(t)) => {
                    value.state.settings.insert(s.clone(), t.clone());
                }
                _ => {}
            }
            if heads.len() > 1 {
                value.variants.push(Variant {
                    slot: slot.clone(),
                    alternatives: self
                        .sorted(heads)
                        .into_iter()
                        .map(|(i, w)| Alternative {
                            writer: self.nodes[i].id.writer.key().to_string(),
                            version: hex(&self.nodes[i].digest),
                            value: w.clone(),
                        })
                        .collect(),
                });
            }
        }
        let mut held: Vec<Lock> = locks
            .iter()
            .filter(|l| !self.lifted(l))
            .map(|l| Lock {
                setting: l.setting.clone(),
                by: l.by.clone(),
            })
            .collect();
        held.sort();
        held.dedup();
        value.state.locks = held;
        let mut heads: Vec<Head> = (0..self.nodes.len())
            .filter(|&i| !self.nodes.iter().any(|n| n.past.contains(&i)))
            .map(|i| Head {
                writer: self.nodes[i].id.writer.key().to_string(),
                seq: self.nodes[i].id.seq.0,
                digest: hex(&self.nodes[i].digest),
            })
            .collect();
        heads.sort();
        value.heads = heads;
        value
    }

    /// `heads` in the alternatives' fixed order: by writer, then version digest.
    fn sorted<'h>(&self, heads: &'h [(usize, Written)]) -> Vec<(usize, &'h Written)> {
        let mut out: Vec<(usize, &Written)> = heads.iter().map(|(i, w)| (*i, w)).collect();
        out.sort_by(|(a, _), (b, _)| {
            let (a, b) = (&self.nodes[*a], &self.nodes[*b]);
            (a.id.writer.key(), a.digest).cmp(&(b.id.writer.key(), b.digest))
        });
        out
    }

    /// The alternative the state shows.
    fn first<'h>(&self, heads: &'h [(usize, Written)]) -> Option<&'h Written> {
        self.sorted(heads).into_iter().next().map(|(_, w)| w)
    }
}

/// The slots a checkpoint's state writes.
fn state_slots(s: &ElementState) -> Vec<(Slot, Written)> {
    let mut out = Vec::new();
    if let Some(k) = &s.kind {
        out.push((Slot::Kind, Written::Text(k.clone())));
    }
    if let Some(p) = &s.place {
        out.push((Slot::Place, Written::Place(p.clone())));
    }
    if s.removed {
        out.push((Slot::Removed, Written::Removed));
    }
    for (k, v) in &s.settings {
        out.push((Slot::Setting(k.clone()), Written::Text(v.clone())));
    }
    out
}

/// `base` with `splice` applied, by characters (offsets past the end clamp to it).
fn spliced(base: &str, splice: &Splice) -> String {
    let chars: Vec<char> = base.chars().collect();
    let at = splice.at.min(chars.len());
    let end = at.saturating_add(splice.remove).min(chars.len());
    let mut out: String = chars[..at].iter().collect();
    out.push_str(&splice.insert);
    out.extend(&chars[end..]);
    out
}

impl MergeState for Applied {
    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError> {
        let decoded = Operation::decode(op.bytes)?;
        let checkpoint = decoded
            .edits
            .iter()
            .any(|t| matches!(t.edit, Edit::Checkpoint(_)));
        if self.lax {
            return Ok(if checkpoint {
                OpKind::Checkpoint
            } else {
                OpKind::Edit
            });
        }
        let claimed: Name = decoded
            .writer
            .parse()
            .map_err(|_| MergeError(format!("the writer {:?} is no name", decoded.writer)))?;
        let key = op.id.writer.key();
        if !key.has_prefix(&claimed) {
            return Err(MergeError(format!(
                "the operation claims the writer {claimed}, but {key} signed it: an operation \
                 speaks only for its own writer"
            )));
        }
        for d in &decoded.basis {
            let digest = unhex(d).ok_or_else(|| {
                MergeError(format!("the basis names {d:?}, which is no SHA-256 digest"))
            })?;
            if op.past.by_digest(&digest).is_none() {
                return Err(MergeError(format!(
                    "the basis names the version {d}, which is no version of this element inside \
                     the operation's past: an operation is made only over versions its writer \
                     held"
                )));
            }
        }
        if decoded.edits.is_empty() {
            return Err(MergeError("an operation with no edit".to_owned()));
        }
        if checkpoint && decoded.edits.len() > 1 {
            return Err(MergeError(
                "a checkpoint stands alone in its operation".to_owned(),
            ));
        }
        Ok(if checkpoint {
            OpKind::Checkpoint
        } else {
            OpKind::Edit
        })
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        let decoded = Operation::decode(op.bytes)?;
        let i = match self.nodes.iter().position(|n| n.id == *op.id) {
            // Applied already: the same answer again.
            Some(i) => i,
            None => {
                let past = (0..self.nodes.len())
                    .filter(|&p| op.past.contains(&self.nodes[p].id))
                    .collect();
                self.nodes.push(Node {
                    id: op.id.clone(),
                    digest: *op.digest,
                    op: decoded,
                    past,
                });
                self.nodes.len() - 1
            }
        };
        Ok(match self.not_counted(i, &self.locks()) {
            Some(why) => {
                self.reported.insert(op.id.clone());
                Counting::NotCounted(why)
            }
            None => Counting::Counted,
        })
    }

    fn now_counted(&mut self) -> Vec<VersionId> {
        let locks = self.locks();
        let counting: Vec<VersionId> = self
            .reported
            .iter()
            .filter(|id| {
                self.nodes
                    .iter()
                    .position(|n| n.id == **id)
                    .is_some_and(|i| self.not_counted(i, &locks).is_none())
            })
            .cloned()
            .collect();
        for id in &counting {
            self.reported.remove(id);
        }
        counting
    }

    fn value(&self) -> Value {
        Value::Rule(Bytes::from(
            serde_json::to_vec(&self.merged()).expect("an element value serializes"),
        ))
    }
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The 32 octets `s` spells in hex.
fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use ndn_data::{Frontier, Past, Seq};

    use super::*;

    /// One version as a test writes it: its writer device, seq, the versions in its past (by
    /// position) and its operation.
    struct V {
        id: VersionId,
        digest: [u8; 32],
        past: Vec<usize>,
        op: Operation,
    }

    struct InPast<'a> {
        all: &'a [V],
        past: &'a [usize],
    }

    impl Past for InPast<'_> {
        fn contains(&self, id: &VersionId) -> bool {
            self.past.iter().any(|&p| self.all[p].id == *id)
        }
        fn by_digest(&self, digest: &[u8; 32]) -> Option<VersionId> {
            self.past
                .iter()
                .find(|&&p| self.all[p].digest == *digest)
                .map(|&p| self.all[p].id.clone())
        }
    }

    fn device(who: &str) -> Name {
        format!("/{who}/laptop").parse().unwrap()
    }

    fn v(all: &[V], who: &str, seq: u64, past: &[usize], edits: Vec<Edit>) -> V {
        let mut op = Operation::by(&device(who));
        for e in edits {
            op = op.then(10, e);
        }
        let key = device(who).append("KEY").append("1");
        let mut digest = [0u8; 32];
        digest[0] = all.len() as u8 + 1;
        V {
            id: VersionId {
                writer: Writer::new(key),
                seq: Seq(seq),
            },
            digest,
            past: past.to_vec(),
            op,
        }
    }

    /// Apply `all` in `order` (each after its past), answering what each apply said, what
    /// counted afterwards, and the value.
    fn run(all: &[V], order: &[usize]) -> (Vec<Counting>, Vec<VersionId>, ElementValue) {
        let mut state = Element::new().start(&Writer::new(device("x")));
        let (mut said, mut counted) = (Vec::new(), Vec::new());
        let parents = Frontier::new();
        for &i in order {
            let bytes = all[i].op.encode();
            let past = InPast {
                all,
                past: &all[i].past,
            };
            let op = Op {
                id: &all[i].id,
                digest: &all[i].digest,
                parents: &parents,
                past: &past,
                bytes: &bytes,
            };
            state.check(&op).expect("a valid operation");
            said.push(state.apply(&op).expect("applies"));
            counted.extend(state.now_counted());
        }
        (
            said,
            counted,
            decode(&state.value()).expect("its own value"),
        )
    }

    fn set(s: &str, value: &str) -> Edit {
        Edit::Set(s.into(), value.into())
    }

    #[test]
    fn concurrent_sets_give_one_variant_whatever_the_order() {
        let mut all = Vec::new();
        all.push(v(&all, "alice", 1, &[], vec![Edit::Create("card".into())]));
        all.push(v(&all, "alice", 2, &[0], vec![set("title", "a")]));
        all.push(v(&all, "bob", 1, &[0], vec![set("title", "b")]));
        let (_, _, one) = run(&all, &[0, 1, 2]);
        let (_, _, two) = run(&all, &[0, 2, 1]);
        assert_eq!(one, two);
        assert_eq!(one.variants.len(), 1);
        assert_eq!(one.variants[0].alternatives.len(), 2);
        assert_eq!(one.heads.len(), 2);
        // A set over both resolves the variant.
        all.push(v(&all, "bob", 2, &[0, 1, 2], vec![set("title", "c")]));
        let (_, _, three) = run(&all, &[0, 2, 1, 3]);
        assert!(three.variants.is_empty());
        assert_eq!(three.state.settings["title"], "c");
    }

    #[test]
    fn a_set_under_another_writers_lock_counts_once_unlocked() {
        let mut all = Vec::new();
        all.push(v(
            &all,
            "alice",
            1,
            &[],
            vec![set("title", "draft"), Edit::Lock("title".into())],
        ));
        all.push(v(&all, "bob", 1, &[0], vec![set("title", "bob")]));
        let (said, counted, value) = run(&all, &[0, 1]);
        assert!(matches!(said[1], Counting::NotCounted(_)));
        assert!(counted.is_empty());
        assert_eq!(value.state.settings["title"], "draft");
        all.push(v(
            &all,
            "alice",
            2,
            &[0],
            vec![Edit::Unlock("title".into())],
        ));
        let (said, counted, unlocked) = run(&all, &[0, 1, 2]);
        assert!(matches!(said[1], Counting::NotCounted(_)));
        assert_eq!(counted, vec![all[1].id.clone()]);
        assert_eq!(unlocked.state.settings["title"], "bob");
        // Unlocked first, it counts at once, to the same value.
        let (said, counted, early) = run(&all, &[0, 2, 1]);
        assert_eq!(said[2], Counting::Counted);
        assert!(counted.is_empty());
        assert_eq!(early, unlocked);
    }

    #[test]
    fn check_refuses_a_basis_outside_the_past_and_another_writers_claim() {
        let mut all = Vec::new();
        all.push(v(&all, "alice", 1, &[], vec![set("t", "1")]));
        all.push(v(&all, "bob", 1, &[], vec![set("t", "2")]));
        let outside = all[0].digest;
        all[1].op = Operation::by(&device("bob")).over([&outside]).set("t", "2");
        all.push(v(&all, "carol", 1, &[], vec![set("t", "3")]));
        all[2].op.writer = device("alice").to_string();
        let state = Element::new().start(&Writer::new(device("x")));
        let lax = Element::lax().start(&Writer::new(device("x")));
        let parents = Frontier::new();
        for i in [1, 2] {
            let bytes = all[i].op.encode();
            let past = InPast {
                all: &all,
                past: &all[i].past,
            };
            let op = Op {
                id: &all[i].id,
                digest: &all[i].digest,
                parents: &parents,
                past: &past,
                bytes: &bytes,
            };
            assert!(state.check(&op).is_err(), "version {i} is refused");
            assert!(lax.check(&op).is_ok(), "the lax copy refuses nothing");
        }
    }

    #[test]
    fn a_checkpoint_replaces_its_past_alike_with_or_without_it() {
        let mut all = Vec::new();
        all.push(v(&all, "alice", 1, &[], vec![Edit::Create("note".into())]));
        all.push(v(&all, "alice", 2, &[0], vec![set("body", "long")]));
        let whole = ElementState {
            kind: Some("note".into()),
            settings: [("body".to_owned(), "long".to_owned())].into(),
            ..ElementState::default()
        };
        all.push(v(&all, "alice", 3, &[0, 1], vec![Edit::Checkpoint(whole)]));
        all.push(v(&all, "bob", 1, &[0, 1, 2], vec![set("by", "bob")]));
        let (_, _, replayed) = run(&all, &[0, 1, 2, 3]);
        let (_, _, late) = run(&all, &[2, 3]);
        assert_eq!(replayed, late);
        assert_eq!(late.state.settings["body"], "long");
        assert_eq!(late.state.settings["by"], "bob");
    }
}
