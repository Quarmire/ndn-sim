//! The store `ndn-heap` runs over in the suite: a memory store that models a disk with a write
//! cache, so a case can cut the power, kill the process, copy the disk, stall the flush and
//! fail it.
//!
//! Reads and writes go to the live state; a `sync` that returned made everything written before
//! it call durable. What a power loss leaves is [`CrashStore::durable`]: the image at the last
//! `sync` that returned. What a process kill leaves is [`CrashStore::live`]: every write that
//! returned, flushed or not (the operating system still holds them).
//!
//! The same shape as the crate's own test kit (`ndn-heap/src/test_kit.rs`), whose store is
//! `cfg(test)` there.

use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex};

use bytes::Bytes;
use ndn_heap::Name;
use ndn_sync::{DataStore, MemoryStore, StoreOp};

/// What a disk holds: the durable image, and the writes made since the last sync that a power
/// loss takes.
#[derive(Default)]
struct Disk {
    image: BTreeMap<Name, Bytes>,
    unsynced: Vec<Vec<StoreOp>>,
}

impl Disk {
    fn fold(&mut self, writes: impl IntoIterator<Item = Vec<StoreOp>>) {
        for op in writes.into_iter().flatten() {
            match op {
                StoreOp::Insert(name, wire) => {
                    self.image.insert(name, wire);
                }
                StoreOp::Remove(name) => {
                    self.image.remove(&name);
                }
            }
        }
    }
}

/// Whether the store's `sync` is held, and who waits for it to be released.
#[derive(Default)]
struct Gate {
    held: Mutex<bool>,
    let_go: Condvar,
}

impl Gate {
    fn set(&self, held: bool) {
        *self.held.lock().expect("the gate's lock") = held;
        if !held {
            self.let_go.notify_all();
        }
    }

    fn is_held(&self) -> bool {
        *self.held.lock().expect("the gate's lock")
    }

    /// Return once the gate is not held.
    fn pass(&self) {
        let mut held = self.held.lock().expect("the gate's lock");
        while *held {
            held = self.let_go.wait(held).expect("the gate's lock");
        }
    }
}

/// A memory store with a disk's write cache; see the module docs.
#[derive(Default)]
pub struct CrashStore {
    live: MemoryStore,
    disk: Mutex<Disk>,
    gate: Gate,
    failure: Mutex<Option<String>>,
}

impl CrashStore {
    /// A store that starts as `image`: live and durable alike.
    pub fn booted(image: BTreeMap<Name, Bytes>) -> Self {
        let store = Self::default();
        for (name, wire) in &image {
            store.live.insert(name.clone(), wire.clone());
        }
        store.disk.lock().expect("the disk's lock").image = image;
        store
    }

    /// What a power loss now leaves: the image at the last `sync` that returned.
    pub fn durable(&self) -> BTreeMap<Name, Bytes> {
        self.disk.lock().expect("the disk's lock").image.clone()
    }

    /// What a process kill now leaves: every write that returned.
    pub fn live(&self) -> BTreeMap<Name, Bytes> {
        self.live.scan_under(&Name::root(), 0).into_iter().collect()
    }

    /// Hold every later `sync` until [`Self::hold`] is called with `false` (a disk that stalls).
    pub fn hold(&self, on: bool) {
        self.gate.set(on);
    }

    /// Whether `sync` is held.
    pub fn held(&self) -> bool {
        self.gate.is_held()
    }

    /// From now on every `sync` fails with `why`; `None`: syncs succeed again.
    pub fn fail(&self, why: Option<&str>) {
        *self.failure.lock().expect("the failure's lock") = why.map(str::to_owned);
    }

    fn write(&self, ops: Vec<StoreOp>) {
        // One lock over both, so the log is in the order the live store saw.
        let mut disk = self.disk.lock().expect("the disk's lock");
        self.live.apply(ops.clone());
        disk.unsynced.push(ops);
    }
}

impl DataStore for CrashStore {
    fn insert(&self, name: Name, wire: Bytes) {
        self.write(vec![StoreOp::Insert(name, wire)]);
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.live.get(name)
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.live.find_under(prefix)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.live.scan_under(prefix, limit)
    }

    fn remove(&self, name: &Name) {
        self.write(vec![StoreOp::Remove(name.clone())]);
    }

    fn apply(&self, ops: Vec<StoreOp>) {
        if !ops.is_empty() {
            self.write(ops);
        }
    }

    fn sync(&self) -> std::io::Result<()> {
        let covered = self.disk.lock().expect("the disk's lock").unsynced.len();
        self.gate.pass();
        if let Some(why) = self.failure.lock().expect("the failure's lock").clone() {
            return Err(std::io::Error::other(why));
        }
        let mut disk = self.disk.lock().expect("the disk's lock");
        let covered = covered.min(disk.unsynced.len());
        let done: Vec<_> = disk.unsynced.drain(..covered).collect();
        disk.fold(done);
        Ok(())
    }

    /// A flush that is not held returns at once, so a virtual-time run flushes inline; a held one
    /// waits on a blocking thread.
    fn sync_is_immediate(&self) -> bool {
        !self.gate.is_held()
    }
}
