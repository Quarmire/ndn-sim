# Probes — validations that currently FAIL (open findings)

Unlike `examples/checks/` (which are green and CI-ready), specs in here are **expected to fail
today**. They are executable statements of properties the stack *should* have but doesn't yet — the
validation platform's diagnostic output, checked into the repo so a future fix flips them green.

Run one with `ndn-lab check examples/probes/<name>.toml`; a non-zero exit is the current, documented
outcome. `tests/validation.rs` asserts every probe here still fails, so one starting to pass is a
loud signal to fix it and promote it to `checks/`.

## Currently: no open probes

The first two findings the platform surfaced have both been **resolved and promoted to
`examples/checks/`**:

| Finding | Resolution |
|---------|-----------|
| Best-route doesn't fail over to a disjoint path mid-flow | Added a per-prefix **strategy** knob (`[[scenario.strategies]]`); a `multicast` strategy floods all next-hops and survives a dead relay. → `checks/relay-failover.toml` |
| Forwarders reported `cs_inserts == 0` for forwarded Data | Root cause was the sim producer emitting `FreshnessPeriod = 0` (correctly rejected by the default admission policy, as NFD does). The producer now stamps freshness; also wired real hit/miss/insert counters into `LruCs` (they were untracked). → `checks/cache-survives-producer.toml` |

New findings go here as failing specs until fixed.
