# Probes — validations that currently FAIL (open findings)

Unlike `examples/checks/` (which are green and CI-ready), the specs in here are **expected to fail
today**. They are executable statements of properties the stack *should* have but doesn't yet — the
validation platform's diagnostic output, checked into the repo so a future fix flips them green.

Run one with `ndn-lab check examples/probes/<name>.toml`; a non-zero exit is the current, documented
outcome. Each file's header explains the finding and what would make it pass.

| Probe | Finding |
|-------|---------|
| `relay-failover.toml` | Best-route does not fail over to an alternate next-hop mid-flow. A dead relay stalls the consumer; there is no scenario knob to select a multicast / retransmit-on-timeout strategy that would recover. |
| `cache-survives-producer.toml` | Forwarders do not populate their Content Store on the forwarding path (`cs_inserts == 0` at a relay that forwarded the Data), so cached content cannot outlive a dead producer. Disruption-tolerant caching — a core NDN value — is not observable in the sim today. |
