//! Single integration-test suite binary for the studies crate (same compile-cost rule as ndn-sim's
//! `tests/suite.rs`: one link, each sibling file pulled in unchanged as a `#[path]` module).
//!
//! These are research checks — the IP plane, the LoRa model, named-time convergence demos — not
//! fleet contracts; the fleet-facing gates live in the ndn-sim core suite.

#[path = "compare.rs"]
mod compare;
#[path = "ip_mobility.rs"]
mod ip_mobility;
#[path = "ip_plane.rs"]
mod ip_plane;
#[path = "lora_ground_truth.rs"]
mod lora_ground_truth;
#[path = "named_time_convergence.rs"]
mod named_time_convergence;
#[path = "named_time_mesh.rs"]
mod named_time_mesh;
#[path = "named_time_svs.rs"]
mod named_time_svs;
#[path = "wifi_modes.rs"]
mod wifi_modes;
