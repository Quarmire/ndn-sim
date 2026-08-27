//! Single integration-test suite binary (P1 compile-cost consolidation).
//!
//! Linking ~53 separate integration-test binaries dominated `cargo test`
//! cost for this crate; `autotests = false` + this one `[[test]]` collapses
//! them into a single link. Each sibling `tests/*.rs` file is pulled in
//! unchanged as a `#[path]` module — test bodies, `#[ignore]` attributes
//! (the ndnd/NFD interop gates), and DES/virtual-time behavior are exactly
//! as they were; only the binary boundary moved. Under nextest each test
//! still runs in its own process, so per-file global-state assumptions
//! (tracing subscribers, env vars, thread-local RNG seeds) are undisturbed.
//!
//! `mavlink.rs` keeps its inner `#![cfg(feature = "mavlink")]`, which now
//! gates the module instead of a whole binary — same effect.

#[path = "adversary_bench.rs"]
mod adversary_bench;
#[path = "analysis.rs"]
mod analysis;
#[path = "app.rs"]
mod app;
#[path = "authenticated_control.rs"]
mod authenticated_control;
#[path = "bridge.rs"]
mod bridge;
#[path = "bridge_flow.rs"]
mod bridge_flow;
#[path = "broadcast_segment.rs"]
mod broadcast_segment;
#[path = "ceiling_finder.rs"]
mod ceiling_finder;
#[path = "compare.rs"]
mod compare;
#[path = "control_plane.rs"]
mod control_plane;
#[path = "cosim.rs"]
mod cosim;
#[path = "des_fabric.rs"]
mod des_fabric;
#[path = "des_link.rs"]
mod des_link;
#[path = "des_radio.rs"]
mod des_radio;
#[path = "determinism.rs"]
mod determinism;
#[path = "dx_ergonomics.rs"]
mod dx_ergonomics;
#[path = "fabric.rs"]
mod fabric;
#[path = "face_catalogue.rs"]
mod face_catalogue;
#[path = "faults.rs"]
mod faults;
#[path = "feed.rs"]
mod feed;
#[path = "field_faults.rs"]
mod field_faults;
#[path = "geometry.rs"]
mod geometry;
#[path = "interop_ndnd.rs"]
mod interop_ndnd;
#[path = "interop_nfd.rs"]
mod interop_nfd;
#[path = "ip_mobility.rs"]
mod ip_mobility;
#[path = "ip_plane.rs"]
mod ip_plane;
#[path = "mavlink.rs"]
mod mavlink;
#[path = "mcp.rs"]
mod mcp;
#[path = "multihop.rs"]
mod multihop;
#[path = "named_time_convergence.rs"]
mod named_time_convergence;
#[path = "named_time_mesh.rs"]
mod named_time_mesh;
#[path = "named_time_svs.rs"]
mod named_time_svs;
#[path = "ndn_radio_mode.rs"]
mod ndn_radio_mode;
#[path = "ns11_persistent_liveness.rs"]
mod ns11_persistent_liveness;
#[path = "otel_export.rs"]
mod otel_export;
#[path = "prefix_accounting.rs"]
mod prefix_accounting;
#[path = "radio_builder.rs"]
mod radio_builder;
#[path = "radio_face.rs"]
mod radio_face;
#[path = "real_time.rs"]
mod real_time;
#[path = "relay_hops.rs"]
mod relay_hops;
#[path = "replay.rs"]
mod replay;
#[path = "scenario.rs"]
mod scenario;
#[path = "scene.rs"]
mod scene;
#[path = "span_capture.rs"]
mod span_capture;
#[path = "stall_matrix.rs"]
mod stall_matrix;
#[path = "steppable.rs"]
mod steppable;
#[path = "streaming.rs"]
mod streaming;
#[path = "telemetry.rs"]
mod telemetry;
#[path = "validation.rs"]
mod validation;
#[path = "virtual_time.rs"]
mod virtual_time;
#[path = "wifi_modes.rs"]
mod wifi_modes;
#[path = "workload.rs"]
mod workload;
#[path = "world_medium.rs"]
mod world_medium;
mod ground_truth;
