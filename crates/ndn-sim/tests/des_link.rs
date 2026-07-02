//! Real sim components on the discrete-event executor (ndn-lab): a `SimLink` — actual `SimFace`
//! delivery code, now on the `Runtime` seam — runs on the from-scratch `DesKernel`, not just
//! synthetic tasks. Deterministic delayed delivery driven by the event queue.

use std::time::Duration;

use bytes::Bytes;
use ndn_sim::{DesKernel, FaceProfile, LinkConfig, SimKernel, SimLink};
use ndn_transport::{FaceId, Transport};

#[test]
fn simlink_delivers_over_the_event_queue() {
    let got = DesKernel::new().run(|k: std::sync::Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        // Real SimFace pair, its delivery timing riding the DES runtime.
        let (a, b) = SimLink::pair_profiled_on(
            FaceId(1),
            FaceId(2),
            &FaceProfile::internal().with_link(LinkConfig {
                delay: Duration::from_millis(10),
                ..LinkConfig::default()
            }),
            16,
            rt,
        );
        a.send_bytes(Bytes::from_static(b"hello")).await.unwrap();
        // The 10 ms link delay is scheduled on the event queue; recv completes when the executor
        // advances the virtual clock to it.
        b.recv_bytes().await.unwrap().to_vec()
    });
    assert_eq!(got, b"hello");
}

#[test]
fn reliable_stream_is_in_order_and_deterministic_on_des() {
    let run = || {
        DesKernel::new().run(|k: std::sync::Arc<dyn SimKernel>| async move {
            let rt = k.runtime();
            // TCP profile with jitter: reliable ⇒ no loss, in-order, even on the event queue.
            let (a, b) = SimLink::pair_profiled_on(
                FaceId(1),
                FaceId(2),
                &FaceProfile::tcp().with_link(LinkConfig {
                    delay: Duration::from_millis(1),
                    jitter: Duration::from_millis(5),
                    loss_rate: 1.0, // ignored by a reliable stream
                    bandwidth_bps: 0,
                }),
                64,
                rt,
            );
            for i in 0..10u8 {
                a.send_bytes(Bytes::copy_from_slice(&[i])).await.unwrap();
            }
            let mut got = Vec::new();
            for _ in 0..10 {
                got.push(b.recv_bytes().await.unwrap()[0]);
            }
            got
        })
    };
    let first = run();
    let second = run();
    assert_eq!(first, (0..10).collect::<Vec<u8>>(), "reliable: all in order on the event queue");
    assert_eq!(first, second, "the event queue replays identically");
}
