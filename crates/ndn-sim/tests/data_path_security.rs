//! Data-path validation across UDP hops, on nodes booted from ndn-fwd configs.
//!
//! A consumer on `gcs` fetches telemetry that `uav` signs with an Ed25519 key; `relay` sits
//! between them (`gcs` <-udp-> `relay` <-udp-> `uav`). No forwarder has the signing key's
//! certificate cached: `uav` serves it under its KeyLocator name, the way a producer publishes its
//! cert, and every validating forwarder on the path must fetch it before the Data may pass.
//!
//! Until the engine fetched certificates through its own faces, `profile = "default"` wired a
//! no-op fetcher and `"accept-signed"` none, so the relay parked the Data, logged "validation:
//! DROPPED — cert fetch timed out" four seconds later, and no cert Interest ever left it
//! (`ndn-rs/docs/nfd-divergence-findings.md`, Round 17).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, Ed25519Signer, FilePib, SignWith, Signer, encode_cert_data};
use ndn_sim::{NodeId, RunningSimulation, SimKernel, Simulation, VirtualKernel};
use tokio_util::sync::CancellationToken;

const TELEMETRY: &str = "/fleet/uav/telemetry/1";
const PAYLOAD: &[u8] = b"lat=47.1 lon=8.5";
const UAV_KEY: &str = "/fleet/uav/KEY/k1";
const ROOT_KEY: &str = "/fleet/KEY/root";
/// The identity every node's PIB holds (`[security] identity`).
const NODE_IDENTITY: &str = "/fleet/node/KEY/1";

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

fn signer(key: &str, seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&[seed; 32], name(key))
}

/// Certificate Data for `subject`, signed by `issuer` (self-signed when they are the same key),
/// named `cert_name` (by default the key name, as ndn-rs names its certificates).
fn cert_named(cert_name: &Name, subject: &Ed25519Signer, issuer: &Ed25519Signer) -> Bytes {
    let pk = subject.public_key().unwrap();
    futures::executor::block_on(encode_cert_data(cert_name, &pk, issuer, 0, u64::MAX)).unwrap()
}

fn cert_wire(subject: &Ed25519Signer, issuer: &Ed25519Signer) -> Bytes {
    cert_named(subject.key_name(), subject, issuer)
}

/// A PIB as an operator provisions a fleet node: its identity key, plus the fleet root
/// certificate as its trust anchor (`ndn-sec anchor add`).
fn provision_pib(dir: &Path, root: &Ed25519Signer) {
    let pib = FilePib::new(dir).unwrap();
    pib.generate_ed25519(&name(NODE_IDENTITY)).unwrap();
    let anchor = Certificate::decode(&Data::decode(cert_wire(root, root)).unwrap()).unwrap();
    pib.add_trust_anchor(&anchor.name, &anchor).unwrap();
}

/// An ndn-fwd config: `security`, a UDP listener, one UDP peer face per `peers` entry, and
/// `routes` as `(prefix, face index)`.
fn config(security: &str, peers: &[&str], routes: &[(&str, usize)]) -> ndn_config::ForwarderConfig {
    let mut toml = format!("{security}\n[[face]]\nkind = \"udp\"\nbind = \"0.0.0.0:6363\"\n");
    for peer in peers {
        toml += &format!(
            "[[face]]\nkind = \"udp\"\nbind = \"0.0.0.0:6363\"\nremote = \"{peer}:6363\"\n"
        );
    }
    for (prefix, face) in routes {
        toml += &format!("[[route]]\nprefix = \"{prefix}\"\nface = {face}\n");
    }
    toml.parse().unwrap()
}

/// What the telemetry producer on `uav` publishes.
#[derive(Clone, Copy)]
enum Producer {
    /// Signed by a key whose certificate the fleet root issued.
    IssuedByRoot,
    /// Signed by a key whose certificate is self-signed (no anchor vouches for it).
    SelfSigned,
    /// As `SelfSigned`, but the Data's signature bytes were tampered with in transit.
    Forged,
    /// As `SelfSigned`, named the way ndn-cxx names it: the KeyLocator is the KEY name
    /// (`/fleet/uav/KEY/k1`) and the certificate answering it is `/fleet/uav/KEY/k1/self/v1`.
    KeyNameLocator,
}

struct Outcome {
    /// The telemetry content the consumer on `gcs` received, if any.
    delivered: Option<Bytes>,
    /// Interests for the certificate that reached the producer.
    cert_requests: usize,
}

fn run(security: &str, producer: Producer) -> Outcome {
    let security = security.to_string();
    VirtualKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new().kernel(k);
        let gcs = sim.add_node_from_config(
            "gcs",
            config(&security, &["10.0.0.2"], &[("/fleet", 1)]),
            "10.0.0.1".parse().unwrap(),
        );
        sim.add_node_from_config(
            "relay",
            config(&security, &["10.0.0.1", "10.0.0.3"], &[("/fleet/uav", 2)]),
            "10.0.0.2".parse().unwrap(),
        );
        let uav = sim.add_node_from_config(
            "uav",
            config(&security, &["10.0.0.2"], &[]),
            "10.0.0.3".parse().unwrap(),
        );
        let fabric = sim.start().await.unwrap();
        let cancel = CancellationToken::new();

        let key = signer(UAV_KEY, 1);
        let cert = match producer {
            Producer::IssuedByRoot => cert_wire(&key, &signer(ROOT_KEY, 9)),
            Producer::SelfSigned | Producer::Forged => cert_wire(&key, &key),
            Producer::KeyNameLocator => {
                cert_named(&name(&format!("{UAV_KEY}/self/v1")), &key, &key)
            }
        };
        let data = {
            let wire = DataBuilder::new(name(TELEMETRY), PAYLOAD)
                .sign_with_sync(&key)
                .unwrap();
            if let Producer::Forged = producer {
                let mut w = wire.to_vec();
                *w.last_mut().unwrap() ^= 0xFF;
                Bytes::from(w)
            } else {
                wire
            }
        };

        let uav_app = engine(&fabric, uav).app_node(cancel.child_token());
        let _telemetry = uav_app
            .serve("/fleet/uav/telemetry", move |_i, r| {
                let data = data.clone();
                async move {
                    let _ = r.respond_bytes(data).await;
                }
            })
            .await
            .unwrap();
        let cert_requests = Arc::new(AtomicUsize::new(0));
        let _cert = uav_app
            .serve(UAV_KEY, {
                let cert_requests = Arc::clone(&cert_requests);
                move |_i, r| {
                    cert_requests.fetch_add(1, Ordering::Relaxed);
                    let cert = cert.clone();
                    async move {
                        let _ = r.respond_bytes(cert).await;
                    }
                }
            })
            .await
            .unwrap();

        let delivered = engine(&fabric, gcs)
            .app_node(cancel.child_token())
            .fetch(TELEMETRY)
            .await
            .ok()
            .and_then(|d| d.content().cloned());

        let outcome = Outcome {
            delivered,
            cert_requests: cert_requests.load(Ordering::Relaxed),
        };
        cancel.cancel();
        fabric.shutdown().await;
        outcome
    })
}

fn engine(fabric: &RunningSimulation, node: NodeId) -> ndn_engine::ForwarderEngine {
    fabric.engine_of(node).unwrap()
}

const ACCEPT_SIGNED: &str = "[security]\nprofile = \"accept-signed\"\n";
const DISABLED: &str = "[security]\nprofile = \"disabled\"\n";

/// Run under `profile = "default"` with every node's identity and the fleet root anchor loaded
/// from a provisioned PIB, as ndn-fwd loads them.
fn run_default(test: &str, producer: Producer) -> Outcome {
    let pib: PathBuf = std::env::temp_dir().join(format!("ndn-sim-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&pib);
    provision_pib(&pib, &signer(ROOT_KEY, 9));
    let security = format!(
        "[security]\nprofile = \"default\"\nidentity = \"{NODE_IDENTITY}\"\npib_path = \"{}\"\n",
        pib.display()
    );
    let out = run(&security, producer);
    let _ = std::fs::remove_dir_all(&pib);
    out
}

#[test]
fn accept_signed_forwards_data_whose_cert_the_forwarders_fetch() {
    let out = run(ACCEPT_SIGNED, Producer::SelfSigned);
    assert_eq!(
        out.delivered.as_deref(),
        Some(PAYLOAD),
        "signed telemetry must cross relay and gcs once they fetch the signer's cert \
         ({} cert Interests reached the producer)",
        out.cert_requests
    );
}

#[test]
fn accept_signed_drops_a_forged_signature_after_fetching_the_cert() {
    let out = run(ACCEPT_SIGNED, Producer::Forged);
    assert!(
        out.cert_requests >= 1,
        "the forwarder never fetched the key to check the signature"
    );
    assert_eq!(out.delivered, None, "a forged signature must not verify");
}

#[test]
fn accept_signed_fetches_the_cert_for_a_key_name_key_locator() {
    let out = run(ACCEPT_SIGNED, Producer::KeyNameLocator);
    assert_eq!(
        out.delivered.as_deref(),
        Some(PAYLOAD),
        "a KeyLocator naming the KEY must be fetched with CanBePrefix and its longer-named cert \
         found under the KEY name ({} cert Interests reached the producer)",
        out.cert_requests
    );
}

#[test]
fn default_forwards_data_that_chains_to_the_pib_anchor() {
    let out = run_default("default-anchored", Producer::IssuedByRoot);
    assert_eq!(
        out.delivered.as_deref(),
        Some(PAYLOAD),
        "telemetry signed under the fleet root must cross relay and gcs once they fetch the \
         signer's cert ({} cert Interests reached the producer)",
        out.cert_requests
    );
}

#[test]
fn default_drops_data_whose_cert_no_anchor_vouches_for() {
    let out = run_default("default-untrusted", Producer::SelfSigned);
    assert!(
        out.cert_requests >= 1,
        "the forwarder never fetched the cert to walk its chain"
    );
    assert_eq!(
        out.delivered, None,
        "a self-signed cert outside the PIB's anchors must not be trusted"
    );
}

/// With no `[security] identity`, a node runs on an ephemeral key (as ndn-fwd does) whose only
/// anchor is itself: `default` must drop everyone else's key-signed Data, never quietly
/// degrade to checking the signature alone.
#[test]
fn default_without_an_identity_fails_closed() {
    let out = run("[security]\nprofile = \"default\"\n", Producer::SelfSigned);
    assert!(
        out.cert_requests >= 1,
        "the forwarder never fetched the cert to walk its chain"
    );
    assert_eq!(
        out.delivered, None,
        "no anchor vouches for the producer: `default` must fail closed"
    );
}

#[test]
fn disabled_forwards_without_fetching_certs() {
    let out = run(DISABLED, Producer::Forged);
    assert_eq!(out.delivered.as_deref(), Some(PAYLOAD));
    assert_eq!(
        out.cert_requests, 0,
        "profile = \"disabled\" must not fetch certificates"
    );
}
