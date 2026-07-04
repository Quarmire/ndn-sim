//! Wi-Fi operating modes + the pluggable propagation backend, exercised through IP-over-Wi-Fi.

use std::sync::Arc;
use std::time::Duration;

use ndn_sim::{
    DesKernel, IpNetwork, Position, RadioLinkConfig, ShortestPath, SimKernel, Wifi, WifiMode,
    WifiOperatingMode,
};

/// In IBSS, two in-range stations talk directly. In AP/infrastructure mode the same two stations may
/// only reach each other **through the AP** (a star), so station→station traffic relays at the AP.
#[test]
fn ap_mode_relays_station_to_station_through_the_ap() {
    let (ibss_ap_fwd, ap_ap_fwd, ap_recv) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let wifi = Wifi::new();
        // AP = node 0 (centre); stations A = node 1, B = node 2, both in range of each other + AP.
        let pos = vec![Position::xy(15.0, 0.0), Position::xy(0.0, 0.0), Position::xy(30.0, 0.0)];

        // IBSS: A↔B link directly.
        let ibss = IpNetwork::from_positions_wifi(
            k.runtime(), pos.clone(), &wifi, &RadioLinkConfig::new(50.0, WifiMode::Managed), &ShortestPath,
        );
        let _ = ibss.node(1).ping(ibss.addr(2), 5, 64, Duration::from_millis(1), Duration::from_millis(300)).await;
        let ibss_ap_fwd = ibss.node(0).stats().forwarded;

        // AP mode: A↔B is not a permitted link; traffic goes A→AP→B.
        let cfg = RadioLinkConfig::new(50.0, WifiMode::Managed).operating(WifiOperatingMode::Ap { ap: 0 });
        let ap = IpNetwork::from_positions_wifi(k.runtime(), pos, &wifi, &cfg, &ShortestPath);
        let r = ap.node(1).ping(ap.addr(2), 5, 64, Duration::from_millis(1), Duration::from_millis(300)).await;
        (ibss_ap_fwd, ap.node(0).stats().forwarded, r.received)
    });
    assert_eq!(ibss_ap_fwd, 0, "IBSS: A↔B direct — the AP node relays nothing");
    assert!(ap_ap_fwd > 0, "AP mode: station→station relays through the AP ({ap_ap_fwd})");
    assert!(ap_recv >= 4, "the AP-relayed flow still delivers ({ap_recv})");
}

/// Infrastructure (AP) mode makes a roaming station **re-associate** every time it leaves and
/// re-enters range — a handoff cost that accrues as control overhead. IBSS/monitor pays none.
#[test]
fn ap_mode_charges_a_handoff_each_time_a_station_roams_back() {
    let (ap_handoffs, ap_overhead, ibss_handoffs) =
        DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
            let wifi = Wifi::new();
            let cfg = RadioLinkConfig::new(50.0, WifiMode::Managed)
                .operating(WifiOperatingMode::Ap { ap: 0 });
            // AP at origin; station starts in range → its initial association is the first handoff.
            let ap = IpNetwork::from_positions_wifi(
                k.runtime(),
                vec![Position::xy(0.0, 0.0), Position::xy(30.0, 0.0)],
                &wifi,
                &cfg,
                &ShortestPath,
            );
            // Roam out of range (deassociate), then back (re-associate) — a second handoff.
            ap.reconnect_wifi(
                &[Position::xy(0.0, 0.0), Position::xy(100.0, 0.0)],
                &wifi,
                &cfg,
                &ShortestPath,
            );
            ap.reconnect_wifi(
                &[Position::xy(0.0, 0.0), Position::xy(30.0, 0.0)],
                &wifi,
                &cfg,
                &ShortestPath,
            );

            // IBSS has no AP association — no handoffs however the station moves.
            let ibss_cfg = RadioLinkConfig::new(50.0, WifiMode::Managed);
            let ibss = IpNetwork::from_positions_wifi(
                k.runtime(),
                vec![Position::xy(0.0, 0.0), Position::xy(30.0, 0.0)],
                &wifi,
                &ibss_cfg,
                &ShortestPath,
            );
            ibss.reconnect_wifi(
                &[Position::xy(0.0, 0.0), Position::xy(100.0, 0.0)],
                &wifi,
                &ibss_cfg,
                &ShortestPath,
            );
            (ap.handoff_count(), ap.association_overhead(), ibss.handoff_count())
        });
    assert_eq!(ap_handoffs, 2, "initial join + one roam-back = two associations");
    assert!(
        ap_overhead >= Duration::from_millis(240),
        "each handoff charges the ~120 ms scan+auth+assoc handshake: {ap_overhead:?}"
    );
    assert_eq!(ibss_handoffs, 0, "IBSS pays no association/handoff cost");
}

/// Swapping the propagation backend changes reach: a link that works under free-space is starved
/// under a lossier log-distance channel (exponent 3.5) at the same distance.
#[test]
fn pluggable_propagation_changes_reach() {
    use ndn_sim::LogDistance;
    let (fs, ld) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let wifi = Wifi::new();
        let pos = vec![Position::xy(0.0, 0.0), Position::xy(120.0, 0.0)];

        let free = RadioLinkConfig::new(4000.0, WifiMode::Monitor);
        let net_fs = IpNetwork::from_positions_wifi(k.runtime(), pos.clone(), &wifi, &free, &ShortestPath);
        let fs = net_fs.node(0).ping(net_fs.addr(1), 20, 64, Duration::from_millis(1), Duration::from_millis(200)).await.received;

        let lossy = RadioLinkConfig::new(4000.0, WifiMode::Monitor)
            .with_propagation(Arc::new(LogDistance { exponent: 3.5, ref_loss_db: 40.0, ref_dist_m: 1.0 }));
        let net_ld = IpNetwork::from_positions_wifi(k.runtime(), pos, &wifi, &lossy, &ShortestPath);
        let ld = net_ld.node(0).ping(net_ld.addr(1), 20, 64, Duration::from_millis(1), Duration::from_millis(200)).await.received;

        (fs, ld)
    });
    assert!(fs > ld, "free-space reaches farther than a lossy log-distance channel ({fs} vs {ld})");
}
