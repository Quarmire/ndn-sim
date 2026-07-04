//! NDN over the radio in Monitor (named-data radio) vs Managed (normal Wi-Fi) mode, with **real NDN
//! engines**. The comparison the whole radio story is about: monitor's one broadcast serves every
//! in-range neighbour in a single airtime (NDN's multicast-native design), while managed Wi-Fi must
//! unicast to each — so the same exchange costs far more airtime on managed.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AppSpec, DesKernel, Position, RangeThreshold, SimKernel, Simulation, WifiMode};
use tokio_util::sync::CancellationToken;

/// One producer + three consumers, fully connected on the radio (every transmission has 3 in-range
/// receivers). Returns `(fetches_delivered, total_airtime)`.
fn run(mode: WifiMode) -> (u32, Duration) {
    DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new()
            .kernel(k)
            .with_radio_medium(Arc::new(RangeThreshold { range_m: 50.0, tx_power_dbm: 20.0 }), 7);
        let p = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let consumers = [
            sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 0.0)),
            sim.add_radio_node(EngineConfig::default(), Position::xy(20.0, 0.0)),
            sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 10.0)),
        ];
        sim.add_app(
            p,
            AppSpec::Producer { prefix: "/svc".into(), content: Some("air".into()), freshness_ms: None },
        );
        let fabric = sim.start().await.unwrap();
        fabric.radio_bus().unwrap().set_mac_mode(mode);

        let mut delivered = 0u32;
        for c in consumers {
            fabric.route_over_radio(c, &"/svc".parse::<Name>().unwrap()).unwrap();
            let mut consumer = fabric.engine_of(c).unwrap().app_consumer(CancellationToken::new());
            let ok = consumer
                .fetch_with(
                    InterestBuilder::new("/svc/0".parse::<Name>().unwrap())
                        .lifetime(Duration::from_secs(10)),
                )
                .await
                .is_ok();
            delivered += u32::from(ok);
        }
        let airtime = fabric.radio_bus().unwrap().total_airtime();
        fabric.shutdown().await;
        (delivered, airtime)
    })
}

#[test]
fn ndn_managed_wifi_costs_more_airtime_than_named_data_radio() {
    let (mon_delivered, mon_airtime) = run(WifiMode::Monitor);
    let (mgd_delivered, mgd_airtime) = run(WifiMode::Managed);

    // Both modes deliver the content (the MAC discipline changes cost, not correctness here).
    assert_eq!(mon_delivered, 3, "monitor delivered all fetches");
    assert_eq!(mgd_delivered, 3, "managed delivered all fetches");

    // Managed unicasts to each in-range neighbour instead of one broadcast → much more airtime.
    assert!(
        mgd_airtime > mon_airtime * 2,
        "named-data radio (monitor) is far more airtime-efficient than managed Wi-Fi: \
         monitor {mon_airtime:?} vs managed {mgd_airtime:?}"
    );
}
