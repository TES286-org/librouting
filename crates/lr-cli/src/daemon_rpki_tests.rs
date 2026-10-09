use super::*;
use lr_core::addr::Prefix;

fn disconnected_state(age: Duration) -> RpkiLoop {
    let mut builder = lr_bgp::RoaTableBuilder::new();
    builder.add("198.51.100.0/24", None, 64513).unwrap();
    let store = Arc::new(RoaStore::from_table(builder.build()));
    let mut client = RtrClient::new();
    client.on_connect();
    for pdu in [
        RtrPdu::CacheResponse { session_id: 1 },
        RtrPdu::Ipv4Prefix {
            announce: true,
            prefix: Prefix::new_v4([192, 0, 2, 0], 24),
            max_length: 24,
            asn: 64512,
        },
        RtrPdu::EndOfData {
            session_id: 1,
            serial: 1,
            refresh_interval: Some(60),
            retry_interval: Some(1),
            expire_interval: Some(120),
        },
    ] {
        let step = client.on_pdu(rtr::RTR_VERSION_MAX, &pdu, 0);
        store.apply_rtr_deltas(&step.roa_deltas);
    }
    assert_eq!(store.rtr_len(), 1);
    let (_, control) = mpsc::channel();
    RpkiLoop {
        store,
        running: Arc::new(AtomicBool::new(true)),
        control,
        status: Arc::new(Mutex::new(RpkiStatus {
            cache: "127.0.0.1:1".into(),
            connected: false,
            version: rtr::RTR_VERSION_MAX,
            phase: "synced",
            session_id: Some(1),
            serial: Some(1),
            static_roas: 1,
            rtr_roas: 1,
            roas: 2,
            refresh_interval: 60,
            retry_interval: 1,
            expire_interval: 120,
            last_sync_age_s: Some(age.as_secs()),
        })),
        cache: "127.0.0.1:1".into(),
        client,
        stream: None,
        buf: Vec::new(),
        start: Instant::now() - age,
        last_sync: Some(Instant::now() - age),
    }
}

#[test]
fn reconnect_backoff_expires_cache_roas_and_preserves_static_roas() {
    let mut state = disconnected_state(Duration::from_secs(121));
    state.sleep_backoff();
    assert_eq!(state.store.rtr_len(), 0, "offline cache data must expire");
    assert_eq!(state.store.static_len(), 1);
    assert_eq!(
        state.client.serial(),
        None,
        "reconnect must use a reset query"
    );
    assert!(state.last_sync.is_none());
    assert_eq!(state.status.lock().unwrap().rtr_roas, 0);
}

#[test]
fn reconnect_backoff_retains_unexpired_cache_roas() {
    let mut state = disconnected_state(Duration::from_secs(61));
    state.sleep_backoff();
    assert_eq!(state.store.rtr_len(), 1);
    assert_eq!(state.store.static_len(), 1);
    assert_eq!(state.client.serial(), Some(1));
}
