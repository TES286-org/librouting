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
        stopped: false,
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

// ============================================================
// Shutdown (issue #92): removing `[bgp.rpki] cache` via SIGHUP
// tears down the live RTR thread instead of leaving it running
// against the stale cache address.
// ============================================================

/// Build an `RpkiLoop` with a connected control channel (the
/// `disconnected_state` helper drops the sender, so `try_recv`
/// returns `Err(Disconnected)` — fine for the backoff tests but
/// not for the shutdown tests, which need to actually push a
/// `RpkiCommand` through the channel).
fn state_with_channel(age: Duration) -> (RpkiLoop, Sender<RpkiCommand>) {
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
    let (tx, rx) = mpsc::channel();
    let state = RpkiLoop {
        store,
        running: Arc::new(AtomicBool::new(true)),
        control: rx,
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
        stopped: false,
    };
    (state, tx)
}

#[test]
fn shutdown_command_drains_as_control_stop() {
    let (mut state, tx) = state_with_channel(Duration::from_secs(0));
    tx.send(RpkiCommand::Shutdown).unwrap();
    let ctrl = state.drain_control();
    assert!(
        matches!(ctrl, Control::Stop),
        "drain_control must return Control::Stop on Shutdown, got {ctrl:?}"
    );
}

#[test]
fn shutdown_clears_rtr_roas_preserves_static_drops_transport_and_latches_stopped() {
    let (mut state, tx) = state_with_channel(Duration::from_secs(0));
    // Pretend the transport is up (the reload path can fire while a
    // sync is in flight — the loop drops the stream on the floor
    // inside `handle_shutdown`).
    let stream = TcpStream::connect("127.0.0.1:1").ok();
    state.stream = stream;
    tx.send(RpkiCommand::Shutdown).unwrap();
    let ctrl = state.drain_control();
    assert!(matches!(ctrl, Control::Stop));
    assert_eq!(state.store.rtr_len(), 0, "shutdown must withdraw RTR ROAs");
    assert_eq!(
        state.store.static_len(),
        1,
        "shutdown must preserve static [[roa]] entries"
    );
    assert!(
        state.stream.is_none(),
        "shutdown must drop the live transport"
    );
    assert!(
        state.last_sync.is_none(),
        "shutdown must clear last_sync (no further age against withdrawn data)"
    );
    assert!(
        state.stopped,
        "shutdown must latch the stopped flag so the loop breaks and status reflects it"
    );
    assert_eq!(
        state.client.serial(),
        None,
        "shutdown must reset the client (no stale session survives)"
    );
    assert_eq!(
        state.status.lock().unwrap().phase,
        "stopped",
        "status phase must render 'stopped' after shutdown"
    );
    assert_eq!(
        state.status.lock().unwrap().rtr_roas,
        0,
        "status rtr_roas must reflect the cleared RTR layer"
    );
    assert_eq!(
        state.status.lock().unwrap().static_roas,
        1,
        "status static_roas must be untouched"
    );
}

#[test]
fn shutdown_during_read_burst_exits_the_loop() {
    // The `read_available` burst loop also drains the control
    // channel between reads; a queued Shutdown must surface the
    // same way as at the loop head (otherwise a slow-drip cache
    // would keep the thread alive past the SIGHUP).
    let (mut state, tx) = state_with_channel(Duration::from_secs(0));
    tx.send(RpkiCommand::Shutdown).unwrap();
    // No stream installed: `read_available` returns false on the
    // first iteration when self.stream is None — but the control
    // drain runs first and consumes the Shutdown.
    let cont = state.read_available();
    assert!(
        !cont,
        "read_available must return false (loop re-enters / exits) on Shutdown"
    );
    assert!(state.stopped, "handle_shutdown must have run");
    assert_eq!(state.store.rtr_len(), 0);
}

#[test]
fn shutdown_during_backoff_exits_the_backoff() {
    // The retry backoff is interruptible; a queued Shutdown must
    // break out of the backoff loop so the outer loop sees the
    // Control::Stop and exits, instead of waiting the full retry
    // interval before noticing.
    let (mut state, tx) = state_with_channel(Duration::from_secs(0));
    tx.send(RpkiCommand::Shutdown).unwrap();
    let start = Instant::now();
    state.sleep_backoff();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "sleep_backoff must exit promptly on Shutdown (took {elapsed:?})"
    );
    assert!(state.stopped);
    assert_eq!(state.store.rtr_len(), 0);
}

#[test]
fn handle_shutdown_idempotent_on_repeated_calls() {
    // A second SIGHUP after the cache was already removed must not
    // panic (the channel still has the receiver alive until the
    // loop exits — but `handle_shutdown` is safe to call twice).
    let (mut state, _) = state_with_channel(Duration::from_secs(0));
    state.handle_shutdown();
    let first_status_phase = state.status.lock().unwrap().phase;
    state.handle_shutdown();
    // The second call must not undo the latch or re-introduce ROAs.
    assert!(state.stopped);
    assert_eq!(state.store.rtr_len(), 0);
    assert_eq!(state.status.lock().unwrap().phase, first_status_phase);
}

#[test]
fn rpki_handle_shutdown_sends_command_and_returns_log_line() {
    // Construct a handle directly so we do not have to spawn a
    // thread: `RpkiHandle::shutdown` only needs to push a
    // `RpkiCommand::Shutdown` into the channel and return the log
    // line. The receiver is dropped unused — the unit test asserts
    // the message arrived and the channel state after.
    let (tx, rx) = mpsc::channel();
    let handle = RpkiHandle {
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
            last_sync_age_s: Some(0),
        })),
        control: tx,
    };
    let line = handle.shutdown();
    assert!(
        line.contains("shutdown requested"),
        "shutdown log line must mention 'shutdown requested': {line}"
    );
    let cmd = rx
        .try_recv()
        .expect("shutdown must enqueue RpkiCommand::Shutdown");
    assert!(
        matches!(cmd, RpkiCommand::Shutdown),
        "enqueued command must be Shutdown, got {cmd:?}"
    );
}

#[test]
fn rpki_handle_shutdown_after_receiver_dropped_returns_gone_message() {
    // After the thread exits (the receiver is dropped), a second
    // reload that re-removes the cache must surface a clear
    // "client thread is gone" diagnostic instead of pretending to
    // shut down a non-existent thread.
    let (tx, rx) = mpsc::channel();
    let handle = RpkiHandle {
        status: Arc::new(Mutex::new(RpkiStatus {
            cache: "127.0.0.1:1".into(),
            connected: false,
            version: rtr::RTR_VERSION_MAX,
            phase: "stopped",
            session_id: None,
            serial: None,
            static_roas: 0,
            rtr_roas: 0,
            roas: 0,
            refresh_interval: 60,
            retry_interval: 1,
            expire_interval: 120,
            last_sync_age_s: None,
        })),
        control: tx,
    };
    drop(rx);
    let line = handle.shutdown();
    assert!(
        line.contains("thread is gone"),
        "shutdown on a dead handle must report the thread is gone: {line}"
    );
    let line2 = handle.reconnect("127.0.0.1:2".to_string(), 60, 1, 120);
    assert!(
        line2.contains("thread is gone"),
        "reconnect on a dead handle must report the thread is gone: {line2}"
    );
}
