//! Two-speaker LDP E2E over real loopback sockets.
//!
//! Two [`LdpEngine`] instances (A on 127.0.0.1, B on 127.0.0.2 — both
//! loopback addresses on Linux) exchange targeted Hellos over UDP,
//! establish the §2.5.4 session over TCP, exchange Address and Label
//! Mapping messages and run the withdrawal and keepalive-expiry
//! lifecycles. The test is the embedder: it owns the sockets, pumps
//! both engines and moves bytes between them.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant as StdInstant};

use lr_core::addr::Prefix;
use lr_core::time::Instant;
use lr_ldp::engine::{EngineEvent, LdpEngine, LdpEngineConfig};
use lr_ldp::mapping::FecKey;
use lr_ldp::session::{SessionDownReason, SessionState};
use lr_ldp::{GenericLabel, IpAddr, LdpId, StatusCode};

struct Speaker {
    engine: LdpEngine,
    udp: UdpSocket,
    listener: TcpListener,
    tcp_port: u16,
    /// The peer's UDP port for targeted Hellos (the engine deals in
    /// addresses; the embedder adds the port).
    peer_udp_port: u16,
    /// The peer's TCP listener port for active connects.
    peer_tcp_port: u16,
    conns: HashMap<u64, TcpStream>,
    next_conn: u64,
}

impl Speaker {
    fn new(lsr_id: [u8; 4], addr: IpAddr, peer_addr: IpAddr, interface_addrs: Vec<IpAddr>) -> Self {
        let mut cfg = LdpEngineConfig::new(LdpId::new(lsr_id, 0), addr);
        cfg.targeted_peers = Vec::from([peer_addr]);
        cfg.accept_targeted = true;
        cfg.keepalive_time = 2; // short for test pacing (§3.5.3: non-zero)
        cfg.targeted_hello_hold = 9; // hello every hold/3 = 3s
        cfg.interface_addresses = interface_addrs;
        let engine = LdpEngine::new(cfg);
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let tcp_port = listener.local_addr().unwrap().port();
        Speaker {
            engine,
            udp,
            listener,
            tcp_port,
            peer_udp_port: 0,
            peer_tcp_port: 0,
            conns: HashMap::new(),
            next_conn: 1,
        }
    }

    fn udp_port(&self) -> u16 {
        self.udp.local_addr().unwrap().port()
    }

    /// One pump round: timers, socket I/O, engine event handling.
    fn pump(&mut self, now: Instant) -> Vec<EngineEvent> {
        self.engine.tick(now);

        // Outbound UDP.
        for (dest, bytes) in self.engine.drain_udp() {
            let sock = dest_socket_addr(&dest, self.peer_udp_port);
            let _ = self.udp.send_to(&bytes, sock);
        }

        // Outbound TCP.
        self.flush_tcp();

        // Inbound UDP.
        let mut buf = [0u8; 65535];
        while let Ok((n, from)) = self.udp.recv_from(&mut buf) {
            self.engine.feed_udp(now, sock_to_ip(from), &buf[..n]);
        }

        // Accept passive connections.
        while let Ok((stream, _peer)) = self.listener.accept() {
            stream.set_nonblocking(true).unwrap();
            let conn = self.next_conn;
            self.next_conn += 1;
            self.conns.insert(conn, stream);
            self.engine.on_accepted(conn);
        }

        // Inbound TCP (established connections only).
        let conns: Vec<u64> = self.conns.keys().copied().collect();
        for conn in conns {
            let mut dead = false;
            if let Some(stream) = self.conns.get_mut(&conn) {
                let mut buf = [0u8; 65535];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            dead = true;
                            break;
                        }
                        Ok(n) => self.engine.feed_tcp(now, conn, &buf[..n]),
                        Err(_) => break,
                    }
                }
            }
            if dead {
                if let Some(stream) = self.conns.remove(&conn) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
                self.engine.on_closed(now, conn);
            }
        }

        // Engine events that drive the transport.
        let events = self.engine.take_events();
        for ev in &events {
            match ev {
                EngineEvent::EstablishTransport {
                    peer_id,
                    transport_addr,
                } => {
                    // The active side opens the TCP connection.
                    let sock = format!("{}:{}", ip_display(transport_addr), self.peer_tcp_port);
                    if let Ok(stream) = TcpStream::connect(&sock) {
                        stream.set_nonblocking(true).unwrap();
                        let conn = self.next_conn;
                        self.next_conn += 1;
                        self.conns.insert(conn, stream);
                        self.engine.on_connected(now, conn, *peer_id);
                    }
                }
                EngineEvent::CloseConnection(conn) => {
                    // Deliver anything the engine queued for the peer
                    // (e.g. a fatal Notification) before the close.
                    self.flush_tcp();
                    if let Some(stream) = self.conns.remove(conn) {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                    }
                }
                _ => {}
            }
        }

        // Drain anything the event handling queued (the Init, etc.).
        self.flush_tcp();

        events
    }

    /// Write every queued TCP payload to its connection.
    fn flush_tcp(&mut self) {
        for (conn, bytes) in self.engine.drain_tcp_all() {
            if let Some(stream) = self.conns.get_mut(&conn) {
                let _ = stream.write_all(&bytes);
            }
        }
    }
}

fn dest_socket_addr(dest: &IpAddr, port: u16) -> std::net::SocketAddr {
    match dest {
        IpAddr::V4(b) => {
            std::net::SocketAddr::from((std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]), port))
        }
        IpAddr::V6(b) => {
            let octets: [u8; 16] = *b;
            std::net::SocketAddr::from((std::net::Ipv6Addr::from(octets), port))
        }
    }
}

fn sock_to_ip(sock: std::net::SocketAddr) -> IpAddr {
    match sock.ip() {
        std::net::IpAddr::V4(v4) => IpAddr::V4(v4.octets()),
        std::net::IpAddr::V6(v6) => IpAddr::V6(v6.octets()),
    }
}

fn ip_display(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(b) => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        IpAddr::V6(_) => String::from("[::1]"),
    }
}

/// A logical millisecond clock that stays monotonic across the tests
/// (std wall-clock could jump, and the FSMs require monotonic time).
fn logical_now() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant as StdInstant;
    static START: std::sync::OnceLock<StdInstant> = std::sync::OnceLock::new();
    static LAST: AtomicU64 = AtomicU64::new(0);
    let start = START.get_or_init(StdInstant::now);
    let now = start.elapsed().as_millis() as u64;
    loop {
        let last = LAST.load(Ordering::Relaxed);
        if now <= last {
            return last + 1; // keep the logical clock monotonic
        }
        if LAST.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed) == Ok(last) {
            return now;
        }
    }
}

fn has_session_up(events: &[EngineEvent], peer: LdpId) -> bool {
    events
        .iter()
        .any(|e| matches!(e, EngineEvent::SessionUp { peer_id, .. } if *peer_id == peer))
}

/// Pump both speakers until `pred` sees what it wants.
fn wait_for<F: FnMut(&[EngineEvent]) -> bool>(
    a: &mut Speaker,
    b: &mut Speaker,
    deadline: Duration,
    mut pred: F,
) -> Vec<EngineEvent> {
    let start = StdInstant::now();
    let mut all_events: Vec<EngineEvent> = Vec::new();
    loop {
        let now = Instant::from_millis(logical_now());
        let ev_a = a.pump(now);
        let ev_b = b.pump(now);
        for e in &ev_a {
            eprintln!("[A] {e:?}");
        }
        for e in &ev_b {
            eprintln!("[B] {e:?}");
        }
        all_events.extend(ev_a);
        all_events.extend(ev_b);
        if pred(&all_events) {
            return all_events;
        }
        if start.elapsed() > deadline {
            panic!("condition not met within {deadline:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

const A_ID: [u8; 4] = [1, 1, 1, 1];
const B_ID: [u8; 4] = [2, 2, 2, 2];
const A_TRANSPORT: IpAddr = IpAddr::V4([127, 0, 0, 1]);
const B_TRANSPORT: IpAddr = IpAddr::V4([127, 0, 0, 2]);

/// Build the two speakers with each other's ports wired in.
fn build_pair() -> (Speaker, Speaker) {
    let mut a = Speaker::new(
        A_ID,
        A_TRANSPORT,
        B_TRANSPORT,
        Vec::from([IpAddr::V4([10, 99, 1, 1])]),
    );
    let mut b = Speaker::new(
        B_ID,
        B_TRANSPORT,
        A_TRANSPORT,
        Vec::from([IpAddr::V4([10, 99, 2, 1])]),
    );
    a.peer_udp_port = b.udp_port();
    a.peer_tcp_port = b.tcp_port;
    b.peer_udp_port = a.udp_port();
    b.peer_tcp_port = a.tcp_port;
    (a, b)
}

#[test]
fn two_speakers_full_lifecycle() {
    let (mut a, mut b) = build_pair();
    let peer_a = LdpId::new(A_ID, 0);
    let peer_b = LdpId::new(B_ID, 0);

    // Phase 1: discovery + session establishment.
    let events = wait_for(&mut a, &mut b, Duration::from_secs(10), |events| {
        has_session_up(events, peer_a) && has_session_up(events, peer_b)
    });
    assert!(
        has_session_up(&events, peer_a) && has_session_up(&events, peer_b),
        "both sessions must come up"
    );
    // §2.5.2: B has the higher transport address (127.0.0.2 > 127.0.0.1),
    // so B is the active side and initiates the TCP connection.
    assert!(events.iter().any(|e| matches!(
        e,
        EngineEvent::EstablishTransport { peer_id, .. } if *peer_id == peer_a
    )));
    // Sessions are keyed by the peer's LDP Identifier.
    assert_eq!(
        a.engine.session_state(peer_b),
        Some(SessionState::Operational)
    );
    assert_eq!(
        b.engine.session_state(peer_a),
        Some(SessionState::Operational)
    );
    // Address messages flowed (each side advertised its interface net).
    assert!(events.iter().any(|e| matches!(
        e,
        EngineEvent::AddressReceived { peer_id, .. } if *peer_id == peer_a
    )));

    // Phase 2: label distribution (DU). A advertises 10.10.0.0/24=100.
    a.engine
        .advertise_mapping(Prefix::new_v4([10, 10, 0, 0], 24), GenericLabel(100));
    let events = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::MappingLearned { peer_id, prefix, .. }
                    if *peer_id == peer_a && *prefix == Prefix::new_v4([10, 10, 0, 0], 24)
            )
        })
    });
    assert!(events.iter().any(|e| matches!(
        e,
        EngineEvent::MappingLearned {
            label: GenericLabel(100),
            ..
        }
    )));
    // The binding is in B's LIB.
    assert_eq!(
        b.engine
            .lib()
            .label_from(peer_a, &FecKey::new(Prefix::new_v4([10, 10, 0, 0], 24))),
        Some(GenericLabel(100))
    );

    // B advertises 10.20.0.0/24=200 back.
    b.engine
        .advertise_mapping(Prefix::new_v4([10, 20, 0, 0], 24), GenericLabel(200));
    wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::MappingLearned { peer_id, prefix, .. }
                    if *peer_id == peer_b && *prefix == Prefix::new_v4([10, 20, 0, 0], 24)
            )
        })
    });
    assert_eq!(
        a.engine
            .lib()
            .label_from(peer_b, &FecKey::new(Prefix::new_v4([10, 20, 0, 0], 24))),
        Some(GenericLabel(200))
    );

    // Phase 3: withdrawal. A withdraws its binding; B must release it
    // (§3.5.10.1) and drop it from the LIB.
    a.engine
        .withdraw_mapping(Prefix::new_v4([10, 10, 0, 0], 24));
    let events = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::MappingReleased { peer_id, prefix }
                    if *peer_id == peer_b && *prefix == Prefix::new_v4([10, 10, 0, 0], 24)
            )
        })
    });
    assert!(events.iter().any(|e| matches!(
        e,
        EngineEvent::MappingWithdrawn { peer_id, prefixes }
            if *peer_id == peer_a && prefixes.contains(&Prefix::new_v4([10, 10, 0, 0], 24))
    )));
    assert_eq!(
        b.engine
            .lib()
            .label_from(peer_a, &FecKey::new(Prefix::new_v4([10, 10, 0, 0], 24))),
        None
    );

    // Phase 4: KeepAlives keep the session up across several intervals
    // (negotiated 2s, sent every 2/3s).
    let start = StdInstant::now();
    while start.elapsed() < Duration::from_secs(3) {
        let now = Instant::from_millis(logical_now());
        a.pump(now);
        b.pump(now);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        a.engine.session_state(peer_b),
        Some(SessionState::Operational)
    );
    assert_eq!(
        b.engine.session_state(peer_a),
        Some(SessionState::Operational)
    );

    // Phase 5: graceful shutdown from A. B must observe the fatal
    // Shutdown notification and drop its session.
    a.engine
        .shutdown_peer(Instant::from_millis(logical_now()), peer_b);
    let events = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| matches!(
            e,
            EngineEvent::SessionDown { peer_id, reason }
                if *peer_id == peer_a && matches!(reason, SessionDownReason::PeerNotification(_))
        ))
    });
    assert!(events.iter().any(|e| matches!(
        e,
        EngineEvent::NotificationReceived { peer_id, status }
            if *peer_id == peer_a && status.code == StatusCode::SHUTDOWN
    )));
    assert_eq!(b.engine.session_state(peer_a), None);
}

/// A PDU whose length field exceeds the negotiated Max PDU Length is a
/// fatal error: the receiver answers with a Bad PDU Length Notification
/// and takes the session down (§3.5.3; FRR's S_BAD_PDU_LEN path).
#[test]
fn oversized_pdu_kills_the_session() {
    let (mut a, mut b) = build_pair();
    let peer_a = LdpId::new(A_ID, 0);
    let peer_b = LdpId::new(B_ID, 0);

    wait_for(&mut a, &mut b, Duration::from_secs(10), |events| {
        has_session_up(events, peer_a) && has_session_up(events, peer_b)
    });

    // Craft a PDU over the wire with a length field of 5000 octets
    // (negotiated Max PDU Length is 4096). The payload is one unknown
    // message carrying one unknown TLV so the PDU still parses — the
    // length check fires before message processing.
    const PDU_LEN: usize = 5000;
    let msg_len = PDU_LEN - 6 - 4;
    let tlv_len = msg_len - 4 - 4;
    let mut rogue = Vec::with_capacity(4 + PDU_LEN);
    rogue.extend_from_slice(&1u16.to_be_bytes()); // Version
    rogue.extend_from_slice(&(PDU_LEN as u16).to_be_bytes()); // PDU Length
    rogue.extend_from_slice(&B_ID); // sender LSR Id
    rogue.extend_from_slice(&0u16.to_be_bytes()); // sender label space
    rogue.extend_from_slice(&(0xBFFFu16).to_be_bytes()); // U=1, type 0x3EFF (unknown)
    rogue.extend_from_slice(&(msg_len as u16).to_be_bytes());
    rogue.extend_from_slice(&1u32.to_be_bytes()); // Message Id
    rogue.extend_from_slice(&(0xBF00u16).to_be_bytes()); // U=1, TLV type 0x3F00 (unknown)
    rogue.extend_from_slice(&(tlv_len as u16).to_be_bytes());
    rogue.resize(4 + PDU_LEN, 0xAB); // TLV value padding

    // B's embedder writes the rogue PDU straight onto the wire,
    // bypassing its own engine.
    let conn = *b.conns.keys().next().expect("B holds the connection");
    b.conns
        .get_mut(&conn)
        .expect("stream")
        .write_all(&rogue)
        .expect("write rogue PDU");

    // A must take the session down with a protocol error, and B must
    // observe the fatal Bad PDU Length Notification (0x80000003).
    let events = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| matches!(
            e,
            EngineEvent::SessionDown { peer_id, reason: SessionDownReason::ProtocolError }
                if *peer_id == peer_b
        ))
            && events.iter().any(|e| matches!(
                e,
                EngineEvent::SessionDown { peer_id, reason: SessionDownReason::PeerNotification(code) }
                    if *peer_id == peer_a && *code == StatusCode::BAD_PDU_LENGTH
            ))
    });
    assert!(events
        .iter()
        .any(|e| matches!(e, EngineEvent::CloseConnection(_))));
    assert_eq!(a.engine.session_state(peer_b), None);
    // Bindings learned over the dead session are purged.
    assert_eq!(a.engine.lib().bindings_from(peer_b).count(), 0);
    assert_eq!(b.engine.session_state(peer_a), None);
}

#[test]
fn frozen_peer_times_the_session_out() {
    let (mut a, mut b) = build_pair();
    let peer_a = LdpId::new(A_ID, 0);
    let peer_b = LdpId::new(B_ID, 0);

    wait_for(&mut a, &mut b, Duration::from_secs(10), |events| {
        has_session_up(events, peer_a) && has_session_up(events, peer_b)
    });

    // Freeze B: stop pumping its engine entirely. The TCP connection
    // stays open (no FIN/RST reaches A), but B stops answering
    // KeepAlives. With the negotiated KeepAlive Time of 2s, A must
    // expire the session per §3.5.1.2.3 instead of holding it forever.
    let start = StdInstant::now();
    loop {
        let now = Instant::from_millis(logical_now());
        let ev_a = a.pump(now);
        if ev_a.iter().any(|e| {
            matches!(
                e,
                EngineEvent::SessionDown {
                    reason: SessionDownReason::KeepAliveExpired,
                    ..
                }
            )
        }) {
            break;
        }
        if start.elapsed() > Duration::from_secs(10) {
            panic!("session did not time out after B froze");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(a.engine.session_state(peer_b), None);
    // The LIB entries learned from the dead peer are purged.
    assert_eq!(a.engine.lib().bindings_from(peer_b).count(), 0);
}
