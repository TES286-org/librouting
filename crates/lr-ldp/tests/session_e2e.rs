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
use lr_core::buf::WriteBuf;
use lr_core::codec::Encoder;
use lr_core::time::Instant;
use lr_ldp::engine::{EngineEvent, LdpEngine, LdpEngineConfig};
use lr_ldp::mapping::FecKey;
use lr_ldp::message::{HelloMsg, LdpCodec, LdpMessage, LdpPdu};
use lr_ldp::session::{SessionDownReason, SessionState};
use lr_ldp::tlv::{DualStackCapability, HelloParams, TransportAddress, TransportPreference};
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
    /// The peer's transport address as the engines see it: inbound
    /// datagrams are attributed to it (the RFC 7552 tests below run
    /// both families over one loopback endpoint, so the harness — not
    /// the kernel — supplies the family-correct source).
    logical_peer: IpAddr,
}

impl Speaker {
    fn new(lsr_id: [u8; 4], addr: IpAddr, peer_addr: IpAddr, interface_addrs: Vec<IpAddr>) -> Self {
        Self::new_with(lsr_id, addr, peer_addr, interface_addrs, |_| {})
    }

    /// Like [`Speaker::new`] but lets the caller tweak the engine
    /// config before the engine is constructed (e.g. RFC 5036 §2.8
    /// Loop Detection settings).
    fn new_with(
        lsr_id: [u8; 4],
        addr: IpAddr,
        peer_addr: IpAddr,
        interface_addrs: Vec<IpAddr>,
        tweak: impl FnOnce(&mut LdpEngineConfig),
    ) -> Self {
        let mut cfg = LdpEngineConfig::new(LdpId::new(lsr_id, 0), addr);
        cfg.targeted_peers = Vec::from([peer_addr]);
        cfg.accept_targeted = true;
        cfg.keepalive_time = 2; // short for test pacing (§3.5.3: non-zero)
        cfg.targeted_hello_hold = 9; // hello every hold/3 = 3s
        cfg.interface_addresses = interface_addrs;
        tweak(&mut cfg);
        let engine = LdpEngine::new(cfg);
        let (udp, listener) = match addr {
            IpAddr::V6(_) => (
                UdpSocket::bind("[::1]:0").unwrap(),
                TcpListener::bind("[::1]:0").unwrap(),
            ),
            IpAddr::V4(_) => (
                UdpSocket::bind("0.0.0.0:0").unwrap(),
                TcpListener::bind("127.0.0.1:0").unwrap(),
            ),
        };
        udp.set_nonblocking(true).unwrap();
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
            logical_peer: peer_addr,
        }
    }

    fn udp_port(&self) -> u16 {
        self.udp.local_addr().unwrap().port()
    }

    /// A dual-stack speaker: IPv4 transport plus an explicit IPv6
    /// transport address (RFC 7552 §6.1.1 dual-stack LSR).
    fn new_dual_stack(
        lsr_id: [u8; 4],
        addr: IpAddr,
        addr_v6: Option<IpAddr>,
        peer_addr: IpAddr,
        interface_addrs: Vec<IpAddr>,
    ) -> Self {
        let mut speaker = Self::new(lsr_id, addr, peer_addr, interface_addrs);
        let mut cfg = LdpEngineConfig::new(LdpId::new(lsr_id, 0), addr);
        cfg.transport_addr_v6 = addr_v6;
        cfg.prefer_ipv6 = true;
        cfg.targeted_peers = Vec::from([peer_addr]);
        cfg.accept_targeted = true;
        cfg.keepalive_time = 2;
        cfg.targeted_hello_hold = 9;
        cfg.interface_addresses = Vec::from([IpAddr::V4([10, 99, 1, 1])]);
        speaker.engine = LdpEngine::new(cfg);
        speaker
    }

    /// One pump round: timers, socket I/O, engine event handling.
    fn pump(&mut self, now: Instant) -> Vec<EngineEvent> {
        self.engine.tick(now);

        // Outbound UDP. A v6 logical destination other than ::1 (the
        // only host loopback address the sandbox grants) rides the
        // ::1 endpoint — the engines only ever see the logical
        // address. Same for v4: Linux binds the whole 127/8 prefix on
        // `lo` so 127.0.0.2 is loopback, but macOS only carries
        // 127.0.0.1 on `lo0` by default (an `ifconfig lo0 alias` step
        // needs root, unavailable on CI runners). Route any 127.0.0.X
        // destination through 127.0.0.1 so the test runs unchanged on
        // both — the engines still see the logical 127.0.0.2 address
        // (RFC 5036 §2.5.2 transport comparison still holds).
        for (dest, bytes) in self.engine.drain_udp() {
            let real = match dest {
                IpAddr::V6(o) if o != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] => {
                    IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                }
                IpAddr::V4(b) if b != [127, 0, 0, 1] => IpAddr::V4([127, 0, 0, 1]),
                other => other,
            };
            let sock = dest_socket_addr(&real, self.peer_udp_port);
            let _ = self.udp.send_to(&bytes, sock);
        }

        // Outbound TCP.
        self.flush_tcp();

        // Inbound UDP, attributed to the peer's transport address (the
        // RFC 7552 tests run both families over one loopback endpoint,
        // so the harness supplies the family-correct logical source).
        let mut buf = [0u8; 65535];
        while let Ok((n, _from)) = self.udp.recv_from(&mut buf) {
            self.engine.feed_udp(now, self.logical_peer, &buf[..n]);
        }

        // Accept passive connections.
        while let Ok((stream, _peer)) = self.listener.accept() {
            stream.set_nonblocking(true).unwrap();
            let local = sock_to_ip(stream.local_addr().unwrap());
            let conn = self.next_conn;
            self.next_conn += 1;
            self.conns.insert(conn, stream);
            self.engine.on_accepted(conn, local);
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
                    // The active side opens the TCP connection. The
                    // engine tells us the logical transport address
                    // (e.g. 127.0.0.2 for B); map any 127.0.0.X
                    // destination to 127.0.0.1 — macOS only carries
                    // 127.0.0.1 on lo0 by default (see the UDP note
                    // above). The peer's TCP listener is bound to
                    // 127.0.0.1:0, so the destination port is what
                    // distinguishes the speakers, not the address.
                    let real = match transport_addr {
                        IpAddr::V4(b) if *b != [127, 0, 0, 1] => {
                            IpAddr::V4([127, 0, 0, 1])
                        }
                        IpAddr::V6(o)
                            if *o != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] =>
                        {
                            IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                        }
                        other => *other,
                    };
                    let sock = format!("{}:{}", ip_display(&real), self.peer_tcp_port);
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
// RFC 7552 speakers. Both live on ::1 in reality (the only loopback
// v6 address the sandbox grants); the engines see the documentation
// addresses 2001:db8::1/:2 and the harness maps the wire traffic.
const A_TRANSPORT_V6: IpAddr =
    IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const B_TRANSPORT_V6: IpAddr =
    IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

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
            EngineEvent::SessionDown { peer_id, reason, .. }
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
            EngineEvent::SessionDown { peer_id, reason: SessionDownReason::ProtocolError, .. }
                if *peer_id == peer_b
        ))
            && events.iter().any(|e| matches!(
                e,
                EngineEvent::SessionDown { peer_id, reason: SessionDownReason::PeerNotification(code), .. }
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

/// Two IPv6-only LSRs (RFC 7552 §6.1 rule 6: a single-stack LSR
/// establishes an LDPoIPv6 session per the enabled family) run the
/// discovery -> session -> binding lifecycle entirely over IPv6.
#[test]
fn ipv6_only_speakers_full_lifecycle() {
    let mut a_cfg_speaker = Speaker::new(
        A_ID,
        A_TRANSPORT_V6,
        B_TRANSPORT_V6,
        Vec::from([IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])]),
    );
    let mut b_speaker = Speaker::new(
        B_ID,
        B_TRANSPORT_V6,
        A_TRANSPORT_V6,
        Vec::from([IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ])]),
    );
    a_cfg_speaker.peer_udp_port = b_speaker.udp_port();
    a_cfg_speaker.peer_tcp_port = b_speaker.tcp_port;
    b_speaker.peer_udp_port = a_cfg_speaker.udp_port();
    b_speaker.peer_tcp_port = a_cfg_speaker.tcp_port;
    let peer_a = LdpId::new(A_ID, 0);
    let peer_b = LdpId::new(B_ID, 0);

    let events = wait_for(
        &mut a_cfg_speaker,
        &mut b_speaker,
        Duration::from_secs(10),
        |events| has_session_up(events, peer_a) && has_session_up(events, peer_b),
    );
    assert!(
        has_session_up(&events, peer_a) && has_session_up(&events, peer_b),
        "both IPv6 sessions must come up"
    );
    // §2.5.2 within IPv6: B (::2) > A (::1) — B is active and
    // connects to A's IPv6 transport address.
    assert!(events.iter().any(|e| matches!(
        e,
        EngineEvent::EstablishTransport { peer_id, transport_addr }
            if *peer_id == peer_a && *transport_addr == A_TRANSPORT_V6
    )));

    // A label binding flows A -> B over the IPv6 session.
    a_cfg_speaker.engine.advertise_mapping(
        Prefix::new_v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 48),
        GenericLabel(24001),
    );
    let events = wait_for(
        &mut a_cfg_speaker,
        &mut b_speaker,
        Duration::from_secs(5),
        |events| {
            events.iter().any(|e| {
                matches!(
                    e,
                    EngineEvent::MappingLearned { peer_id, prefix, .. }
                        if *peer_id == peer_a && matches!(prefix.addr, IpAddr::V6(_))
                )
            })
        },
    );
    assert_eq!(
        b_speaker.engine.session_state(peer_a),
        Some(SessionState::Operational)
    );
    // The binding sits in B's LIB under A's id.
    assert_eq!(
        b_speaker
            .engine
            .lib()
            .bindings_from(peer_a)
            .filter(|(p, _)| p.prefix.addr.is_ipv6())
            .count(),
        1
    );
    let _ = events;
}

/// RFC 7552 §6.1.1 rule 1: a dual-stack LSR discards a Hello whose
/// Dual-Stack capability preference does not match its own — and if a
/// session was already in place, resets it with the fatal Transport
/// Connection Mismatch notification (0x00000032).
#[test]
fn dual_stack_preference_mismatch_resets_session() {
    // A is dual-stack (v4 transport + a v6 transport, preferring
    // LDPoIPv6 — the RFC default); B is a v4 speaker that advertises
    // TR = LDPoIPv4.
    let mut a = Speaker::new_dual_stack(
        A_ID,
        A_TRANSPORT,
        Some(A_TRANSPORT_V6),
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
    let peer_a = LdpId::new(A_ID, 0);
    let peer_b = LdpId::new(B_ID, 0);

    // The v4-only adjacency (B never says anything dual-stack in its
    // discovery) still establishes a session: single-AF deployments
    // are legitimate.
    let events = wait_for(&mut a, &mut b, Duration::from_secs(10), |events| {
        has_session_up(events, peer_a) && has_session_up(events, peer_b)
    });
    assert!(has_session_up(&events, peer_a));

    // Now B sends a Hello advertising TR = LDPoIPv4 — the opposite of
    // A's preference. A must tear the session down with the fatal
    // notification (§6.1.1 rule 1).
    let hello = build_dual_stack_hello(B_ID, peer_a, TransportPreference::Ipv4);
    b.udp
        .send_to(&hello, dest_socket_addr(&A_TRANSPORT, a.udp_port()))
        .unwrap();
    let events = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::NotificationReceived { peer_id, status }
                    if *peer_id == peer_b
                        && status.code == StatusCode::TRANSPORT_CONNECTION_MISMATCH
            )
        }) || events
            .iter()
            .any(|e| matches!(e, EngineEvent::SessionDown { peer_id, .. } if *peer_id == peer_b))
    });
    assert!(
        events.iter().any(|e| matches!(
            e,
            EngineEvent::SessionDown { peer_id, .. } if *peer_id == peer_b
        )),
        "the session must be reset after the preference mismatch"
    );
}

/// RFC 7552 §6.1.1 rule 3c: a peer heard in BOTH address families
/// without the Dual-Stack capability is a noncompliant dual-stack
/// neighbor and must never get a session.
#[test]
fn dual_stack_noncompliance_blocks_session() {
    use lr_ldp::engine::LdpEngineConfig as Cfg;
    // Engine-level: feed one engine Hellos from the same peer id in
    // both families, no capability.
    let mut cfg = Cfg::new(LdpId::new(A_ID, 0), A_TRANSPORT);
    cfg.transport_addr_v6 = Some(A_TRANSPORT_V6);
    cfg.prefer_ipv6 = true;
    let mut a = LdpEngine::new(cfg);
    let now = Instant::from_millis(logical_now());

    let v4_hello = hello_pdu_from(B_ID, Some(B_TRANSPORT), None, None);
    let v6_hello = hello_pdu_from(B_ID, None, Some(B_TRANSPORT_V6), None);
    a.feed_udp(now, B_TRANSPORT, &v4_hello);
    a.feed_udp(now, B_TRANSPORT_V6, &v6_hello);
    a.tick(now);

    let events = a.take_events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            EngineEvent::HelloDiscarded { reason, .. }
                if reason.contains("noncompliance")
        )),
        "the noncompliance must be surfaced: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, EngineEvent::EstablishTransport { .. })),
        "no transport connection may be attempted"
    );
}

/// Encode a targeted Hello carrying the Dual-Stack capability, as a
/// noncompliant speaker would put on the wire.
fn build_dual_stack_hello(from: [u8; 4], _to: LdpId, preference: TransportPreference) -> Vec<u8> {
    let pdu = LdpPdu {
        version: 1,
        sender: LdpId::new(from, 0),
        messages: vec![LdpMessage::Hello(HelloMsg {
            message_id: 7,
            params: HelloParams {
                hold_time: 15,
                targeted: true,
                request_targeted: false,
            },
            transport_addr: Some(TransportAddress(IpAddr::V4([127, 0, 0, 2]))),
            transport_addr_v6: None,
            config_seq: None,
            dual_stack: Some(DualStackCapability { preference }),
            unknown_tlvs: Vec::new(),
        })],
    };
    let mut out = vec![0u8; 4096];
    let mut w = WriteBuf::new(&mut out);
    let n = LdpCodec.encode(&pdu, &mut w).unwrap();
    out.truncate(n);
    out
}

/// Encode a plain targeted Hello with the given transport TLVs.
fn hello_pdu_from(
    from: [u8; 4],
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    ds: Option<TransportPreference>,
) -> Vec<u8> {
    let pdu = LdpPdu {
        version: 1,
        sender: LdpId::new(from, 0),
        messages: vec![LdpMessage::Hello(HelloMsg {
            message_id: 9,
            params: HelloParams {
                hold_time: 15,
                targeted: true,
                request_targeted: false,
            },
            transport_addr: v4.map(TransportAddress),
            transport_addr_v6: v6.map(TransportAddress),
            config_seq: None,
            dual_stack: ds.map(|preference| DualStackCapability { preference }),
            unknown_tlvs: Vec::new(),
        })],
    };
    let mut out = vec![0u8; 4096];
    let mut w = WriteBuf::new(&mut out);
    let n = LdpCodec.encode(&pdu, &mut w).unwrap();
    out.truncate(n);
    out
}

// ---------------------------------------------------------------------------
// RFC 5036 §2.8 / §3.4.4.1 / A.2.6 — Loop Detection
// ---------------------------------------------------------------------------

use lr_ldp::message::{LabelMappingMsg, LabelRequestMsg};
use lr_ldp::tlv::{Fec, HopCount, PathVector};

fn build_pair_with_loop_detection_on_b() -> (Speaker, Speaker) {
    let mut a = Speaker::new(
        A_ID,
        A_TRANSPORT,
        B_TRANSPORT,
        Vec::from([IpAddr::V4([10, 99, 1, 1])]),
    );
    let mut b = Speaker::new_with(
        B_ID,
        B_TRANSPORT,
        A_TRANSPORT,
        Vec::from([IpAddr::V4([10, 99, 2, 1])]),
        |cfg| {
            cfg.loop_detection = true;
            cfg.hop_count_limit = 32;
            cfg.path_vector_limit = 32;
        },
    );
    a.peer_udp_port = b.udp_port();
    a.peer_tcp_port = b.tcp_port;
    b.peer_udp_port = a.udp_port();
    b.peer_tcp_port = a.tcp_port;
    (a, b)
}

/// Encode a one-message PDU as speaker `from` would send it.
fn craft_pdu(from: [u8; 4], message: LdpMessage) -> Vec<u8> {
    let pdu = LdpPdu {
        version: 1,
        sender: LdpId::new(from, 0),
        messages: vec![message],
    };
    let mut out = vec![0u8; 4096];
    let mut w = WriteBuf::new(&mut out);
    let n = LdpCodec.encode(&pdu, &mut w).unwrap();
    out.truncate(n);
    out
}

/// Inject raw bytes into speaker `a`'s session connection (the embedder
/// write path — the engine sees the bytes on the next pump).
fn inject_tcp(a: &mut Speaker, bytes: &[u8]) {
    let conn = *a.conns.keys().next().expect("session connection");
    use std::io::Write;
    a.conns
        .get_mut(&conn)
        .expect("connection stream")
        .write_all(bytes)
        .unwrap();
}

#[test]
fn loop_detection_rejects_mapping_over_hop_count_limit() {
    let (mut a, mut b) = build_pair_with_loop_detection_on_b();
    let peer_a = LdpId::new(A_ID, 0);
    let peer_b = LdpId::new(B_ID, 0);

    wait_for(&mut a, &mut b, Duration::from_secs(10), |events| {
        has_session_up(events, peer_a) && has_session_up(events, peer_b)
    });

    // A normal mapping (Hop Count 1) is still learned with Loop
    // Detection configured.
    a.engine
        .advertise_mapping(Prefix::new_v4([10, 30, 0, 0], 24), GenericLabel(300));
    wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::MappingLearned { peer_id, prefix, .. }
                    if *peer_id == peer_a && *prefix == Prefix::new_v4([10, 30, 0, 0], 24)
            )
        })
    });

    // A looping mapping (Hop Count 33 > the limit of 32) crafted on
    // the wire: B must reject it, release the label with Loop
    // Detected, and keep the session up.
    inject_tcp(
        &mut a,
        &craft_pdu(
            A_ID,
            LdpMessage::LabelMapping(LabelMappingMsg {
                message_id: 77,
                fec: Fec::prefix(Prefix::new_v4([10, 31, 0, 0], 24)),
                label: GenericLabel(301),
                hop_count: Some(HopCount(33)),
                path_vector: None,
                request_message_id: None,
                unknown_tlvs: vec![],
            }),
        ),
    );
    let events = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::LoopDetected { peer_id, prefix, .. }
                    if *peer_id == peer_a && *prefix == Prefix::new_v4([10, 31, 0, 0], 24)
            )
        })
    });
    assert!(
        events.iter().any(|e| matches!(
            e,
            EngineEvent::LoopDetected { reason, .. }
                if *reason == "hop count exceeds the configured maximum"
        )),
        "the rejection reason must be reported: {events:?}"
    );
    // The looping binding never entered B's LIB.
    assert_eq!(
        b.engine
            .lib()
            .label_from(peer_a, &FecKey::new(Prefix::new_v4([10, 31, 0, 0], 24))),
        None
    );
    // The healthy binding from before survives.
    assert_eq!(
        b.engine
            .lib()
            .label_from(peer_a, &FecKey::new(Prefix::new_v4([10, 30, 0, 0], 24))),
        Some(GenericLabel(300))
    );
    // A learns of the rejection via the §3.4.5.1.2 Label Release
    // carrying the Loop Detected Status TLV.
    let events_a = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::MappingReleased { peer_id, prefix }
                    if *peer_id == peer_b && *prefix == Prefix::new_v4([10, 31, 0, 0], 24)
            )
        })
    });
    assert!(
        events_a.iter().any(|e| matches!(
            e,
            EngineEvent::MappingReleased { peer_id, prefix }
                if *peer_id == peer_b && *prefix == Prefix::new_v4([10, 31, 0, 0], 24)
        )),
        "A must see the loop-detected release for the FEC"
    );
    // The session stays up (Loop Detected is non-fatal, E=0).
    assert_eq!(
        b.engine.session_state(peer_a),
        Some(SessionState::Operational)
    );
}

#[test]
fn loop_detection_rejects_request_with_own_path_vector() {
    let (mut a, mut b) = build_pair_with_loop_detection_on_b();
    let peer_a = LdpId::new(A_ID, 0);
    let peer_b = LdpId::new(B_ID, 0);

    wait_for(&mut a, &mut b, Duration::from_secs(10), |events| {
        has_session_up(events, peer_a) && has_session_up(events, peer_b)
    });

    // A Label Request whose Path Vector already contains B's LSR Id
    // (0x02020202) has traversed a loop: B answers with a Loop
    // Detected Notification instead of a mapping.
    inject_tcp(
        &mut a,
        &craft_pdu(
            A_ID,
            LdpMessage::LabelRequest(LabelRequestMsg {
                message_id: 88,
                fec: Fec::prefix(Prefix::new_v4([10, 32, 0, 0], 24)),
                hop_count: Some(HopCount(3)),
                path_vector: Some(PathVector(Vec::from([0x0303_0303, 0x0202_0202]))),
                unknown_tlvs: vec![],
            }),
        ),
    );
    let events = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::LoopDetected { peer_id, prefix, .. }
                    if *peer_id == peer_a && *prefix == Prefix::new_v4([10, 32, 0, 0], 24)
            )
        })
    });
    assert!(
        events.iter().any(|e| matches!(
            e,
            EngineEvent::LoopDetected { reason, .. }
                if *reason == "path vector contains the local LSR Id"
        )),
        "the rejection reason must be reported"
    );
    // A receives the non-fatal Loop Detected notification (0x0B).
    let events_a = wait_for(&mut a, &mut b, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            matches!(
                e,
                EngineEvent::NotificationReceived { peer_id, status }
                    if *peer_id == peer_b && status.code == StatusCode::LOOP_DETECTED
            )
        })
    });
    assert!(
        events_a.iter().any(|e| matches!(
            e,
            EngineEvent::NotificationReceived { peer_id, status }
                if *peer_id == peer_b && status.code == StatusCode::LOOP_DETECTED
        )),
        "A must receive the Loop Detected notification"
    );
    // The session survives (§3.9: Loop Detected, E = 0).
    assert_eq!(
        b.engine.session_state(peer_a),
        Some(SessionState::Operational)
    );
    assert_eq!(
        a.engine.session_state(peer_b),
        Some(SessionState::Operational)
    );
}
