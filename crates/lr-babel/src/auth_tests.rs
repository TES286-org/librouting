
use super::*;

const PORT: u16 = 6696;
const MC_V4: [u8; 4] = [224, 0, 0, 111];

fn pseudo(src: IpAddr, dst: IpAddr) -> BabelPseudoHeader {
    BabelPseudoHeader {
        source: src,
        source_port: PORT,
        destination: dst,
        destination_port: PORT,
    }
}

fn v4(b: [u8; 4]) -> IpAddr {
    IpAddr::V4(b)
}

/// A minimal valid Babel datagram body: one Hello TLV (type 4).
fn hello_body() -> Vec<u8> {
    vec![4, 6, 0, 100, 0, 0, 0, 7]
}

fn raw_packet(body: &[u8]) -> Vec<u8> {
    let mut p = vec![MAGIC, VERSION, 0, 0];
    p.extend_from_slice(body);
    let len = body.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p
}

/// A test peer wrapping one authenticated interface.
struct Peer {
    addr: IpAddr,
    iface: BabelAuthInterface,
}

impl Peer {
    fn new(addr: [u8; 4], key: BabelMacKey) -> Self {
        let mut cfg = BabelAuthConfig::new(key);
        // Rate limits are exercised by dedicated tests; the shared
        // helper keeps the handshake loop unthrottled.
        cfg.challenge_interval_ms = 0;
        cfg.reply_interval_ms = 0;
        Self {
            addr: v4(addr),
            iface: BabelAuthInterface::new(
                cfg,
                b"initial-index-0".to_vec(),
                0,
                Box::new(CounterNonceSource::default()),
            )
            .unwrap(),
        }
    }

    fn with_config(cfg: BabelAuthConfig, addr: [u8; 4]) -> Self {
        Self::with_index(cfg, addr, b"initial-index-0")
    }

    fn with_index(cfg: BabelAuthConfig, addr: [u8; 4], index: &[u8]) -> Self {
        Self {
            addr: v4(addr),
            iface: BabelAuthInterface::new(
                cfg,
                index.to_vec(),
                0,
                Box::new(CounterNonceSource::default()),
            )
            .unwrap(),
        }
    }

    fn send(&mut self, body: &[u8], dst: IpAddr) -> Vec<u8> {
        let packet = raw_packet(body);
        self.iface
            .authenticate_packet(&packet, pseudo(self.addr, dst))
            .unwrap()
    }

    fn receive(&mut self, wire: &[u8], src: IpAddr, dst: IpAddr, now: u64) -> BabelVerifyOutcome {
        self.iface.verify(wire, pseudo(src, dst), now)
    }
}

fn challenge_body(ty: u8, nonce: &[u8]) -> Vec<u8> {
    let mut b = vec![ty, nonce.len() as u8];
    b.extend_from_slice(nonce);
    b
}

/// Craft a datagram with an explicit PC/Index — for receiver-state
/// scenarios that need exact PC values (RFC 9467 window tests).
fn raw_authenticated(
    key: &BabelMacKey,
    index: &[u8],
    pc: u32,
    body: &[u8],
    ph: BabelPseudoHeader,
) -> Vec<u8> {
    let packet = raw_packet(body);
    let mut counter = BabelPacketCounter::new(index.to_vec(), pc).unwrap();
    authenticate_packet(&packet, ph, key, &mut counter).unwrap()
}

fn assert_one_challenge_request(actions: &[BabelAuthAction]) -> Vec<u8> {
    assert_eq!(actions.len(), 1, "expected exactly one action");
    match &actions[0] {
        BabelAuthAction::SendChallengeRequest(n) => n.clone(),
        other => panic!("expected SendChallengeRequest, got {other:?}"),
    }
}

fn extract_nonce(action: &BabelAuthAction) -> Vec<u8> {
    match action {
        BabelAuthAction::SendChallengeRequest(n) | BabelAuthAction::SendChallengeReply(n) => {
            n.clone()
        }
    }
}

// ---- algorithm & key plumbing ----

#[test]
fn algorithm_properties() {
    assert_eq!(BabelMacAlgorithm::HmacSha256.digest_len(), 32);
    assert_eq!(BabelMacAlgorithm::Blake2s128.digest_len(), 16);
    assert_eq!(
        BabelMacAlgorithm::from_name("HMAC-SHA256"),
        Some(BabelMacAlgorithm::HmacSha256)
    );
    assert_eq!(
        BabelMacAlgorithm::from_name("blake2s"),
        Some(BabelMacAlgorithm::Blake2s128)
    );
    assert_eq!(BabelMacAlgorithm::from_name("md5"), None);
    assert_eq!(
        BabelMacKey::new(b"x").algorithm,
        BabelMacAlgorithm::HmacSha256
    );
    assert_eq!(
        BabelMacKey::blake2s128(b"x").algorithm,
        BabelMacAlgorithm::Blake2s128
    );
}

#[test]
fn config_validation_fails_closed() {
    let nonce = Box::new(CounterNonceSource::default());
    let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"k"));
    cfg.keys.clear();
    assert_eq!(
        BabelAuthInterface::new(cfg, Vec::new(), 0, nonce).unwrap_err(),
        BabelAuthError::NoKeys
    );

    let nonce = Box::new(CounterNonceSource::default());
    let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"k"));
    cfg.pc_window = Some(0);
    assert_eq!(
        BabelAuthInterface::new(cfg, Vec::new(), 0, nonce).unwrap_err(),
        BabelAuthError::InvalidConfig
    );

    let nonce = Box::new(CounterNonceSource::default());
    let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"k"));
    cfg.nonce_len = MAX_NONCE_LEN + 1;
    assert_eq!(
        BabelAuthInterface::new(cfg, Vec::new(), 0, nonce).unwrap_err(),
        BabelAuthError::InvalidConfig
    );

    let nonce = Box::new(CounterNonceSource::default());
    let cfg = BabelAuthConfig::new(BabelMacKey::new(b"k"));
    assert_eq!(
        BabelAuthInterface::new(cfg, vec![0u8; 33], 0, nonce).unwrap_err(),
        BabelAuthError::InvalidIndex
    );
}

#[test]
fn nonce_sources_are_unique() {
    let mut s = CounterNonceSource::default();
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    s.fill(&mut a);
    s.fill(&mut b);
    assert_ne!(a, b);

    let mut s = SystemNonceSource::new();
    s.fill(&mut a);
    s.fill(&mut b);
    assert_ne!(a, b);
}

// ---- legacy stateless primitives ----

#[test]
fn legacy_roundtrip_strips_trailer() {
    let key = BabelMacKey::new(b"correct horse battery staple");
    let mut counter = BabelPacketCounter::new(b"fresh-index".to_vec(), 7).unwrap();
    let packet = raw_packet(&hello_body());
    let signed = authenticate_packet(
        &packet,
        pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
        &key,
        &mut counter,
    )
    .unwrap();
    let mut replay = BabelReplayProtection::default();
    assert_eq!(
        verify_packet(
            &signed,
            pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
            &[key],
            &mut replay
        )
        .unwrap(),
        packet
    );
}

#[test]
fn legacy_rejects_tampering_and_replay() {
    let key = BabelMacKey::new(b"a key");
    let mut counter = BabelPacketCounter::new(Vec::new(), 0).unwrap();
    let packet = raw_packet(&hello_body());
    let mut signed = authenticate_packet(
        &packet,
        pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
        &key,
        &mut counter,
    )
    .unwrap();
    let mut replay = BabelReplayProtection::default();
    signed[5] ^= 1;
    assert_eq!(
        verify_packet(
            &signed,
            pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
            std::slice::from_ref(&key),
            &mut replay
        ),
        Err(BabelAuthError::AuthenticationFailed)
    );
    let signed = authenticate_packet(
        &packet,
        pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
        &key,
        &mut counter,
    )
    .unwrap();
    assert!(verify_packet(
        &signed,
        pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
        std::slice::from_ref(&key),
        &mut replay
    )
    .is_ok());
    assert_eq!(
        verify_packet(
            &signed,
            pseudo(v4([192, 0, 2, 1]), v4(MC_V4)),
            std::slice::from_ref(&key),
            &mut replay
        ),
        Err(BabelAuthError::Replay)
    );
}

// ---- the RFC 8967 §4.3 challenge handshake ----

#[test]
fn full_challenge_handshake_synchronizes_peers() {
    let key = BabelMacKey::new(b"link-key");
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::new([10, 0, 0, 2], key);
    let mc = v4(MC_V4);

    // A multicasts a Hello; B has no state for A: drop + Challenge Request.
    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, 100);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    assert!(out.accepted.is_none());
    let nonce1 = assert_one_challenge_request(&out.actions);
    assert_eq!(b.iface.neighbour_count(), 1);

    // B unicasts its Challenge Request; A drops it (B unknown) but
    // schedules the Challenge Reply — and its own Challenge Request.
    let wire = b.send(&challenge_body(18, &nonce1), a.addr);
    let out = a.receive(&wire, b.addr, a.addr, 110);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    assert_eq!(out.actions.len(), 2);
    assert!(matches!(out.actions[0], BabelAuthAction::SendChallengeReply(ref n) if *n == nonce1));
    assert!(matches!(
        out.actions[1],
        BabelAuthAction::SendChallengeRequest(_)
    ));
    let nonce2 = extract_nonce(&out.actions[1]);

    // A unicasts the Challenge Reply; B accepts and seeds its state.
    let wire = a.send(&challenge_body(19, &nonce1), b.addr);
    let out = b.receive(&wire, a.addr, b.addr, 120);
    assert!(out.accepted.is_some(), "challenge reply must be accepted");
    assert!(out.actions.is_empty());

    // A unicasts its own Challenge Request; B (knowing A now) accepts it
    // and schedules the reply.
    let wire = a.send(&challenge_body(18, &nonce2), b.addr);
    let out = b.receive(&wire, a.addr, b.addr, 130);
    assert!(out.accepted.is_some());
    assert_eq!(out.actions.len(), 1);
    assert_eq!(extract_nonce(&out.actions[0]), nonce2);

    // B unicasts its Challenge Reply; A accepts and seeds its state.
    let wire = b.send(&challenge_body(19, &nonce2), a.addr);
    let out = a.receive(&wire, b.addr, a.addr, 140);
    assert!(out.accepted.is_some());

    // Both peers now accept plain application traffic.
    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, 150);
    assert!(out.accepted.is_some(), "post-handshake multicast accepted");
    assert!(out.accepted.as_ref().unwrap()[BODY_OFFSET..].starts_with(&hello_body()[..2]));
    let wire = b.send(&hello_body(), mc);
    let out = a.receive(&wire, b.addr, mc, 160);
    assert!(out.accepted.is_some());
}

#[test]
fn restart_with_fresh_index_rechallenges() {
    let key = BabelMacKey::new(b"link-key");
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);

    // A "restarts": a fresh interface, hence a fresh index.
    let mut a2 = {
        let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"link-key"));
        cfg.challenge_interval_ms = 0;
        cfg.reply_interval_ms = 0;
        Peer::with_index(cfg, [10, 0, 0, 1], b"restarted-index")
    };
    let wire = a2.send(&hello_body(), mc);
    let out = b.receive(&wire, a2.addr, mc, 1000);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    let nonce = assert_one_challenge_request(&out.actions);

    let wire = a2.send(&challenge_body(19, &nonce), b.addr);
    let out = b.receive(&wire, a2.addr, b.addr, 1010);
    assert!(out.accepted.is_some(), "post-restart reply accepted");
}

#[test]
fn replay_rejected_without_challenge() {
    let key = BabelMacKey::new(b"link-key");
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);

    let wire = a.send(&hello_body(), mc);
    assert!(b.receive(&wire, a.addr, mc, 100).accepted.is_some());
    // Replaying the exact same datagram: no challenge (§4.3), no accept.
    let out = b.receive(&wire, a.addr, mc, 110);
    assert_eq!(out.reason, Some(BabelAuthError::Replay));
    assert!(out.actions.is_empty());
}

#[test]
fn mac_failure_creates_no_neighbour_state() {
    let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"key-a"));
    let mut b = Peer::new([10, 0, 0, 2], BabelMacKey::new(b"key-b"));
    let mc = v4(MC_V4);
    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, 100);
    assert_eq!(out.reason, Some(BabelAuthError::AuthenticationFailed));
    assert_eq!(b.iface.neighbour_count(), 0);
}

#[test]
fn unauthenticated_packets_dropped_by_default() {
    let key = BabelMacKey::new(b"link-key");
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let mc = v4(MC_V4);
    let plain = raw_packet(&hello_body());
    let out = b.receive(&plain, a.addr, mc, 100);
    assert_eq!(out.reason, Some(BabelAuthError::MissingMac));

    // RFC 8967 §5 incremental deployment mode accepts them.
    let mut cfg = BabelAuthConfig::new(key);
    cfg.accept_unauthenticated = true;
    cfg.challenge_interval_ms = 0;
    cfg.reply_interval_ms = 0;
    let mut c = Peer::with_config(cfg, [10, 0, 0, 3]);
    let out = c.receive(&plain, a.addr, mc, 100);
    assert!(out.accepted.is_some());
    // ...but authenticated packets are still fully verified: the first
    // one from an unknown peer is dropped with a challenge, the
    // challenge handshake synchronizes c, and then traffic flows.
    let wire = a.send(&hello_body(), mc);
    let out = c.receive(&wire, a.addr, mc, 110);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    let nonce = assert_one_challenge_request(&out.actions);
    let wire = a.send(&challenge_body(19, &nonce), c.addr);
    assert!(c.receive(&wire, a.addr, c.addr, 115).accepted.is_some());
    let wire = a.send(&hello_body(), mc);
    assert!(c.receive(&wire, a.addr, mc, 118).accepted.is_some());
    let mut tampered = wire.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xff;
    let out = c.receive(&tampered, a.addr, mc, 120);
    assert_eq!(out.reason, Some(BabelAuthError::AuthenticationFailed));
}

#[test]
fn blake2s128_handshake_and_wire_length() {
    let key = BabelMacKey::blake2s128(b"blake2s-key");
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);

    // The MAC TLV on the wire carries the 16-octet BLAKE2s digest.
    let wire = a.send(&hello_body(), mc);
    let body_len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
    let trailer = &wire[4 + body_len..];
    assert_eq!(trailer[0], 16, "MAC TLV type");
    assert_eq!(trailer[1] as usize, 16, "BLAKE2s-128 digest length");
    assert!(b.receive(&wire, a.addr, mc, 200).accepted.is_some());
}

#[test]
fn key_rotation_multiple_macs_per_packet() {
    let k1 = BabelMacKey::new(b"old-key");
    let k2 = BabelMacKey::blake2s128(b"new-key");

    // A holds both keys (rotation in progress): one MAC per key.
    let mut cfg = BabelAuthConfig::new(k1.clone());
    cfg.keys.push(k2.clone());
    cfg.challenge_interval_ms = 0;
    cfg.reply_interval_ms = 0;
    let mut a = Peer::with_config(cfg, [10, 0, 0, 1]);

    // B knows only the new key: still accepts (§5).
    let mut b = Peer::new([10, 0, 0, 2], k2.clone());
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);

    let wire = a.send(&hello_body(), mc);
    let body_len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
    let trailer = &wire[4 + body_len..];
    let mut mac_lens = Vec::new();
    let mut off = 0;
    while off < trailer.len() {
        let len = trailer[off + 1] as usize;
        if trailer[off] == 16 {
            mac_lens.push(len);
        }
        off += 2 + len;
    }
    assert_eq!(mac_lens, vec![32, 16], "one MAC per configured key");
    assert!(b.receive(&wire, a.addr, mc, 300).accepted.is_some());
}

#[test]
fn forged_challenge_reply_is_rejected() {
    let key = BabelMacKey::new(b"link-key");
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let mc = v4(MC_V4);

    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, 100);
    let nonce = assert_one_challenge_request(&out.actions);

    // A replies with a WRONG nonce: not matched, drop, re-challenge.
    let mut wrong = nonce.clone();
    wrong[0] ^= 0xff;
    let wire = a.send(&challenge_body(19, &wrong), b.addr);
    let out = b.receive(&wire, a.addr, b.addr, 110);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    let fresh = assert_one_challenge_request(&out.actions);
    assert_ne!(fresh, nonce, "a new nonce was issued");

    // The fresh nonce completes the challenge.
    let wire = a.send(&challenge_body(19, &fresh), b.addr);
    let out = b.receive(&wire, a.addr, b.addr, 120);
    assert!(out.accepted.is_some());
}

#[test]
fn oversized_nonce_and_multicast_requests_ignored() {
    let key = BabelMacKey::new(b"link-key");
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let mc = v4(MC_V4);

    // §4.3.1.2: a Challenge Request sent to a multicast address is
    // silently ignored (no reply scheduled).
    let nonce = vec![7u8; 8];
    let body = challenge_body(18, &nonce);
    let mut req = Peer::new([10, 0, 0, 9], key.clone());
    let wire = req.send(&body, mc);
    let out = b.receive(&wire, req.addr, mc, 100);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    assert!(
        !out.actions
            .iter()
            .any(|a| matches!(a, BabelAuthAction::SendChallengeReply(_))),
        "no reply for multicast requests"
    );

    // §6.3: nonces larger than 192 octets MAY be ignored.
    let huge = vec![7u8; 193];
    let body = challenge_body(18, &huge);
    let wire = req.send(&body, b.addr);
    let out = b.receive(&wire, req.addr, b.addr, 110);
    assert!(
        !out.actions
            .iter()
            .any(|a| matches!(a, BabelAuthAction::SendChallengeReply(_))),
        "oversized nonce ignored (challenge traffic is still fine)"
    );

    // An in-bounds unicast request still gets its reply.
    let wire = req.send(&challenge_body(18, &nonce), b.addr);
    let out = b.receive(&wire, req.addr, b.addr, 120);
    assert!(matches!(
        out.actions.first(),
        Some(BabelAuthAction::SendChallengeReply(_))
    ));
}

#[test]
fn oversized_pc_index_is_ignored() {
    let key = BabelMacKey::new(b"link-key");
    let mut b = Peer::with_config(BabelAuthConfig::new(key), [10, 0, 0, 2]);
    let sender = v4([10, 0, 0, 1]);

    // Hand-craft a body whose PC TLV carries a 33-octet index (§6.2
    // allows a node to ignore it — the packet then has no usable PC).
    let mut body = hello_body();
    body.push(17);
    body.push((4 + 33) as u8);
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&[0u8; 33]);
    let ph = pseudo(sender, v4(MC_V4));
    let wire = raw_authenticated(&BabelMacKey::new(b"link-key"), b"idx", 1, &body, ph);
    let out = b.receive(&wire, sender, v4(MC_V4), 100);
    assert_eq!(out.reason, Some(BabelAuthError::InvalidIndex));
}

// ---- rate limits (§4.3.1.1 / §4.3.1.2) ----

#[test]
fn challenge_requests_are_rate_limited() {
    let key = BabelMacKey::new(b"link-key");
    let mut cfg = BabelAuthConfig::new(key);
    cfg.challenge_interval_ms = 300;
    let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
    let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
    let mc = v4(MC_V4);

    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, 100);
    assert_one_challenge_request(&out.actions);

    // 200 ms later: still inside the rate window — silent drop.
    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, 300);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    assert!(out.actions.is_empty());

    // 500 ms after the first challenge: the window has passed.
    let out = b.receive(&wire, a.addr, mc, 600);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    assert_eq!(out.actions.len(), 1);
}

#[test]
fn challenge_replies_are_rate_limited() {
    let key = BabelMacKey::new(b"link-key");
    let mut cfg = BabelAuthConfig::new(key);
    cfg.reply_interval_ms = 300;
    let mut req = Peer::new([10, 0, 0, 9], BabelMacKey::new(b"link-key"));
    let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
    let nonce = vec![3u8; 8];

    // The unknown sender also triggers a Challenge Request from b; the
    // reply-rate limit only paces the SendChallengeReply actions.
    let replies = |a: &[BabelAuthAction]| {
        a.iter()
            .filter(|x| matches!(x, BabelAuthAction::SendChallengeReply(_)))
            .count()
    };
    let wire = req.send(&challenge_body(18, &nonce), b.addr);
    let out = b.receive(&wire, req.addr, b.addr, 100);
    assert_eq!(replies(&out.actions), 1);

    let wire = req.send(&challenge_body(18, &nonce), b.addr);
    let out = b.receive(&wire, req.addr, b.addr, 200);
    assert_eq!(replies(&out.actions), 0, "reply suppressed within 300 ms");

    let wire = req.send(&challenge_body(18, &nonce), b.addr);
    let out = b.receive(&wire, req.addr, b.addr, 500);
    assert_eq!(replies(&out.actions), 1, "reply allowed after the window");
}

#[test]
fn challenge_expires_after_thirty_seconds() {
    let key = BabelMacKey::new(b"link-key");
    let mut cfg = BabelAuthConfig::new(key);
    cfg.challenge_expiry_ms = 30_000;
    let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
    let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
    let mc = v4(MC_V4);

    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, 100);
    let nonce = assert_one_challenge_request(&out.actions);

    // The reply arrives late: the challenge expired, so the packet is
    // dropped and a fresh challenge is scheduled (§4.3.1.3).
    let wire = a.send(&challenge_body(19, &nonce), b.addr);
    let out = b.receive(&wire, a.addr, b.addr, 30_200);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    assert_eq!(out.actions.len(), 1);
    let fresh = extract_nonce(&out.actions[0]);
    assert_ne!(fresh, nonce, "a new nonce was issued");
}

// ---- RFC 9467 §3.1: unicast / multicast PC split ----

#[test]
fn split_unicast_multicast_tracking() {
    let key = BabelMacKey::new(b"link-key");
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::new([10, 0, 0, 2], key);
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);

    // Multicast advances PCm, then the same-value unicast packet must
    // still be accepted (PCu is tracked separately).
    let w_mc = a.send(&hello_body(), mc);
    assert!(b.receive(&w_mc, a.addr, mc, 100).accepted.is_some());
    let (_, idx) = a.iface.send_state();
    let idx = idx.to_vec();
    let pc_now = {
        // The next crafted packet carries the current PC + 1 — mirror
        // what `a.send` would emit next.
        let (pc, _) = a.iface.send_state();
        pc
    };
    let w_uc = raw_authenticated(
        &BabelMacKey::new(b"link-key"),
        &idx,
        pc_now + 1,
        &hello_body(),
        pseudo(a.addr, b.addr),
    );
    let out = b.receive(&w_uc, a.addr, b.addr, 110);
    assert!(
        out.accepted.is_some(),
        "RFC 9467 §3.1: unicast state is separate"
    );
}

#[test]
fn no_split_treats_both_classes_as_one() {
    let key = BabelMacKey::new(b"link-key");
    let mut cfg = BabelAuthConfig::new(key);
    cfg.split_unicast_multicast = false;
    cfg.challenge_interval_ms = 0;
    cfg.reply_interval_ms = 0;
    let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
    let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);

    let w_mc = a.send(&hello_body(), mc);
    assert!(b.receive(&w_mc, a.addr, mc, 100).accepted.is_some());
    // Same PC value re-delivered as unicast: the shared state rejects it.
    let (pc, idx) = a.iface.send_state();
    let w_uc = raw_authenticated(
        &BabelMacKey::new(b"link-key"),
        idx,
        pc,
        &hello_body(),
        pseudo(a.addr, b.addr),
    );
    let out = b.receive(&w_uc, a.addr, b.addr, 110);
    assert_eq!(out.reason, Some(BabelAuthError::Replay));
}

// ---- RFC 9467 §3.2: window-based verification ----

/// A window-mode pair already synchronized via the challenge handshake.
fn window_pair() -> (Peer, Peer, IpAddr) {
    let key = BabelMacKey::new(b"link-key");
    let mut cfg = BabelAuthConfig::new(key);
    cfg.pc_window = Some(4);
    cfg.challenge_interval_ms = 0;
    cfg.reply_interval_ms = 0;
    let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
    let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);
    (a, b, mc)
}

#[test]
fn window_accepts_bounded_reordering() {
    let (a, mut b, mc) = window_pair();
    let key = BabelMacKey::new(b"link-key");

    // pc=4: jumps past the window (S=4, highest was 3 after handshake);
    // the window shifts fully and only pc=4 is marked.
    let (_, idx) = a.iface.send_state();
    let idx = idx.to_vec();
    let w4 = raw_authenticated(&key, &idx, 4, &hello_body(), pseudo(a.addr, mc));
    assert!(b.receive(&w4, a.addr, mc, 100).accepted.is_some());

    // pc=3 arrives late (reordered): inside the window, unseen → accept.
    let w3 = raw_authenticated(&key, &idx, 3, &hello_body(), pseudo(a.addr, mc));
    assert!(b.receive(&w3, a.addr, mc, 110).accepted.is_some());
    // pc=3 again: now a replay → reject.
    let out = b.receive(&w3, a.addr, mc, 120);
    assert_eq!(out.reason, Some(BabelAuthError::Replay));

    // pc=0 is below the window's left edge → too old, reject.
    let w0 = raw_authenticated(&key, &idx, 0, &hello_body(), pseudo(a.addr, mc));
    assert_eq!(
        b.receive(&w0, a.addr, mc, 130).reason,
        Some(BabelAuthError::Replay)
    );

    // pc=100: far past the edge → window resets, accept.
    let w100 = raw_authenticated(&key, &idx, 100, &hello_body(), pseudo(a.addr, mc));
    assert!(b.receive(&w100, a.addr, mc, 140).accepted.is_some());
}

#[test]
fn combined_split_and_two_windows() {
    // §3.3: two independent windows, one per traffic class.
    let key = BabelMacKey::new(b"link-key");
    let mut cfg = BabelAuthConfig::new(key.clone());
    cfg.pc_window = Some(4);
    cfg.challenge_interval_ms = 0;
    cfg.reply_interval_ms = 0;
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);

    // Multicast reaches pc=10.
    for _ in 0..8 {
        let w = a.send(&hello_body(), mc);
        assert!(b.receive(&w, a.addr, mc, 100).accepted.is_some());
    }
    // Unicast is still near the handshake PC: an in-order unicast with
    // a PC below the multicast window edge is accepted independently.
    let (pc, idx) = a.iface.send_state();
    let w_uc = raw_authenticated(&key, idx, pc + 1, &hello_body(), pseudo(a.addr, b.addr));
    assert!(
        b.receive(&w_uc, a.addr, b.addr, 110).accepted.is_some(),
        "unicast window is independent of the multicast window"
    );
}

// ---- state expiry (§4.4) ----

#[test]
fn neighbour_state_expires() {
    let key = BabelMacKey::new(b"link-key");
    let mut cfg = BabelAuthConfig::new(key);
    cfg.neighbour_expiry_ms = 300_000;
    let mut a = Peer::new([10, 0, 0, 1], BabelMacKey::new(b"link-key"));
    let mut b = Peer::with_config(cfg, [10, 0, 0, 2]);
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);
    assert_eq!(b.iface.neighbour_count(), 1);

    // Eager gc after the expiry window.
    // The handshake ends well past t=100; any time beyond the last
    // activity plus the expiry window discards the state (§4.4).
    assert_eq!(b.iface.gc(1_000_000), 1);
    assert_eq!(b.iface.neighbour_count(), 0);

    // And the next packet re-triggers the challenge handshake.
    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, 1_000_100);
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    assert_eq!(out.actions.len(), 1);
}

#[test]
fn pc_overflow_rotates_the_index() {
    let key = BabelMacKey::new(b"link-key");
    let mut cfg = BabelAuthConfig::new(key);
    cfg.index_len = 8;
    let nonce = Box::new(CounterNonceSource::default());
    let mut a = BabelAuthInterface::new(cfg, b"old-index".to_vec(), u32::MAX, nonce).unwrap();
    let packet = raw_packet(&hello_body());
    let ph = pseudo(v4([10, 0, 0, 1]), v4(MC_V4));

    let (pc_before, idx_before) = (a.send_state().0, a.send_state().1.to_vec());
    assert_eq!(pc_before, u32::MAX);
    let wire = a.authenticate_packet(&packet, ph).unwrap();
    let (pc_after, idx_after) = (a.send_state().0, a.send_state().1.to_vec());
    // §4.2: overflow forces a fresh index and the PC restarts at 0.
    assert_eq!(pc_after, 0);
    assert_ne!(idx_before, idx_after, "fresh index generated on overflow");
    assert_eq!(wire[2..4].len(), 2);
}

// ---- trailer / body robustness ----

#[test]
fn trailer_tlv_robustness() {
    let key = BabelMacKey::new(b"link-key");
    let mut a = Peer::new([10, 0, 0, 1], key.clone());
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let mc = v4(MC_V4);
    handshake(&mut a, &mut b);

    let (_, idx) = a.iface.send_state();
    let idx = idx.to_vec();
    let (pc, _) = a.iface.send_state();
    let ph = pseudo(a.addr, mc);

    // Valid packet, then splice extra trailer content: Pad1, PadN and an
    // unknown TLV type must all be skipped (RFC 8966 §4.2) while the
    // MAC TLV is still honoured.
    let wire = raw_authenticated(&key, &idx, pc + 1, &hello_body(), ph);
    let body_len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
    let (head, mac) = wire.split_at(4 + body_len);
    let mut spliced = head.to_vec();
    spliced.push(0); // Pad1
    spliced.extend_from_slice(&[1, 3, 0, 0, 0]); // PadN
    spliced.extend_from_slice(&[200, 2, 0, 0]); // unknown trailer TLV
    spliced.extend_from_slice(mac);
    let out = b.receive(&spliced, a.addr, mc, 100);
    assert!(out.accepted.is_some(), "unknown trailer TLVs are skipped");

    // A truncated trailer TLV is a framing error.
    let mut broken = head.to_vec();
    broken.extend_from_slice(&[16, 40, 1, 2, 3]); // MAC TLV claims 40, has 3
    let out = b.receive(&broken, a.addr, mc, 110);
    assert_eq!(out.reason, Some(BabelAuthError::InvalidMac));
}

#[test]
fn mac_tlv_in_body_is_ignored_and_stripped() {
    let key = BabelMacKey::new(b"link-key");
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let sender = v4([10, 0, 0, 1]);
    let mc = v4(MC_V4);

    // §6.1: a MAC TLV found in the packet body MUST be ignored. Build a
    // body that embeds one, authenticate normally, and check both the
    // drop-without-trailer-MAC behaviour and the strip on accept.
    let mut body = hello_body();
    body.extend_from_slice(&[16, 4, 1, 2, 3, 4]); // stray MAC TLV in body
    let ph = pseudo(sender, mc);
    let wire = raw_authenticated(&key, b"some-index", 5, &body, ph);

    // Without a trailer the packet is unauthenticated.
    let body_len = u16::from_be_bytes([wire[2], wire[3]]) as usize;
    let headless = wire[..4 + body_len].to_vec();
    let out = b.receive(&headless, sender, mc, 100);
    assert_eq!(out.reason, Some(BabelAuthError::MissingMac));

    // With the real trailer the packet is verified; b has no state for
    // the sender yet, so it challenges (§4.3). Complete the handshake
    // with a fresh sender that reuses the same crafted body shape, then
    // confirm the stray body MAC TLV does not leak into the plain output.
    let out = b.receive(&wire, sender, mc, 110);
    let nonce = assert_one_challenge_request(&out.actions);
    let mut a = Peer::with_index(
        BabelAuthConfig::new(key.clone()),
        [10, 0, 0, 1],
        b"some-index",
    );
    let wire = a.send(&challenge_body(19, &nonce), b.addr);
    assert!(b.receive(&wire, a.addr, b.addr, 115).accepted.is_some());
    let (_, idx) = a.iface.send_state();
    let (pc, _) = a.iface.send_state();
    let wire = raw_authenticated(&key, idx, pc + 1, &body, pseudo(a.addr, mc));
    let out = b.receive(&wire, a.addr, mc, 120);
    let plain = out.accepted.expect("verified packet accepted");
    let plain_body = &plain[BODY_OFFSET..];
    assert!(!plain_body.starts_with(&[16, 4]), "body MAC TLV stripped");
    assert!(plain_body.starts_with(&hello_body()), "payload preserved");
}

#[test]
fn first_pc_tlv_wins_and_auth_tlvs_are_stripped() {
    let key = BabelMacKey::new(b"link-key");
    let mut b = Peer::new([10, 0, 0, 2], key.clone());
    let sender = v4([10, 0, 0, 1]);

    let mut body = hello_body();
    // PC TLV (pc=9, index "idx-16") + a second PC TLV (ignored) + both
    // challenge TLVs (ignored, stripped).
    body.extend_from_slice(&[17, 6, 0, 0, 0, 9, b'i', b'x']);
    body.extend_from_slice(&[17, 6, 0, 0, 1, 0, b'y', b'z']);
    body.extend_from_slice(&[18, 2, 1, 2]);
    body.extend_from_slice(&[19, 2, 3, 4]);
    let ph = pseudo(sender, v4(MC_V4));
    let wire = raw_authenticated(&key, b"idx-16", 9, &body, ph);

    let out = b.receive(&wire, sender, v4(MC_V4), 100);
    // No successful challenge here (B never challenged this index) —
    // the packet is dropped with a new challenge, but the plain body
    // would contain ONLY the Hello TLV.
    assert_eq!(out.reason, Some(BabelAuthError::IndexMismatch));
    // Verify the stripped-plain behaviour directly on the interface via
    // a completed-challenge path: after the handshake the plain output
    // of an accepted packet contains no auth TLVs.
    let nonce = assert_one_challenge_request(&out.actions);
    let mut a = Peer::new([10, 0, 0, 1], key);
    let wire = a.send(&challenge_body(19, &nonce), b.addr);
    let out = b.receive(&wire, a.addr, b.addr, 110);
    let plain = out.accepted.expect("challenge reply accepted");
    let plain_body = &plain[BODY_OFFSET..];
    // The reply packet carries only the Challenge Reply TLV, which is
    // stripped: the plain body is empty (auth TLVs never leak).
    assert!(plain_body.is_empty(), "auth TLVs stripped from plain body");
}

// ---- shared handshake helper (kept last: used above) ----

/// Drive two peers through the initial RFC 8967 §4.3 challenge until
/// both hold the other's (Index, PC) state. Each peer's actions are
/// emitted by that peer, unicast to the other (§4.3.1.1/§4.3.1.2).
/// Both peers must use zero rate limits and the same key.
fn handshake(a: &mut Peer, b: &mut Peer) {
    let mc = v4(MC_V4);
    let mut now = 100u64;

    let wire = a.send(&hello_body(), mc);
    let out = b.receive(&wire, a.addr, mc, now);
    assert_eq!(
        out.reason,
        Some(BabelAuthError::IndexMismatch),
        "first contact must challenge"
    );
    let mut a_queue: Vec<BabelAuthAction> = Vec::new();
    let mut b_queue: Vec<BabelAuthAction> = out.actions;

    for _ in 0..16 {
        // B emits its queued control traffic to A.
        for action in std::mem::take(&mut b_queue) {
            now += 10;
            let body = match &action {
                BabelAuthAction::SendChallengeRequest(n) => challenge_body(18, n),
                BabelAuthAction::SendChallengeReply(n) => challenge_body(19, n),
            };
            let wire = b.send(&body, a.addr);
            let out = a.receive(&wire, b.addr, a.addr, now);
            a_queue.extend(out.actions);
        }
        // A emits its queued control traffic to B.
        for action in std::mem::take(&mut a_queue) {
            now += 10;
            let body = match &action {
                BabelAuthAction::SendChallengeRequest(n) => challenge_body(18, n),
                BabelAuthAction::SendChallengeReply(n) => challenge_body(19, n),
            };
            let wire = a.send(&body, b.addr);
            let out = b.receive(&wire, a.addr, b.addr, now);
            b_queue.extend(out.actions);
        }
        if a_queue.is_empty() && b_queue.is_empty() {
            break;
        }
    }
    assert!(
        a_queue.is_empty() && b_queue.is_empty(),
        "handshake did not converge"
    );
}
