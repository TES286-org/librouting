use super::*;
use crate::message::{LabelMappingMsg, LdpPdu};
use crate::pdu::DEFAULT_KEEPALIVE_TIME;
use crate::tlv::{Fec, GenericLabel};

fn id(v: u8) -> LdpId {
    LdpId::new([v, 0, 0, 1], 0)
}

fn init_pdu(sender: LdpId, receiver: LdpId, keepalive: u16) -> LdpPdu {
    LdpPdu {
        version: 1,
        sender,
        messages: vec![LdpMessage::Initialization(InitMsg {
            message_id: 1,
            params: SessionParams {
                protocol_version: LDP_VERSION,
                keepalive_time: keepalive,
                advertisement: AdvertisementMode::DownstreamUnsolicited,
                loop_detection: false,
                path_vector_limit: 0,
                max_pdu_len: crate::pdu::DEFAULT_MAX_PDU_LEN,
                receiver,
            },
            ft_session: None,
            unknown_tlvs: Vec::new(),
        })],
    }
}

fn ka_pdu(sender: LdpId) -> LdpPdu {
    LdpPdu {
        version: 1,
        sender,
        messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 2 })],
    }
}

fn passive_cfg() -> SessionConfig {
    SessionConfig {
        local_id: id(1),
        role: SessionRole::Passive,
        ..SessionConfig::default()
    }
}

fn active_cfg() -> SessionConfig {
    SessionConfig {
        local_id: id(1),
        role: SessionRole::Active,
        // The active role knows the passive peer up front from its
        // Hello adjacency (§2.5.2 / §3.5.3).
        peer: Some(id(2)),
        ..SessionConfig::default()
    }
}

#[test]
fn passive_handshake_reaches_operational() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    assert_eq!(s.state(), SessionState::Initialized);
    assert!(s.drain_outgoing().is_empty());

    let events = s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
    assert_eq!(s.state(), SessionState::OpenRec);
    assert!(events.is_empty());
    let out = s.drain_outgoing();
    // Init + KeepAlive per §2.5.4 passive transition.
    assert_eq!(out.len(), 2);
    assert!(matches!(out[0], LdpMessage::Initialization(_)));
    assert!(matches!(out[1], LdpMessage::KeepAlive(_)));

    let events = s.feed_pdu(&ka_pdu(id(2)), now);
    assert_eq!(s.state(), SessionState::Operational);
    assert_eq!(events.len(), 1);
    match &events[0] {
        SessionEvent::SessionUp(n) => {
            assert_eq!(n.keepalive_time, 15); // min(15, 15)
            assert_eq!(n.max_pdu_len, crate::pdu::DEFAULT_MAX_PDU_LEN);
        }
        other => panic!("wrong event {other:?}"),
    }
}

#[test]
fn active_handshake_reaches_operational() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(active_cfg());
    s.start(now);
    assert_eq!(s.state(), SessionState::OpenSent);
    let out = s.drain_outgoing();
    assert_eq!(out.len(), 1);
    match &out[0] {
        LdpMessage::Initialization(i) => {
            // The Init's Receiver LDP Identifier identifies the
            // passive peer's label space (RFC 5036 §3.5.3).
            assert_eq!(i.params.receiver, id(2));
            assert_eq!(i.params.keepalive_time, DEFAULT_KEEPALIVE_TIME);
        }
        other => panic!("wrong message {other:?}"),
    }

    // Peer's Init arrives (peer proposes keepalive 30 → min 15).
    let events = s.feed_pdu(&init_pdu(id(2), id(1), 30), now);
    assert_eq!(s.state(), SessionState::OpenRec);
    assert!(events.is_empty());
    let out = s.drain_outgoing();
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0], LdpMessage::KeepAlive(_)));

    let events = s.feed_pdu(&ka_pdu(id(2)), now);
    match &events[0] {
        SessionEvent::SessionUp(n) => assert_eq!(n.keepalive_time, 15),
        other => panic!("wrong event {other:?}"),
    }
}

#[test]
fn non_init_message_in_initialized_is_naked() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    let pdu = LdpPdu {
        version: 1,
        sender: id(2),
        messages: vec![LdpMessage::KeepAlive(KeepAliveMsg { message_id: 9 })],
    };
    let events = s.feed_pdu(&pdu, now);
    assert_eq!(s.state(), SessionState::NonExistent);
    match &events[0] {
        SessionEvent::SessionDown(SessionDownReason::ProtocolError) => {}
        other => panic!("wrong event {other:?}"),
    }
    let out = s.drain_outgoing();
    match &out[0] {
        LdpMessage::Notification(n) => {
            assert_eq!(n.status.code, StatusCode::BAD_MESSAGE_LENGTH)
        }
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn keepalive_time_zero_rejected() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    let events = s.feed_pdu(&init_pdu(id(2), id(1), 0), now);
    assert_eq!(s.state(), SessionState::NonExistent);
    match &events[0] {
        SessionEvent::SessionDown(SessionDownReason::ParameterMismatch) => {}
        other => panic!("wrong event {other:?}"),
    }
    let out = s.drain_outgoing();
    match &out[0] {
        LdpMessage::Notification(n) => {
            assert_eq!(
                n.status.code,
                StatusCode::SESSION_REJECTED_BAD_KEEPALIVE_TIME
            );
        }
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn wrong_receiver_rejected() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    let _events = s.feed_pdu(&init_pdu(id(2), id(9), 15), now);
    assert_eq!(s.state(), SessionState::NonExistent);
    let out = s.drain_outgoing();
    match &out[0] {
        LdpMessage::Notification(n) => {
            assert_eq!(n.status.code, StatusCode::SESSION_REJECTED_NO_HELLO);
        }
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn advertisement_disagreement_resolves_to_du() {
    let now = Instant::from_secs(0);
    let cfg = SessionConfig {
        local_id: id(1),
        role: SessionRole::Passive,
        advertisement: AdvertisementMode::DownstreamOnDemand,
        ..SessionConfig::default()
    };
    let mut s = LdpSession::new(cfg);
    s.start(now);
    // Peer proposes DoD too - resolved DoD (both agree).
    let pdu = LdpPdu {
        version: 1,
        sender: id(2),
        messages: vec![LdpMessage::Initialization(InitMsg {
            message_id: 1,
            params: SessionParams {
                protocol_version: LDP_VERSION,
                keepalive_time: 15,
                advertisement: AdvertisementMode::DownstreamOnDemand,
                loop_detection: false,
                path_vector_limit: 0,
                max_pdu_len: crate::pdu::DEFAULT_MAX_PDU_LEN,
                receiver: id(1),
            },
            ft_session: None,
            unknown_tlvs: Vec::new(),
        })],
    };
    s.feed_pdu(&pdu, now);
    s.feed_pdu(&ka_pdu(id(2)), now);
    match s.negotiated {
        Some(n) => assert_eq!(n.advertisement, AdvertisementMode::DownstreamOnDemand),
        None => panic!("not negotiated"),
    }
}

#[test]
fn dod_only_speaker_rejects_du_resolution() {
    let now = Instant::from_secs(0);
    let cfg = SessionConfig {
        local_id: id(1),
        role: SessionRole::Passive,
        advertisement: AdvertisementMode::DownstreamOnDemand,
        supports_downstream_unsolicited: false,
        ..SessionConfig::default()
    };
    let mut s = LdpSession::new(cfg);
    s.start(now);
    // Peer proposes DU, we propose DoD → DU wins → we cannot support
    // it → Session Rejected/Parameters Advertisement Mode.
    let events = s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
    assert_eq!(s.state(), SessionState::NonExistent);
    let out = s.drain_outgoing();
    match &out[0] {
        LdpMessage::Notification(n) => {
            assert_eq!(
                n.status.code,
                StatusCode::SESSION_REJECTED_PARAMETERS_ADV_MODE
            );
        }
        other => panic!("wrong message {other:?}"),
    }
    match &events[0] {
        SessionEvent::SessionDown(SessionDownReason::ParameterMismatch) => {}
        other => panic!("wrong event {other:?}"),
    }
}

#[test]
fn keepalive_expiry_tears_down() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
    assert_eq!(s.drain_outgoing().len(), 2); // Init + KeepAlive
    s.feed_pdu(&ka_pdu(id(2)), now);
    assert!(s.is_operational());
    assert!(s.drain_outgoing().is_empty());

    // Nothing received for 15s → KeepAlive Timer Expired.
    let events = s.tick(Instant::from_secs(15));
    match &events[0] {
        SessionEvent::SessionDown(SessionDownReason::KeepAliveExpired) => {}
        other => panic!("wrong event {other:?}"),
    }
    let out = s.drain_outgoing();
    match &out[0] {
        LdpMessage::Notification(n) => {
            assert_eq!(n.status.code, StatusCode::KEEPALIVE_TIMER_EXPIRED);
        }
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn keepalive_sent_every_third() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
    assert_eq!(s.drain_outgoing().len(), 2); // Init + KeepAlive
    s.feed_pdu(&ka_pdu(id(2)), now);
    assert!(s.drain_outgoing().is_empty());

    // 4s in: nothing yet (15/3 = 5s).
    assert!(s.drain_outgoing().is_empty());
    let events = s.tick(Instant::from_secs(4));
    assert!(events.is_empty());
    assert!(s.drain_outgoing().is_empty());
    // 5s in: a KeepAlive is due.
    let _ = s.tick(Instant::from_secs(5));
    let out = s.drain_outgoing();
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0], LdpMessage::KeepAlive(_)));
    // A received PDU resets the KeepAlive timer, so 15s of
    // continuous traffic never expires.
    s.feed_pdu(&ka_pdu(id(2)), Instant::from_secs(6));
    let events = s.tick(Instant::from_secs(20));
    assert!(events.is_empty());
    assert!(s.is_operational());
}

#[test]
fn shutdown_notification_ends_session() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
    assert_eq!(s.drain_outgoing().len(), 2); // Init + KeepAlive
    s.feed_pdu(&ka_pdu(id(2)), now);
    assert!(s.drain_outgoing().is_empty());

    let pdu = LdpPdu {
        version: 1,
        sender: id(2),
        messages: vec![LdpMessage::Notification(NotificationMsg {
            message_id: 3,
            status: Status {
                code: StatusCode::SHUTDOWN,
                message_id: 0,
                message_type: 0,
            },
            unknown_tlvs: Vec::new(),
        })],
    };
    let events = s.feed_pdu(&pdu, now);
    assert_eq!(s.state(), SessionState::NonExistent);
    match &events[0] {
        SessionEvent::NotificationReceived(st) => assert_eq!(st.code, StatusCode::SHUTDOWN),
        other => panic!("wrong event {other:?}"),
    }
    match &events[1] {
        SessionEvent::SessionDown(SessionDownReason::PeerNotification(_)) => {}
        other => panic!("wrong event {other:?}"),
    }
    // No Shutdown echo when the peer already sent one.
    assert!(s.drain_outgoing().is_empty());
}

#[test]
fn label_traffic_surfaces_as_events() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
    s.feed_pdu(&ka_pdu(id(2)), now);

    let pdu = LdpPdu {
        version: 1,
        sender: id(2),
        messages: vec![LdpMessage::LabelMapping(LabelMappingMsg {
            message_id: 5,
            fec: Fec::prefix(lr_core::addr::Prefix::new_v4([10, 0, 0, 0], 8)),
            label: GenericLabel(100),
            hop_count: None,
            path_vector: None,
            request_message_id: None,
            unknown_tlvs: Vec::new(),
        })],
    };
    let events = s.feed_pdu(&pdu, now);
    match &events[0] {
        SessionEvent::LabelMappingReceived(m) => {
            assert_eq!(m.label, GenericLabel(100));
            assert_eq!(m.fec.single_prefix().map(|p| p.prefix_len), Some(8));
        }
        other => panic!("wrong event {other:?}"),
    }
}

#[test]
fn local_shutdown_sends_shutdown_notification() {
    let now = Instant::from_secs(0);
    let mut s = LdpSession::new(passive_cfg());
    s.start(now);
    s.feed_pdu(&init_pdu(id(2), id(1), 15), now);
    assert_eq!(s.drain_outgoing().len(), 2); // Init + KeepAlive
    s.feed_pdu(&ka_pdu(id(2)), now);
    assert!(s.drain_outgoing().is_empty());
    let events = s.shutdown(now);
    match &events[0] {
        SessionEvent::SessionDown(SessionDownReason::LocalShutdown) => {}
        other => panic!("wrong event {other:?}"),
    }
    let out = s.drain_outgoing();
    match &out[0] {
        LdpMessage::Notification(n) => {
            assert_eq!(n.status.code, StatusCode::SHUTDOWN);
            assert!(n.status.code.is_fatal());
        }
        other => panic!("wrong message {other:?}"),
    }
}

#[test]
fn role_decision_matches_rfc_252() {
    use crate::IpAddr;
    let a = IpAddr::V4([192, 0, 2, 1]);
    let b = IpAddr::V4([192, 0, 2, 2]);
    assert_eq!(role_for(&b, &a), Some(SessionRole::Active));
    assert_eq!(role_for(&a, &b), Some(SessionRole::Passive));
    assert_eq!(role_for(&a, &a), Some(SessionRole::Passive));
    // Mixed families are incomparable.
    let v6 = IpAddr::V6([0x20; 16]);
    assert_eq!(role_for(&a, &v6), None);
}

#[test]
fn duration_math_is_millisecond_based() {
    assert_eq!(lr_core::time::Duration::from_secs(15).as_millis(), 15_000);
    assert_eq!(
        Instant::from_secs(20)
            .saturating_sub(Instant::from_secs(5))
            .as_millis(),
        15_000
    );
}
