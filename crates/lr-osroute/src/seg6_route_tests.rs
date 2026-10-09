
use super::*;
use core::str::FromStr;
use lr_srv6::Sid;

/// A `Seg6Netlink` with no live socket — enough to exercise
/// `build_request`, which only touches `seq`/`pid` (never `fd`).
fn test_netlink() -> Seg6Netlink {
    Seg6Netlink {
        fd: -1,
        seq: AtomicU32::new(7),
        pid: 123,
        last_req: std::cell::RefCell::new(None),
        last_resp: std::cell::RefCell::new(None),
    }
}

/// Walk the RTA attributes of a built request (they start at offset 28)
/// and return the payload of the one with type `want`, if present.
fn find_attr(req: &[u8], want: u16) -> Option<&[u8]> {
    let msg_len = u32::from_ne_bytes(req[0..4].try_into().unwrap()) as usize;
    let mut cursor = 28;
    while cursor + 4 <= msg_len {
        let attr_len = u16::from_ne_bytes([req[cursor], req[cursor + 1]]) as usize;
        if attr_len < 4 || cursor + attr_len > msg_len {
            return None;
        }
        let attr_type = u16::from_ne_bytes([req[cursor + 2], req[cursor + 3]]) & NLA_TYPE_MASK;
        if attr_type == want {
            return Some(&req[cursor + 4..cursor + attr_len]);
        }
        let aligned = (attr_len + 3) & !3;
        cursor += aligned;
    }
    None
}

/// Decode a nested RTA_ENCAP payload (a list of inner RTAs) and
/// return the payload of the inner attribute with type `want`.
fn find_encap_attr(encap_payload: &[u8], want: u16) -> Option<&[u8]> {
    let mut cursor = 0;
    while cursor + 4 <= encap_payload.len() {
        let attr_len =
            u16::from_ne_bytes([encap_payload[cursor], encap_payload[cursor + 1]]) as usize;
        if attr_len < 4 || cursor + attr_len > encap_payload.len() {
            return None;
        }
        let attr_type = u16::from_ne_bytes([encap_payload[cursor + 2], encap_payload[cursor + 3]])
            & NLA_TYPE_MASK;
        if attr_type == want {
            return Some(&encap_payload[cursor + 4..cursor + attr_len]);
        }
        let aligned = (attr_len + 3) & !3;
        cursor += aligned;
    }
    None
}

#[test]
fn seg6_route_build_request_shape() {
    let sid1 = Sid::from_str("fcbb:bb00:0:0:0:0:0:1").unwrap();
    let sid2 = Sid::from_str("fcbb:bb01:0:0:0:0:0:1").unwrap();
    let srh = Srh::new(vec![sid1, sid2]).unwrap();
    let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
    let route = Seg6Route::new(prefix, srh).with_mode(Seg6EncapMode::Encap);
    let req = test_netlink()
        .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    // Message type.
    assert_eq!(u16::from_ne_bytes([req[4], req[5]]), RTM_NEWROUTE);
    // Family.
    assert_eq!(req[16], AF_INET6 as u8);
    // Prefix length.
    assert_eq!(req[17], 48);
    // RT_TABLE_MAIN.
    assert_eq!(req[20], RT_TABLE_MAIN);
    // RTA_DST = the prefix's IPv6 address (16 bytes).
    let dst = find_attr(&req, RTA_DST).unwrap();
    assert_eq!(dst.len(), 16);
    assert_eq!(&dst[..8], &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0]);
    // RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6 (5).
    let encap_type = find_attr(&req, RTA_ENCAP_TYPE).unwrap();
    assert_eq!(encap_type, &(LWTUNNEL_ENCAP_SEG6 as u16).to_ne_bytes());
    // RTA_ENCAP is nested, contains SEG6_IPTUNNEL_SRH (type 1).
    let encap = find_attr(&req, RTA_ENCAP).unwrap();
    let srh_attr = find_encap_attr(encap, SEG6_IPTUNNEL_SRH).unwrap();
    // The SRH attribute payload is: 4-byte mode + SRH bytes.
    let mode = u32::from_ne_bytes([srh_attr[0], srh_attr[1], srh_attr[2], srh_attr[3]]);
    assert_eq!(mode, SEG6_IPTUN_MODE_ENCAP);
    // The SRH starts at offset 4 — verify the routing type byte.
    assert_eq!(srh_attr[4 + 2], lr_srv6::SRH_ROUTING_TYPE);
}

#[test]
fn seg6_route_inline_mode_uses_zero_mode_value() {
    let sid1 = Sid::from_str("fcbb:bb00::1").unwrap();
    let srh = Srh::new(vec![sid1]).unwrap();
    let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
    let route = Seg6Route::new(prefix, srh).with_mode(Seg6EncapMode::Inline);
    let req = test_netlink()
        .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let encap = find_attr(&req, RTA_ENCAP).unwrap();
    let srh_attr = find_encap_attr(encap, SEG6_IPTUNNEL_SRH).unwrap();
    let mode = u32::from_ne_bytes([srh_attr[0], srh_attr[1], srh_attr[2], srh_attr[3]]);
    assert_eq!(mode, SEG6_IPTUN_MODE_INLINE);
}

#[test]
fn seg6_route_rejects_ipv4_prefix() {
    let sid1 = Sid::from_str("fcbb:bb00::1").unwrap();
    let srh = Srh::new(vec![sid1]).unwrap();
    let prefix: lr_core::addr::Prefix = "192.0.2.0/24".parse().unwrap();
    let route = Seg6Route::new(prefix, srh);
    let err = test_netlink()
        .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap_err();
    assert!(matches!(err, Seg6RouteError::BadSrh(_)));
}

#[test]
fn seg6local_route_build_request_shape() {
    let sid = Sid::from_str("fcbb:bb00:0:0:0:0:0:1").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::End).with_if_index(2);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    // Family / prefix length.
    assert_eq!(req[16], AF_INET6 as u8);
    assert_eq!(req[17], 128, "seg6local SIDs are always /128");
    // RT_TABLE_LOCAL — seg6local routes live in the local table.
    assert_eq!(req[20], RT_TABLE_LOCAL);
    // RTA_DST = the SID's 16 bytes.
    let dst = find_attr(&req, RTA_DST).unwrap();
    assert_eq!(dst.len(), 16);
    assert_eq!(dst, sid.as_bytes());
    // RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6_LOCAL — the kernel's
    // uapi value is 7 (6 in that position is LWTUNNEL_ENCAP_BPF,
    // whose parser rejects SEG6_LOCAL_ACTION with EINVAL — the
    // run-36153545939 failure).
    assert_eq!(LWTUNNEL_ENCAP_SEG6_LOCAL, 7);
    let encap_type = find_attr(&req, RTA_ENCAP_TYPE).unwrap();
    assert_eq!(
        encap_type,
        &(LWTUNNEL_ENCAP_SEG6_LOCAL as u16).to_ne_bytes()
    );
    // The SEG6_LOCAL_ACTION attribute lives directly inside
    // RTA_ENCAP (not nested inside another attribute), with a
    // 4-byte u32 payload = the KERNEL action code (End: IANA 1 →
    // kernel 1; the identity ONLY for End — see
    // seg6local_end_x_encodes_the_kernel_action_code).
    let encap = find_attr(&req, RTA_ENCAP).unwrap();
    let action_attr = find_encap_attr(encap, SEG6LOCAL_ACTION).unwrap();
    assert_eq!(
        action_attr.len(),
        4,
        "SEG6_LOCAL_ACTION payload is a single u32"
    );
    let action = u32::from_ne_bytes([
        action_attr[0],
        action_attr[1],
        action_attr[2],
        action_attr[3],
    ]);
    assert_eq!(action, 1, "SEG6_LOCAL_ACTION_END");
}

#[test]
fn seg6local_request_matches_iproute2_wire() {
    // Byte-for-byte conformance pin. The reference is the request
    // iproute2 itself builds for `ip -6 route add
    // 2001:db8:dead:beef::abcd/128 encap seg6local action End dev
    // lo table local`, captured off the wire (strace-equivalent
    // sendmsg dump) and accepted by a real kernel:
    //
    //   4c000000 18000506 <seq> <pid>
    //   0a800000 ff030001 00000000
    //   14000100 20010db8deadbeef000000000000abcd
    //   0c001680 0800010001000000
    //   06001500 07000000
    //   08000400 01000000
    //
    // Attribute ORDER differs (iproute2 emits DST, ENCAP,
    // ENCAP_TYPE, OIF; this builder emits DST, OIF, ENCAP_TYPE,
    // ENCAP — the kernel's nla parser is order-insensitive) and
    // the flags differ by design (iproute2 `add` requests
    // CREATE|EXCL 0x0605; this builder requests CREATE|REPLACE
    // 0x0505 so a re-install over an existing row replaces it —
    // the same choice mpls_route makes). Everything else — the
    // 76-byte length, the rtmsg, every attribute's type, length
    // and payload — must match exactly.
    let sid = Sid::from_str("2001:db8:dead:beef::abcd").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::End).with_if_index(1);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let expected: Vec<u8> = [
        // nlmsghdr: len 76, RTM_NEWROUTE, REQUEST|ACK|REPLACE|CREATE,
        // seq 7 (test_netlink's first), pid 123.
        &[
            0x4c, 0x00, 0x00, 0x00, 0x18, 0x00, 0x05, 0x05, 0x07, 0x00, 0x00, 0x00, 0x7b, 0x00,
            0x00, 0x00,
        ][..],
        // rtmsg: AF_INET6, dst_len 128, table LOCAL(0xff), proto
        // RTPROT_BGP(0xba), scope UNIVERSE, type UNICAST.
        &[
            0x0a, 0x80, 0x00, 0x00, 0xff, 0xba, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ][..],
        // RTA_DST (1) = 2001:db8:dead:beef::abcd.
        &[0x14, 0x00, 0x01, 0x00][..],
        &[
            0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xab, 0xcd,
        ][..],
        // RTA_OIF (4) = 1.
        &[0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00][..],
        // RTA_ENCAP_TYPE (21) = 7 (LWTUNNEL_ENCAP_SEG6_LOCAL), u16
        // payload, NLA_U16 policy form — identical to iproute2's
        // `06 00 15 00 07 00 00 00`.
        &[0x06, 0x00, 0x15, 0x00, 0x07, 0x00, 0x00, 0x00][..],
        // RTA_ENCAP (22|NLA_F_NESTED) = { SEG6_LOCAL_ACTION (1) =
        // END (1) } — identical to iproute2's
        // `0c 00 16 80 08 00 01 00 01 00 00 00`.
        &[
            0x0c, 0x00, 0x16, 0x80, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        ][..],
    ]
    .concat();
    assert_eq!(
        req, expected,
        "seg6local wire bytes drifted from the \
             iproute2-verified form — check LWTUNNEL_ENCAP_SEG6_LOCAL, the \
             SEG6_LOCAL_* attribute numbers and the ACTION translation"
    );
}

#[test]
fn seg6local_end_x_encodes_the_kernel_action_code() {
    // End.X is IANA 5 but SEG6_LOCAL_ACTION_END_X is 2 — the two
    // registries deliberately differ, and conflating them encodes
    // a different behavior than the caller asked for.
    assert_eq!(Behavior::EndX.wire_value(), 5);
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let nh6 = Sid::from_str("2001:db8::1").unwrap().octets();
    let route = Seg6LocalRoute::new(sid, Behavior::EndX)
        .with_nh6(nh6)
        .with_if_index(1);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let encap = find_attr(&req, RTA_ENCAP).unwrap();
    let action_attr = find_encap_attr(encap, SEG6LOCAL_ACTION).unwrap();
    let action = u32::from_ne_bytes([
        action_attr[0],
        action_attr[1],
        action_attr[2],
        action_attr[3],
    ]);
    assert_eq!(action, 2, "SEG6_LOCAL_ACTION_END_X — kernel numbering");
}

#[test]
fn seg6local_rejects_stray_parameters() {
    // The kernel's parse_nla_action answers EINVAL when an action
    // carries a parameter its descriptor does not list: plain End
    // accepts NO parameter attributes.
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::End).with_oif(2);
    let err = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap_err();
    match err {
        Seg6RouteError::UnsupportedAction(s) => {
            assert!(s.contains("oif"), "error names the stray parameter: {s}");
        }
        other => panic!("expected UnsupportedAction, got {:?}", other),
    }
}

#[test]
fn seg6local_rejects_missing_required_parameters() {
    // End.X mandates NH6 in the kernel's descriptor — an End.X
    // route without it would install nothing and EINVAL at the
    // kernel instead.
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::EndX);
    let err = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap_err();
    match err {
        Seg6RouteError::UnsupportedAction(s) => {
            assert!(s.contains("nh6"), "error names the missing parameter: {s}");
        }
        other => panic!("expected UnsupportedAction, got {:?}", other),
    }
}

#[test]
fn seg6local_rejects_kernel_unimplemented_behaviors() {
    // Flavor variants (End.PSP etc.) have no seg6_action_table
    // descriptor — encoding them would be a guaranteed EINVAL.
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    for behavior in [Behavior::EndPsp, Behavior::EndDT46, Behavior::EndBM] {
        let route = Seg6LocalRoute::new(sid, behavior);
        let err = test_netlink()
            .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
            .unwrap_err();
        assert!(
            matches!(err, Seg6RouteError::UnsupportedAction(_)),
            "{behavior} should be rejected before the wire"
        );
    }
}

#[test]
fn seg6local_route_attaches_nh4_for_end_dx4() {
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let nh4 = [192, 0, 2, 1];
    let route = Seg6LocalRoute::new(sid, Behavior::EndDX4).with_nh4(nh4);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let encap = find_attr(&req, RTA_ENCAP).unwrap();
    // SEG6_LOCAL_NH4 (kernel uapi type 4) is a sibling attribute
    // inside RTA_ENCAP.
    assert_eq!(SEG6_LOCAL_NH4, 4);
    let nh4_attr = find_encap_attr(encap, SEG6_LOCAL_NH4).unwrap();
    assert_eq!(nh4_attr, &nh4);
    // End.DX4: IANA 17 → SEG6_LOCAL_ACTION_END_DX4 (6).
    let action_attr = find_encap_attr(encap, SEG6LOCAL_ACTION).unwrap();
    assert_eq!(u32::from_ne_bytes(action_attr.try_into().unwrap()), 6);
}

#[test]
fn seg6local_route_attaches_nh6_for_end_dx6() {
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let nh6 = Sid::from_str("2001:db8::1").unwrap().octets();
    let route = Seg6LocalRoute::new(sid, Behavior::EndDX6).with_nh6(nh6);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let encap = find_attr(&req, RTA_ENCAP).unwrap();
    assert_eq!(SEG6_LOCAL_NH6, 5);
    let nh6_attr = find_encap_attr(encap, SEG6_LOCAL_NH6).unwrap();
    assert_eq!(nh6_attr, &nh6);
    // End.DX6: IANA 16 → SEG6_LOCAL_ACTION_END_DX6 (5).
    let action_attr = find_encap_attr(encap, SEG6LOCAL_ACTION).unwrap();
    assert_eq!(u32::from_ne_bytes(action_attr.try_into().unwrap()), 5);
}

#[test]
fn seg6local_route_attaches_table_for_end_dt6() {
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::EndDT6).with_table(100);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let encap = find_attr(&req, RTA_ENCAP).unwrap();
    // SEG6_LOCAL_TABLE is kernel uapi type 3 (the enum order is
    // UNSPEC, ACTION, SRH, TABLE, NH4, NH6, IIF, OIF, …).
    assert_eq!(SEG6_LOCAL_TABLE, 3);
    let table_attr = find_encap_attr(encap, SEG6_LOCAL_TABLE).unwrap();
    let table = u32::from_ne_bytes([table_attr[0], table_attr[1], table_attr[2], table_attr[3]]);
    assert_eq!(table, 100);
    // End.DT6: IANA 18 → SEG6_LOCAL_ACTION_END_DT6 (7).
    let action_attr = find_encap_attr(encap, SEG6LOCAL_ACTION).unwrap();
    assert_eq!(u32::from_ne_bytes(action_attr.try_into().unwrap()), 7);
}

#[test]
fn seg6local_route_emits_rta_oif_for_the_egress_device() {
    // The kernel's fib6_nh_init rejects an IPv6 route naming
    // neither an egress device nor a gateway with ENODEV, so a
    // seg6local install MUST carry RTA_OIF (run 36136529031's
    // "netlink error -19").
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::End).with_if_index(1);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let oif = find_attr(&req, RTA_OIF).expect("seg6local request must carry RTA_OIF");
    assert_eq!(oif.len(), 4);
    assert_eq!(u32::from_ne_bytes([oif[0], oif[1], oif[2], oif[3]]), 1);
    // The route-level RTA_OIF is distinct from the End.X action
    // parameter: with no action oif set, SEG6_LOCAL_OIF must be
    // absent from the encap attributes.
    let encap = find_attr(&req, RTA_ENCAP).unwrap();
    assert!(find_encap_attr(encap, SEG6_LOCAL_OIF).is_none());
}

#[test]
fn rta_encap_carries_the_nested_flag_and_u16_encap_type() {
    // iproute2's rta_nest() marks RTA_ENCAP with NLA_F_NESTED and
    // sends RTA_ENCAP_TYPE as the policy's NLA_U16 (two-byte
    // payload) — the canonical wire form the kernel's nested
    // parsers are written against.
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::End).with_if_index(1);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let msg_len = u32::from_ne_bytes(req[0..4].try_into().unwrap()) as usize;
    let mut cursor = 28;
    let mut encap_type_payload: Option<Vec<u8>> = None;
    let mut encap_nested = false;
    while cursor + 4 <= msg_len {
        let attr_len = u16::from_ne_bytes([req[cursor], req[cursor + 1]]) as usize;
        if attr_len < 4 || cursor + attr_len > msg_len {
            break;
        }
        let attr_type = u16::from_ne_bytes([req[cursor + 2], req[cursor + 3]]);
        match attr_type & NLA_TYPE_MASK {
            RTA_ENCAP_TYPE => {
                encap_type_payload = Some(req[cursor + 4..cursor + attr_len].to_vec());
            }
            RTA_ENCAP => {
                encap_nested = attr_type & NLA_F_NESTED != 0;
            }
            _ => {}
        }
        cursor += (attr_len + 3) & !3;
    }
    assert_eq!(
        encap_type_payload.as_deref(),
        Some((LWTUNNEL_ENCAP_SEG6_LOCAL as u16).to_ne_bytes().as_slice()),
        "RTA_ENCAP_TYPE is a two-byte NLA_U16 payload"
    );
    assert!(encap_nested, "RTA_ENCAP must carry NLA_F_NESTED");
}

#[test]
fn seg6local_route_omits_rta_oif_when_unset() {
    let sid = Sid::from_str("fcbb:bb00::1").unwrap();
    let route = Seg6LocalRoute::new(sid, Behavior::End);
    let req = test_netlink()
        .build_seg6local_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    assert!(find_attr(&req, RTA_OIF).is_none());
}

#[test]
fn seg6_route_emits_rta_oif_when_if_index_set() {
    let sid1 = Sid::from_str("fcbb:bb00::1").unwrap();
    let srh = Srh::new(vec![sid1]).unwrap();
    let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
    let route = Seg6Route::new(prefix, srh).with_if_index(3);
    let req = test_netlink()
        .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let oif = find_attr(&req, RTA_OIF).expect("RTA_OIF expected");
    assert_eq!(u32::from_ne_bytes([oif[0], oif[1], oif[2], oif[3]]), 3);
}

#[test]
fn check_ack_names_enodev() {
    let mut resp = vec![0u8; 20];
    resp[0..4].copy_from_slice(&20u32.to_ne_bytes());
    resp[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    resp[16..20].copy_from_slice(&(-19i32).to_ne_bytes());
    let err = check_ack(&resp).unwrap_err();
    match err {
        Seg6RouteError::Kernel(s) => assert!(s.contains("ENODEV")),
        other => panic!("expected Kernel error, got {:?}", other),
    }
}

#[test]
fn check_ack_carries_the_kernel_extack_message() {
    // NLMSG_ERROR with a capped echo (TLVs at offset 36) carrying
    // NLMSGERR_ATTR_MSG. The kernel marks the REPLY's own flags
    // with NLM_F_CAPPED when it caps the echo.
    let msg = b"Egress device not specified\0";
    let tlv_len = 4 + msg.len();
    let total = 36 + tlv_len;
    let mut resp = vec![0u8; total];
    resp[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
    resp[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    // Reply flags: NLM_F_CAPPED (0x100).
    resp[6..8].copy_from_slice(&0x100u16.to_ne_bytes());
    // errno at offset 16.
    resp[16..20].copy_from_slice(&(-22i32).to_ne_bytes());
    // Echoed original header at 20 (its length is irrelevant when
    // the reply is capped).
    resp[20..24].copy_from_slice(&28u32.to_ne_bytes());
    // TLV at 36: NLMSGERR_ATTR_MSG (1).
    resp[36..38].copy_from_slice(&(tlv_len as u16).to_ne_bytes());
    resp[38..40].copy_from_slice(&1u16.to_ne_bytes());
    resp[40..40 + msg.len()].copy_from_slice(msg);
    let err = check_ack(&resp).unwrap_err();
    match err {
        Seg6RouteError::Kernel(s) => {
            assert!(s.contains("EINVAL"));
            assert!(
                s.contains("Egress device not specified"),
                "extack message folded in: {s}"
            );
        }
        other => panic!("expected Kernel error, got {:?}", other),
    }
}

#[test]
fn extack_msg_handles_uncapped_echo() {
    // Without NLM_F_CAPPED on the reply, the original payload is
    // echoed and the TLVs start after it (20 + orig_len, aligned).
    let msg = b"Nexthop device is not up\0";
    let tlv_len = 4 + msg.len();
    let orig_len = 28usize; // header + 12-byte rtmsg
    let tlv_off = (20 + orig_len + 3) & !3; // 48
    let total = tlv_off + tlv_len;
    let mut resp = vec![0u8; total];
    resp[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
    resp[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    // Reply flags empty: uncapped.
    resp[16..20].copy_from_slice(&(-119i32).to_ne_bytes());
    resp[20..24].copy_from_slice(&(orig_len as u32).to_ne_bytes());
    resp[tlv_off..tlv_off + 2].copy_from_slice(&(tlv_len as u16).to_ne_bytes());
    resp[tlv_off + 2..tlv_off + 4].copy_from_slice(&1u16.to_ne_bytes());
    resp[tlv_off + 4..tlv_off + 4 + msg.len()].copy_from_slice(msg);
    assert_eq!(
        extack_msg(&resp).as_deref(),
        Some("Nexthop device is not up")
    );
}

#[test]
fn add_flags_never_set_the_excl_bit() {
    // NLM_F_ACK_TLVS == NLM_F_EXCL == 0x200: the extack request
    // belongs on the SOCKET (NETLINK_EXT_ACK), never in the
    // message flags — 0x200 on a route add silently demands
    // exclusivity (run 36147424519's re-install EEXIST).
    assert_eq!(ADD_ROUTE_FLAGS & 0x200, 0, "adds must not set EXCL");
    assert_eq!(DEL_ROUTE_FLAGS & 0x200, 0, "deletes must not set EXCL");
    assert_eq!(ADD_ROUTE_FLAGS & 0x100, 0x100, "adds replace");
}

#[test]
fn delete_acks_are_idempotent_on_esrch() {
    // -ESRCH on a delete = already withdrawn = success.
    let mut resp = vec![0u8; 20];
    resp[0..4].copy_from_slice(&20u32.to_ne_bytes());
    resp[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    resp[16..20].copy_from_slice(&(-3i32).to_ne_bytes());
    assert!(check_ack_idempotent(&resp).is_ok());
    // Any other errno still fails.
    resp[16..20].copy_from_slice(&(-22i32).to_ne_bytes());
    assert!(check_ack_idempotent(&resp).is_err());
}

#[test]
fn check_ack_parses_done() {
    // Build a NLMSG_DONE response: nlmsghdr (16) + 4 bytes of zero.
    let mut resp = vec![0u8; 20];
    // nlmsg_len = 20
    resp[0..4].copy_from_slice(&20u32.to_ne_bytes());
    // nlmsg_type = NLMSG_DONE (3)
    resp[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
    assert!(check_ack(&resp).is_ok());
}

#[test]
fn check_ack_parses_error_zero() {
    // NLMSG_ERROR with errno=0 is an ACK.
    let mut resp = vec![0u8; 20];
    resp[0..4].copy_from_slice(&20u32.to_ne_bytes());
    resp[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    // errno at offset 16: 0
    resp[16..20].copy_from_slice(&0i32.to_ne_bytes());
    assert!(check_ack(&resp).is_ok());
}

#[test]
fn check_ack_returns_error_on_nonzero_errno() {
    let mut resp = vec![0u8; 20];
    resp[0..4].copy_from_slice(&20u32.to_ne_bytes());
    resp[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    resp[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
    let err = check_ack(&resp).unwrap_err();
    match err {
        Seg6RouteError::Kernel(s) => assert!(s.contains("EPERM")),
        other => panic!("expected Kernel error, got {:?}", other),
    }
}

#[test]
fn seg6_route_helpers_are_idempotent() {
    // Build the same route twice — the requests should be byte-
    // identical (modulo the netlink sequence number).
    let sid1 = Sid::from_str("fcbb:bb00::1").unwrap();
    let sid2 = Sid::from_str("fcbb:bb01::1").unwrap();
    let srh = Srh::new(vec![sid1, sid2]).unwrap();
    let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
    let route = Seg6Route::new(prefix, srh);
    let nl = test_netlink();
    let req1 = nl
        .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    let req2 = nl
        .build_seg6_request(RTM_NEWROUTE, ADD_ROUTE_FLAGS, &route)
        .unwrap();
    // Same length, same content except for the seq number (bytes 8-12).
    assert_eq!(req1.len(), req2.len());
    assert_eq!(&req1[0..8], &req2[0..8]);
    assert_eq!(&req1[12..], &req2[12..]);
}
