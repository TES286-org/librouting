
use super::*;

/// A `MplsNetlink` with no live socket — enough to exercise
/// `build_request`, which only touches `seq`/`pid` (never `fd`).
fn test_netlink() -> MplsNetlink {
    MplsNetlink {
        fd: -1,
        seq: AtomicU32::new(7),
        pid: 123,
    }
}

/// Walk the RTA attributes of a built request (they start at offset 28)
/// and return the payload of the one with type `want`, if present.
fn find_attr(req: &[u8], want: u16) -> Option<&[u8]> {
    let msg_len = u32::from_ne_bytes(req[0..4].try_into().unwrap()) as usize;
    let mut cursor = 28;
    while cursor + 4 <= msg_len.min(req.len()) {
        let rta_len = u16::from_ne_bytes([req[cursor], req[cursor + 1]]) as usize;
        if rta_len < 4 || cursor + rta_len > req.len() {
            return None;
        }
        let rta_type = u16::from_ne_bytes([req[cursor + 2], req[cursor + 3]]);
        if rta_type == want {
            return Some(&req[cursor + 4..cursor + rta_len]);
        }
        cursor += (rta_len + 3) & !3;
    }
    None
}

#[test]
fn platform_labels_reads_without_panic() {
    // In CI without mpls_router loaded this returns 0; in a
    // privileged lab it returns 16 or 20. Either way it must not
    // panic.
    let _ = mpls_platform_labels();
}

#[test]
fn connect_returns_not_enabled_when_sysctl_is_zero() {
    // Skip when MPLS is actually enabled (lab/CI with mpls_router).
    if mpls_enabled() {
        return;
    }
    match MplsNetlink::connect() {
        Err(MplsRouteError::NotEnabled) => { /* expected */ }
        other => panic!("expected NotEnabled, got {:?}", other),
    }
}

/// The kernel `struct rtvia` has a 2-byte `sa_family_t` — the RTA_VIA
/// payload must be `<family:2> <addr>`, not `<family:1> <addr>`. The
/// family is in HOST byte order (kernel `nla_put_via`/`nla_get_via`
/// treat it as a plain `sa_family_t`, no `ntohs`), matching how
/// sockaddr families are read everywhere else in the socket API.
#[test]
fn build_rta_via_ipv4_layout() {
    let via = MplsNetlink::build_rta_via(IpAddr::V4([192, 0, 2, 1]));
    // rta_len (2) + rta_type (2) + family (2) + addr (4) = 10, padded to 12
    assert_eq!(via.len(), 12);
    assert_eq!(u16::from_ne_bytes([via[0], via[1]]), 10);
    assert_eq!(u16::from_ne_bytes([via[2], via[3]]), RTA_VIA);
    // family is a 2-byte sa_family_t in host byte order
    assert_eq!(u16::from_ne_bytes([via[4], via[5]]), AF_INET);
    assert_eq!(&via[6..10], &[192, 0, 2, 1]);
}

#[test]
fn build_rta_via_ipv6_layout() {
    let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let via = MplsNetlink::build_rta_via(IpAddr::V6(addr));
    // rta_len (2) + rta_type (2) + family (2) + addr (16) = 22, padded to 24
    assert_eq!(via.len(), 24);
    assert_eq!(u16::from_ne_bytes([via[0], via[1]]), 22);
    assert_eq!(u16::from_ne_bytes([via[2], via[3]]), RTA_VIA);
    assert_eq!(u16::from_ne_bytes([via[4], via[5]]), AF_INET6);
    assert_eq!(&via[6..22], &addr);
}

/// `build_request` for a Pop action: RTA_DST in-label, RTA_VIA with a
/// 2-byte family, RTA_OIF. Exercises the full request encoder, not a
/// hand-mirrored layout.
#[test]
fn build_request_pop_route_encodes_via() {
    let nl = test_netlink();
    let route = MplsRoute::pop(Label::new(100), IpAddr::V4([192, 0, 2, 1]), 2);
    let req = nl
        .build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route)
        .unwrap();
    // nlmsghdr + rtmsg fields.
    assert_eq!(req[16], AF_MPLS); // rtm_family
    assert_eq!(req[17], MPLS_LABEL_LEN); // rtm_dst_len
                                         // RTA_DST: 4-octet in-label (kernel `nla_get_labels` shifts >> 12).
    let dst = find_attr(&req, RTA_DST).expect("RTA_DST");
    assert_eq!(dst.len(), 4);
    assert_eq!(u32::from_be_bytes(dst.try_into().unwrap()) >> 12, 100);
    // RTA_VIA: 2-byte host-order family + 4 address bytes.
    let via = find_attr(&req, RTA_VIA).expect("RTA_VIA");
    assert_eq!(via.len(), 6);
    assert_eq!(u16::from_ne_bytes([via[0], via[1]]), AF_INET);
    assert_eq!(&via[2..6], &[192, 0, 2, 1]);
    // RTA_OIF present.
    assert_eq!(find_attr(&req, RTA_OIF).expect("RTA_OIF").len(), 4);
}

/// `build_request` for a Swap action: RTA_NEWDST carries the new stack
/// and RTA_VIA the gateway.
#[test]
fn build_request_swap_route_encodes_newdst_and_via() {
    let nl = test_netlink();
    let route = MplsRoute::swap(
        Label::new(100),
        LabelStack::from_values([200]),
        IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        3,
    );
    let req = nl
        .build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route)
        .unwrap();
    let new_dst = find_attr(&req, RTA_NEWDST).expect("RTA_NEWDST");
    assert_eq!(new_dst.len(), 4);
    assert_eq!(u32::from_be_bytes(new_dst.try_into().unwrap()) >> 12, 200);
    let via = find_attr(&req, RTA_VIA).expect("RTA_VIA");
    assert_eq!(via.len(), 18);
    assert_eq!(u16::from_ne_bytes([via[0], via[1]]), AF_INET6);
}

#[test]
fn build_request_swap_route_rejects_empty_stack() {
    let nl = test_netlink();
    let route = MplsRoute::swap(
        Label::new(100),
        LabelStack::new(),
        IpAddr::V4([192, 0, 2, 1]),
        2,
    );
    match nl.build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route) {
        Err(MplsRouteError::EmptyLabelStack) => { /* expected */ }
        other => panic!("expected EmptyLabelStack, got {:?}", other),
    }
}

/// `add_route` must carry NLM_F_REPLACE — the kernel's
/// `mpls_route_add()` returns -EEXIST for an existing in-label
/// without it, contradicting the "replaces any existing route" doc.
#[test]
fn add_route_flags_include_replace() {
    assert_ne!(ADD_ROUTE_FLAGS & NLM_F_REQUEST, 0);
    assert_ne!(ADD_ROUTE_FLAGS & NLM_F_ACK, 0);
    assert_ne!(ADD_ROUTE_FLAGS & NLM_F_CREATE, 0);
    assert_ne!(ADD_ROUTE_FLAGS & NLM_F_REPLACE, 0);
}

/// Pop *without* a via gateway (`pop_local`): no RTA_VIA, RTA_OIF
/// present. The kernel forwards the decapsulated packet to the
/// output device's own link address — local delivery on `lo`.
#[test]
fn build_request_pop_local_route_omits_via() {
    let nl = test_netlink();
    let route = MplsRoute::pop_local(Label::new(100), 1);
    let req = nl
        .build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route)
        .unwrap();
    assert!(find_attr(&req, RTA_VIA).is_none(), "no RTA_VIA expected");
    let oif = find_attr(&req, RTA_OIF).expect("RTA_OIF");
    assert_eq!(u32::from_ne_bytes(oif.try_into().unwrap()), 1);
}

/// The kernel assigns the output device in `mpls_nh_assign_dev` —
/// with no via and no device there is nothing to assign, so the
/// request builder must refuse the shape before the syscall.
#[test]
fn build_request_pop_local_requires_oif() {
    let nl = test_netlink();
    let route = MplsRoute::pop_local(Label::new(100), 0);
    match nl.build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route) {
        Err(MplsRouteError::MissingOutputInterface) => { /* expected */ }
        other => panic!("expected MissingOutputInterface, got {:?}", other),
    }
}

/// LSP head-end request for an IPv4 prefix: an AF_INET route with
/// RTA_DST + RTA_GATEWAY + RTA_ENCAP_TYPE=MPLS + a nested RTA_ENCAP
/// carrying MPLS_IPTUNNEL_DST.
#[test]
fn build_encap_request_ipv4_layout() {
    let nl = test_netlink();
    let prefix: lr_core::addr::Prefix = "198.51.100.0/24".parse().unwrap();
    let req = nl
        .build_encap_request(
            RTM_NEWROUTE,
            ADD_ROUTE_FLAGS,
            &prefix,
            &LabelStack::from_values([100]),
            IpAddr::V4([192, 0, 2, 1]),
            0,
        )
        .unwrap();
    assert_eq!(req[16], 2); // rtm_family = AF_INET
    assert_eq!(req[17], 24); // rtm_dst_len
    assert_eq!(req[21], RTPROT_BGP);
    let dst = find_attr(&req, RTA_DST).expect("RTA_DST");
    assert_eq!(dst, &[198, 51, 100, 0]);
    let gw = find_attr(&req, RTA_GATEWAY).expect("RTA_GATEWAY");
    assert_eq!(gw, &[192, 0, 2, 1]);
    assert!(find_attr(&req, RTA_OIF).is_none(), "OIF=0 must be omitted");
    let encap_type = find_attr(&req, RTA_ENCAP_TYPE).expect("RTA_ENCAP_TYPE");
    assert_eq!(
        u32::from_ne_bytes(encap_type.try_into().unwrap()),
        LWTUNNEL_ENCAP_MPLS
    );
    // The nested RTA_ENCAP payload is itself a netlink attribute list:
    // MPLS_IPTUNNEL_DST with the 4-byte label entry.
    let encap = find_attr(&req, RTA_ENCAP).expect("RTA_ENCAP");
    let inner_len = u16::from_ne_bytes([encap[0], encap[1]]) as usize;
    assert_eq!(u16::from_ne_bytes([encap[2], encap[3]]), MPLS_IPTUNNEL_DST);
    let label_entry = &encap[4..inner_len];
    assert_eq!(label_entry.len(), 4);
    let entry = u32::from_be_bytes(label_entry.try_into().unwrap());
    assert_eq!(entry >> 12, 100); // label value
    assert_eq!(entry & 0x100, 0x100); // bottom-of-stack set on the last entry
    assert_eq!(entry & 0xff, 0); // TTL clear
}

/// Same shape for IPv6, with a two-label stack: 8 bytes in
/// MPLS_IPTUNNEL_DST, bottom-of-stack only on the last entry.
#[test]
fn build_encap_request_ipv6_multilabel_layout() {
    let nl = test_netlink();
    let prefix: lr_core::addr::Prefix = "2001:db8:1::/48".parse().unwrap();
    let req = nl
        .build_encap_request(
            RTM_NEWROUTE,
            ADD_ROUTE_FLAGS,
            &prefix,
            &LabelStack::from_values([100, 200]),
            IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            0,
        )
        .unwrap();
    assert_eq!(req[16], 10); // rtm_family = AF_INET6
    assert_eq!(req[17], 48); // rtm_dst_len
    let dst = find_attr(&req, RTA_DST).expect("RTA_DST");
    assert_eq!(dst.len(), 16);
    let encap = find_attr(&req, RTA_ENCAP).expect("RTA_ENCAP");
    let inner_len = u16::from_ne_bytes([encap[0], encap[1]]) as usize;
    let label_entry = &encap[4..inner_len];
    assert_eq!(label_entry.len(), 8);
    let first = u32::from_be_bytes(label_entry[0..4].try_into().unwrap());
    let last = u32::from_be_bytes(label_entry[4..8].try_into().unwrap());
    assert_eq!(first >> 12, 100);
    assert_eq!(first & 0x100, 0, "non-bottom label must not carry BOS");
    assert_eq!(last >> 12, 200);
    assert_eq!(last & 0x100, 0x100, "last label must carry BOS");
}

/// Label 3 never appears in an encapsulation (kernel `nla_get_labels`
/// rejects it outright; RFC 3032 §2.1) — fail before the syscall.
#[test]
fn build_encap_request_rejects_implicit_null() {
    let nl = test_netlink();
    let prefix: lr_core::addr::Prefix = "198.51.100.0/24".parse().unwrap();
    match nl.build_encap_request(
        RTM_NEWROUTE,
        ADD_ROUTE_FLAGS,
        &prefix,
        &LabelStack::from_values([Label::IMPLICIT_NULL.value]),
        IpAddr::V4([192, 0, 2, 1]),
        0,
    ) {
        Err(MplsRouteError::ImplicitNullLabel) => { /* expected */ }
        other => panic!("expected ImplicitNullLabel, got {:?}", other),
    }
}

/// RTA_NEWDST (swap) goes through the same `nla_get_labels()` —
/// implicit null is rejected there too.
#[test]
fn build_request_swap_rejects_implicit_null() {
    let nl = test_netlink();
    let route = MplsRoute::swap(
        Label::new(100),
        LabelStack::from_values([Label::IMPLICIT_NULL.value]),
        IpAddr::V4([192, 0, 2, 1]),
        2,
    );
    match nl.build_request(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, &route) {
        Err(MplsRouteError::ImplicitNullLabel) => { /* expected */ }
        other => panic!("expected ImplicitNullLabel, got {:?}", other),
    }
}

/// Build a synthetic `RTM_GETROUTE` reply (nlmsghdr + rtmsg +
/// attributes) the way the kernel answers a FIB lookup.
fn getroute_reply(attrs: &[(&u16, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (t, data) in attrs {
        body.extend(MplsNetlink::build_rta_attribute(**t, data));
    }
    let total_len = 16 + 12 + body.len();
    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
    buf[16] = AF_INET as u8;
    buf[17] = 32;
    buf[28..].copy_from_slice(&body);
    buf
}

#[test]
fn parse_getroute_reply_reads_oif_gateway_prefsrc() {
    let oif = 5u32.to_ne_bytes();
    let gw = [10u8, 0, 0, 1];
    let prefsrc = [192u8, 0, 2, 254];
    let reply = getroute_reply(&[
        (&RTA_OIF, &oif),
        (&RTA_GATEWAY, &gw),
        (&7, &prefsrc), // RTA_PREFSRC
    ]);
    let info = parse_getroute_reply(&reply, IpAddr::V4([10, 0, 0, 9])).unwrap();
    assert_eq!(info.if_index, 5);
    assert_eq!(info.gateway, Some(IpAddr::V4([10, 0, 0, 1])));
    assert_eq!(info.prefsrc, Some(IpAddr::V4([192, 0, 2, 254])));
}

#[test]
fn parse_getroute_reply_directly_connected_has_no_gateway() {
    let oif = 7u32.to_ne_bytes();
    let reply = getroute_reply(&[(&RTA_OIF, &oif)]);
    let info = parse_getroute_reply(&reply, IpAddr::V4([10, 0, 0, 9])).unwrap();
    assert_eq!(info.if_index, 7);
    assert_eq!(info.gateway, None);
}

#[test]
fn parse_getroute_reply_error_message_is_an_error() {
    // NLMSG_ERROR with EINVAL.
    let mut buf = vec![0u8; 28];
    buf[0..4].copy_from_slice(&28u32.to_ne_bytes());
    buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
    buf[16..20].copy_from_slice(&(-22i32).to_ne_bytes());
    assert!(parse_getroute_reply(&buf, IpAddr::V4([10, 0, 0, 9])).is_err());
}

#[test]
fn parse_getroute_reply_requires_an_oif() {
    let prefsrc = [192u8, 0, 2, 254];
    let reply = getroute_reply(&[(&7, &prefsrc)]);
    assert!(parse_getroute_reply(&reply, IpAddr::V4([10, 0, 0, 9])).is_err());
}

#[test]
fn parse_getroute_reply_handles_v6_gateway() {
    let oif = 3u32.to_ne_bytes();
    let gw: [u8; 16] = core::array::from_fn(|i| i as u8);
    let reply = getroute_reply(&[(&RTA_OIF, &oif), (&RTA_GATEWAY, &gw)]);
    let queried = IpAddr::V6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let info = parse_getroute_reply(&reply, queried).unwrap();
    assert_eq!(info.if_index, 3);
    assert_eq!(info.gateway, Some(IpAddr::V6(gw)));
}
