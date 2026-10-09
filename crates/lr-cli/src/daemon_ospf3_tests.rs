use super::*;
use crate::daemon_config::{DaemonConfig, OspfSrv6LocatorSpec};

fn locator_spec(prefix: &str) -> OspfSrv6LocatorSpec {
    OspfSrv6LocatorSpec {
        prefix: Some(prefix.to_string()),
        ..Default::default()
    }
}

fn v6_octets(text: &str) -> [u8; 16] {
    match text.parse::<IpAddr>().expect("valid v6") {
        IpAddr::V6(o) => o,
        _ => panic!("not v6"),
    }
}

#[test]
fn srv6_off_without_locators() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_srv6_receive = true;
    // Reception alone does not turn origination on: the daemon
    // carries SRv6 state only when locators are configured.
    assert!(Srv6Origination::maybe_from_config(&cfg).is_none());
    cfg.ospf_srv6_locators = vec![locator_spec("2001:db8:a:1::/48")];
    assert!(Srv6Origination::maybe_from_config(&cfg).is_some());
}

#[test]
fn srv6_origination_defaults() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_srv6_locators = vec![locator_spec("2001:db8:a:1::/48")];
    let s = Srv6Origination::from_config(&cfg);
    // No O-flag by default; algorithm 0 derived from the locator.
    assert_eq!(s.capabilities, 0);
    assert_eq!(s.algorithms, vec![0]);
    assert!(s.msds.is_empty());
    assert_eq!(s.locators.len(), 1);
    let loc = &s.locators[0];
    assert_eq!(loc.route_type, locator_route_type::INTRA_AREA);
    assert_eq!(loc.algorithm, 0);
    assert_eq!(loc.locator_len, 48);
    assert_eq!(loc.options, 0);
    assert_eq!(loc.metric, 0);
    assert_eq!(loc.prefix, v6_octets("2001:db8:a:1::"));
    // The End SID defaults to the locator prefix, behavior End,
    // no SID Structure sub-TLV.
    assert_eq!(loc.end_sids.len(), 1);
    let sid = &loc.end_sids[0];
    assert_eq!(sid.behavior, 1);
    assert_eq!(sid.sid, v6_octets("2001:db8:a:1::"));
    assert!(sid.structure.is_none());
    // The encoded TLV round-trips through the slice-2 decoder.
    let mut wire = Vec::new();
    loc.encode(&mut wire);
    let (decoded, _) = Srv6LocatorTlv::decode(&wire, 0).expect("decodable");
    assert_eq!(&decoded, loc);
}

#[test]
fn srv6_origination_full_attributes() {
    let mut cfg = DaemonConfig::with_defaults();
    cfg.protocol = "ospf".to_string();
    cfg.ospf_srv6_o_flag = true;
    cfg.ospf_srv6_max_sl = Some(8);
    cfg.ospf_srv6_max_end_d = Some(6);
    cfg.ospf_srv6_locators = vec![
        OspfSrv6LocatorSpec {
            prefix: Some("2001:db8:a:1::/64".to_string()),
            algorithm: Some(128), // flexible-algorithm space
            metric: Some(30),
            anycast: Some(true),
            sid: Some("2001:db8:a:1:f00d::".to_string()),
            behavior: Some(1),
            block_len: Some(32),
            node_len: Some(16),
            function_len: Some(16),
            argument_len: Some(0),
        },
        locator_spec("2001:db8:a:2::/64"),
    ];
    let s = Srv6Origination::from_config(&cfg);
    assert_eq!(s.capabilities, SRV6_CAP_O_FLAG);
    // Distinct algorithms, ascending (BTreeSet order).
    assert_eq!(s.algorithms, vec![0, 128]);
    // MSD pairs in the 41/42/44/45 wire order, only the configured ones.
    assert_eq!(
        s.msds,
        vec![(msd_type::SRH_MAX_SL, 8), (msd_type::SRH_MAX_END_D, 6)]
    );
    assert_eq!(s.locators.len(), 2);
    let first = &s.locators[0];
    assert_eq!(first.options, PREFIX_OPT_AC);
    assert_eq!(first.metric, 30);
    assert_eq!(first.end_sids[0].sid, v6_octets("2001:db8:a:1:f00d::"));
    assert_eq!(
        first.end_sids[0].structure,
        Some(Srv6SidStructure {
            lb_len: 32,
            ln_len: 16,
            func_len: 16,
            arg_len: 0,
        })
    );
    // The full TLV round-trips through the slice-2 decoder.
    let mut wire = Vec::new();
    first.encode(&mut wire);
    let (decoded, _) = Srv6LocatorTlv::decode(&wire, 0).expect("decodable");
    assert_eq!(&decoded, first);
}

#[test]
fn lan_end_x_base_masks_host_bits() {
    // /96: the low 32 bits clear — the Router-ID argument slot.
    assert_eq!(
        mask_lan_base("2001:db8:a:1:ffff:ffff:ffff:ffff/96", &[])
            .unwrap()
            .0,
        v6_octets("2001:db8:a:1:ffff:ffff::")
    );
    // /64: everything below the prefix clears.
    assert_eq!(
        mask_lan_base("2001:db8:a:1:dead:beef::1/64", &[])
            .unwrap()
            .0,
        v6_octets("2001:db8:a:1::")
    );
    // A non-byte-aligned length keeps the partial octet's high
    // bits (100 = 12 bytes + 4 bits: 0xff & 0xf0 = 0xf0).
    assert_eq!(
        mask_lan_base("2001:db8:a:1:0:0:ffff:ffff/100", &[])
            .unwrap()
            .0,
        v6_octets("2001:db8:a:1::f000:0")
    );
    // The covering locator's algorithm rides along (algorithm 128
    // on the covering locator, 0 default on the other).
    let locators = vec![
        locator_spec("2001:db8:a:1::/48"),
        OspfSrv6LocatorSpec {
            prefix: Some("2001:db8:b::/48".to_string()),
            algorithm: Some(128),
            ..Default::default()
        },
    ];
    assert_eq!(
        mask_lan_base("2001:db8:b:ffff::/96", &locators).unwrap().1,
        128
    );
    assert_eq!(
        mask_lan_base("2001:db8:a:1:ffff::/96", &locators)
            .unwrap()
            .1,
        0
    );
}

#[test]
fn e_router_links_broadcast_carries_9_1_and_9_2() {
    // A BDR's transit link (§A.4.3 type 2): Full with the DR
    // 3.3.3.3 and the DR-Others 4.4.4.4 + 5.5.5.5. RFC 9513 §9:
    // the plain End.X (§9.1) covers the DR adjacency, one LAN
    // End.X (§9.2) per DR-Other, all riding the same link.
    let links = vec![lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_TRANSIT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 77,
        neighbor_router_id: 0x0303_0303, // the DR
    }];
    let end_x_by_if = BTreeMap::new();
    let mut lan_end_x_by_if = BTreeMap::new();
    lan_end_x_by_if.insert(
        5u32,
        LanEndXSpec {
            dr_sid: Some((v6_octets("2001:db8:a:1::100"), 0)),
            base: Some((v6_octets("2001:db8:a:1:ffff::"), 0)),
            neighbors: vec![0x0404_0404, 0x0505_0505],
        },
    );
    let out = e_router_links(&links, &end_x_by_if, &lan_end_x_by_if);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].link_type, LINK_TYPE_TRANSIT);
    // §9.1: one plain End.X, the configured SID verbatim.
    let plain = lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs);
    assert_eq!(plain.len(), 1);
    assert_eq!(plain[0].sid, v6_octets("2001:db8:a:1::100"));
    assert_eq!(plain[0].behavior, 5); // End.X (RFC 8986)
    assert_eq!(plain[0].algorithm, 0);
    assert_eq!(plain[0].flags, 0);
    // §9.2: one LAN End.X per neighbor, the SID derived as
    // base | Router-ID (the RID fills the low 32 bits).
    let lan = lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs);
    assert_eq!(lan.len(), 2);
    assert_eq!(lan[0].neighbor_router_id, 0x0404_0404);
    assert_eq!(lan[0].sid, v6_octets("2001:db8:a:1:ffff::404:404"));
    assert_eq!(lan[0].behavior, 5);
    assert_eq!(lan[1].neighbor_router_id, 0x0505_0505);
    assert_eq!(lan[1].sid, v6_octets("2001:db8:a:1:ffff::505:505"));
    // The §9.1 sub-TLV precedes the §9.2 instances on the wire
    // (type 31 before 32 in emission order; the §9.1 instance is
    // 4 + 24 = 28 octets, 4-aligned, so the LAN form starts at
    // 28).
    let t = u16::from_be_bytes([out[0].sub_tlvs[0], out[0].sub_tlvs[1]]);
    assert_eq!(t, lr_ospf::lsa::srv6::EXT_SUBTLV_END_X_SID);
    let t2 = u16::from_be_bytes([out[0].sub_tlvs[28], out[0].sub_tlvs[29]]);
    assert_eq!(t2, lr_ospf::lsa::srv6::EXT_SUBTLV_LAN_END_X_SID);
}

#[test]
fn e_router_links_dr_has_no_9_1_dr_adjacency() {
    // The DR describes itself (§A.4.3 self-referential shape): it
    // has no adjacency to a DR, so no §9.1 sub-TLV — only the
    // §9.2 LAN End.X per Full neighbor (BDR + DR-Others).
    let links = vec![lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_TRANSIT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 5,
        neighbor_router_id: 0x0303_0303, // ourselves
    }];
    let end_x_by_if = BTreeMap::new();
    let mut lan_end_x_by_if = BTreeMap::new();
    lan_end_x_by_if.insert(
        5u32,
        LanEndXSpec {
            dr_sid: None,
            base: Some((v6_octets("2001:db8:a:1:ffff::"), 0)),
            neighbors: vec![0x0202_0202, 0x0404_0404],
        },
    );
    let out = e_router_links(&links, &end_x_by_if, &lan_end_x_by_if);
    assert!(lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs).is_empty());
    let lan = lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs);
    assert_eq!(lan.len(), 2);
    assert_eq!(lan[0].neighbor_router_id, 0x0202_0202);
    assert_eq!(lan[0].sid, v6_octets("2001:db8:a:1:ffff::202:202"));
}

#[test]
fn e_router_links_p2p_keeps_the_plain_form() {
    // A p2p link (§A.4.3 type 1) with the §9.1 SID configured:
    // exactly one plain End.X, no LAN forms.
    let links = vec![lr_ospf::lsa::v3::V3RouterLink {
        link_type: LINK_TYPE_POINTTOPOINT,
        metric: 10,
        interface_id: 5,
        neighbor_interface_id: 77,
        neighbor_router_id: 0x0202_0202,
    }];
    let mut end_x_by_if = BTreeMap::new();
    end_x_by_if.insert(5u32, (v6_octets("2001:db8:a:1::100"), 0));
    let out = e_router_links(&links, &end_x_by_if, &BTreeMap::new());
    let plain = lr_ospf::lsa::srv6::walk_end_x_sub_tlvs(&out[0].sub_tlvs);
    assert_eq!(plain.len(), 1);
    assert_eq!(plain[0].sid, v6_octets("2001:db8:a:1::100"));
    assert!(lr_ospf::lsa::srv6::walk_lan_end_x_sub_tlvs(&out[0].sub_tlvs).is_empty());
}
