use super::*;

#[test]
fn strip_ipv4_header_extracts_ospf() {
    let pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        7,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![],
    )
    .unwrap();
    // Simulate a raw-socket datagram: 20-byte IP header (protocol 89)
    // in front of the OSPF packet.
    let mut dg = vec![0u8; 20];
    dg[0] = 0x45; // IPv4, IHL 5
    dg[9] = 89; // OSPF
    dg.extend_from_slice(&pkt);
    let stripped = strip_ipv4_header(&dg).unwrap();
    assert_eq!(stripped, &pkt[..]);
    // Non-OSPF protocol, wrong version, truncated → None.
    let mut other = dg.clone();
    other[9] = 6; // TCP
    assert!(strip_ipv4_header(&other).is_none());
    let mut v6 = dg.clone();
    v6[0] = 0x65;
    assert!(strip_ipv4_header(&v6).is_none());
    assert!(strip_ipv4_header(&dg[..12]).is_none());
}

#[test]
fn demux_header_parses_and_rejects() {
    let pkt = build_hello(
        RouterId::from_u32(0x0a00_0001),
        7,
        &HelloWire {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            dead_interval: 40,
            priority: 1,
            dr: 0,
            bdr: 0,
        },
        vec![0x0a00_0002],
    )
    .unwrap();
    let (rid, area, len) = demux_header(&pkt).unwrap();
    assert_eq!(rid, 0x0a00_0001);
    assert_eq!(area, 7);
    assert_eq!(len as usize, pkt.len());
    // Short / wrong version / bad length → None.
    assert!(demux_header(&pkt[..20]).is_none());
    let mut v3 = pkt.clone();
    v3[0] = 3;
    assert!(demux_header(&v3).is_none());
    let mut bad_len = pkt.clone();
    bad_len[3] = 0xff; // length > buffer
    assert!(demux_header(&bad_len).is_none());
}

#[test]
fn area_kind_mapping() {
    use lr_router::OspfAreaType;
    let mut spec = OspfAreaSpec {
        id: Some(1),
        kind: Some("stub".into()),
        no_summary: Some(false),
        stub_metric: Some(42),
    };
    assert_eq!(area_kind(&spec), Some(OspfAreaType::stub(42)));
    spec.no_summary = Some(true);
    assert_eq!(area_kind(&spec), Some(OspfAreaType::stub_no_summary(42)));
    spec.kind = Some("nssa".into());
    assert_eq!(area_kind(&spec), Some(OspfAreaType::nssa_no_summary(42)));
    spec.no_summary = Some(false);
    spec.stub_metric = None;
    assert_eq!(
        area_kind(&spec),
        Some(OspfAreaType::nssa(DEFAULT_STUB_METRIC))
    );
    // normal / unset → no router call needed.
    spec.kind = None;
    assert_eq!(area_kind(&spec), None);
    spec.kind = Some("normal".into());
    assert_eq!(area_kind(&spec), None);
}
