
use super::*;
use crate::handle::lr_route_t;

fn v4_route(octets: [u8; 4], len: u8) -> lr_route_t {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&octets);
    unsafe { lr_route_new_v4(addr.as_ptr(), len, LrProtocol::Bgp as i32) }
}

#[test]
fn route_attribute_round_trip() {
    let r = v4_route([203, 0, 113, 0], 24);
    assert!(!r.is_null());

    // next hop both families
    let nh6: [u8; 16] = {
        let mut a = [0u8; 16];
        a[15] = 1;
        a
    };
    assert_eq!(unsafe { lr_route_set_next_hop(r, nh6.as_ptr(), 1) }, 0);
    let mut out = [0u8; 16];
    let mut is_v6: i32 = -1;
    assert_eq!(
        unsafe { lr_route_next_hop(r, out.as_mut_ptr(), &mut is_v6) },
        0
    );
    assert_eq!(is_v6, 1);
    assert_eq!(out, nh6);

    let v4 = [192u8, 0, 2, 1];
    assert_eq!(unsafe { lr_route_set_next_hop(r, v4.as_ptr(), 0) }, 0);
    assert_eq!(
        unsafe { lr_route_next_hop(r, out.as_mut_ptr(), &mut is_v6) },
        0
    );
    assert_eq!(is_v6, 0);

    // local pref / med / metric / tag / origin
    assert_eq!(unsafe { lr_route_set_local_pref(r, 250) }, 0);
    let mut v: u32 = 0;
    assert_eq!(unsafe { lr_route_local_pref(r, &mut v) }, 0);
    assert_eq!(v, 250);
    let mut m: u32 = 0;
    assert_eq!(unsafe { lr_route_med(r, &mut m) }, 1); // absent
    assert_eq!(unsafe { lr_route_set_med(r, 50) }, 0);
    assert_eq!(unsafe { lr_route_med(r, &mut m) }, 0);
    assert_eq!(m, 50);
    assert_eq!(unsafe { lr_route_set_metric(r, 42) }, 0);
    let mut v: u32 = 0;
    assert_eq!(unsafe { lr_route_metric(r, &mut v) }, 0);
    assert_eq!(v, 42);
    assert_eq!(unsafe { lr_route_set_tag(r, 1, 65000) }, 0);
    let mut v: u32 = 0;
    assert_eq!(unsafe { lr_route_tag(r, &mut v) }, 0);
    assert_eq!(v, 65000);
    assert_eq!(unsafe { lr_route_set_tag(r, 0, 0) }, 0);
    assert_eq!(unsafe { lr_route_tag(r, &mut v) }, 1);

    assert_eq!(unsafe { lr_route_set_origin(r, LR_ORIGIN_IGP) }, 0);
    let mut o: u8 = 9;
    assert_eq!(unsafe { lr_route_origin(r, &mut o) }, 0);
    assert_eq!(o, LR_ORIGIN_IGP);
    assert_eq!(unsafe { lr_route_set_origin(r, 7) }, -3);
    assert_eq!(unsafe { lr_route_set_origin(std::ptr::null_mut(), 0) }, -1);

    unsafe { lr_route_free(r) };
}

#[test]
fn as_path_and_communities_round_trip() {
    let r = v4_route([198, 51, 100, 0], 24);

    // AS_PATH: set, size-probe, read back.
    let path: [u32; 3] = [64513, 65010, 64512];
    assert_eq!(unsafe { lr_route_set_as_path(r, path.as_ptr(), 3) }, 0);
    let n = unsafe { lr_route_as_path(r, std::ptr::null_mut(), 0) };
    assert_eq!(n, 3);
    let mut got = [0u32; 3];
    assert_eq!(unsafe { lr_route_as_path(r, got.as_mut_ptr(), 2) }, -3); // too small
    assert_eq!(unsafe { lr_route_as_path(r, got.as_mut_ptr(), 3) }, 3);
    assert_eq!(got, path);
    // Empty sequence drops the attribute.
    assert_eq!(unsafe { lr_route_set_as_path(r, std::ptr::null(), 0) }, 0);
    assert_eq!(unsafe { lr_route_as_path(r, std::ptr::null_mut(), 0) }, 0);

    // Standard communities (packed asn<<16|val).
    let comms: [u64; 2] = [(64512u64 << 16) | 100, (65000u64 << 16) | 7];
    assert_eq!(unsafe { lr_route_set_communities(r, comms.as_ptr(), 2) }, 0);
    assert_eq!(unsafe { lr_route_add_community(r, 64512, 100) }, 0); // duplicate: not added
    let n = unsafe { lr_route_communities(r, std::ptr::null_mut(), 0) };
    assert_eq!(n, 2);
    let mut got = [0u64; 2];
    assert_eq!(unsafe { lr_route_communities(r, got.as_mut_ptr(), 2) }, 2);
    assert_eq!(got, comms);
    assert_eq!(unsafe { lr_route_add_community(r, 4294967295, 1) }, -3); // ASN > 16 bits

    // Large communities (flat triples).
    let triples: [u32; 6] = [4200000000, 7, 9, 64512, 1, 2];
    assert_eq!(
        unsafe { lr_route_set_large_communities(r, triples.as_ptr(), 2) },
        0
    );
    assert_eq!(unsafe { lr_route_add_large_community(r, 1, 2, 3) }, 0);
    let n = unsafe { lr_route_large_communities(r, std::ptr::null_mut(), 0) };
    assert_eq!(n, 9);
    let mut got = [0u32; 9];
    assert_eq!(
        unsafe { lr_route_large_communities(r, got.as_mut_ptr(), 9) },
        9
    );
    assert_eq!(&got[..6], &triples);
    assert_eq!(&got[6..], &[1, 2, 3]);

    // Extended communities.
    assert_eq!(
        unsafe { lr_route_add_ext_community(r, 0x42, 0x02, 64512, 5) },
        0
    );
    let n = unsafe { lr_route_ext_communities(r, std::ptr::null_mut(), 0) };
    assert_eq!(n, 1);
    let mut got = [lr_ext_comm_t {
        kind: 0,
        subtype: 0,
        global: 0,
        local: 0,
    }; 1];
    assert_eq!(
        unsafe { lr_route_ext_communities(r, got.as_mut_ptr(), 1) },
        1
    );
    assert_eq!(got[0].kind, 0x42);
    assert_eq!(got[0].subtype, 0x02);
    assert_eq!(got[0].global, 64512);
    assert_eq!(got[0].local, 5);

    unsafe { lr_route_free(r) };
}

#[test]
fn route_construction_rejections() {
    let mut addr = [0u8; 16];
    addr[0] = 203;
    // bad v4 length
    assert!(unsafe { lr_route_new_v4(addr.as_ptr(), 33, 0) }.is_null());
    // unknown protocol
    assert!(unsafe { lr_route_new_v4(addr.as_ptr(), 24, 77) }.is_null());
    // null octets
    assert!(unsafe { lr_route_new_v4(std::ptr::null(), 24, 0) }.is_null());
    // v6 with an illegal length (> 128)
    assert!(unsafe { lr_route_new_v6(addr.as_ptr(), 129, 0) }.is_null());
    let v6: [u8; 16] = {
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a
    };
    assert!(!unsafe { lr_route_new_v6(v6.as_ptr(), 48, LrProtocol::Babel as i32) }.is_null());
    unsafe { lr_route_free(std::ptr::null_mut()) }; // no-op
}

#[test]
fn prefix_list_match_semantics() {
    let l = lr_prefix_list_new();
    let p8 = {
        let mut p = lr_prefix_t {
            addr: [0u8; 16],
            is_ipv6: 0,
            prefix_len: 8,
        };
        p.addr[0] = 10;
        p
    };
    // permit 10.0.0.0/8 ge 16 le 24
    assert_eq!(unsafe { lr_prefix_list_add(l, &p8, 16, 24, 1) }, 0);
    let inside = {
        let mut p = lr_prefix_t {
            addr: [0u8; 16],
            is_ipv6: 0,
            prefix_len: 24,
        };
        p.addr[0] = 10;
        p.addr[1] = 1;
        p
    };
    let shorter = {
        let mut p = inside;
        p.prefix_len = 8;
        p
    };
    let longer = {
        let mut p = inside;
        p.prefix_len = 25;
        p
    };
    assert_eq!(unsafe { lr_prefix_list_match(l, &inside) }, 1);
    assert_eq!(unsafe { lr_prefix_list_match(l, &shorter) }, 0); // ge gate
    assert_eq!(unsafe { lr_prefix_list_match(l, &longer) }, 0); // le gate
                                                                // implicit deny for a disjoint prefix
    let other = {
        let mut p = lr_prefix_t {
            addr: [0u8; 16],
            is_ipv6: 0,
            prefix_len: 24,
        };
        p.addr[0] = 192;
        p
    };
    assert_eq!(unsafe { lr_prefix_list_match(l, &other) }, 0);
    assert_eq!(
        unsafe { lr_prefix_list_add(l, std::ptr::null(), 0, 255, 1) },
        -1
    );
    unsafe { lr_prefix_list_free(l) };
    unsafe { lr_prefix_list_free(std::ptr::null_mut()) };
}

#[test]
fn route_map_evaluate_with_resolver() {
    // Resolver: prefix-list "all-v4" (id 0) permits everything;
    // community list "rich" (id 0) permits 64512:100.
    let resolver = lr_resolver_new();
    let list = lr_prefix_list_new();
    let any = {
        let mut p = lr_prefix_t {
            addr: [0u8; 16],
            is_ipv6: 0,
            prefix_len: 0,
        };
        p.addr[0] = 10;
        p
    };
    assert_eq!(unsafe { lr_prefix_list_add(list, &any, 0, 32, 1) }, 0);
    let id = unsafe { lr_resolver_add_prefix_list(resolver, c"all-v4".as_ptr(), list) };
    assert_eq!(id, 0);

    let comm = [(64512u64 << 16) | 100];
    let comm_entry = lr_community_entry_t {
        communities: comm.as_ptr(),
        count: 1,
        permit: 1,
    };
    let cid = unsafe { lr_resolver_add_community_list(resolver, c"rich".as_ptr(), &comm_entry, 1) };
    assert_eq!(cid, 0);

    // Route-map: entry 10 = match prefix-list 0 -> set local-pref 250, permit.
    let map = lr_route_map_new();
    let m = [lr_match_t {
        kind: LR_MATCH_PREFIX_IN,
        list_id: 0,
        protocol: 0,
    }];
    let s = [lr_set_t {
        kind: LR_SET_LOCAL_PREF,
        is_ipv6: 0,
        addr: [0u8; 16],
        value: 250,
        value2: 0,
    }];
    assert_eq!(
        unsafe { lr_route_map_add_entry(map, m.as_ptr(), 1, s.as_ptr(), 1, LR_VERDICT_PERMIT) },
        0
    );

    let r = v4_route([203, 0, 113, 0], 24);
    let mut verdict: i32 = 9;
    assert_eq!(
        unsafe { lr_route_map_evaluate(map, r, resolver, &mut verdict) },
        0
    );
    assert_eq!(verdict, LR_EVAL_PERMIT);
    let mut lp: u32 = 0;
    assert_eq!(unsafe { lr_route_local_pref(r, &mut lp) }, 0);
    assert_eq!(lp, 250);

    // A protocol-is match (no lists needed) works even with a NULL resolver.
    let map2 = lr_route_map_new();
    let m2 = [lr_match_t {
        kind: LR_MATCH_PROTOCOL_IS,
        list_id: 0,
        protocol: LrProtocol::Bgp as u8,
    }];
    assert_eq!(
        unsafe {
            lr_route_map_add_entry(map2, m2.as_ptr(), 1, std::ptr::null(), 0, LR_VERDICT_DENY)
        },
        0
    );
    let mut verdict: i32 = 9;
    assert_eq!(
        unsafe { lr_route_map_evaluate(map2, r, std::ptr::null_mut(), &mut verdict) },
        0
    );
    assert_eq!(verdict, LR_EVAL_DENY);
    unsafe { lr_route_free(r) };

    // Fallthrough: empty map.
    let map3 = lr_route_map_new();
    let r = v4_route([203, 0, 113, 0], 24);
    let mut verdict: i32 = 9;
    assert_eq!(
        unsafe { lr_route_map_evaluate(map3, r, resolver, &mut verdict) },
        0
    );
    assert_eq!(verdict, LR_EVAL_FALLTHROUGH);

    // Rejection matrix: unknown match kind / set kind / verdict.
    let bad_m = [lr_match_t {
        kind: 99,
        list_id: 0,
        protocol: 0,
    }];
    assert_eq!(
        unsafe {
            lr_route_map_add_entry(
                map3,
                bad_m.as_ptr(),
                1,
                std::ptr::null(),
                0,
                LR_VERDICT_PERMIT,
            )
        },
        -3
    );
    let bad_s = [lr_set_t {
        kind: 99,
        is_ipv6: 0,
        addr: [0u8; 16],
        value: 0,
        value2: 0,
    }];
    assert_eq!(
        unsafe {
            lr_route_map_add_entry(
                map3,
                std::ptr::null(),
                0,
                bad_s.as_ptr(),
                1,
                LR_VERDICT_PERMIT,
            )
        },
        -3
    );
    assert_eq!(
        unsafe { lr_route_map_add_entry(map3, std::ptr::null(), 0, std::ptr::null(), 0, 5) },
        -3
    );

    unsafe { lr_route_free(r) };
    unsafe { lr_route_map_free(map) };
    unsafe { lr_route_map_free(map2) };
    unsafe { lr_route_map_free(map3) };
    unsafe { lr_resolver_free(resolver) };
    unsafe { lr_resolver_free(std::ptr::null_mut()) };
}

#[test]
fn as_path_list_registration_and_match() {
    let resolver = lr_resolver_new();
    let filters = [
        lr_as_path_filter_t {
            pattern: c"^65001$".as_ptr(),
            permit: 0,
        },
        lr_as_path_filter_t {
            pattern: c"_65002_".as_ptr(),
            permit: 1,
        },
    ];
    let id =
        unsafe { lr_resolver_add_as_path_list(resolver, c"paths".as_ptr(), filters.as_ptr(), 2) };
    assert_eq!(id, 0);

    // Match via a route-map entry: match as-path list 0, permit.
    let map = lr_route_map_new();
    let m = [lr_match_t {
        kind: LR_MATCH_AS_PATH_IN,
        list_id: 0,
        protocol: 0,
    }];
    assert_eq!(
        unsafe {
            lr_route_map_add_entry(map, m.as_ptr(), 1, std::ptr::null(), 0, LR_VERDICT_PERMIT)
        },
        0
    );
    let r = v4_route([203, 0, 113, 0], 24);
    let path: [u32; 3] = [64513, 65002, 64512];
    assert_eq!(unsafe { lr_route_set_as_path(r, path.as_ptr(), 3) }, 0);
    let mut verdict: i32 = 9;
    assert_eq!(
        unsafe { lr_route_map_evaluate(map, r, resolver, &mut verdict) },
        0
    );
    assert_eq!(verdict, LR_EVAL_PERMIT); // _65002_ permits
    unsafe { lr_route_free(r) };
    unsafe { lr_route_map_free(map) };
    unsafe { lr_resolver_free(resolver) };
}
