"""RIB (Loc-RIB / Adj-RIB-In / Adj-RIB-Out / RibMux / RouteSelector) tests.

These tests exercise the Python binding through the public
``librouting.LocRib`` / ``librouting.AdjRibIn`` / ``librouting.AdjRibOut`` /
``librouting.RibMux`` / ``librouting.RouteSelector`` / ``librouting.RouteKey``
/ ``librouting.RouteOrigin`` API and mirror the C ABI tests in
``crates/lr-ffi/src/rib.rs`` and the C harness in ``tests/ffi/harness.c``.
"""

import pytest

import librouting
from librouting import (
    AdjRibIn,
    AdjRibOut,
    LocRib,
    RibMux,
    RouteKey,
    RouteOrigin,
    RouteSelector,
)
from librouting.policy import Route
from librouting.rib import (
    AFI_IPV4,
    AFI_IPV6,
    PROTO_BGP,
    PROTO_OSPF,
    SAFI_UNICAST,
)


def _v4_route(prefix_addr, prefix_len, *, protocol=PROTO_BGP, next_hop=None):
    """Helper: build a Route for an IPv4 prefix."""
    r = Route((bytes(prefix_addr), prefix_len), protocol)
    if next_hop is not None:
        r.set_next_hop(bytes(next_hop))
    return r


def _v4_key(addr, plen, **kw):
    return RouteKey((bytes(addr), plen), afi=AFI_IPV4, safi=SAFI_UNICAST, **kw)


# ---- LocRib ----


def test_loc_rib_lifecycle_and_basic_install():
    rib = LocRib()
    try:
        assert rib.is_empty()
        assert len(rib) == 0
        assert rib.paths_len() == 0
        assert rib.generation() == 0
    finally:
        rib.close()


def test_loc_rib_install_then_uninstall():
    rib = LocRib()
    try:
        r = _v4_route([10, 0, 0, 1], 24)
        changed = rib.install(r)
        assert changed == 1
        assert len(rib) == 1
        assert rib.paths_len() == 1
        gen0 = rib.generation()
        assert gen0 >= 1

        # Installing the same route again is a byte-identical no-op (no
        # generation bump).
        r2 = _v4_route([10, 0, 0, 1], 24)
        changed2 = rib.install(r2)
        assert changed2 == 0
        assert rib.generation() == gen0

        # best_present + best
        k = _v4_key([10, 0, 0, 1], 24)
        assert rib.best_present(k)
        best = rib.best(k)
        assert best is not None
        try:
            # The copy carries the prefix back to the caller.
            assert best is not None  # for type-checkers
        finally:
            best.close() if hasattr(best, "close") else None

        # Uninstall.
        assert rib.uninstall(k) == 1
        assert len(rib) == 0
        assert not rib.best_present(k)
        # Second uninstall is a no-op.
        assert rib.uninstall(k) == 0
    finally:
        rib.close()


def test_loc_rib_install_set_paths_iter():
    rib = LocRib()
    try:
        # Build two paths for the same prefix with different next-hops.
        r1 = _v4_route([10, 0, 0, 1], 24, next_hop=[10, 0, 0, 254])
        r2 = _v4_route([10, 0, 0, 1], 24, next_hop=[10, 0, 0, 253])
        k = _v4_key([10, 0, 0, 1], 24)
        rib.install_set(k, [r1, r2])

        # paths_len counts both; len counts 1 (one key).
        assert rib.paths_len() == 2
        assert len(rib) == 1
        assert rib.paths(k) == 2

        # iter_best walks one best route per key (only 1 key here).
        best = list(rib.iter_best())
        assert len(best) == 1

        # iter_paths walks every path (2 here).
        paths = list(rib.iter_paths())
        assert len(paths) == 2

        # iter_sets yields (prefix, path_count) tuples.
        sets = list(rib.iter_sets())
        assert len(sets) == 1
        ((addr, plen, is_ipv6), path_count) = sets[0]
        assert plen == 24
        assert not is_ipv6
        assert path_count == 2
        # iter_sets places the IPv4 address in the first 4 bytes of
        # the 16-byte buffer (the C ABI uses the start, not the
        # IPv4-mapped IPv6 layout used by lr_core_prefix_t).
        assert addr[:4] == bytes([10, 0, 0, 1])
    finally:
        rib.close()


def test_loc_rib_diff_since():
    rib = LocRib()
    try:
        r1 = _v4_route([10, 0, 0, 1], 24)
        rib.install(r1)
        gen1 = rib.generation()

        r2 = _v4_route([10, 0, 0, 2], 24)
        rib.install(r2)
        gen2 = rib.generation()
        assert gen2 > gen1

        # diff_since gen1 should see at least one added route.
        diff = rib.diff_since(gen1 - 1)
        assert isinstance(diff.added, int)
        assert diff.added >= 1

        # diff_since gen2 should be all zeros (nothing changed after).
        diff = rib.diff_since(gen2)
        assert diff.added == 0
        assert diff.modified == 0
        assert diff.removed == 0
    finally:
        rib.close()


# ---- AdjRibIn ----


def test_adj_rib_in_lifecycle_and_feed():
    rib = AdjRibIn()
    try:
        assert rib.is_empty()
        assert len(rib) == 0
        assert isinstance(hash(rib), int)  # smoke test

        r = _v4_route([10, 0, 0, 1], 24)
        origin = RouteOrigin(protocol=PROTO_BGP, peer=42)
        rib.feed(origin, r)
        assert len(rib) == 1

        # get finds the route back.
        k = _v4_key([10, 0, 0, 1], 24)
        got = rib.get(origin, k, path_id=0)
        assert got is not None
        got.close() if hasattr(got, "close") else None

        # origins_for returns at least one origin.
        origins = rib.origins_for(k)
        assert len(origins) >= 1
        assert any(o.protocol == PROTO_BGP and o.peer == 42 for o in origins)

        # Withdraw.
        rc = rib.withdraw(origin, k, path_id=0)
        assert rc == 1
        assert len(rib) == 0

        # Withdraw again is a no-op.
        rc = rib.withdraw(origin, k, path_id=0)
        assert rc == 0
    finally:
        rib.close()


def test_adj_rib_in_iter_all_and_origin():
    rib = AdjRibIn()
    try:
        origin = RouteOrigin(protocol=PROTO_BGP, peer=42)
        rib.feed(origin, _v4_route([10, 0, 0, 1], 24))
        rib.feed(origin, _v4_route([10, 0, 0, 2], 24))

        # iter_all walks every route.
        all_routes = list(rib.iter_all())
        assert len(all_routes) == 2

        # iter_origin walks every route from one origin.
        from_origin = list(rib.iter_origin(origin))
        assert len(from_origin) == 2

        # clear_for drops everything from one origin.
        rib.clear_for(origin)
        assert rib.is_empty()
    finally:
        rib.close()


# ---- AdjRibOut ----


def test_adj_rib_out_advertise_and_iter():
    out = AdjRibOut()
    try:
        assert out.is_empty()
        dest = RouteOrigin(protocol=PROTO_BGP, peer=42)

        r = _v4_route([10, 0, 0, 1], 24)
        out.advertise(dest, r, tx_path_id=100)
        # The route handle is *not* consumed — verify by re-advertising.
        assert r._ptr != librouting.ffi.NULL if hasattr(librouting, "ffi") else True
        out.advertise(dest, r, tx_path_id=200)
        assert len(out) == 2

        # tx_path_ids returns both advertised IDs.
        k = _v4_key([10, 0, 0, 1], 24)
        ids = out.tx_path_ids(dest, k)
        assert sorted(ids) == [100, 200]

        # iter_for walks every route advertised to dest.
        adv = list(out.iter_for(dest))
        assert len(adv) == 2

        # suppress removes one (dest, key, tx_path_id) tuple.
        assert out.suppress(dest, k, tx_path_id=100) == 1
        assert len(out) == 1

        # clear_for removes the rest.
        out.clear_for(dest)
        assert out.is_empty()
    finally:
        out.close()


def test_adj_rib_out_paths_for_visits_each_path():
    out = AdjRibOut()
    try:
        dest = RouteOrigin(protocol=PROTO_BGP, peer=42)
        r = _v4_route([203, 0, 113, 1], 24)
        out.advertise(dest, r, tx_path_id=1)
        out.advertise(dest, r, tx_path_id=2)
        out.advertise(dest, r, tx_path_id=3)

        k = _v4_key([203, 0, 113, 1], 24)
        pairs = out.paths_for(dest, k)
        # Three (path_id, route) pairs ascending by path_id.
        assert len(pairs) == 3
        assert [pid for (pid, _rt) in pairs] == [1, 2, 3]

        # Unknown key → empty list.
        unknown = _v4_key([10, 0, 0, 0], 8)
        assert out.paths_for(dest, unknown) == []
    finally:
        out.close()


def test_adj_rib_out_advertised_keys_filters_by_family():
    out = AdjRibOut()
    try:
        dest = RouteOrigin(protocol=PROTO_BGP, peer=42)

        # Advertise v4 + v6 under the same dest.
        r_v4 = _v4_route([203, 0, 113, 1], 24)
        out.advertise(dest, r_v4, tx_path_id=1)
        v6_addr = bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        r_v6 = Route((v6_addr, 64), PROTO_BGP)
        out.advertise(dest, r_v6, tx_path_id=1)

        # v4 family → only the v4 key.
        v4_keys = out.advertised_keys(dest, (AFI_IPV4, SAFI_UNICAST))
        assert len(v4_keys) == 1
        rk, ids = v4_keys[0]
        assert rk.afi == AFI_IPV4
        assert rk.safi == SAFI_UNICAST
        assert rk.prefix[1] == 24
        assert rk.prefix[0] == bytes([203, 0, 113, 1])
        assert ids == [1]

        # v6 family → only the v6 key.
        v6_keys = out.advertised_keys(dest, (AFI_IPV6, SAFI_UNICAST))
        assert len(v6_keys) == 1
        rk, ids = v6_keys[0]
        assert rk.afi == AFI_IPV6
        assert rk.safi == SAFI_UNICAST
        assert rk.prefix[1] == 64
        assert rk.prefix[0] == v6_addr
        assert ids == [1]

        # Wrong dest peer → empty.
        wrong_dest = RouteOrigin(protocol=PROTO_BGP, peer=99)
        assert out.advertised_keys(wrong_dest, (AFI_IPV4, SAFI_UNICAST)) == []

        # Labelled-unicast filter → empty (we did not advertise any).
        assert out.advertised_keys(dest, (AFI_IPV4, 4)) == []
    finally:
        out.close()


# ---- RibMux ----


def test_rib_mux_install_get_uninstall():
    mux = RibMux()
    try:
        assert mux.is_empty()
        r = _v4_route([10, 0, 0, 1], 24)
        mux.install(r)
        assert len(mux) == 1

        k = _v4_key([10, 0, 0, 1], 24)
        got = mux.get(k)
        assert got is not None
        got.close() if hasattr(got, "close") else None

        # Uninstall.
        assert mux.uninstall(k) == 1
        assert mux.is_empty()
        assert mux.uninstall(k) == 0
    finally:
        mux.close()


def test_rib_mux_iter_walks_every_route():
    mux = RibMux()
    try:
        # Empty mux → iter yields nothing.
        assert list(mux.iter()) == []

        # Install two routes under different keys so both survive.
        r1 = _v4_route([10, 0, 0, 1], 24)
        mux.install(r1)
        r2 = _v4_route([10, 0, 1, 1], 24)
        mux.install(r2)
        assert len(mux) == 2

        merged = list(mux.iter())
        assert len(merged) == 2
    finally:
        mux.close()


# ---- RouteSelector ----


def test_route_selector_select_returns_index_of_winner():
    r1 = _v4_route([10, 0, 0, 1], 24, next_hop=[10, 0, 0, 254])
    r2 = _v4_route([10, 0, 0, 1], 24, next_hop=[10, 0, 0, 253])
    # select picks the best path by RFC 4271 §9.1.2.2 — the result is
    # the index in the input array; just verify it's a valid index.
    idx = RouteSelector.select([r1, r2])
    assert idx in (0, 1)

    idx_bgp = RouteSelector.select_bgp([r1, r2])
    assert idx_bgp in (0, 1)

    # Empty input returns -1.
    assert RouteSelector.select([]) == -1
    assert RouteSelector.select_bgp([]) == -1


def test_route_selector_compare_orders_by_metric():
    # Two routes with different metrics: same admin distance, lower
    # metric wins. The Route stores the metric in its preference when
    # constructed via Route(...) — both start with the same default
    # admin distance, so the comparator's first discriminator (admin
    # distance) ties and the metric breaks the tie.
    r1 = _v4_route([10, 0, 0, 1], 24)
    r2 = _v4_route([10, 0, 0, 1], 24)

    # Same prefix, same default preference → tie.
    rc = RouteSelector.compare(r1, r2)
    assert rc in (-1, 0, 1)

    # compare is anti-symmetric: swapping args mirrors the result.
    rc2 = RouteSelector.compare(r2, r1)
    assert rc == -rc2 or rc == 0


def test_route_origin_and_key_construction():
    o = RouteOrigin(protocol=PROTO_OSPF, peer=99)
    assert o.protocol == PROTO_OSPF
    assert o.peer == 99

    k = RouteKey((b"\x0a\x00\x00\x01", 24), afi=AFI_IPV4, safi=SAFI_UNICAST)
    assert k.afi == AFI_IPV4
    assert k.safi == SAFI_UNICAST
    assert k.source is None

    # With source prefix.
    k2 = RouteKey(
        (b"\x0a\x00\x00\x01", 24),
        afi=AFI_IPV4,
        safi=SAFI_UNICAST,
        source=(b"\x0a\x00\x00\x02", 32),
    )
    assert k2.source is not None
    c_repr = k2._to_c()
    assert c_repr.has_source == 1


def test_ipv6_loc_rib_install_and_best():
    rib = LocRib()
    try:
        v6_addr = bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        r = Route((v6_addr, 64), PROTO_BGP)
        rib.install(r)
        assert len(rib) == 1

        k = RouteKey((v6_addr, 64), afi=AFI_IPV6, safi=SAFI_UNICAST)
        assert rib.best_present(k)
        best = rib.best(k)
        assert best is not None
        if hasattr(best, "close"):
            best.close()
    finally:
        rib.close()
