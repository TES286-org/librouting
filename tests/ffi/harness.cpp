// harness.cpp — minimal C++ test that exercises the librouting.hpp RAII
// wrapper. Mirrors the assertions in tests/ffi/harness.c but uses the C++
// API surface so the wrapper itself is covered in CI.
//
// Build:
//   c++ -std=c++17 -Iinclude tests/ffi/harness.cpp \
//       -Ltarget/release -llr_ffi -o /tmp/lr_harness_cpp
// Run:
//   LD_LIBRARY_PATH=target/release /tmp/lr_harness_cpp

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "librouting.hpp"

static int failures = 0;

static void check(bool cond, const char* what) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    } else {
        std::printf("ok: %s\n", what);
    }
}

int main() {
    using namespace librouting;

    // ABI version
    std::uint32_t v = lr_abi_version();
    check(v != 0, "abi_version > 0");

    // D5.4 encoder surface (stateless — before the router lifecycle).
    {
        auto ka = encode_keepalive();
        check(lr_bytes_len(ka.get()) == 19, "encode_keepalive is 19 bytes");

        auto open = encode_open(64512, 90, {10, 0, 0, 1}, true);
        check(lr_bytes_ptr(open.get())[18] == 1, "encode_open type=1");
        check(lr_bytes_len(open.get()) > 29, "encode_open carries parameters");
        bool threw = false;
        try {
            encode_open(4200000000u, 90, {10, 0, 0, 1}, false);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "encode_open rejects a 4-byte AS with as4 off");

        auto n = encode_notification(6, 3);
        check(lr_bytes_len(n.get()) == 21, "encode_notification without data");
        auto nd = encode_notification(2, 4, {1, 2});
        check(lr_bytes_len(nd.get()) == 23, "encode_notification with data");

        auto w = encode_update_withdraw_v4(
            {make_prefix({203, 0, 113, 0}, 24), make_prefix({198, 51, 100, 0}, 24)});
        check(lr_bytes_len(w.get()) == 31, "encode_update_withdraw_v4 (2 prefixes)");
        threw = false;
        try {
            lr_prefix_t bad{};
            bad.is_ipv6 = 1;
            bad.prefix_len = 32;
            encode_update_withdraw_v4({bad});
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "withdraw rejects IPv6 in the legacy NLRI section");

        auto a = encode_update_announce_v4({make_prefix({203, 0, 113, 0}, 24)},
                                           {192, 0, 2, 1}, {64513, 64512}, 0, false);
        check(lr_bytes_ptr(a.get())[18] == 2, "encode_update_announce_v4 type=2");
        check(lr_bytes_len(a.get()) > 23, "announce carries attributes + NLRI");
        threw = false;
        try {
            encode_update_announce_v4({make_prefix({203, 0, 113, 0}, 24)},
                                      {192, 0, 2, 1}, {}, 3, false);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "announce rejects ORIGIN 3");
    }

    // RAII lifecycle: the Router unique_ptr must free the handle on scope
    // exit. We wrap the block so the destructor runs before the final
    // report.
    {
        Router r = make_router();
        check(static_cast<bool>(r), "make_router");

        // Plain BGP session via the convenience overload (defaults:
        // hold 90s, keepalive auto, asn4 on, GR on 120s).
        std::uint64_t h = add_bgp_session(r, 64512, 64513, 0x0a000001u);
        check(h == 1, "add_bgp_session handle == 1");

        // Extended session creation (RFC 4724 GR + RFC 9494 LLGR knobs)
        std::uint64_t h2 = add_bgp_session_ext(
            r, 64512, 64513, 0x0a000001u,
            /*hold*/ 90, /*keepalive*/ 0, /*asn4*/ true,
            /*gr*/ true, /*gr_time*/ 120,
            /*llgr*/ true, /*llgr_stale*/ 3600, /*llgr_max*/ 0);
        check(h2 == 2, "add_bgp_session_ext handle == 2");

        // Peer router for a full LLGR handshake
        Router peer = make_router();
        check(static_cast<bool>(peer), "peer make_router");
        std::uint64_t ph = add_bgp_session_ext(
            peer, 64513, 64512, 0x0a000002u,
            90, 0, true, true, 90, true, 1800, 0);

        // Drive the OPEN/KEEPALIVE exchange byte-by-byte.
        int rc = lr_router_start_session(r.get(), h2);
        check(rc == 0, "start ext session");
        rc = lr_router_start_session(peer.get(), ph);
        check(rc == 0, "start peer session");

        Bytes a_open = drain_output(r, h2);
        Bytes b_open = drain_output(peer, ph);

        // The OPEN must carry the LLGR capability (code 71, RFC 9494).
        {
            auto vec = to_vec(a_open);
            bool has_llgr = false;
            for (std::size_t i = 19; i + 1 < vec.size(); ++i) {
                if (vec[i] == 71 && vec[i + 1] == 7) {
                    has_llgr = true;
                    break;
                }
            }
            check(has_llgr, "OPEN advertises LLGR capability (code 71)");
        }

        feed_input(r, h2, to_vec(b_open).data(), to_vec(b_open).size());
        feed_input(peer, ph, to_vec(a_open).data(), to_vec(a_open).size());

        Bytes a_ka = drain_output(r, h2);
        Bytes b_ka = drain_output(peer, ph);
        feed_input(r, h2, to_vec(b_ka).data(), to_vec(b_ka).size());
        feed_input(peer, ph, to_vec(a_ka).data(), to_vec(a_ka).size());
        // peer goes out of scope here — its destructor must run cleanly
        // (no double-free, no leak).
    }

    // RAII: a fresh router after the previous one's destruction should
    // still allocate handle 1.
    Router r = make_router();
    check(static_cast<bool>(r), "make_router (2nd)");

    std::uint64_t h = add_bgp_session(r, 64512, 64513, 0x0a000001u);
    check(h == 1, "add_bgp_session handle == 1 (fresh router)");

    // Tick once
    tick(r, 0);

    // RFC 5549 Extended Next-Hop setter (we don't drive the session to
    // Established here, just verify the setter accepts the canonical
    // {1,1,2} tuple and doesn't throw).
    try {
        set_extended_next_hop(r, h, {{1, 1, 2}});
        check(true, "set_extended_next_hop accepts canonical {1,1,2}");
    } catch (const Error& e) {
        std::fprintf(stderr, "set_extended_next_hop threw: %s\n", e.what());
        check(false, "set_extended_next_hop accepts canonical {1,1,2}");
    }

    // MP-BGP family setter — IPv4 + IPv6 unicast.
    try {
        set_mp_families(r, h, {{1, 1}, {2, 1}});
        check(true, "set_mp_families accepts IPv4 + IPv6 unicast");
    } catch (const Error& e) {
        std::fprintf(stderr, "set_mp_families threw: %s\n", e.what());
        check(false, "set_mp_families accepts IPv4 + IPv6 unicast");
    }

    // Local address setter — IPv4 form.
    try {
        set_local_address(r, h, {192, 0, 2, 1});
        check(true, "set_local_address accepts IPv4");
    } catch (const Error& e) {
        std::fprintf(stderr, "set_local_address threw: %s\n", e.what());
        check(false, "set_local_address accepts IPv4");
    }

    // Local address setter — IPv6 form.
    try {
        set_local_address(r, h, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1});
        check(true, "set_local_address accepts IPv6");
    } catch (const Error& e) {
        std::fprintf(stderr, "set_local_address threw: %s\n", e.what());
        check(false, "set_local_address accepts IPv6");
    }

    // Bad local address length (3 bytes) must throw.
    bool threw = false;
    try {
        set_local_address(r, h, {1, 2, 3});
    } catch (const Error&) {
        threw = true;
    }
    check(threw, "set_local_address rejects 3-byte address");

    // D5.5 event polling through the RAII surface.
    {
        originate_v4(r, {203, 0, 113, 0}, 24);
        originate_v4(r, {198, 51, 100, 0}, 24);
        auto events = poll_events(r, 8);
        bool saw_installed = false;
        for (const auto& ev : events) {
            if (ev.kind == EventKind::RouteInstalled) {
                saw_installed = true;
                check(ev.prefix_len <= 32, "installed event prefix length sane");
                check(ev.prefix.size() == 4, "installed event carries a v4 prefix");
            }
        }
        check(saw_installed, "poll_events observed RouteInstalled");
        // Drain to empty.
        while (!poll_events(r, 8).empty()) {
        }
        // Requeue semantics: one slot at a time drains everything.
        originate_v4(r, {192, 0, 2, 0}, 24);
        originate_v4(r, {198, 18, 0, 0}, 15);
        auto slot = poll_events(r, 1);
        check(slot.size() == 1, "one slot takes one event");
        check(!poll_events(r, 1).empty(), "the requeued remainder arrives next");
        while (!poll_events(r, 1).empty()) {
        }
        bool threw = false;
        try {
            poll_events(r, 0);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "poll_events rejects zero capacity");
        // Leave the router clean for the sections that follow: retract
        // everything this block originated and drain the tail events.
        check(withdraw_v4(r, {203, 0, 113, 0}, 24), "cleanup withdraw 1");
        check(withdraw_v4(r, {198, 51, 100, 0}, 24), "cleanup withdraw 2");
        check(withdraw_v4(r, {192, 0, 2, 0}, 24), "cleanup withdraw 3");
        check(withdraw_v4(r, {198, 18, 0, 0}, 15), "cleanup withdraw 4");
        while (!poll_events(r, 8).empty()) {
        }
    }

    // Originate a route: 203.0.113.0/24 via 192.0.2.1
    {
        const std::uint8_t prefix[4] = {203, 0, 113, 0};
        const std::uint8_t nh[4] = {192, 0, 2, 1};
        int rc = lr_router_originate_v4(r.get(), prefix, 24, nh);
        check(rc == 0, "originate_v4");
    }

    // IPv6 origination + the withdraw lifecycle (ROADMAP-v3 D5.6/D5.7),
    // through the RAII helper surface.
    {
        const std::array<std::uint8_t, 16> v6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0};
        const std::array<std::uint8_t, 4> v4 = {203, 0, 113, 0};
        check(!withdraw_v6(r, v6, 32), "withdraw_v6 on non-originated prefix is a no-op");
        originate_v6(r, v6, 32);
        check(withdraw_v4(r, v4, 24), "withdraw_v4 removes the origination");
        check(!withdraw_v4(r, v4, 24), "repeat withdraw_v4 is a no-op");
        check(withdraw_v6(r, v6, 32), "withdraw_v6 removes the v6 origination");
    }

    // Loc-RIB is empty again (both origins withdrawn above).
    int64_t n = lr_router_rib_len(r.get());
    check(n == 0, "rib_len == 0 after the withdraw lifecycle");

    // RIB dump of the now-empty Loc-RIB still succeeds (empty output).
    {
        auto out = std::make_unique<lr_bytes_t>();
        int rc = lr_router_rib_dump(r.get(), out.get());
        check(rc == 0, "rib_dump");
        check(lr_bytes_len(out.get()) == 0, "rib_dump empty after withdrawals");
        lr_bytes_free(out.get());
    }

    // Error path: feed_input with an unknown session must throw, and the
    // exception message must come from lr_last_error().
    bool err_threw = false;
    try {
        feed_input(r, 999, nullptr, 0);
    } catch (const Error& e) {
        err_threw = true;
        check(std::string(e.what()).find("feed_input") != std::string::npos,
              "Error message identifies the failing call");
    }
    check(err_threw, "feed_input on unknown handle throws");

    // ---- OSPF/OSPFv3/Babel session RAII wrappers (ROADMAP-v3 D5.1):
    // defaults, the ext knob set, the rejection matrix via exceptions. ----
    {
        auto oh = add_ospf_session(r, 0x0a000001u, 0);
        check(oh != 0, "add_ospf_session (RAII) defaults");
        auto oh3 = add_ospfv3_session(r, 0x0a000001u, 3);
        check(oh3 != 0, "add_ospfv3_session (RAII) defaults");

        auto ohx = add_ospf_session_ext(r, OspfVersion::V2, 0x0a000001u, 1,
                                        OspfAreaKind::NssaNoSummary, 1000, 1500,
                                        OspfNetType::Broadcast, true, 0x0a000101u,
                                        true, 0x0a000102u);
        check(ohx != 0, "add_ospf_session_ext (RAII) totally-NSSA + broadcast");

        bool threw = false;
        try {
            add_ospf_session(r, 0x0a000002u, 5);
        } catch (const Error& err) {
            threw = std::string(err.what()).find("add_ospf_session") != std::string::npos;
        }
        check(threw, "router-id mismatch throws");

        threw = false;
        try {
            add_ospf_session_ext(r, OspfVersion::V2, 0x0a000001u, 0,
                                 OspfAreaKind::Stub, 1000, 1500, OspfNetType::Ptp,
                                 false, 0, false, 0);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "backbone stub throws (RFC 2328 3.6)");

        threw = false;
        try {
            add_babel_session(r, {1, 2, 3});
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "babel rejects a 3-byte address");

        auto bh = add_babel_session(r, {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 1});
        check(bh != 0, "add_babel_session (RAII) v6");
        auto bh4 = add_babel_session(r, {192, 0, 2, 1});
        check(bh4 != 0, "add_babel_session (RAII) v4");
    }

    // ---- Policy objects RAII wrapper (ROADMAP-v3 D5.3): route
    // handle, prefix-list, resolver + route-map — the FRR flow. ----
    {
        auto rt = make_route_v4({203, 0, 113, 0}, 24, Protocol::Bgp);
        check(rt != nullptr, "make_route_v4 (RAII)");

        set_local_pref(rt, 250);
        check(local_pref(rt) == std::optional<std::uint32_t>(250),
              "local_pref (RAII) round trip");
        set_origin(rt, 0);
        check(origin(rt) == std::optional<std::uint8_t>(0), "origin (RAII)");
        set_as_path(rt, {64513, 65010, 64512});
        check(as_path(rt).size() == 3 && as_path(rt)[1] == 65010, "as_path (RAII)");
        set_communities(rt, {(64512ull << 16) | 100});
        check(communities(rt).size() == 1, "communities (RAII)");
        add_large_community(rt, 4200000000u, 7, 9);
        check(large_communities(rt).size() == 3, "large_communities (RAII)");
        add_ext_community(rt, 0x42, 0x02, 64512, 5);
        check(ext_communities(rt).size() == 1 && ext_communities(rt)[0].kind == 0x42,
              "ext_communities (RAII)");
        set_metric(rt, 42);
        check(metric(rt) == 42, "metric (RAII)");
        set_tag(rt, std::nullopt);
        check(!tag(rt).has_value(), "tag cleared (RAII)");

        auto pl = make_prefix_list();
        auto p8 = make_prefix({10, 0, 0, 0}, 8);
        prefix_list_add(pl, p8, 16, 24, true);
        auto inside = make_prefix({10, 1, 1, 0}, 24);
        check(prefix_list_match(pl, inside), "prefix_list_match (RAII) in-range");
        auto shorter = make_prefix({10, 0, 0, 0}, 8);
        check(!prefix_list_match(pl, shorter), "prefix_list_match (RAII) ge gate");

        auto res = make_resolver();
        // A 0.0.0.0/0 ge-0 le-32 permit list: matches everything.
        auto any4 = make_prefix_list();
        prefix_list_add(any4, make_prefix({10, 0, 0, 0}, 0), 0, 32, true);
        check(resolver_add_prefix_list(res, "all-v4", any4) == 0,
              "resolver_add_prefix_list (RAII)");

        auto map = make_route_map();
        route_map_add_entry(map,
                            {{LR_MATCH_PREFIX_IN, 0, 0}},
                            {{LR_SET_LOCAL_PREF, 0, {}, 300, 0}},
                            MapVerdict::Permit);
        auto verdict = route_map_evaluate(map, rt, &res);
        check(verdict == EvalVerdict::Permit, "route_map_evaluate (RAII) permits");
        check(local_pref(rt) == std::optional<std::uint32_t>(300),
              "route_map set applied (RAII)");

        auto empty = make_route_map();
        check(route_map_evaluate(empty, rt, &res) == EvalVerdict::Fallthrough,
              "empty map falls through (RAII)");

        // A NULL resolver fails the list-backed match (fail closed):
        // the permit-only entry falls through.
        auto nomatch = make_route_map();
        route_map_add_entry(nomatch, {{LR_MATCH_PREFIX_IN, 0, 0}}, {}, MapVerdict::Permit);
        check(route_map_evaluate(nomatch, rt, nullptr) == EvalVerdict::Fallthrough,
              "NULL resolver: match fails, falls through (RAII)");

        // An explicit deny entry with a matching list really denies.
        auto deny = make_route_map();
        route_map_add_entry(deny, {{LR_MATCH_PREFIX_IN, 0, 0}}, {}, MapVerdict::Deny);
        check(route_map_evaluate(deny, rt, &res) == EvalVerdict::Deny,
              "explicit deny via resolver (RAII)");

        bool threw = false;
        try {
            route_map_add_entry(map, {{99, 0, 0}}, {}, MapVerdict::Permit);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "unknown match kind throws (RAII)");
    }

    // ---- ROA store RAII wrapper (RFC 6482 / RFC 6811 / RFC 8210;
    // ROADMAP-v3 D2.3): static layer replace, RTR delta batch, the
    // three RFC 6811 §2 outcomes. ----
    {
        auto store = make_roa_store();
        check(lr_roa_store_len(store.get()) == 0, "roa store starts empty");

        lr_roa_entry_t e;
        std::memset(&e, 0, sizeof(e));
        e.addr[0] = 203; e.addr[1] = 0; e.addr[2] = 113; e.addr[3] = 0;
        e.is_ipv6 = 0;
        e.prefix_len = 24; e.max_length = 26; e.asn = 64512;
        roa_store_replace_static(store, {e});
        check(lr_roa_store_len(store.get()) == 1, "roa replace_static applies");

        std::uint8_t v4[4] = {203, 0, 113, 0};
        check(roa_store_validate(store, v4, nullptr, 24, 64512, true) == LR_ROA_VALID,
              "roa_validate (C++ RAII) valid origin");
        check(roa_store_validate(store, v4, nullptr, 27, 64512, true) == LR_ROA_INVALID,
              "roa_validate (C++ RAII) too-specific is invalid");
        check(roa_store_validate(store, v4, nullptr, 24, 64512, false) == LR_ROA_NOT_FOUND,
              "roa_validate (C++ RAII) no origin AS is not-found");

        // Error path: a malformed entry throws and identifies the call.
        bool threw = false;
        try {
            e.max_length = 4; /* < prefix_len (RFC 6482 §3.3) */
            roa_store_replace_static(store, {e});
        } catch (const Error& err) {
            threw = std::string(err.what()).find("replace_static") != std::string::npos;
        }
        check(threw, "malformed ROA entry throws with call identity");

        // RAII cleanup runs when the store leaves scope.
    }

    // Router goes out of scope — RAII cleanup runs.
    if (failures == 0) {
        std::printf("ALL PASS\n");
        return 0;
    }
    std::fprintf(stderr, "%d failures\n", failures);
    return 1;
}
