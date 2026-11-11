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

    // ---- Filter DSL RAII wrapper (ROADMAP-v3 D5.2): compile,
    // accept/reject + reason, ROA override through the callback
    // table, parse-error throwing. ----
    {
        auto f = make_filter("cpp-f", "if bgp.local_pref >= 200 then { accept; } else { reject with \"low\"; }");
        check(filter_name(f) == "cpp-f", "filter_name (RAII)");

        auto rt = make_route_v4({203, 0, 113, 0}, 24, Protocol::Bgp);
        set_local_pref(rt, 250);
        check(filter_evaluate(f, rt) == FilterVerdict::Accept,
              "filter accepts (RAII)");
        set_local_pref(rt, 100);
        std::string reason;
        check(filter_evaluate(f, rt, nullptr, &reason) == FilterVerdict::Reject &&
                  reason == "low",
              "filter rejects with reason (RAII)");

        // Parse errors throw.
        bool threw = false;
        try {
            make_filter("cpp-bad", "if bgp.local_pref = ");
        } catch (const Error& err) {
            threw = std::string(err.what()).find("cpp-bad") != std::string::npos;
        }
        check(threw, "filter parse error throws with name (RAII)");

        // ROA override via a C callback table.
        auto rf = make_filter("cpp-roa", "if roa.state == \"invalid\" then { reject; } accept;");
        check(filter_evaluate(rf, rt) == FilterVerdict::Accept,
              "built-in roa not-found accepts (RAII)");
        struct Ud { uint8_t state; } ud{LR_ROA_INVALID};
        lr_filter_context_t table{};
        table.user_data = &ud;
        table.roa_state = [](void* p, lr_route_t) -> uint8_t {
            return static_cast<Ud*>(p)->state;
        };
        check(filter_evaluate(rf, rt, &table) == FilterVerdict::Reject,
              "callback table overrides roa.state (RAII)");
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

    // ---- BGP message inspection (parsed-form readers): decode an
    // OPEN and read the variant fields; decode a NOTIFICATION and
    // read code/subcode/data; decode an UPDATE and walk NLRI. ----
    {
        // Encode then decode a 4-byte-AS OPEN — the FFI reader must
        // surface the real 32-bit AS (RFC 6793 §7 unwraps AS_TRANS).
        auto bytes = to_vec(encode_open(4'200'000'000, 180, {10, 0, 0, 1}, true));
        auto m = decode_bgp_message(bytes);
        check(message_kind(m) == BgpMessageKind::Open, "OPEN message kind");
        check(open_version(m) == 4, "OPEN version 4");
        check(open_my_as(m) == 4'200'000'000, "OPEN my_as unwraps AS_TRANS → 4-byte AS");
        check(open_hold_time(m) == 180, "OPEN hold time");
        auto id = open_bgp_id(m);
        check(id == std::array<std::uint8_t, 4>{10, 0, 0, 1}, "OPEN bgp_id");

        // Exactly one optional parameter: the capabilities TLV
        // holding the Four-Octet-AS capability (code 65, len 4).
        check(open_param_count(m) == 1, "OPEN has one optional parameter");
        auto p = open_param_at(m, 0);
        check(p.param_type == 2, "OPEN param type 2 (capabilities, RFC 5492)");
        check(p.value.size() >= 6, "OPEN capabilities payload has at least 6 bytes");
        check(p.value[0] == 65, "OPEN capability code 65 (Four-Octet-AS)");
        check(p.value[1] == 4, "OPEN capability length 4");
        std::uint32_t as_in_cap = (static_cast<std::uint32_t>(p.value[2]) << 24) |
                                  (static_cast<std::uint32_t>(p.value[3]) << 16) |
                                  (static_cast<std::uint32_t>(p.value[4]) << 8) |
                                  static_cast<std::uint32_t>(p.value[5]);
        check(as_in_cap == 4'200'000'000, "OPEN capability carries the real 4-byte AS");

        // Out-of-range param access throws.
        bool threw_oob = false;
        try { open_param_at(m, 99); } catch (const Error&) { threw_oob = true; }
        check(threw_oob, "OPEN out-of-range param throws");

        // Variant-mismatch reader throws (NOTIFICATION reader on an OPEN).
        bool threw_mismatch = false;
        try { notification_code(m); } catch (const Error&) { threw_mismatch = true; }
        check(threw_mismatch, "NOTIFICATION reader on OPEN throws");

        // NOTIFICATION with diagnostic data.
        auto notif = encode_notification(1, 2, {0xde, 0xad, 0xbe, 0xef});
        auto nm = decode_bgp_message(to_vec(notif));
        check(message_kind(nm) == BgpMessageKind::Notification, "NOTIFICATION message kind");
        check(notification_code(nm) == 1, "NOTIFICATION code 1 (Header)");
        check(notification_subcode(nm) == 2, "NOTIFICATION subcode 2 (Conn-Not-Sync)");
        auto nd = notification_data(nm);
        check(nd == std::vector<std::uint8_t>{0xde, 0xad, 0xbe, 0xef},
              "NOTIFICATION diagnostic data round-trips");

        // Withdraw-only UPDATE: two prefixes, zero attributes.
        std::vector<lr_prefix_t> prefixes = {
            make_prefix({203, 0, 113, 0}, 24),
            make_prefix({198, 51, 100, 0}, 25),
        };
        auto upd = encode_update_withdraw_v4(prefixes);
        auto um = decode_bgp_message(to_vec(upd));
        check(message_kind(um) == BgpMessageKind::Update, "UPDATE message kind");
        check(update_withdrawn_count(um) == 2, "UPDATE has 2 withdrawn routes");
        check(update_nlri_count(um) == 0, "UPDATE withdraw-only has no NLRI");
        check(update_attr_count(um) == 0, "UPDATE withdraw-only has 0 attributes");
        auto w0 = update_withdrawn_at(um, 0);
        check(std::memcmp(w0.addr, prefixes[0].addr, 4) == 0 && w0.prefix_len == 24,
              "UPDATE withdrawn[0] = 203.0.113.0/24");
        auto w1 = update_withdrawn_at(um, 1);
        check(std::memcmp(w1.addr, prefixes[1].addr, 4) == 0 && w1.prefix_len == 25,
              "UPDATE withdrawn[1] = 198.51.100.0/25");

        // KEEPALIVE — variant tag only, no fields to read.
        auto km = decode_bgp_message(to_vec(encode_keepalive()));
        check(message_kind(km) == BgpMessageKind::Keepalive, "KEEPALIVE message kind");

        // RAII cleanup runs when each BgpMessage leaves scope.
    }

    // ===== Structured inspection surface (issue #92) =====
    {
        auto r = make_router();

        // Fresh router: zero sessions, zero areas.
        check(session_count(r) == 0, "session_count: 0 on fresh router");
        check(session_summaries(r).empty(), "session_summaries: empty on fresh router");
        check(ospf_area_count(r) == 0, "ospf_area_count: 0 on fresh router");
        check(ospf_area_ids(r).empty(), "ospf_area_ids: empty on fresh router");

        // Adding one BGP session surfaces one summary.
        std::uint64_t h = add_bgp_session(r, 64512, 64513, 0x0a000001u);
        auto summaries = session_summaries(r);
        check(summaries.size() == 1, "session_summaries: 1 after BGP session");
        if (!summaries.empty()) {
            const auto& s = summaries[0];
            check(s.handle == h, "session_summaries: handle matches add_bgp_session return");
            check(s.kind == SessionKind::Bgp, "session_summaries: kind is Bgp");
            check(s.kind_text == "bgp", "session_summaries: kind_text is 'bgp'");
            check(s.local_as == 64512, "session_summaries: local_as");
            check(s.peer_as == 64513, "session_summaries: peer_as");
        }

        // Out-of-range index throws.
        bool threw = false;
        try {
            (void)session_summary_at(r, 99);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "session_summary_at: out-of-range throws Error");

        // bgp_session_identity_hash returns a u64 (no exceptions).
        std::uint64_t hash = bgp_session_identity_hash(r);
        check(hash <= 0xFFFFFFFFFFFFFFFFULL, "bgp_session_identity_hash: fits in u64");

        // OSPF area IDs: fresh router has zero; unknown area raises.
        check(ospf_area_ids(r).empty(), "ospf_area_ids: still empty after BGP session");
        threw = false;
        try {
            (void)ospf_area_topology_version(r, 99);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "ospf_area_topology_version: unknown area throws Error");

        threw = false;
        try {
            (void)ospf_area_lsa(r, 0, 1, 1, 1);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "ospf_area_lsa: unknown LSA throws Error");

        // drain_ospf_grace_events returns an empty vector on a fresh
        // router — no events pending.
        auto gr_events = drain_ospf_grace_events(r);
        check(gr_events.empty(), "drain_ospf_grace_events: empty on fresh router");
    }

    // ---- RouterInstance session-state + Babel runtime (issue #92) ----
    {
        auto r = make_router();

        // BGP session: handle-keyed state inspection.
        auto h = add_bgp_session(r, 65001, 65002, 0x01020304);
        auto state = session_peer_state(r, h);
        check(state.has_value(), "session_peer_state: BGP returns a state");
        check(*state == "Idle" || *state == "Connect" || *state == "Active" ||
                  *state == "OpenSent" || *state == "OpenConfirm" ||
                  *state == "Established",
              "session_peer_state: valid FSM state name");
        check(!session_was_established(r, h),
              "session_was_established: false on a fresh session");
        check(!take_collision_lost(r, h),
              "take_collision_lost: false on a fresh session");
        auto cooldown = session_restart_cooldown_remaining(r, h);
        check(!cooldown.has_value(),
              "session_restart_cooldown_remaining: nullopt on fresh session");

        // rib_paths_count starts at zero on a fresh router.
        check(rib_paths_count(r) == 0, "rib_paths_count: 0 on fresh router");

        // rib_path_at on an empty Loc-RIB throws Error.
        bool threw = false;
        try {
            (void)rib_path_at(r, 0);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "rib_path_at: throws on out-of-range index");

        // Originate one route — the Add-Path view should report 1
        // path, and rib_path_at(0) should return a non-null Route.
        std::array<std::uint8_t, 4> pfx{10, 0, 0, 1};
        check(0 == lr_router_originate_v4(r.get(), pfx.data(), 24, nullptr),
              "lr_router_originate_v4 OK");
        check(rib_paths_count(r) == 1, "rib_paths_count: 1 after originate");
        auto route = rib_path_at(r, 0);
        check(route != nullptr, "rib_path_at(0): non-null Route");

        // Flush the Loc-RIB — the shutdown hook RFC 4271 leaves to
        // the implementor. Idempotent: a second call sees an empty
        // Loc-RIB and queues nothing.
        flush_rib_for_shutdown(r);
        flush_rib_for_shutdown(r);

        // Babel session: babel_reachable / babel_flush / babel_gc /
        // babel_egress_nexthops / etc.
        std::vector<std::uint8_t> v6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 1};
        auto hb = add_babel_session(r, v6);
        babel_gc(r, 1000);
        babel_flush_session(r, hb);

        // set_babel_own_router_id with an 8-byte router-id.
        std::array<std::uint8_t, 8> id{1, 2, 3, 4, 5, 6, 7, 8};
        set_babel_own_router_id(r, hb, id);

        // set_babel_link_cost_params.
        set_babel_link_cost_params(r, hb, 1000, 100000, 96);

        // babel_rtt_us / babel_rtt_echo_pair return nullopt on a
        // fresh session (no RTT sample yet).
        check(!babel_rtt_us(r, hb, 0).has_value(),
              "babel_rtt_us: nullopt on fresh session");
        check(!babel_rtt_echo_pair(r, hb, 0).has_value(),
              "babel_rtt_echo_pair: nullopt on fresh session");

        // babel_egress_nexthops returns a non-nullopt pair for a
        // Babel session. The session was constructed with a v6 local
        // address (fe80::1), and the BabelNeighbor initial address
        // is the local address — so before any peer is noted, the
        // v6 next hop is the local v6 (peer-address fallback per
        // RFC 8966 §3.5.3) and the v4 next hop is None.
        auto nexthops = babel_egress_nexthops(r, hb);
        check(nexthops.has_value(),
              "babel_egress_nexthops: Babel session returns a value");
        check(!nexthops->first.has_value(),
              "babel_egress_nexthops: v4 absent before note_peer");
        check(nexthops->second.has_value(),
              "babel_egress_nexthops: v6 = local address");
        const auto& v6_nexthop = *nexthops->second;
        check(std::equal(v6_nexthop.begin(), v6_nexthop.end(), v6.begin()),
              "babel_egress_nexthops: v6 == local");

        // babel_take_route_request / babel_take_own_seqno_request
        // are false / nullopt on a fresh session.
        check(!babel_take_route_request(r, hb),
              "babel_take_route_request: false on fresh session");
        check(!babel_take_own_seqno_request(r, hb).has_value(),
              "babel_take_own_seqno_request: nullopt on fresh session");

        // babel_egress_nexthops on a non-Babel session returns
        // nullopt (the C ABI's "no info" return code).
        auto nexthops_bgp = babel_egress_nexthops(r, h);
        check(!nexthops_bgp.has_value(),
              "babel_egress_nexthops: nullopt on non-Babel session");

        // babel_note_peer with a v4 address. After this, the v4
        // next hop is the noted peer (peer_v4 = Some(peer)), and the
        // v6 next hop falls back to None (the noted peer is v4, so
        // peer_v6 = None).
        std::vector<std::uint8_t> v4 = {192, 0, 2, 100};
        babel_note_peer(r, hb, v4);
        auto nexthops_after = babel_egress_nexthops(r, hb);
        check(nexthops_after.has_value(),
              "babel_egress_nexthops: still returns a value after note_peer");
        check(nexthops_after->first.has_value(),
              "babel_egress_nexthops: v4 present after noting v4 peer");
        const auto& v4_nexthop = *nexthops_after->first;
        check(std::equal(v4_nexthop.begin(), v4_nexthop.end(), v4.begin()),
              "babel_egress_nexthops: v4 == noted peer");
        check(!nexthops_after->second.has_value(),
              "babel_egress_nexthops: v6 absent after noting v4 peer");

        // babel_note_peer with a bad length throws Error.
        threw = false;
        try {
            babel_note_peer(r, hb, std::vector<std::uint8_t>{1, 2, 3});
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "babel_note_peer: throws on bad address length");
    }

    // ---- MPLS Label / LabelStack (RFC 3032 §2.1, RFC 8277 §2.2/§2.3) ----
    {
        auto l = make_label(100);
        check(label_value(l) == 100, "label_value(100)");
        check(label_tc(l) == 0, "label_tc defaults to 0");
        check(label_ttl(l) == 64, "label_ttl defaults to 64");
        check(!label_is_reserved(l), "label 100 is not reserved");

        auto r0 = make_label(0);
        check(label_is_reserved(r0), "label 0 is reserved");

        bool threw = false;
        try {
            make_label_checked(0x100000);  // 1 << 20 = MAX + 1
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "make_label_checked rejects oversize value");

        // with_tc / with_ttl chain (consumes the receiver).
        auto l2 = make_label(0xFFFFF);
        l2 = label_with_tc(l2, 7);
        l2 = label_with_ttl(l2, 255);
        check(label_tc(l2) == 7, "label_with_tc(7)");
        check(label_ttl(l2) == 255, "label_with_ttl(255)");

        auto l3 = make_label(16);
        l3 = label_with_tc(l3, 0xFF);
        check(label_tc(l3) == 0x07, "label_with_tc masks high bits");

        // encode_3octet / encode_4octet on label 100 (TC=0, TTL=64).
        auto l4 = make_label(100);
        l4 = label_with_tc(l4, 0);
        l4 = label_with_ttl(l4, 64);
        auto e3 = label_encode_3octet(l4, true);
        check(e3.size() == 3, "label_encode_3octet returns 3 bytes");
        check(e3[0] == 0x00 && e3[1] == 0x06 && e3[2] == 0x41,
              "label_encode_3octet(100, bottom) = 00 06 41");
        auto e4 = label_encode_4octet(l4, true);
        check(e4.size() == 4, "label_encode_4octet returns 4 bytes");
        check(e4[0] == 0x00 && e4[1] == 0x06 && e4[2] == 0x41 && e4[3] == 0x40,
              "label_encode_4octet(100, bottom) = 00 06 41 40");

        // Stack from values — round-trip through 4-octet wire form.
        auto s = make_label_stack_from_values({16, 240, 1048575});
        check(label_stack_len(s) == 3, "label_stack_len = 3");
        check(!label_stack_is_empty(s), "label_stack not empty");
        auto mid = label_stack_at(s, 1);
        check(mid.value == 240, "label_stack_at(1).value = 240");

        auto enc = label_stack_encode_4octet(s);
        check(lr_bytes_len(enc.get()) == 12, "label_stack_encode_4octet = 12 bytes");

        auto dec = decode_label_stack_4octet(lr_bytes_ptr(enc.get()), lr_bytes_len(enc.get()));
        check(label_stack_len(dec) == 3, "decoded label_stack_len = 3");
        auto last = label_stack_at(dec, 2);
        check(last.value == 1048575, "decoded At(2).value = 1048575");

        // Stack from labels — round-trip through 3-octet NLRI form.
        std::vector<MplsLabelSpec> specs = {
            {16, 0, 0},
            {240, 0, 0},
        };
        auto s2 = make_label_stack_from_labels(specs);
        auto enc2 = label_stack_encode_3octet(s2);
        check(lr_bytes_len(enc2.get()) == 6, "label_stack_encode_3octet = 6 bytes");
        auto dec2 = decode_label_stack_3octet(lr_bytes_ptr(enc2.get()), lr_bytes_len(enc2.get()));
        check(label_stack_len(dec2) == 2, "decoded 3-octet label_stack_len = 2");

        // push / pop semantics.
        auto s3 = make_label_stack();
        auto top = make_label(100);
        label_stack_push(s3, top);
        auto bot = make_label(200);
        label_stack_push_bottom(s3, bot);
        check(label_stack_len(s3) == 2, "after push: len = 2");
        check(label_stack_at(s3, 0).value == 100, "top is 100");

        check(label_stack_pop(s3), "pop top returns true");
        check(label_stack_len(s3) == 1, "after pop: len = 1");
        check(label_stack_at(s3, 0).value == 200, "bottom is now at 0");

        check(label_stack_pop(s3), "pop bottom returns true");
        check(label_stack_is_empty(s3), "after 2 pops: empty");
        check(!label_stack_pop(s3), "pop on empty stack returns false");

        // At() out of range throws.
        threw = false;
        try {
            (void)label_stack_at(s3, 0);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "label_stack_at out-of-range throws");

        // decode_4octet rejects uneven-length input.
        threw = false;
        try {
            (void)decode_label_stack_4octet(std::vector<std::uint8_t>{0, 1, 2});
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "decode_label_stack_4octet rejects uneven length");

        // label_stack_labels returns all specs.
        auto s4 = make_label_stack_from_values({16, 240, 1048575});
        auto all = label_stack_labels(s4);
        check(all.size() == 3, "label_stack_labels returns 3 specs");
        check(all[2].value == 1048575, "label_stack_labels[2].value = 1048575");
    }

    // ---- BFD Control packet (RFC 5880 §4.1) ----
    {
        auto p = make_bfd_packet();
        check(bfd_packet_version(p) == 1, "bfd_packet_version = 1");
        check(bfd_packet_state(p) == bfd_state::kDown, "default state = Down");
        check(bfd_packet_detect_mult(p) == 3, "default detect_mult = 3");
        check(bfd_packet_desired_min_tx_interval(p) == 1'000'000, "default tx_interval = 1s");
        check(bfd_packet_length(p) == 24, "default length = 24");

        auto hb = make_bfd_heartbeat(0xDEADBEEF, 0xCAFEBABE);
        check(bfd_packet_state(hb) == bfd_state::kUp, "heartbeat state = Up");
        check(bfd_packet_my_discriminator(hb) == 0xDEADBEEF, "heartbeat my_disc");
        check(bfd_packet_your_discriminator(hb) == 0xCAFEBABE, "heartbeat your_disc");

        // Setters.
        bfd_packet_set_diag(p, bfd_diag::kCtrlExpired);
        bfd_packet_set_state(p, bfd_state::kUp);
        bfd_packet_set_flags(p, 0x20);  // Poll bit
        bfd_packet_set_detect_mult(p, 5);
        bfd_packet_set_my_discriminator(p, 0xAABBCCDD);
        check(bfd_packet_diag(p) == bfd_diag::kCtrlExpired, "set_diag");
        check(bfd_packet_state(p) == bfd_state::kUp, "set_state");
        check(bfd_packet_flags(p) == 0x20, "set_flags");
        check(bfd_packet_detect_mult(p) == 5, "set_detect_mult");
        check(bfd_packet_my_discriminator(p) == 0xAABBCCDD, "set_my_disc");

        // SetState clamps invalid values.
        bfd_packet_set_state(p, 99);
        check(bfd_packet_state(p) == bfd_state::kAdminDown, "invalid state clamps to AdminDown");

        // SetFlags masks reserved bits.
        bfd_packet_set_flags(p, 0xFF);
        check(bfd_packet_flags(p) == 0x3f, "reserved flag bits masked");

        // Encode/decode roundtrip.
        auto hb2 = make_bfd_heartbeat(0xDEADBEEF, 0xCAFEBABE);
        auto enc = bfd_packet_encode(hb2);
        check(lr_bytes_len(enc.get()) == 24, "encoded length = 24");
        auto dec = decode_bfd_packet(lr_bytes_ptr(enc.get()), lr_bytes_len(enc.get()));
        check(bfd_packet_state(dec) == bfd_state::kUp, "decoded state = Up");
        check(bfd_packet_my_discriminator(dec) == 0xDEADBEEF, "decoded my_disc");
        check(bfd_packet_your_discriminator(dec) == 0xCAFEBABE, "decoded your_disc");
    }

    // ---- BFD AuthType readers (RFC 5880 §8 IANA codes) ----
    {
        check(bfd_auth_type_expected_digest_len(bfd_auth_type::kKeyedMd5) == 16,
              "MD5 expected digest length = 16");
        check(bfd_auth_type_expected_digest_len(bfd_auth_type::kKeyedSha1) == 20,
              "SHA1 expected digest length = 20");
        check(bfd_auth_type_expected_digest_len(bfd_auth_type::kMeticulousKeyedMd5) == 16,
              "Meticulous MD5 expected digest length = 16");
        check(bfd_auth_type_expected_digest_len(bfd_auth_type::kMeticulousKeyedSha1) == 20,
              "Meticulous SHA1 expected digest length = 20");
        check(bfd_auth_type_expected_digest_len(bfd_auth_type::kSimplePassword) == -1,
              "Simple Password has no fixed digest length");
        check(bfd_auth_type_expected_digest_len(99) == -1,
              "Unknown type has no fixed digest length");
        check(bfd_auth_type_is_keyed_hash(bfd_auth_type::kKeyedMd5), "MD5 is keyed-hash");
        check(!bfd_auth_type_is_keyed_hash(bfd_auth_type::kSimplePassword),
              "Simple Password is not keyed-hash");
        check(bfd_auth_type_is_meticulous(bfd_auth_type::kMeticulousKeyedMd5),
              "Meticulous MD5 is meticulous");
        check(!bfd_auth_type_is_meticulous(bfd_auth_type::kKeyedMd5),
              "Plain Keyed MD5 is not meticulous");
    }

    // ---- BFD AuthKey lifecycle ----
    {
        std::vector<std::uint8_t> secret(16, 0);
        for (std::size_t i = 0; i < 16; ++i) secret[i] = static_cast<std::uint8_t>('0' + i);
        auto k = make_bfd_auth_key(7, secret);
        check(bfd_auth_key_key_id(k) == 7, "AuthKey key_id = 7");
        check(bfd_auth_key_data_len(k) == 16, "AuthKey data_len = 16");
        auto data = bfd_auth_key_data(k);
        check(data.size() == 16, "AuthKey data out_len = 16");
        check(data == secret, "AuthKey data round-trips");

        // simple_password constructor
        std::vector<std::uint8_t> pw{'h', 'u', 'n', 't', 'e', 'r', '2'};
        auto sk = make_bfd_auth_key_simple_password(3, pw);
        check(bfd_auth_key_key_id(sk) == 3, "Simple Password key_id = 3");
        check(bfd_auth_key_data_len(sk) == 7, "Simple Password data_len = 7");
    }

    // ---- BFD AuthSection lifecycle ----
    {
        // Simple Password
        std::vector<std::uint8_t> pw{'h', 'u', 'n', 't', 'e', 'r', '2'};
        auto s = make_bfd_auth_section_simple_password(pw, 7);
        check(bfd_auth_section_auth_type(s) == bfd_auth_type::kSimplePassword,
              "Simple Password auth_type = 1");
        check(bfd_auth_section_key_id(s) == 7, "Simple Password key_id = 7");
        check(!bfd_auth_section_sequence(s).has_value(),
              "Simple Password has no sequence");
        check(bfd_auth_section_data_len(s) == 7, "Simple Password data_len = 7");
        check(bfd_auth_section_wire_len(s) == 3 + 7, "Simple Password wire_len = 10");
        auto data = bfd_auth_section_data(s);
        check(data == pw, "Simple Password data round-trips");

        // Keyed MD5
        std::vector<std::uint8_t> digest16(16, 0);
        auto md5 = make_bfd_auth_section_keyed_md5(2, 0xDEADBEEF, digest16);
        check(bfd_auth_section_auth_type(md5) == bfd_auth_type::kKeyedMd5,
              "Keyed MD5 auth_type = 2");
        check(bfd_auth_section_key_id(md5) == 2, "Keyed MD5 key_id = 2");
        check(bfd_auth_section_sequence(md5).has_value(), "Keyed MD5 has sequence");
        check(bfd_auth_section_sequence(md5).value() == 0xDEADBEEF,
              "Keyed MD5 seq = 0xDEADBEEF");
        check(bfd_auth_section_data_len(md5) == 16, "Keyed MD5 data_len = 16");
        check(bfd_auth_section_wire_len(md5) == 24, "Keyed MD5 wire_len = 24");

        // Keyed SHA1
        std::vector<std::uint8_t> digest20(20, 0);
        auto sha1 = make_bfd_auth_section_keyed_sha1(4, 0xFEEDFACE, digest20);
        check(bfd_auth_section_auth_type(sha1) == bfd_auth_type::kKeyedSha1,
              "Keyed SHA1 auth_type = 4");
        check(bfd_auth_section_wire_len(sha1) == 28, "Keyed SHA1 wire_len = 28");

        // Meticulous variants
        auto mmd5 = make_bfd_auth_section_meticulous_keyed_md5(3, 42, digest16);
        check(bfd_auth_section_auth_type(mmd5) == bfd_auth_type::kMeticulousKeyedMd5,
              "Meticulous Keyed MD5 auth_type = 3");
        auto msha1 = make_bfd_auth_section_meticulous_keyed_sha1(5, 42, digest20);
        check(bfd_auth_section_auth_type(msha1) == bfd_auth_type::kMeticulousKeyedSha1,
              "Meticulous Keyed SHA1 auth_type = 5");
    }

    // ---- BfdPacket auth integration ----
    {
        auto p = make_bfd_packet();
        check(!bfd_packet_auth_present(p), "fresh packet has no auth");
        check(!bfd_packet_auth(p).has_value(), "auth returns nullopt when no auth attached");

        // Install a Simple Password section
        std::vector<std::uint8_t> pw{'h', 'u', 'n', 't', 'e', 'r', '2'};
        auto s = make_bfd_auth_section_simple_password(pw, 7);
        bfd_packet_set_auth(p, std::move(s));
        check(bfd_packet_auth_present(p), "packet now carries auth");

        // Read it back
        auto sec_out = bfd_packet_auth(p);
        check(sec_out.has_value(), "auth returns a value when attached");
        check(bfd_auth_section_auth_type(*sec_out) == bfd_auth_type::kSimplePassword,
              "read-back auth_type = Simple Password");
        check(bfd_auth_section_key_id(*sec_out) == 7, "read-back key_id = 7");
        check(bfd_auth_section_data_len(*sec_out) == 7, "read-back data_len = 7");

        // Clear via a NULL handle (default-constructed BfdAuthSection).
        BfdAuthSection null_section;
        bfd_packet_set_auth(p, std::move(null_section));
        check(!bfd_packet_auth_present(p), "auth now absent");
    }

    // ---- BfdKeyedAuth auth_section_for_tx / sign / verify ----
    {
        std::vector<std::uint8_t> secret(16, 0);
        for (std::size_t i = 0; i < 16; ++i) secret[i] = static_cast<std::uint8_t>('0' + i);
        auto a = make_bfd_keyed_auth(bfd_auth_algo::kKeyedMd5, 7, secret);
        check(bfd_keyed_auth_xmit_seq(a) == 0, "fresh xmit_seq = 0");
        check(bfd_keyed_auth_key_id(a) == 7, "key_id = 7");
        check(bfd_keyed_auth_digest_len(a) == 16, "digest_len = 16");
        check(!bfd_keyed_auth_is_meticulous(a), "KeyedMd5 is not meticulous");

        // auth_section_for_tx: returns the wire auth section with the
        // shared key in the digest field.
        auto sec = bfd_keyed_auth_auth_section_for_tx(a);
        check(bfd_auth_section_auth_type(sec) == bfd_auth_type::kKeyedMd5,
              "auth_section_for_tx auth_type = Keyed MD5");
        check(bfd_auth_section_key_id(sec) == 7, "auth_section_for_tx key_id = 7");
        check(bfd_auth_section_sequence(sec).has_value(), "auth_section_for_tx has seq");
        check(bfd_auth_section_sequence(sec).value() == 0,
              "auth_section_for_tx seq = 0 (xmit_seq before any advance)");
        check(bfd_auth_section_data_len(sec) == 16,
              "auth_section_for_tx data_len = 16 (MD5 digest field)");
        auto data = bfd_auth_section_data(sec);
        check(data == secret, "auth_section_for_tx carries shared key in digest field");

        // advance_xmit_seq bumps the counter.
        bfd_keyed_auth_advance_xmit_seq(a);
        check(bfd_keyed_auth_xmit_seq(a) == 1, "xmit_seq = 1 after advance");
    }

    // ---- SRv6 structured types (RFC 8754 / RFC 8986) ----
    {
        // Sid parse + render roundtrip.
        auto sid = parse_srv6_sid("fcbb:bb00:0:0:0:0:0:1");
        check(srv6_sid_to_string(sid) == "fcbb:bb00::1",
              "Sid::from_str renders canonical RFC 5952 §4 form");
        // Sid::from_octets roundtrip.
        std::array<std::uint8_t, 16> oct{};
        for (std::size_t i = 0; i < 16; ++i) oct[i] = static_cast<std::uint8_t>(i);
        auto sid2 = make_srv6_sid(oct);
        auto got = srv6_sid_octets(sid2);
        check(got == oct, "Sid::from_octets round-trips 16 bytes");

        // Sid::is_unspecified.
        auto unspec = make_srv6_sid_unspecified();
        check(srv6_sid_is_unspecified(unspec), "all-zeros SID is unspecified");
        check(!srv6_sid_is_unspecified(sid), "non-zero SID is not unspecified");

        // Sid::locator_slice.
        auto sl = srv6_sid_locator_slice(sid, 32);
        check(sl.has_value(), "locator_slice(32) succeeds on a /32 boundary");
        check(sl->first == 0 && sl->second == 4, "locator_slice(32) = (0, 4)");
        check(!srv6_sid_locator_slice(sid, 33).has_value(),
              "locator_slice(33) fails (not multiple of 8)");

        // Sid::is_inside_locator.
        std::vector<std::uint8_t> loc_bytes{0xFC, 0xBB, 0xBB, 0x00};
        check(srv6_sid_is_inside_locator(sid, loc_bytes, 32),
              "Sid falls inside fcbb:bb00::/32");
        std::vector<std::uint8_t> other_bytes{0xFC, 0xBB, 0xBB, 0x01};
        check(!srv6_sid_is_inside_locator(sid, other_bytes, 32),
              "Sid does NOT fall inside fcbb:bb01::/32");

        // Sid::from_locator_tail.
        std::vector<std::uint8_t> tail(12, 0);
        auto sid3 = make_srv6_sid_from_locator_tail(loc_bytes, tail, 32);
        auto sid3_octets = srv6_sid_octets(sid3);
        check(sid3_octets[0] == 0xFC && sid3_octets[3] == 0x00,
              "Sid::from_locator_tail copies locator bytes");
        check(srv6_sid_is_inside_locator(sid3, loc_bytes, 32),
              "Sid::from_locator_tail is inside its own locator");

        // Sid parse error variants.
        bool threw_empty = false;
        try { parse_srv6_sid(""); }
        catch (const Srv6SidParseException& e) {
            threw_empty = e.code() == Srv6SidParseError::Empty;
        }
        check(threw_empty, "Sid::from_str(\"\") raises Empty");

        bool threw_double_colon = false;
        try { parse_srv6_sid("1::2::3"); }
        catch (const Srv6SidParseException& e) {
            threw_double_colon = e.code() == Srv6SidParseError::DoubleDoubleColon;
        }
        check(threw_double_colon, "Sid::from_str(\"1::2::3\") raises DoubleDoubleColon");

        bool threw_bad_hextet = false;
        try { parse_srv6_sid("1:2:3:4:5:6:7:8g"); }
        catch (const Srv6SidParseException& e) {
            threw_bad_hextet = e.code() == Srv6SidParseError::BadHextet;
        }
        check(threw_bad_hextet, "Sid::from_str(\"1:2:3:4:5:6:7:8g\") raises BadHextet");

        bool threw_wrong_length = false;
        try { parse_srv6_sid("1:2:3:4:5:6:7"); }
        catch (const Srv6SidParseException& e) {
            threw_wrong_length = e.code() == Srv6SidParseError::WrongLength;
        }
        check(threw_wrong_length, "Sid::from_str(\"1:2:3:4:5:6:7\") raises WrongLength");

        // Locator parse + render roundtrip.
        auto loc = parse_srv6_locator("fcbb:bb00::/48");
        check(srv6_locator_block_bits(loc) == 48, "Locator block_bits = 48");
        check(srv6_locator_to_string(loc) == "fcbb:bb00::/48",
              "Locator renders canonical RFC 5952 + /prefix form");

        // Locator::from_sid.
        auto loc2 = make_srv6_locator_from_sid(sid, 32);
        check(srv6_locator_block_bits(loc2) == 32, "from_sid preserves block_bits");

        // Locator::contains_sid.
        check(srv6_locator_contains_sid(loc, sid),
              "Locator contains its own SID");
        auto other_sid = parse_srv6_sid("2001:db8::1");
        check(!srv6_locator_contains_sid(loc, other_sid),
              "Locator does NOT contain a SID outside it");

        // Locator::sid_with_tail.
        // loc is /48 (block_bytes=6), so the tail's first 6 bytes are
        // overwritten by the locator. Put the meaningful byte at index 6.
        std::array<std::uint8_t, 16> tail16{};
        tail16[6] = 0xE1;
        auto sid4 = srv6_locator_sid_with_tail(loc, tail16);
        auto sid4_octets = srv6_sid_octets(sid4);
        check(sid4_octets[0] == 0xFC && sid4_octets[3] == 0x00,
              "sid_with_tail copies the locator prefix");
        check(sid4_octets[6] == 0xE1, "sid_with_tail preserves the tail FUNCT byte");

        // Locator::sid_with_index.
        auto sid5 = srv6_locator_sid_with_index(loc, 42);
        check(static_cast<bool>(sid5), "sid_with_index(42) on /48 returns a SID");
        if (sid5) {
            auto sid5_octets = srv6_sid_octets(sid5);
            // Locator block_bytes = 6 for /48, so function index (4 BE
            // bytes) lands at octets[6..10]. 42 = 0x2A → byte 9.
            check(sid5_octets[6] == 0 && sid5_octets[9] == 42,
                  "sid_with_index places the function index in big-endian bytes 6..10");
        }

        // Locator::sid_with_index returns nullptr when no room.
        auto loc_short = make_srv6_locator(std::array<std::uint8_t, 16>{}, 120);
        auto sid6 = srv6_locator_sid_with_index(loc_short, 42);
        check(!static_cast<bool>(sid6),
              "sid_with_index returns nullptr when locator leaves no room");

        // Locator parse errors.
        bool threw_missing_prefix = false;
        try { parse_srv6_locator("fcbb:bb00::"); }
        catch (const Srv6LocatorParseException& e) {
            threw_missing_prefix = e.code() == Srv6LocatorParseError::MissingPrefixLen;
        }
        check(threw_missing_prefix,
              "Locator::from_str(\"fcbb:bb00::\") raises MissingPrefixLen");

        bool threw_bad_prefix = false;
        try { parse_srv6_locator("fcbb:bb00::/999"); }
        catch (const Srv6LocatorParseException& e) {
            threw_bad_prefix = e.code() == Srv6LocatorParseError::BadPrefixLen;
        }
        check(threw_bad_prefix,
              "Locator::from_str(\"fcbb:bb00::/999\") raises BadPrefixLen");

        // Srh construction + accessors.
        auto seg1 = parse_srv6_sid("fcbb:bb00::1");
        auto seg1_octets = srv6_sid_octets(seg1);
        auto seg2 = parse_srv6_sid("fcbb:bb00::2");
        auto seg2_octets = srv6_sid_octets(seg2);
        std::vector<std::array<std::uint8_t, 16>> segs = {seg1_octets, seg2_octets};
        auto srh = make_srv6_srh(segs);
        check(srv6_srh_segment_count(srh) == 2, "SRH carries 2 segments");
        check(srv6_srh_last_entry(srh) == 1, "SRH last_entry = 1");
        check(srv6_srh_segments_left(srh) == 1, "SRH segments_left defaults to last_entry");

        // Builder-style setters.
        srv6_srh_set_next_header(srh, 59);
        srv6_srh_set_flags(srh, 0x20);  // SRv6FlagOAM
        srv6_srh_set_tag(srh, 0x1234);
        check(srv6_srh_next_header(srh) == 59, "SRH next_header = 59");
        check(srv6_srh_flags(srh) == 0x20, "SRH flags = 0x20 (OAM)");
        check(srv6_srh_tag(srh) == 0x1234, "SRH tag = 0x1234");

        // first_segment / current_destination.
        check(srv6_srh_first_segment(srh) == seg1_octets,
              "SRH first_segment = Segment List[0]");
        check(srv6_srh_current_destination(srh) == seg2_octets,
              "SRH current_destination = Segment List[Segments Left]");

        // Encode produces a 40-byte SRH (8 + 2 * 16).
        auto wire = srv6_srh_encode(srh);
        check(lr_bytes_len(wire.get()) == 40, "SRH encode = 40 bytes");

        // Srh with explicit segments_left.
        auto srh2 = make_srv6_srh_with_segments_left(segs, 0);
        check(srv6_srh_segments_left(srh2) == 0, "explicit segments_left = 0");

        // Srh empty list error.
        bool threw_empty_srh = false;
        try { make_srv6_srh({}); }
        catch (const Srv6SrhErrorException& e) {
            threw_empty_srh = e.code() == Srv6SrhError::EmptySegmentList;
        }
        check(threw_empty_srh, "make_srv6_srh({}) raises EmptySegmentList");

        // Behavior registry.
        auto end_bh = srv6_behavior_from_wire(0x0001);
        check(end_bh.has_value(), "Behavior::from_wire(0x0001) succeeds");
        if (end_bh) check(end_bh->second == "End", "End behavior name = \"End\"");
        check(srv6_behavior_name(0x0005) == "End.X", "Behavior::name(0x0005) = \"End.X\"");
        check(!srv6_behavior_from_wire(0xFFFF).has_value(),
              "Behavior::from_wire(0xFFFF) returns nullopt");
        check(srv6_behavior_is_cross_connect(0x0005),
              "End.X (0x0005) is a cross-connect behavior");
    }

    // ===== lr-ospf: retransmit list / LSDB / LSA / external dest =====
    {
        // Retransmit list — empty, record, contains, remove, clear,
        // apply-acks (incl. stray-ack silent acceptance), poll timing.
        OspfRetransmitList rtx;
        check(rtx.empty(), "OspfRetransmitList starts empty");
        check(rtx.size() == 0, "OspfRetransmitList size = 0");

        auto lsa = OspfLsaHandle::make(OspfLsaHeader{
            0, 0, 1, 0xa, 0xa, 0x80000001, 0, 20});
        rtx.record_flood(std::move(lsa), 0);
        check(rtx.size() == 1, "after RecordFlood size = 1");
        check(rtx.contains({1, 0xa, 0xa}), "Contains(0xa/0xa) = true");
        check(!rtx.contains({1, 0xb, 0xa}), "Contains(0xb/0xa) = false");

        check(rtx.remove({1, 0xa, 0xa}), "Remove(0xa/0xa) = true");
        check(rtx.size() == 0, "after Remove size = 0");

        // Re-add and test Clear.
        rtx.record_flood(OspfLsaHandle::make(OspfLsaHeader{
            0, 0, 1, 1, 0xa, 0x80000001, 0, 20}), 0);
        rtx.record_flood(OspfLsaHandle::make(OspfLsaHeader{
            0, 0, 1, 2, 0xa, 0x80000001, 0, 20}), 0);
        check(rtx.size() == 2, "after 2 record_floods size = 2");
        rtx.clear();
        check(rtx.empty(), "after Clear empty = true");

        // Apply-acks key-match drain.
        rtx.record_flood(OspfLsaHandle::make(OspfLsaHeader{
            0, 0, 1, 0xa, 0xa, 0x80000001, 0, 20}), 0);
        rtx.record_flood(OspfLsaHandle::make(OspfLsaHeader{
            0, 0, 1, 0xb, 0xa, 0x80000001, 0, 20}), 0);
        std::vector<OspfLsaHeader> acks = {
            {0, 0, 1, 0xa, 0xa, 1, 0, 20},
        };
        check(rtx.apply_acks(acks) == 1, "ApplyAcks removes 1 entry");
        check(rtx.size() == 1, "after ApplyAcks size = 1");
        check(rtx.contains({1, 0xb, 0xa}),
              "ApplyAcks(0xa) leaves 0xb intact");

        // Stray ack — §13.7 step 5 silent acceptance.
        std::vector<OspfLsaHeader> stray = {
            {0, 0, 1, 0xdead, 0xbeef, 1, 0, 20},
        };
        check(rtx.apply_acks(stray) == 0, "stray ack removes 0 entries");
        check(rtx.size() == 1, "after stray ack size = 1");

        // Poll timing — at RxmtInterval the LSA retransmits.
        rtx.clear();
        rtx.record_flood(OspfLsaHandle::make(OspfLsaHeader{
            0, 0, 1, 0xa, 0xa, 0x80000001, 0, 20}), 1000);
        auto before = rtx.poll(1500, 5000);
        check(before.empty(), "Poll at 1.5s returns empty");
        auto at = rtx.poll(6000, 5000);
        check(at.size() == 1, "Poll at 6s returns 1 LSA");
        if (at.size() == 1) {
            auto borrowed = at.at(0);
            check(borrowed.key().link_state_id == 0xa,
                  "Poll returns the right LSA");
        }
        auto after = rtx.poll(10999, 5000);
        check(after.empty(),
              "Poll at 10.999s returns empty (last_sent_ms was bumped)");

        // LSDB — install, get, headers, remove.
        OspfLsdb db;
        check(db.empty(), "OspfLsdb starts empty");
        auto lsa2 = OspfLsaHandle::make(OspfLsaHeader{
            0, 0, 1, 0xa, 0xa, 0x80000001, 0, 20});
        int rc = db.install(std::move(lsa2), 0);
        check(rc == 1, "LSDB install returns 1 (New)");
        check(db.size() == 1, "LSDB size after install = 1");
        auto got = db.get({1, 0xa, 0xa});
        check(got.has_value(), "LSDB get returns the LSA");
        if (got) {
            check(got->header().ls_sequence_number == 0x80000001,
                  "LSA seqno round-trip");
            check(got->key().advertising_router == 0xa, "LSA key adv = 0xa");
        }
        auto headers = db.headers();
        check(headers.size() == 1, "LSDB headers size = 1");
        check(db.remove({1, 0xa, 0xa}), "LSDB Remove returns true");
        check(db.empty(), "LSDB empty after Remove");

        // External dest — v4 construction + setters.
        unsigned char v4[4] = {203, 0, 113, 0};
        auto ext = OspfExternalDest::v4(v4, 24, 100,
                                        OspfExternalMetricType::Type1);
        check(ext.metric() == 100, "ExternalDest metric = 100");
        check(ext.metric_type() == OspfExternalMetricType::Type1,
              "ExternalDest metric_type = Type1");
        ext.set_forwarding_addr_v4(0x0A000001);
        ext.set_route_tag(42);
        ext.set_p_bit(1);
        check(ext.route_tag() == 42, "ExternalDest route_tag = 42");
        check(ext.p_bit() == 1, "ExternalDest p_bit = 1");

        // ExternalDest v3 — RFC 5340 §4.4.3.6.
        std::array<std::uint8_t, 16> v3_pfx = {
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01};
        auto v3_ext = OspfV3ExternalDest::v6(v3_pfx.data(), 48, 100, false);
        check(v3_ext.metric() == 100, "V3ExternalDest metric = 100");
        check(!v3_ext.type2(), "V3ExternalDest type2 = false");
        std::array<std::uint8_t, 16> fa_v6 = {
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0xfe};
        v3_ext.set_forwarding_addr(fa_v6.data());
        v3_ext.set_route_tag(0xDEADBEEF);
        check(v3_ext.forwarding_addr().has_value(), "V3ExternalDest FA set");
        check(v3_ext.route_tag().has_value(), "V3ExternalDest route_tag set");
        check(v3_ext.route_tag().value() == 0xDEADBEEF, "V3ExternalDest route_tag = 0xDEADBEEF");
        v3_ext.clear_forwarding_addr();
        v3_ext.clear_route_tag();
        check(!v3_ext.forwarding_addr().has_value(), "V3ExternalDest FA cleared");
        check(!v3_ext.route_tag().has_value(), "V3ExternalDest route_tag cleared");
        // V3 external dest prefix reader.
        lr_core_prefix_t pfx_out = v3_ext.prefix();
        check(pfx_out.prefix_len == 48, "V3ExternalDest prefix_len = 48");
        check(lr_core_prefix_is_ipv6(pfx_out) == 1, "V3ExternalDest prefix is IPv6");

        // OSPF virtual link + redistribute lifecycle (RFC 2328 §15 +
        // §12.4.3). Use a fresh Router so the OSPF area map is the
        // only state. Build an OSPFv2 session through the C ABI so
        // `ospf_router_id` is set.
        {
            auto r2 = make_router();
            // Attach an OSPFv2 session in area 1 (the C ABI takes the
            // session's router-id from the `router_id` parameter).
            std::uint64_t session_h = 0;
            int rc = lr_router_add_ospf_session_ext(
                r2.get(), /*version=*/2, /*router_id=*/0xc0a80001,
                /*area_id=*/1, /*area_kind=*/0 /* normal */,
                /*default_metric=*/0, /*mtu=*/1500, /*net_type=*/0 /* ptp */,
                /*has_interface_ip=*/0, /*interface_ip=*/0,
                /*has_neighbor_ip=*/0, /*neighbor_ip=*/0,
                &session_h);
            check(rc == 0, "lr_router_add_ospf_session_ext returns 0 (C ABI)");

            // Before redistribution: not ASBR.
            check(!ospf_is_asbr(r2), "OSPF router with no externals is not ASBR");
            // vlink to self refused.
            check(!ospf_add_virtual_link(r2, /*transit_area=*/1,
                                         /*endpoint=*/0xc0a80001),
                  "vlink to self refused");
            // vlink across normal area accepted.
            check(ospf_add_virtual_link(r2, 1, 0xc0a80002),
                  "vlink across normal area accepted");
            // duplicate add refused.
            check(!ospf_add_virtual_link(r2, 1, 0xc0a80002),
                  "duplicate vlink refused");
            // link down (no SPF reach).
            check(!ospf_virtual_link_up(r2, 1, 0xc0a80002),
                  "vlink down before SPF reaches endpoint");
            check(!ospf_virtual_link_session(r2, 1, 0xc0a80002).has_value(),
                  "vlink session is std::nullopt when down");
            // remove.
            check(ospf_remove_virtual_link(r2, 1, 0xc0a80002),
                  "vlink remove succeeds");
            check(!ospf_remove_virtual_link(r2, 1, 0xc0a80002),
                  "vlink remove again returns false");

            // Redistribute v2.
            unsigned char v4_pfx[4] = {10, 0, 0, 0};
            auto ext_v2 = OspfExternalDest::v4(v4_pfx, 24, 100,
                                              OspfExternalMetricType::Type1);
            check(ospf_redistribute(r2, ext_v2), "v2 redistribute succeeds");
            check(ospf_is_asbr(r2), "OSPF router with v2 externals is ASBR");
            lr_core_prefix_t v2_unred = lr_core_prefix_v4(v4_pfx, 24);
            check(ospf_unredistribute(r2, v2_unred), "v2 unredistribute succeeds");
            check(!ospf_is_asbr(r2), "OSPF router with no externals is not ASBR");

            // Redistribute v3.
            auto ext_v3 = OspfV3ExternalDest::v6(v3_pfx.data(), 48, 100, false);
            check(ospf_redistribute_v3(r2, ext_v3), "v3 redistribute succeeds");
            check(ospf_is_asbr(r2), "OSPF router with v3 externals is ASBR");
            lr_core_prefix_t v3_unred = lr_core_prefix_v6(v3_pfx.data(), 48);
            ospf_unredistribute_v3(r2, v3_unred);
            check(!ospf_is_asbr(r2), "OSPF router with no v3 externals is not ASBR");

            // V3 with link-local FA rejected by the router.
            auto ext_v3_bad = OspfV3ExternalDest::v6(v3_pfx.data(), 48, 100, false);
            std::array<std::uint8_t, 16> ll_fa = {
                0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0x01};
            ext_v3_bad.set_forwarding_addr(ll_fa.data());
            check(!ospf_redistribute_v3(r2, ext_v3_bad),
                  "v3 redistribute rejects link-local FA");
        }

        // ---- OspfAreaType value-type wrapper (issue #92) ----
        {
            // Constructors round-trip through readers.
            auto normal = OspfAreaType::normal();
            check(normal.kind() == OspfAreaType::Kind::Normal,
                  "OspfAreaType::normal kind == Normal");
            check(!normal.is_stub() && !normal.is_nssa() && !normal.is_stubby(),
                  "Normal is not stubby");
            check(!normal.no_summary(), "Normal does not set no_summary");
            check(!normal.default_metric().has_value(),
                  "Normal default_metric is std::nullopt");

            auto stub = OspfAreaType::stub(42);
            check(stub.kind() == OspfAreaType::Kind::Stub,
                  "OspfAreaType::stub(42) kind == Stub");
            check(stub.is_stub() && !stub.is_nssa() && stub.is_stubby(),
                  "Stub is stubby");
            check(!stub.no_summary(), "Stub (not no_summary) is false");
            check(stub.default_metric().has_value() &&
                  stub.default_metric().value() == 42,
                  "Stub default_metric == 42");

            auto stub_ns = OspfAreaType::stub_no_summary(7);
            check(stub_ns.kind() == OspfAreaType::Kind::StubNoSummary,
                  "stub_no_summary kind == StubNoSummary");
            check(stub_ns.is_stub() && stub_ns.is_stubby() && stub_ns.no_summary(),
                  "stub_no_summary has all the stub flags");
            check(stub_ns.default_metric().has_value() &&
                  stub_ns.default_metric().value() == 7,
                  "stub_no_summary default_metric == 7");

            auto nssa = OspfAreaType::nssa(99);
            check(nssa.kind() == OspfAreaType::Kind::Nssa,
                  "OspfAreaType::nssa(99) kind == Nssa");
            check(!nssa.is_stub() && nssa.is_nssa() && nssa.is_stubby(),
                  "Nssa is stubby");
            check(!nssa.no_summary(), "Nssa (not no_summary) is false");
            check(nssa.default_metric().has_value() &&
                  nssa.default_metric().value() == 99,
                  "Nssa default_metric == 99");

            auto nssa_ns = OspfAreaType::nssa_no_summary(3);
            check(nssa_ns.kind() == OspfAreaType::Kind::NssaNoSummary,
                  "nssa_no_summary kind == NssaNoSummary");
            check(nssa_ns.is_nssa() && nssa_ns.is_stubby() && nssa_ns.no_summary(),
                  "nssa_no_summary has all the nssa flags");
            check(nssa_ns.default_metric().has_value() &&
                  nssa_ns.default_metric().value() == 3,
                  "nssa_no_summary default_metric == 3");

            // Router with an attached NSSA area reads back the
            // pinned struct-value (with default_metric).
            auto r2 = make_router();
            std::uint64_t session_h = 0;
            int rc = lr_router_add_ospf_session_ext(
                r2.get(), /*version=*/2, /*router_id=*/0xc0a80001,
                /*area_id=*/7, /*area_kind=*/3 /* nssa */,
                /*default_metric=*/42, /*mtu=*/1500, /*net_type=*/0,
                /*has_interface_ip=*/0, /*interface_ip=*/0,
                /*has_neighbor_ip=*/0, /*neighbor_ip=*/0,
                &session_h);
            check(rc == 0, "lr_router_add_ospf_session_ext (NSSA) returns 0");
            auto t = ospf_area_type(r2, /*area_id=*/7);
            check(t.has_value(), "ospf_area_type returns the attached area");
            check(t->is_nssa(), "attached area is NSSA");
            check(t->kind() == OspfAreaType::Kind::Nssa,
                  "attached area kind == Nssa");
            check(t->default_metric().has_value() &&
                  t->default_metric().value() == 42,
                  "attached area default_metric == 42");
            // Unknown area reads back as std::nullopt.
            check(!ospf_area_type(r2, /*area_id=*/999).has_value(),
                  "ospf_area_type unknown area is std::nullopt");

            // Runtime conversion via the struct-value setter carries
            // the new default_metric.
            check(ospf_set_area_type(r2, /*area_id=*/7,
                                     OspfAreaType::nssa_no_summary(7)),
                  "convert area 7 to totally-NSSA(7) succeeds");
            auto t2 = ospf_area_type(r2, /*area_id=*/7);
            check(t2.has_value() &&
                  t2->kind() == OspfAreaType::Kind::NssaNoSummary,
                  "area 7 kind is now NssaNoSummary");
            check(t2->no_summary(), "area 7 no_summary flag set");
            check(t2->default_metric().has_value() &&
                  t2->default_metric().value() == 7,
                  "area 7 default_metric is 7");
            // No-op conversion returns false.
            check(!ospf_set_area_type(r2, /*area_id=*/7,
                                      OspfAreaType::nssa_no_summary(7)),
                  "no-op conversion returns false");
            // Backbone cannot become stub.
            auto r3 = make_router();
            std::uint64_t bb_h = 0;
            int rc2 = lr_router_add_ospf_session_ext(
                r3.get(), /*version=*/2, /*router_id=*/0xc0a80002,
                /*area_id=*/0, /*area_kind=*/0 /* normal */,
                /*default_metric=*/0, /*mtu=*/1500, /*net_type=*/0,
                0, 0, 0, 0, &bb_h);
            check(rc2 == 0, "backbone area attaches");
            check(!ospf_set_area_type(r3, /*area_id=*/0,
                                       OspfAreaType::stub(1)),
                  "backbone cannot become stub");
        }

        // ---- OSPF DR/BDR election reporting + Router-LSA flags reader ----
        // Mirrors `DefaultRouter::set_ospf_dr_state` (RFC 2328 §9.4 step 7)
        // and `DefaultRouter::ospf_router_lsa_flags` (RFC 2328 §A.4.2
        // V/E/B bits). The router-LSA flags reader must report the empty
        // (V=0, E=0, B=0) shape before any redistribution / vlink
        // activity, and the E-bit must flip on after one v2 redistribution.
        {
            auto r = make_router();
            std::uint64_t session_h = 0;
            int rc = lr_router_add_ospf_session_ext(
                r.get(), /*version=*/2, /*router_id=*/0xc0a80001,
                /*area_id=*/1, /*area_kind=*/0 /* normal */,
                /*default_metric=*/0, /*mtu=*/1500, /*net_type=*/0,
                0, 0, 0, 0, &session_h);
            check(rc == 0, "lr_router_add_ospf_session_ext returns 0");

            // Reader before any state change: V=0, E=0, B=0.
            auto flags = ospf_router_lsa_flags(r, /*area_id=*/1);
            check(flags.has_value(), "ospf_router_lsa_flags area 1 present");
            if (flags) {
                check(!flags->virtual_link, "V-bit empty area = false");
                check(!flags->asbr, "E-bit empty area = false");
                check(!flags->border, "B-bit single area = false");
            }

            // Unknown area: std::nullopt.
            check(!ospf_router_lsa_flags(r, /*area_id=*/999).has_value(),
                  "ospf_router_lsa_flags unknown area is std::nullopt");

            // DR/BDR no-op: pushing 0/0 against a freshly-attached
            // session (the runtime starts with dr=bdr=0) returns
            // changed=false.
            check(!set_ospf_dr_state(r, session_h, /*dr=*/0, /*bdr=*/0),
                  "no-op DR/BDR push returns false");

            // Push a real DR/BDR pair: changed=true (the runtime
            // fields move from 0 to the new values).
            check(set_ospf_dr_state(r, session_h, /*dr=*/0xc0a80001,
                                    /*bdr=*/0xc0a80002),
                  "first real DR/BDR push returns true");
            // Push the same pair again: changed=false.
            check(!set_ospf_dr_state(r, session_h, /*dr=*/0xc0a80001,
                                     /*bdr=*/0xc0a80002),
                  "same DR/BDR again returns false");

            // After redistribution: E-bit must flip on.
            unsigned char v4_pfx[4] = {10, 0, 0, 0};
            auto ext_v2 = OspfExternalDest::v4(v4_pfx, 24, 100,
                                              OspfExternalMetricType::Type1);
            check(ospf_redistribute(r, ext_v2), "v2 redistribute succeeds");
            auto flags2 = ospf_router_lsa_flags(r, /*area_id=*/1);
            check(flags2.has_value(), "ospf_router_lsa_flags after redist");
            if (flags2) {
                check(!flags2->virtual_link, "V-bit still 0");
                check(flags2->asbr, "E-bit set after redistribute");
                check(!flags2->border, "B-bit still 0");
            }
        }

        // ---- Simple router-wide readers (issue #92) ----
        // Round-trip the readers against their setters.
        {
            auto r = make_router();
            // enforce_first_as: default off.
            check(!enforce_first_as(r), "enforce_first_as default = false");
            lr_router_set_enforce_first_as(r.get(), 1);
            check(enforce_first_as(r), "enforce_first_as(1) → true");
            lr_router_set_enforce_first_as(r.get(), 0);
            check(!enforce_first_as(r), "enforce_first_as(0) → false");

            // add_path_max_paths: default 1.
            check(add_path_max_paths(r) == 1, "add_path_max_paths default = 1");
            lr_router_set_add_path_max_paths(r.get(), 4);
            check(add_path_max_paths(r) == 4, "set(4) → 4");
            lr_router_set_add_path_max_paths(r.get(), 0);
            check(add_path_max_paths(r) == 1, "set(0) clamped to 1");

            // roa_validate_enabled: default off.
            check(!roa_validate_enabled(r), "roa_validate default = false");
            lr_router_set_roa_validate(r.get(), 1);
            check(roa_validate_enabled(r), "set_roa_validate(1) → true");
            lr_router_set_roa_validate(r.get(), 0);
            check(!roa_validate_enabled(r), "set_roa_validate(0) → false");
        }

        // ---- Seg6Route / Seg6LocalRoute / Seg6Netlink (issue #92) ----
        // Build a SID and an SRH for the route constructors.
        std::array<std::uint8_t, 16> sid_octets = {
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1};
        Srv6Sid sid = make_srv6_sid(sid_octets);
        check(static_cast<bool>(sid), "Srv6Sid from octets is non-null");

        std::vector<std::array<std::uint8_t, 16>> segs = {sid_octets};
        Srv6Srh srh = make_srv6_srh(segs);
        check(static_cast<bool>(srh), "Srv6Srh from single segment is non-null");

        // IPv6 prefix for the seg6 encap route.
        lr_prefix_t v6_prefix{};
        v6_prefix.is_ipv6 = 1;
        v6_prefix.prefix_len = 64;
        std::array<std::uint8_t, 16> pfx_octets = {
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0};
        std::copy(pfx_octets.begin(), pfx_octets.end(), v6_prefix.addr);

        auto seg6_route = make_seg6_route(v6_prefix, srh.get());
        check(static_cast<bool>(seg6_route), "make_seg6_route returned non-null");
        seg6_route_set_mode(seg6_route, Seg6EncapMode::Inline);
        seg6_route_set_mode(seg6_route, Seg6EncapMode::Encap);
        seg6_route_set_if_index(seg6_route, 7);
        check(true, "Seg6Route builder setters succeed");

        // IPv4 prefix should be rejected.
        lr_prefix_t v4_prefix{};
        v4_prefix.is_ipv6 = 0;
        v4_prefix.prefix_len = 24;
        v4_prefix.addr[0] = 203; v4_prefix.addr[1] = 0;
        v4_prefix.addr[2] = 113; v4_prefix.addr[3] = 0;
        try {
            make_seg6_route(v4_prefix, srh.get());
            check(false, "make_seg6_route(IPv4) should have thrown");
        } catch (const Error&) {
            check(true, "make_seg6_route(IPv4) throws");
        }

        // Seg6LocalRoute — End behavior (IANA wire value 1).
        auto local_route = make_seg6_local_route(sid.get(), 1);
        check(static_cast<bool>(local_route), "make_seg6_local_route returned non-null");
        seg6_local_route_set_if_index(local_route, 1);
        std::array<std::uint8_t, 4> nh4 = {203, 0, 113, 1};
        seg6_local_route_set_nh4(local_route, nh4);
        std::array<std::uint8_t, 16> nh6 = {};
        nh6.fill(0xfe);
        seg6_local_route_set_nh6(local_route, nh6);
        seg6_local_route_set_iif(local_route, 2);
        seg6_local_route_set_oif(local_route, 3);
        seg6_local_route_set_table(local_route, 254);
        seg6_local_route_set_vrf_table(local_route, 100);
        seg6_local_route_set_srh(local_route, srh.get());
        check(true, "Seg6LocalRoute builder setters succeed");

        // Unknown behavior wire value (0xFFFF) should be rejected.
        try {
            make_seg6_local_route(sid.get(), 0xFFFF);
            check(false, "make_seg6_local_route(0xFFFF) should have thrown");
        } catch (const Error&) {
            check(true, "make_seg6_local_route(unknown behavior) throws");
        }

        // Seg6Netlink::connect — on a kernel without SRv6 (typical
        // CI runner) it throws Seg6RouteErrorException with code
        // NotEnabled or Unsupported. Either is acceptable.
        try {
            auto nl = make_seg6_netlink();
            // On a kernel with SRv6 enabled the handle is non-null;
            // no further exercise here (no root inside the runner
            // to actually install routes).
            check(static_cast<bool>(nl), "make_seg6_netlink returned non-null");
        } catch (const Seg6RouteErrorException& e) {
            auto code = e.code();
            check(code == Seg6RouteError::NotEnabled ||
                      code == Seg6RouteError::Unsupported,
                  "make_seg6_netlink throws NotEnabled or Unsupported");
        }

        // lr_seg6_route_err_name lookup on every known code.
        for (auto code : {Seg6RouteError::Unsupported,
                          Seg6RouteError::NotEnabled,
                          Seg6RouteError::Syscall,
                          Seg6RouteError::Kernel,
                          Seg6RouteError::BadSrh,
                          Seg6RouteError::UnsupportedAction}) {
            const char* n = Seg6RouteErrorException::name(code);
            check(n != nullptr && std::string(n) != "unknown",
                  "Seg6RouteError name lookup is non-null");
        }
    }

    // ---- RTR client RAII wrapper (RFC 8210 §6-§8): construct,
    // readers, intervals, on_connect, on_pdu_raw, step accessor for
    // roa_deltas/logs. Mirrors the FFI test in
    // crates/lr-ffi/src/rtr_client.rs. ----
    {
        RtrClient c;
        check(c.version() != 0, "RtrClient default version > 0");
        check(!c.session_id().has_value(), "RtrClient session_id empty on fresh client");
        check(!c.serial().has_value(), "RtrClient serial empty on fresh client");
        check(c.phase_name() == "awaiting-reset",
              "RtrClient phase_name is awaiting-reset");

        auto [refresh, retry, expire] = c.intervals();
        check(refresh == 3600 && retry == 600 && expire == 7200,
              "RtrClient default intervals (RFC 8210 §6)");

        c.set_intervals(100, 60, 600);
        auto [r2, re2, e2] = c.intervals();
        check(r2 == 100 && re2 == 60 && e2 == 600, "RtrClient set_intervals round-trips");

        // on_connect emits a Reset Query (8 bytes, RFC 8210 §5.3).
        auto bytes = c.on_connect();
        check(bytes.size() == 8, "RtrClient on_connect emits 8-byte Reset Query");
        check(bytes[1] == 2, "RtrClient Reset Query type byte == 2");

        // poll on a fresh client returns an empty step. The RAII
        // wrapper frees the underlying C struct on scope exit.
        {
            auto step = c.poll(0);
            check(!step.synced(), "RtrClientStep fresh poll is not synced");
            check(!step.expired(), "RtrClientStep fresh poll is not expired");
            check(step.roa_delta_count() == 0, "RtrClientStep fresh poll has 0 deltas");
            check(step.log_count() == 0, "RtrClientStep fresh poll has 0 logs");
            check(step.send_bytes().empty(), "RtrClientStep fresh poll send_bytes empty");
            check(!step.roa_delta_at(0).has_value(),
                  "RtrClientStep out-of-bounds delta returns nullopt");
            check(!step.log_at(0).has_value(),
                  "RtrClientStep out-of-bounds log returns nullopt");
        }

        // snapshot on a fresh client is empty.
        auto snap = c.snapshot();
        check(snap.empty(), "RtrClient snapshot empty on fresh client");

        // The fresh-poll step exposes zero counts for the new
        // attestation surfaces (RFC 8210 §5.10 Router Key and
        // §5.11 ASPA) — the full-wire test lives in the Rust FFI
        // suite (`ffi_rtr_client_step_router_key_and_aspa_deltas_after_v2_sync`),
        // the C++ harness pins the empty-step shape so a regression
        // that drops a method breaks at the wrapper layer too.
        {
            auto step = c.poll(0);
            check(step.router_key_delta_count() == 0,
                  "RtrClientStep fresh poll router_key_delta_count == 0");
            check(step.aspa_delta_count() == 0,
                  "RtrClientStep fresh poll aspa_delta_count == 0");
            check(!step.router_key_delta_at(0).has_value(),
                  "RtrClientStep out-of-bounds Router Key delta returns nullopt");
            check(!step.aspa_delta_at(0).has_value(),
                  "RtrClientStep out-of-bounds ASPA delta returns nullopt");
            check(step.router_key_deltas().empty(),
                  "RtrClientStep router_key_deltas() empty on fresh poll");
            check(step.aspa_deltas().empty(),
                  "RtrClientStep aspa_deltas() empty on fresh poll");
        }
    }

    // ---- RIB RAII wrappers (lr_rib mirror): LocRib / AdjRibIn /
    // AdjRibOut / RibMux / RouteSelector. Mirrors the FFI tests in
    // crates/lr-ffi/src/rib.rs. ----
    {
        // LocRib lifecycle + install / uninstall / best.
        LocRib rib;
        check(rib.empty(), "LocRib fresh is empty");
        check(rib.size() == 0, "LocRib size == 0");
        check(rib.paths_size() == 0, "LocRib paths_size == 0");
        check(rib.generation() == 0, "LocRib generation == 0");

        auto r1 = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        bool changed = rib.install(std::move(r1));
        check(changed, "LocRib install changed");
        check(rib.size() == 1, "LocRib size == 1 after install");
        check(rib.paths_size() == 1, "LocRib paths_size == 1 after install");
        auto gen0 = rib.generation();
        check(gen0 >= 1, "LocRib generation advanced");

        RouteKey k;
        k.addr = {10, 0, 0, 1};
        k.prefix_len = 24;
        k.afi = AFI_IPV4;
        k.safi = SAFI_UNICAST;
        check(rib.best_present(k), "LocRib best_present");
        auto best = rib.best(k);
        check(best != nullptr, "LocRib best non-null");

        // Re-install the same prefix is a no-op (no generation bump).
        auto r1b = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        bool changed2 = rib.install(std::move(r1b));
        check(!changed2, "LocRib re-install is no-op");
        check(rib.generation() == gen0, "LocRib generation unchanged on no-op");

        // Uninstall.
        check(rib.uninstall(k), "LocRib uninstall returns true");
        check(rib.size() == 0, "LocRib size == 0 after uninstall");
        check(!rib.best_present(k), "LocRib best_present false after uninstall");
        check(!rib.uninstall(k), "LocRib second uninstall is no-op");

        // Install_set (RFC 7911 Add-Path) + iter_best / iter_paths /
        // iter_sets.
        auto p1 = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        auto p2 = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        std::vector<Route> paths;
        paths.push_back(std::move(p1));
        paths.push_back(std::move(p2));
        rib.install_set(k, paths);
        check(rib.paths_size() == 2, "LocRib paths_size == 2 after install_set");
        check(rib.size() == 1, "LocRib size == 1 after install_set");
        check(rib.paths(k) == 2, "LocRib paths(k) == 2");

        std::size_t n_best = rib.iter_best([&](lr_route_t) {});
        check(n_best == 1, "LocRib iter_best count == 1");
        std::size_t n_paths = rib.iter_paths([&](lr_route_t) {});
        check(n_paths == 2, "LocRib iter_paths count == 2");
        std::size_t n_sets = rib.iter_sets([&](std::array<std::uint8_t, 16> addr,
                                                std::uint8_t plen, bool is_v6,
                                                std::size_t cnt) {
            check(plen == 24, "LocRib iter_sets prefix_len == 24");
            check(!is_v6, "LocRib iter_sets not IPv6");
            check(cnt == 2, "LocRib iter_sets path_count == 2");
            check(addr[0] == 10 && addr[1] == 0 && addr[2] == 0 && addr[3] == 1,
                  "LocRib iter_sets addr[:4] == 10.0.0.1");
        });
        check(n_sets == 1, "LocRib iter_sets count == 1");

        // diff_since: at least one added route.
        auto diff = rib.diff_since(0);
        check(diff.added >= 1, "LocRib diff_since added >= 1");

        // IPv6 install + best.
        LocRib v6rib;
        RouteKey k6;
        k6.addr = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        k6.prefix_len = 64;
        k6.afi = AFI_IPV6;
        k6.safi = SAFI_UNICAST;
        std::array<std::uint8_t, 16> v6_octets = {
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        auto v6 = make_route_v6(v6_octets, 64, Protocol::Bgp);
        v6rib.install(std::move(v6));
        check(v6rib.best_present(k6), "LocRib v6 best_present");

        // AdjRibIn lifecycle + feed / withdraw / get / origins_for /
        // iter_all / iter_origin / clear_for.
        AdjRibIn adj_in;
        check(adj_in.empty(), "AdjRibIn fresh is empty");
        RouteOrigin origin{Protocol::Bgp, 42};
        auto in_r = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        adj_in.feed(origin, std::move(in_r));
        check(adj_in.size() == 1, "AdjRibIn size == 1 after feed");
        auto in_got = adj_in.get(origin, k, 0);
        check(in_got != nullptr, "AdjRibIn get non-null");
        auto origins = adj_in.origins_for(k);
        check(!origins.empty(), "AdjRibIn origins_for non-empty");
        bool found = false;
        for (const auto& o : origins) {
            if (o.protocol == Protocol::Bgp && o.peer == 42) found = true;
        }
        check(found, "AdjRibIn origins_for contains (Bgp, 42)");

        auto in_r2 = make_route_v4({10, 0, 0, 2}, 24, Protocol::Bgp);
        adj_in.feed(origin, std::move(in_r2));
        std::size_t n_all = adj_in.iter_all([&](lr_route_t) {});
        check(n_all == 2, "AdjRibIn iter_all count == 2");
        std::size_t n_org = adj_in.iter_origin(origin, [&](lr_route_t) {});
        check(n_org == 2, "AdjRibIn iter_origin count == 2");
        adj_in.clear_for(origin);
        check(adj_in.empty(), "AdjRibIn empty after clear_for");

        // AdjRibOut: advertise / suppress / tx_path_ids / iter_for /
        // clear_for.
        AdjRibOut out;
        check(out.empty(), "AdjRibOut fresh is empty");
        auto out_r = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        out.advertise(origin, out_r, 100);
        out.advertise(origin, out_r, 200);
        check(out.size() == 2, "AdjRibOut size == 2 after 2 advertises");
        auto ids = out.tx_path_ids(origin, k);
        check(ids.size() == 2, "AdjRibOut tx_path_ids size == 2");
        std::size_t n_for = out.iter_for(origin, [&](lr_route_t) {});
        check(n_for == 2, "AdjRibOut iter_for count == 2");
        check(out.suppress(origin, k, 100), "AdjRibOut suppress returns true");
        check(out.size() == 1, "AdjRibOut size == 1 after suppress");
        check(!out.suppress(origin, k, 100), "AdjRibOut suppress (no-op)");
        out.clear_for(origin);
        check(out.empty(), "AdjRibOut empty after clear_for");

        // AdjRibOut::paths_for — walk (tx_path_id, route) pairs.
        {
            auto pr = make_route_v4({203, 0, 113, 1}, 24, Protocol::Bgp);
            out.advertise(origin, pr, 1);
            out.advertise(origin, pr, 2);
            out.advertise(origin, pr, 3);
            check(out.size() == 3, "AdjRibOut paths_for size == 3");
            RouteKey pk;
            pk.addr = std::vector<std::uint8_t>{203, 0, 113, 1};
            pk.prefix_len = 24;
            pk.afi = AFI_IPV4;
            pk.safi = SAFI_UNICAST;
            std::vector<std::uint32_t> seen_ids;
            std::size_t n_pf = out.paths_for(origin, pk, [&](std::uint32_t pid, lr_route_t) {
                seen_ids.push_back(pid);
            });
            check(n_pf == 3, "AdjRibOut paths_for count == 3");
            check(seen_ids.size() == 3, "AdjRibOut paths_for seen 3 ids");
            check(seen_ids[0] == 1 && seen_ids[1] == 2 && seen_ids[2] == 3,
                  "AdjRibOut paths_for ids ascending 1, 2, 3");
            // Unknown key returns 0.
            RouteKey unk;
            unk.addr = std::vector<std::uint8_t>{10, 0, 0, 0};
            unk.prefix_len = 8;
            unk.afi = AFI_IPV4;
            unk.safi = SAFI_UNICAST;
            std::size_t n_unk = out.paths_for(origin, unk, [&](std::uint32_t, lr_route_t) {});
            check(n_unk == 0, "AdjRibOut paths_for (unknown) == 0");
            out.clear_for(origin);
        }

        // AdjRibOut::advertised_keys — filter by (dest, family).
        {
            auto rv4 = make_route_v4({203, 0, 113, 1}, 24, Protocol::Bgp);
            out.advertise(origin, rv4, 1);
            auto rv6 = make_route_v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 1}, 64, Protocol::Bgp);
            out.advertise(origin, rv6, 1);

            auto v4_keys = out.advertised_keys(origin, AFI_IPV4, SAFI_UNICAST);
            check(v4_keys.size() == 1, "AdjRibOut advertised_keys (v4) size == 1");
            check(v4_keys[0].first.afi == AFI_IPV4, "advertised_keys (v4) AFI");
            check(v4_keys[0].first.prefix_len == 24, "advertised_keys (v4) prefix_len");
            check(v4_keys[0].second.size() == 1 && v4_keys[0].second[0] == 1,
                  "advertised_keys (v4) tx_path_ids [1]");

            auto v6_keys = out.advertised_keys(origin, AFI_IPV6, SAFI_UNICAST);
            check(v6_keys.size() == 1, "AdjRibOut advertised_keys (v6) size == 1");
            check(v6_keys[0].first.afi == AFI_IPV6, "advertised_keys (v6) AFI");
            check(v6_keys[0].first.prefix_len == 64, "advertised_keys (v6) prefix_len");

            auto labeled_keys = out.advertised_keys(origin, AFI_IPV4, SAFI_LABELED_UNICAST);
            check(labeled_keys.empty(), "AdjRibOut advertised_keys (labeled) empty");

            RouteOrigin wrong{Protocol::Bgp, 99};
            auto wrong_keys = out.advertised_keys(wrong, AFI_IPV4, SAFI_UNICAST);
            check(wrong_keys.empty(), "AdjRibOut advertised_keys (wrong peer) empty");

            out.clear_for(origin);
        }

        // RibMux: install / uninstall / get.
        RibMux mux;
        check(mux.empty(), "RibMux fresh is empty");
        auto mux_r = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        mux.install(std::move(mux_r));
        check(mux.size() == 1, "RibMux size == 1 after install");
        auto mux_got = mux.get(k);
        check(mux_got != nullptr, "RibMux get non-null");
        check(mux.uninstall(k), "RibMux uninstall returns true");
        check(mux.empty(), "RibMux empty after uninstall");
        check(!mux.uninstall(k), "RibMux uninstall (no-op)");

        // RibMux::iter — walk every merged route.
        {
            check(mux.empty(), "RibMux iter — empty pre-condition");
            std::size_t n_empty = mux.iter([&](lr_route_t) {});
            check(n_empty == 0, "RibMux iter (empty) count == 0");

            auto m1 = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
            mux.install(std::move(m1));
            auto m2 = make_route_v4({10, 0, 1, 1}, 24, Protocol::Bgp);
            mux.install(std::move(m2));
            check(mux.size() == 2, "RibMux iter — size == 2 after two installs");

            std::size_t n_iter = mux.iter([&](lr_route_t) {});
            check(n_iter == 2, "RibMux iter count == 2");
        }

        // RouteSelector.
        auto s1 = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        auto s2 = make_route_v4({10, 0, 0, 1}, 24, Protocol::Bgp);
        std::vector<lr_route_t> sel = {s1.get(), s2.get()};
        auto idx = RouteSelector::select(sel);
        check(idx == 0 || idx == 1, "RouteSelector::select returns valid index");
        auto idx_bgp = RouteSelector::select_bgp(sel);
        check(idx_bgp == 0 || idx_bgp == 1, "RouteSelector::select_bgp returns valid index");
        auto empty = std::vector<lr_route_t>{};
        check(RouteSelector::select(empty) == -1, "RouteSelector::select empty == -1");

        // RouteSelector::compare — anti-symmetric comparator.
        {
            auto cmp = RouteSelector::compare(s1.get(), s2.get());
            check(cmp == 0, "RouteSelector::compare identical routes tie");
            auto cmp_swap = RouteSelector::compare(s2.get(), s1.get());
            check(cmp_swap == 0, "RouteSelector::compare swapped identical tie");
            // Self-compare is zero.
            auto cmp_self = RouteSelector::compare(s1.get(), s1.get());
            check(cmp_self == 0, "RouteSelector::compare self == 0");
        }

        // ----------------------------------------------------------------
        // Babel — RFC 8966 + RFC 8967. Mirrors the Python and Go
        // binding coverage of the same surface.
        // ----------------------------------------------------------------

        // BabelFrame lifecycle.
        auto frame = BabelFrame::empty();
        check(frame.tlv_count() == 0, "BabelFrame::empty tlv_count == 0");
        frame.push(BabelTlv::pad1());
        check(frame.tlv_count() == 1, "BabelFrame tlv_count == 1 after push");
        check(frame.tlv_type_at(0) == babel_tlv_type::Pad1,
              "BabelFrame tlv_type_at(0) == Pad1");
        auto wire = frame.encode();
        check(!wire.empty() && wire[0] == 0x2A,
              "BabelFrame encode starts with Babel magic 0x2A");

        // Round-trip through decode.
        auto decoded = BabelFrame::decode(wire);
        check(decoded.tlv_count() >= 1, "BabelFrame::decode recovers >= 1 TLV");

        // BabelRouteTable lifecycle.
        BabelRouteTable tab;
        check(tab.empty(), "BabelRouteTable fresh is empty");
        check(tab.size() == 0, "BabelRouteTable size == 0");

        BabelRouteKey key;
        key.destination_addr = std::vector<std::uint8_t>{10, 0, 0, 0};
        key.destination_prefix_len = 8;
        key.router_id = std::array<std::uint8_t, 8>{1, 1, 1, 1, 1, 1, 1, 1};

        BabelRoute r;
        r.key = key;
        r.seqno = 1;
        r.metric = 100;
        r.next_hop = std::vector<std::uint8_t>{10, 0, 0, 1};
        tab.insert(r);
        check(tab.size() == 1, "BabelRouteTable size == 1 after insert");
        check(tab.contains(key), "BabelRouteTable contains inserted key");
        auto got = tab.get(key);
        check(got.has_value(), "BabelRouteTable::get returns value");
        check(got->seqno == 1, "BabelRoute::seqno == 1");
        check(got->metric == 100, "BabelRoute::metric == 100");
        check(got->feasible, "BabelRoute::feasible (fresh route is feasible)");
        check(got->next_hop == std::vector<std::uint8_t>{10, 0, 0, 1},
              "BabelRoute::next_hop round-trips");

        std::size_t n_iter_all = 0;
        tab.iter_all([&](const BabelRoute&) { n_iter_all++; });
        check(n_iter_all == 1, "BabelRouteTable iter_all visits 1 route");
        std::size_t n_iter_best = 0;
        tab.iter_best([&](const BabelRoute&) { n_iter_best++; });
        check(n_iter_best == 1, "BabelRouteTable iter_best visits 1 route");
        check(tab.best_routes_count() == 1, "BabelRouteTable best_routes_count == 1");

        tab.withdraw(key);
        check(tab.size() == 0, "BabelRouteTable size == 0 after withdraw");
        check(!tab.contains(key), "BabelRouteTable !contains after withdraw");
        check(!tab.get(key).has_value(), "BabelRouteTable::get returns nullopt after withdraw");

        // BabelNeighbor lifecycle.
        BabelNeighbor nbr{std::vector<std::uint8_t>{10, 0, 0, 1}, 1000};
        nbr.hello(1, 100, 1100);
        nbr.ihu(96, 100, 1100);
        check(!nbr.rtt_valid(1200), "BabelNeighbor rtt_valid == false (no timestamped Hello)");
        check(nbr.rtt_us(1200) == 0, "BabelNeighbor rtt_us == 0");

        // MacKey + PseudoHeader + PacketCounter + ReplayProtection.
        auto mk = BabelMacKey::hmac_sha256(std::vector<std::uint8_t>{97, 98, 99});
        check(mk.algorithm() == babel_mac::HMACSHA256, "BabelMacKey hmac_sha256 algorithm");
        check(mk.digest_len() == 32, "BabelMacKey hmac_sha256 digest_len == 32");
        check(mk.secret() == std::vector<std::uint8_t>{97, 98, 99},
              "BabelMacKey secret round-trips");

        auto mk2 = BabelMacKey::blake2s128(std::vector<std::uint8_t>{97, 98, 99});
        check(mk2.algorithm() == babel_mac::Blake2s128, "BabelMacKey blake2s128 algorithm");
        check(mk2.digest_len() == 16, "BabelMacKey blake2s128 digest_len == 16");

        auto ph = BabelPseudoHeader::v4(
            std::array<std::uint8_t, 4>{10, 0, 0, 1}, 6696,
            std::array<std::uint8_t, 4>{10, 0, 0, 2}, 6696);
        auto ph_wire = ph.encode();
        check(!ph_wire.empty(), "BabelPseudoHeader::encode non-empty");

        BabelPacketCounter pc{std::vector<std::uint8_t>{1, 2, 3, 4, 5}, 10};
        check(pc.counter() == 10, "BabelPacketCounter::counter == 10");
        check(pc.index_len() == 5, "BabelPacketCounter::index_len == 5");
        check(pc.index() == std::vector<std::uint8_t>{1, 2, 3, 4, 5},
              "BabelPacketCounter::index round-trips");

        BabelReplayProtection rp;
        check(rp.accept(std::vector<std::uint8_t>{1}, 5), "ReplayProtection accept(5)");
        check(!rp.accept(std::vector<std::uint8_t>{1}, 3), "ReplayProtection !accept(3, replay)");
        check(!rp.accept(std::vector<std::uint8_t>{1}, 5), "ReplayProtection !accept(5, equal)");
        check(rp.accept(std::vector<std::uint8_t>{1}, 6), "ReplayProtection accept(6)");

        // Message constructors.
        BabelHello h{1, 100};
        check(h.seqno() == 1, "BabelHello::seqno == 1");
        check(h.interval_cs() == 100, "BabelHello::interval_cs == 100");
        h.set_unicast(true);
        check(h.flags() != 0, "BabelHello::flags != 0 after set_unicast(true)");
        check(!h.encode().empty(), "BabelHello::encode non-empty");

        BabelIhu ihu{96, 100};
        check(ihu.rxcost() == 96, "BabelIhu::rxcost == 96");
        check(ihu.interval_cs() == 100, "BabelIhu::interval_cs == 100");

        BabelAckReq ar{42, 200};
        check(ar.nonce() == 42, "BabelAckReq::nonce == 42");
        check(ar.interval_cs() == 200, "BabelAckReq::interval_cs == 200");

        BabelAck ack{42};
        check(ack.opaque() == 42, "BabelAck::opaque == 42");
        check(!ack.encode().empty(), "BabelAck::encode non-empty");

        BabelNextHop nh{std::vector<std::uint8_t>{10, 0, 0, 1}};
        check(nh.ae() == babel_ae::IPv4, "BabelNextHop IPv4 ae");
        check(nh.address() == std::vector<std::uint8_t>{10, 0, 0, 1},
              "BabelNextHop::address round-trips");

        BabelRouterId rid{std::array<std::uint8_t, 8>{1, 1, 1, 1, 1, 1, 1, 1}};
        check(rid.bytes() == std::array<std::uint8_t, 8>{1, 1, 1, 1, 1, 1, 1, 1},
              "BabelRouterId::bytes round-trips");

        BabelRouteRequest rr = BabelRouteRequest::wildcard();

        BabelSeqnoRequest sr{std::vector<std::uint8_t>{10, 0, 0, 0}, 8, 1,
                              std::array<std::uint8_t, 8>{1, 1, 1, 1, 1, 1, 1, 1}, 255};

        // Free function helpers.
        check(babel_rtt_penalty(1'000'000, 10'000, 120'000, 96) == 96,
              "babel_rtt_penalty clamps at max_penalty");
        check(babel_route_metric_sum({100, 200, 300}) == 600,
              "babel_route_metric_sum([100,200,300]) == 600");
        check(babel_feasible(1, 100, 0, 200), "babel_feasible strictly better");
        check(!babel_feasible(1, 100, 1, 100), "babel_feasible equal -> false");
    }

    // ----- Attributes container + apply_set_checked (issue #92). -----
    // Mirrors crates/lr-ffi/src/attributes.rs and policy_batch.rs
    // (and bindings/lr-python/tests/test_attributes.py /
    // bindings/lr-go/attributes_test.go). The C++ surface exercises
    // every method on the Attributes RAII class plus every
    // apply_set_checked variant handled by the C ABI.
    {
        // Empty container.
        Attributes a;
        check(a.size() == 0, "Attributes::size == 0 on construction");
        check(a.empty(), "Attributes::empty == true on construction");

        // Insert + Get round trip.
        std::vector<std::uint8_t> v{0, 0, 0, 100};  // 100 as u32 BE
        a.insert(5, 0x40,
                 std::string_view(reinterpret_cast<const char*>(v.data()), v.size()));
        check(a.size() == 1, "Attributes::size == 1 after insert");
        check(!a.empty(), "Attributes::empty == false after insert");
        auto got = a.get(5);
        check(got.has_value(), "Attributes::get(5) returns value");
        check(got->first == 0x40, "Attributes::get(5).flags == 0x40");
        check(got->second == v, "Attributes::get(5).value round-trips");
        check(a.get_u32_be(5) == 100, "Attributes::get_u32_be(5) == 100");

        // Absent tag returns nullopt.
        check(!a.get(99).has_value(), "Attributes::get(99) returns nullopt");

        // Typed readers round-trip.
        std::uint64_t big = 0x0123'4567'89AB'CDEFull;
        std::vector<std::uint8_t> big_be(8);
        for (int i = 0; i < 8; ++i) {
            big_be[i] = static_cast<std::uint8_t>(big >> (56 - 8 * i));
        }
        a.insert(9, 0,
                 std::string_view(reinterpret_cast<const char*>(big_be.data()), 8));
        check(a.get_u64_be(9) == big, "Attributes::get_u64_be round-trip");
        a.insert(11, 0, std::string_view("\x2a", 1));
        check(a.get_u8(11) == 42, "Attributes::get_u8 round-trip");

        // Insert / replace on the same tag.
        a.insert(5, 0, std::string_view("\x00\x00\x00\x02", 4));
        check(a.size() == 3, "Attributes::size still 3 after replace (tag 5)");
        check(a.get_u32_be(5) == 2, "Attributes::get_u32_be(5) == 2 (latest value)");

        // at + for_each iterate in ascending tag order.
        // BTreeMap ordering: tag 5, 9, 11.
        auto e1 = a.at(0);
        check(e1.has_value(), "Attributes::at(0) returns value");
        check(e1->tag == 5, "Attributes::at(0).tag == 5");
        auto e3 = a.at(2);
        check(e3.has_value(), "Attributes::at(2) returns value");
        check(e3->tag == 11, "Attributes::at(2).tag == 11");
        check(!a.at(99).has_value(), "Attributes::at(99) returns nullopt");
        std::vector<std::uint8_t> tags;
        a.for_each([&](std::uint8_t t, std::uint8_t, const std::vector<std::uint8_t>&) {
            tags.push_back(t);
            return true;
        });
        check(tags == std::vector<std::uint8_t>{5, 9, 11},
              "Attributes::for_each yields in ascending tag order");

        // Remove returns presence.
        check(a.remove(5), "Attributes::remove(5) returns true (present)");
        check(!a.remove(5), "Attributes::remove(5) returns false (absent)");
    }

    // ----- apply_set_checked variants (issue #92). -----
    {
        auto make_route = []() {
            return make_route_v4({203, 0, 113, 0}, 24, Protocol::Bgp);
        };

        // SetMetric round trip.
        {
            auto r = make_route();
            apply_set_checked(r.get(), SetActionKind::Metric, 42);
            std::uint32_t v = 0;
            int rc = lr_route_metric(r.get(), &v);
            check(rc == 0, "lr_route_metric rc == 0");
            check(v == 42, "apply_set_checked(SetMetric, 42) round-trips");
        }

        // SetTag round trip.
        {
            auto r = make_route();
            apply_set_checked(r.get(), SetActionKind::Tag, 0xDEADBEEFu);
            std::uint32_t v = 0;
            int rc = lr_route_tag(r.get(), &v);
            check(rc == 0, "lr_route_tag rc == 0");
            check(v == 0xDEADBEEFu, "apply_set_checked(SetTag, 0xDEADBEEF) round-trips");
        }

        // SetLocalPref round trip (default build has bgp feature).
        {
            auto r = make_route();
            apply_set_checked(r.get(), SetActionKind::LocalPref, 100);
            std::uint32_t v = 0;
            int rc = lr_route_local_pref(r.get(), &v);
            check(rc == 0, "lr_route_local_pref rc == 0");
            check(v == 100, "apply_set_checked(SetLocalPref, 100) round-trips");
        }

        // SetMed round trip.
        {
            auto r = make_route();
            apply_set_checked(r.get(), SetActionKind::Med, 50);
            std::uint32_t v = 0;
            int rc = lr_route_med(r.get(), &v);
            check(rc == 0, "lr_route_med rc == 0");
            check(v == 50, "apply_set_checked(SetMed, 50) round-trips");
        }

        // Unknown kind throws ApplySetError.
        bool threw = false;
        try {
            auto r = make_route();
            // The C++ wrapper takes SetActionKind; cast a non-LR_SET_*
            // value through the enum to drive the unknown-kind branch.
            apply_set_checked(r.get(),
                              static_cast<SetActionKind>(99), 0, 0, 0);
        } catch (const ApplySetError& e) {
            threw = true;
            check(e.code() == LR_APPLY_SET_ERROR_UNKNOWN,
                  "ApplySetError::code == UNKNOWN for invalid kind");
            check(std::string(e.what()).find("unknown") != std::string::npos,
                  "ApplySetError::what mentions unknown");
        }
        check(threw, "apply_set_checked(99) throws ApplySetError");

        // ApplySetError name lookup.
        check(apply_set_error_name(LR_APPLY_SET_ERROR_OK) == "ok",
              "apply_set_error_name(OK) == \"ok\"");
        check(apply_set_error_name(LR_APPLY_SET_ERROR_LOCAL_PREF_NO_BGP)
                  .find("bgp") != std::string::npos,
              "apply_set_error_name(LocalPrefNoBgp) mentions bgp");
    }

    // =================================================================
    // BgpPathAttrs — RFC 4271 §5.1 PathAttributes RAII surface.
    // Mirrors the FFI tests in crates/lr-ffi/src/bgp_path.rs.
    // =================================================================
    {
        auto a = make_bgp_path_attrs();
        check(bgp_path_attrs_len(a) == 0, "fresh BgpPathAttrs len == 0");
        check(bgp_path_attrs_is_empty(a), "fresh BgpPathAttrs is_empty");
        check(bgp_path_attrs_count(a) == 0, "fresh BgpPathAttrs count == 0");

        // LOCAL_PREF round-trip.
        bgp_path_attrs_set_local_pref(a, 100);
        check(bgp_path_attrs_count(a) == 1, "count == 1 after set_local_pref");
        auto lp = bgp_path_attrs_local_pref(a);
        check(lp.has_value() && *lp == 100, "local_pref round-trip 100");

        // at(0) returns the LOCAL_PREF entry.
        auto p = bgp_path_attrs_at(a, 0);
        check(p.has_value(), "at(0) has value");
        check(p->attr_type == static_cast<std::uint8_t>(BgpAttrType::LocalPref),
              "at(0) attr_type == LocalPref");
        check(p->flags == 0x40, "at(0) flags == 0x40 (transitive)");
        check(p->value.size() == 4 && p->value[3] == 100,
              "at(0) value == 100 BE");

        // at(99) out of range.
        check(!bgp_path_attrs_at(a, 99).has_value(), "at(99) returns nullopt");

        // get(LocalPref).
        auto g = bgp_path_attrs_get(a, BgpAttrType::LocalPref);
        check(g.has_value() && g->attr_type == static_cast<std::uint8_t>(BgpAttrType::LocalPref),
              "get(LocalPref) returns the attr");

        // get(Origin) absent on a fresh+LocalPref set.
        check(!bgp_path_attrs_get(a, BgpAttrType::Origin).has_value(),
              "get(Origin) returns nullopt");

        // remove(LocalPref) returns true; remove again returns false.
        check(bgp_path_attrs_remove(a, BgpAttrType::LocalPref),
              "remove(LocalPref) returns true");
        check(!bgp_path_attrs_local_pref(a).has_value(),
              "local_pref after remove is nullopt");
        check(!bgp_path_attrs_remove(a, BgpAttrType::LocalPref),
              "remove(LocalPref) twice returns false");

        // insert_raw round-trip — LOCAL_PREF, flags 0x40, value 250 BE.
        bgp_path_attrs_insert_raw(a, 0x40, BgpAttrType::LocalPref,
                                  {0, 0, 0, 250});
        auto lp2 = bgp_path_attrs_local_pref(a);
        check(lp2.has_value() && *lp2 == 250,
              "insert_raw LOCAL_PREF round-trip 250");
    }

    // BgpPathAttrs — well-known readers absent on fresh attrs.
    {
        auto a = make_bgp_path_attrs();
        check(!bgp_path_attrs_med(a).has_value(), "med absent");
        check(!bgp_path_attrs_origin(a).has_value(), "origin absent");
        check(!bgp_path_attrs_atomic_aggregate(a), "atomic_aggregate absent");
        check(!bgp_path_attrs_aggregator(a).has_value(), "aggregator absent");

        auto nh = bgp_path_attrs_next_hop(a);
        check(!nh.present, "next_hop absent on fresh attrs");

        check(bgp_path_attrs_as_path(a) == nullptr, "as_path absent");
        check(bgp_path_attrs_as_path_wire(a, true) == nullptr, "as_path_wire(true) absent");
        check(bgp_path_attrs_as_path_wire(a, false) == nullptr, "as_path_wire(false) absent");
        check(bgp_path_attrs_as4_path(a) == nullptr, "as4_path absent");

        check(!bgp_path_attrs_originator_id(a).has_value(), "originator_id absent");
        check(!bgp_path_attrs_has_cluster_list(a), "has_cluster_list absent");
        check(bgp_path_attrs_cluster_list(a).empty(), "cluster_list empty");

        check(bgp_path_attrs_communities(a).empty(), "communities empty");
        check(bgp_path_attrs_ext_communities(a).empty(), "ext_communities empty");
        check(bgp_path_attrs_large_communities(a).empty(), "large_communities empty");

        check(!bgp_path_attrs_has_aigp(a), "has_aigp absent");
        check(!bgp_path_attrs_aigp(a).has_value(), "aigp absent");
        check(!bgp_path_attrs_has_otc(a), "has_otc absent");
        check(!bgp_path_attrs_otc(a).has_value(), "otc absent");
        check(!bgp_path_attrs_has_pmsi_tunnel(a), "has_pmsi_tunnel absent");

        check(bgp_path_attrs_label_stack(a) == nullptr, "label_stack absent");
        check(!bgp_path_attrs_mp_reach(a).has_value(), "mp_reach absent");
        check(!bgp_path_attrs_mp_unreach(a).has_value(), "mp_unreach absent");

        check(!bgp_path_attrs_has_ospf_metric2(a), "has_ospf_metric2 absent");
        check(!bgp_path_attrs_has_ospf_router_id(a), "has_ospf_router_id absent");
        check(!bgp_path_attrs_has_babel_seqno(a), "has_babel_seqno absent");
        check(!bgp_path_attrs_has_babel_router_id(a), "has_babel_router_id absent");
        check(!bgp_path_attrs_has_igp_metric(a), "has_igp_metric absent");
        check(!bgp_path_attrs_has_peer_source_address(a), "has_peer_source_address absent");
    }

    // BgpPathAttrs — communities round-trip.
    {
        auto a = make_bgp_path_attrs();
        std::uint32_t c = (64512u << 16) | 100u;
        bgp_path_attrs_insert_community(a, c);
        auto v = bgp_path_attrs_communities(a);
        check(v.size() == 1 && v[0] == c, "insert_community round-trips one community");
        check(bgp_path_attrs_has_community(a, c), "has_community after insert");
        check(!bgp_path_attrs_has_community(a, c + 1), "has_community(c+1) false");

        // Large community round-trip.
        auto lc = make_bgp_large_community(65001, 1, 2);
        check(bgp_large_community_global_admin(lc) == 65001, "lc.global_admin == 65001");
        check(bgp_large_community_local_data1(lc) == 1, "lc.local_data1 == 1");
        check(bgp_large_community_local_data2(lc) == 2, "lc.local_data2 == 2");
        bgp_path_attrs_insert_large_community(a, lc);
        auto large = bgp_path_attrs_large_communities(a);
        check(large.size() == 1, "large_communities size == 1");
        check(large[0].global_admin == 65001 &&
              large[0].local_data1 == 1 &&
              large[0].local_data2 == 2, "large_communities[0] == 65001:1:2");
    }

    // BgpPathAttrs — OSPF / Babel / IGP / peer source address round-trips.
    {
        auto a = make_bgp_path_attrs();
        bgp_path_attrs_set_ospf_metric2(a, 123);
        check(bgp_path_attrs_has_ospf_metric2(a), "has_ospf_metric2 after set");
        auto m2 = bgp_path_attrs_ospf_metric2(a);
        check(m2.has_value() && *m2 == 123, "ospf_metric2 round-trip 123");

        bgp_path_attrs_set_ospf_router_id(a, 0x01020304);
        check(bgp_path_attrs_has_ospf_router_id(a), "has_ospf_router_id after set");
        auto rid = bgp_path_attrs_ospf_router_id(a);
        check(rid.has_value() && *rid == 0x01020304, "ospf_router_id round-trip");

        bgp_path_attrs_set_babel_seqno(a, 65535);
        check(bgp_path_attrs_has_babel_seqno(a), "has_babel_seqno after set");
        auto bs = bgp_path_attrs_babel_seqno(a);
        check(bs.has_value() && *bs == 65535, "babel_seqno round-trip 65535");

        bgp_path_attrs_set_babel_router_id(a, 0x0123456789ABCDEFULL);
        check(bgp_path_attrs_has_babel_router_id(a), "has_babel_router_id after set");
        auto brid = bgp_path_attrs_babel_router_id(a);
        check(brid.has_value() && *brid == 0x0123456789ABCDEFULL,
              "babel_router_id round-trip");

        bgp_path_attrs_set_igp_metric(a, 1000);
        check(bgp_path_attrs_has_igp_metric(a), "has_igp_metric after set");
        auto im = bgp_path_attrs_igp_metric(a);
        check(im.has_value() && *im == 1000, "igp_metric round-trip 1000");

        // Peer source address v4 round-trip.
        std::vector<std::uint8_t> v4_addr = {0xc0, 0xa8, 0x01, 0x01};
        bgp_path_attrs_set_peer_source_address(a, v4_addr, false);
        check(bgp_path_attrs_has_peer_source_address(a),
              "has_peer_source_address after v4 set");
        auto psa = bgp_path_attrs_peer_source_address(a);
        check(psa.has_value(), "peer_source_address returns value after set");
        check(psa->second == false, "peer_source_address is_ipv6 == false");
        check(psa->first == v4_addr, "peer_source_address v4 round-trips");

        // Peer source address v6 round-trip.
        std::vector<std::uint8_t> v6_addr(16, 0);
        v6_addr[15] = 1;
        bgp_path_attrs_set_peer_source_address(a, v6_addr, true);
        auto psa6 = bgp_path_attrs_peer_source_address(a);
        check(psa6.has_value() && psa6->second == true,
              "peer_source_address v6 returns is_ipv6=true");
        check(psa6->first == v6_addr, "peer_source_address v6 round-trips");

        // Length-mismatch throws.
        bool threw = false;
        try {
            std::vector<std::uint8_t> bad = {0, 1};
            bgp_path_attrs_set_peer_source_address(a, bad, false);
        } catch (const Error&) {
            threw = true;
        }
        check(threw, "set_peer_source_address(v4 with 2 bytes) throws");
    }

    // BgpPathAttrs — RFC 8277 label stack round-trip via the existing
    // MplsLabelStack RAII.
    {
        auto a = make_bgp_path_attrs();
        auto stack = make_label_stack_from_values({16, 17});
        bgp_path_attrs_set_label_stack(a, stack);
        auto out = bgp_path_attrs_label_stack(a);
        check(out != nullptr, "label_stack returns non-null after set");
        check(label_stack_len(out) == 2, "label_stack_len == 2");
    }

    // ---- Foundational lr-core value types + owned buffer / timer /
    // memory conn (issue #92). Mirrors the new sections in
    // include/librouting.hpp. ----

    // IpAddress — v4 round-trip.
    {
        IpAddress a = IpAddress::v4({10, 0, 0, 1});
        check(a.is_ipv4(), "IpAddress v4 is_ipv4");
        check(!a.is_ipv6(), "IpAddress v4 not is_ipv6");
        auto o = a.octets();
        check(o.size() == 4 && o[0] == 10 && o[3] == 1,
              "IpAddress v4 octets == [10,0,0,1]");
        auto o4 = a.octets4();
        check(o4[0] == 10 && o4[3] == 1, "IpAddress v4 octets4");
    }

    // IpAddress — v6 unspecified.
    {
        IpAddress a = IpAddress::v6({});
        check(a.is_ipv6(), "IpAddress v6 is_ipv6");
        check(a.is_unspecified(), "IpAddress v6 zero is_unspecified");
    }

    // IpAddress — multicast detection.
    {
        IpAddress v4 = IpAddress::v4({224, 0, 0, 1});
        check(v4.is_multicast(), "IpAddress v4 224.0.0.1 is_multicast");
        std::array<std::uint8_t, 16> v6buf{};
        v6buf[0] = 0xff;
        v6buf[1] = 0x02;
        IpAddress v6 = IpAddress::v6(v6buf);
        check(v6.is_multicast(), "IpAddress v6 ff02:: is_multicast");
    }

    // IpAddress — equality.
    {
        IpAddress a = IpAddress::v4({10, 0, 0, 1});
        IpAddress b = IpAddress::v4({10, 0, 0, 1});
        IpAddress c = IpAddress::v4({10, 0, 0, 2});
        check(a == b, "IpAddress equality (equal)");
        check(!(a == c), "IpAddress equality (different)");
    }

    // BoxedIpAddr — IPv4-mapped IPv6 round-trip.
    {
        auto a = make_boxed_ipv4({10, 0, 0, 1});
        check(static_cast<bool>(a), "make_boxed_ipv4 returns non-null");
        check(!ip_addr_is_ipv4_mapped_ipv6(a), "V4 not IPv4-mapped IPv6");
        auto mapped = ip_addr_to_ipv4_mapped(a);
        check(static_cast<bool>(mapped), "to_ipv4_mapped returns non-null for V4 input");
        check(ip_addr_is_ipv4_mapped_ipv6(mapped),
              "mapped is IPv4-mapped IPv6");
    }

    // BoxedIpAddr — V6 input returns null from to_ipv4_mapped.
    {
        std::array<std::uint8_t, 16> buf{};
        buf[0] = 0xfe;
        buf[1] = 0x80;
        auto a = make_boxed_ipv6(buf);
        auto mapped = ip_addr_to_ipv4_mapped(a);
        check(!static_cast<bool>(mapped), "to_ipv4_mapped returns null for V6 input");
    }

    // BoxedIpAddr — make_boxed_ip_from_bytes dispatch.
    {
        auto a = make_boxed_ip_from_bytes({10, 0, 0, 1});
        check(static_cast<bool>(a), "make_boxed_ip_from_bytes(v4)");
        auto b = make_boxed_ip_from_bytes(
            {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
        check(static_cast<bool>(b), "make_boxed_ip_from_bytes(v6)");
        bool threw = false;
        try { make_boxed_ip_from_bytes({1, 2, 3}); }
        catch (const Error&) { threw = true; }
        check(threw, "make_boxed_ip_from_bytes(bad length) throws");
    }

    // CorePrefix — v4 network + contains bit-level.
    {
        CorePrefix p = CorePrefix::v4({10, 0, 0, 5}, 24);
        check(p.is_ipv4(), "CorePrefix v4 is_ipv4");
        check(p.prefix_len() == 24, "CorePrefix prefix_len == 24");
        IpAddress net = p.network();
        auto o = net.octets4();
        check(o[0] == 10 && o[3] == 0, "CorePrefix network == 10.0.0.0");
        check(p.contains(IpAddress::v4({10, 0, 0, 5})),
              "CorePrefix /24 contains 10.0.0.5");
        check(!p.contains(IpAddress::v4({10, 0, 1, 1})),
              "CorePrefix /24 NOT contains 10.0.1.1");
    }

    // CorePrefix — contains_prefix.
    {
        CorePrefix outer = CorePrefix::v4({10, 0, 0, 0}, 16);
        CorePrefix inner = CorePrefix::v4({10, 0, 5, 0}, 24);
        CorePrefix notInner = CorePrefix::v4({10, 1, 0, 0}, 24);
        check(outer.contains_prefix(inner), "outer contains inner");
        check(!outer.contains_prefix(notInner), "outer NOT contains notInner");
    }

    // Asn — private + AS_TRANS + as_u16.
    {
        Asn a(65001);
        check(a.value() == 65001, "Asn value");
        check(a.is_private(), "Asn 65001 is_private");
        Asn trans(23456);
        check(trans.is_as_trans(), "Asn 23456 is_as_trans");
        check(trans.is_as23456(), "Asn 23456 is_as23456");
        Asn big(70000);
        check(big.as_u16() == 0, "Asn 70000 as_u16 == 0 (AS_TRANS)");
        check(big.as_u32() == 70000, "Asn 70000 as_u32 == 70000");
    }

    // RouterId — round-trip.
    {
        RouterId r = RouterId::from_v4({10, 0, 0, 1});
        auto o = r.to_v4_bytes();
        check(o[0] == 10 && o[3] == 1, "RouterId from_v4 round-trip");
        RouterId r2(0x0a000001);
        check(r.value() == r2.value(), "RouterId value equality");
    }

    // Protocol helpers — bird_name + admin distance.
    {
        check(protocol_bird_name(protocol::bgp) == "bgp",
              "protocol_bird_name(bgp) == bgp");
        check(protocol_bird_name(protocol::ospfv2) == "ospf",
              "protocol_bird_name(ospfv2) == ospf");
        check(protocol_bird_name(protocol::ospfv3) == "ospf3",
              "protocol_bird_name(ospfv3) == ospf3");
        check(protocol_bird_name(protocol::babel) == "babel",
              "protocol_bird_name(babel) == babel");
        check(protocol_bird_name(protocol::other) == "unknown",
              "protocol_bird_name(other) == unknown");
        check(protocol_default_admin_distance(protocol::bgp) == 20,
              "BGP admin distance == 20");
        check(protocol_default_admin_distance(protocol::ospfv2) == 110,
              "OSPF admin distance == 110");
    }

    // Instant / Duration — round-trip + checked_sub.
    {
        std::uint64_t i = instant_from_secs(5);
        check(instant_as_secs(i) == 5, "instant_from_secs -> instant_as_secs");
        check(instant_as_millis(i) == 5000, "instant_as_millis == 5000");
        check(instant_saturating_sub(i, instant_from_secs(8)) == 3000,
              "instant_saturating_sub clamps to 0");
        auto sub = instant_checked_sub(instant_from_secs(8),
                                        instant_from_secs(5));
        check(sub.has_value() && *sub == 3000, "instant_checked_sub success");
        auto under = instant_checked_sub(instant_from_secs(5),
                                          instant_from_secs(8));
        check(!under.has_value(), "instant_checked_sub underflow -> nullopt");
        std::uint64_t d = duration_from_secs(5);
        check(duration_as_secs(d) == 5, "duration_from_secs -> duration_as_secs");
        check(duration_as_millis(d) == 5000, "duration_as_millis == 5000");
    }

    // RawRouteKey — with + without source.
    {
        CorePrefix p = CorePrefix::v4({10, 0, 0, 0}, 24);
        auto k = RawRouteKey::make(p, 0x0101);
        check(k.afi_safi() == 0x0101, "RawRouteKey afi_safi == 0x0101");
        check(!k.has_source(), "RawRouteKey no source");
        CorePrefix s = CorePrefix::v4({192, 168, 0, 0}, 24);
        auto ks = RawRouteKey::make_with_source(p, 0x0101, s);
        check(ks.has_source(), "RawRouteKey with source has_source");
        check(ks.source_prefix().is_ipv4(), "RawRouteKey source is_ipv4");
    }

    // Preference — round-trip.
    {
        Preference p(20, 100);
        check(p.admin_distance() == 20, "Preference admin_distance");
        check(p.metric() == 100, "Preference metric");
    }

    // NlriFamily — all 9 constructors.
    {
        check(nlri_family_ipv4_unicast().afi() == 1 &&
              nlri_family_ipv4_unicast().safi() == 1,
              "nlri_family_ipv4_unicast (1, 1)");
        check(nlri_family_ipv6_unicast().afi() == 2 &&
              nlri_family_ipv6_unicast().safi() == 1,
              "nlri_family_ipv6_unicast (2, 1)");
        check(nlri_family_ipv4_multicast().safi() == 2,
              "nlri_family_ipv4_multicast safi == 2");
        check(nlri_family_ipv4_mpls_vpn().safi() == 128,
              "nlri_family_ipv4_mpls_vpn safi == 128");
        check(nlri_family_ipv4_labeled_unicast().is_labeled_unicast(),
              "ipv4_labeled_unicast is_labeled_unicast");
        check(nlri_family_bgp_ls().is_bgp_ls(), "bgp_ls is_bgp_ls");
        check(!nlri_family_bgp_ls().is_bgp_ls_vpn(),
              "bgp_ls NOT is_bgp_ls_vpn");
        check(nlri_family_bgp_ls_vpn().is_bgp_ls(),
              "bgp_ls_vpn is_bgp_ls (matches both)");
        check(nlri_family_bgp_ls_vpn().is_bgp_ls_vpn(),
              "bgp_ls_vpn is_bgp_ls_vpn");
    }

    // NlriFamily — from_addr.
    {
        auto a = make_boxed_ipv4({10, 0, 0, 1});
        auto f = nlri_family_from_addr(a);
        check(f.afi() == 1 && f.safi() == 1,
              "nlri_family_from_addr(v4) == (1, 1)");
        std::array<std::uint8_t, 16> buf{};
        buf[0] = 0xfe;
        buf[1] = 0x80;
        auto b = make_boxed_ipv6(buf);
        auto g = nlri_family_from_addr(b);
        check(g.afi() == 2 && g.safi() == 1,
              "nlri_family_from_addr(v6) == (2, 1)");
    }

    // CRC / Fletcher / OSPF LSA checksum.
    {
        std::vector<std::uint8_t> data = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
        check(crc16_arc(data) == 0xBB3D, "crc16_arc(123456789) == 0xBB3D");
        check(crc32c(data) == 0xE3069283, "crc32c(123456789) == 0xE3069283");
        check(crc16_arc(std::vector<std::uint8_t>{}) == 0,
              "crc16_arc(empty) == 0");
        check(crc32c(std::vector<std::uint8_t>{}) == 0,
              "crc32c(empty) == 0");
        check(fletcher32(std::vector<std::uint8_t>{}) == 0,
              "fletcher32(empty) == 0");
        // OSPF LSA checksum round-trip on a 20-byte header.
        std::vector<std::uint8_t> lsa(20, 0);
        lsa[0] = 0x01;
        std::uint16_t cs = ospf_lsa_checksum(lsa);
        lsa[16] = static_cast<std::uint8_t>((cs >> 8) & 0xFF);
        lsa[17] = static_cast<std::uint8_t>(cs & 0xFF);
        check(ospf_lsa_checksum_ok(lsa), "ospf_lsa_checksum round-trip");
        // Short LSA — checksum 0, ok false.
        std::vector<std::uint8_t> short_lsa(19, 0);
        check(ospf_lsa_checksum(short_lsa) == 0, "ospf_lsa_checksum(short) == 0");
        check(!ospf_lsa_checksum_ok(short_lsa), "ospf_lsa_checksum_ok(short) false");
    }

    // ReadBuf — get_u8 / get_u16_be / chunk.
    {
        std::vector<std::uint8_t> data = {1, 2, 3, 4};
        auto rb = make_read_buf(data);
        check(read_buf_position(rb) == 0, "read_buf_position == 0");
        check(read_buf_remaining(rb) == 4, "read_buf_remaining == 4");
        auto v = read_buf_get_u8(rb);
        check(v.has_value() && *v == 1, "read_buf_get_u8 == 1");
        auto w = read_buf_get_u16_be(rb);
        check(w.has_value() && *w == 0x0203, "read_buf_get_u16_be == 0x0203");
        read_buf_advance(rb, 1);
        check(read_buf_position(rb) == 4, "read_buf_position == 4 after advance");
        auto empty = read_buf_get_u8(rb);
        check(!empty.has_value(), "read_buf_get_u8 exhausted -> nullopt");
    }

    // ReadBuf — chunk does not advance.
    {
        std::vector<std::uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
        auto rb = make_read_buf(data);
        auto chunk = read_buf_chunk(rb);
        check(chunk.size() == 5 && chunk[0] == 'h' && chunk[4] == 'o',
              "read_buf_chunk == 'hello'");
        check(read_buf_position(rb) == 0, "read_buf_chunk does not advance");
    }

    // WriteBuf — put / patch / take_bytes.
    {
        auto wb = make_write_buf(64);
        write_buf_put_u16_be(wb, 0);  // placeholder length
        write_buf_put_bytes(wb, {'p', 'a', 'y', 'l', 'o', 'a', 'd'});
        write_buf_patch(wb, 0, {0x00, 0x07});
        auto out = write_buf_written(wb);
        check(out.size() == 9 && out[0] == 0x00 && out[1] == 0x07 &&
              out[2] == 'p' && out[8] == 'd',
              "write_buf_written == 0x00 0x07 payload");
        auto taken = write_buf_take_bytes(wb);
        check(taken == out, "write_buf_take_bytes == written");
        check(write_buf_position(wb) == 0, "write_buf_position reset after take");
    }

    // WriteBuf — u32 / u64 BE.
    {
        auto wb = make_write_buf(16);
        write_buf_put_u32_be(wb, 0x12345678);
        auto o = write_buf_written(wb);
        check(o.size() == 4 && o[0] == 0x12 && o[3] == 0x78,
              "write_buf_put_u32_be == 12 34 56 78");
        auto wb2 = make_write_buf(16);
        write_buf_put_u64_be(wb2, 0x0102030405060708);
        auto o2 = write_buf_written(wb2);
        check(o2.size() == 8 && o2[0] == 1 && o2[7] == 8,
              "write_buf_put_u64_be == 1..8");
    }

    // TimerQueue — arm + tick + cancel.
    {
        auto tq = make_timer_queue();
        check(timer_queue_is_empty(tq), "timer_queue_is_empty");
        check(timer_queue_len(tq) == 0, "timer_queue_len == 0");
        timer_queue_arm(tq, 0, 1, TimerSpec::once(100));
        check(timer_queue_len(tq) == 1, "timer_queue_len == 1 after arm");
        check(timer_queue_next_fire_ms(tq) == 100,
              "timer_queue_next_fire_ms == 100");
        auto fired1 = timer_queue_tick(tq, 50);
        check(fired1.empty(), "tick(50) no fire");
        auto fired2 = timer_queue_tick(tq, 150);
        check(fired2.size() == 1 && fired2[0] == 1, "tick(150) fires [1]");
        check(timer_queue_is_empty(tq), "timer_queue_is_empty after fire");

        timer_queue_arm(tq, 0, 2, TimerSpec::once(100));
        timer_queue_arm(tq, 0, 3, TimerSpec::once(200));
        timer_queue_cancel(tq, 2);
        check(timer_queue_len(tq) == 1, "timer_queue_len == 1 after cancel");
        timer_queue_cancel_all(tq);
        check(timer_queue_is_empty(tq), "timer_queue_is_empty after cancel_all");
    }

    // TimerQueue — periodic refires.
    {
        auto tq = make_timer_queue();
        timer_queue_arm(tq, 0, 1, TimerSpec::periodic(100, 50));
        auto f1 = timer_queue_tick(tq, 100);
        check(f1.size() == 1 && f1[0] == 1, "periodic tick(100) fires [1]");
        auto f2 = timer_queue_tick(tq, 150);
        check(f2.size() == 1 && f2[0] == 1, "periodic tick(150) fires [1]");
    }

    // MemoryConn — push_input + take_input + put_output + drain_output.
    {
        auto c = make_memory_conn();
        memory_conn_push_input(c, {'h', 'e', 'l', 'l', 'o'});
        auto in = memory_conn_take_input(c);
        check(in.size() == 5 && in[0] == 'h' && in[4] == 'o',
              "memory_conn_take_input == 'hello'");
        auto in2 = memory_conn_take_input(c);
        check(in2.empty(), "memory_conn_take_input empty after drain");
        memory_conn_put_output(c, {'w', 'o', 'r', 'l', 'd'});
        auto out = memory_conn_drain_output(c);
        check(out.size() == 5 && out[0] == 'w' && out[4] == 'd',
              "memory_conn_drain_output == 'world'");
    }

    // MemoryConn — pair returns two independent conns.
    {
        auto pr = make_memory_conn_pair();
        memory_conn_push_input(pr.first, {'f', 'o', 'o'});
        auto in = memory_conn_take_input(pr.first);
        check(in.size() == 3 && in[0] == 'f', "pair a.take_input == 'foo'");
        memory_conn_put_output(pr.second, {'b', 'a', 'r'});
        auto out = memory_conn_drain_output(pr.second);
        check(out.size() == 3 && out[0] == 'b', "pair b.drain_output == 'bar'");
    }

    // -----------------------------------------------------------------
    // namespace gen — auto-generated C++ RAII wrappers (issue #92).
    // Every handle in the C ABI gets a `XHandle = unique_ptr<OpaqueX, XDeleter>`
    // typedef + a `make_X_new(...)` factory function. These tests exercise
    // a representative sample to confirm the generated block compiles and
    // the wrappers round-trip through the C ABI.
    // -----------------------------------------------------------------
    {
        using namespace librouting::gen;

        // BgpCommunity — value-typed constructor + readers (RFC 1997).
        auto c = make_bgpcommunity_new(64512, 100);
        check(static_cast<bool>(c), "gen::make_bgpcommunity_new returns non-null");
        check(asn(c) == 64512, "gen::BgpCommunity.asn() == 64512");
        check(value(c) == 100, "gen::BgpCommunity.value() == 100");

        // BabelHello — value-typed constructor (RFC 8967 §2.3). The
        // per-handle readers (`lr_babel_hello_seqno` etc.) are NOT
        // emitted as wrapper methods in the gen namespace — the C++
        // generator emits only constructors and free functions for
        // non-handle-attached functions. Direct C ABI calls still
        // work via the handle's `.get()` accessor.
        auto h = make_babelhello_new(0xABCD, 200);
        check(static_cast<bool>(h), "gen::make_babelhello_new returns non-null");
        check(lr_babel_hello_seqno(h.get()) == 0xABCD,
              "lr_babel_hello_seqno(BabelHelloHandle) == 0xABCD");

        // BgpCodec — no-arg constructor; handle is freed by RAII on scope exit.
        auto codec = make_bgpcodec_new();
        check(static_cast<bool>(codec), "gen::make_bgpcodec_new returns non-null");

        // LdpLabel — value-typed constructor + reader (called via the
        // raw C ABI; gen namespace doesn't emit handle-attached methods).
        auto lbl = make_ldplabel_new(100);
        check(static_cast<bool>(lbl), "gen::make_ldplabel_new returns non-null");
        check(lr_ldp_label_value(lbl.get()) == 100,
              "lr_ldp_label_value(LdpLabelHandle) == 100");

        // Srv6Sid — uses the struct OpaqueSrv6Sid * -> lr_srv6_sid_t
        // return-type normalization in abi_parse.py. Without that
        // normalization, gen_cpp would not emit the constructor and
        // this line would not compile.
        std::uint8_t sid_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0};
        auto sid = make_srv6sid_new(sid_bytes);
        check(static_cast<bool>(sid), "gen::make_srv6sid_new returns non-null");
    }

    // Router goes out of scope — RAII cleanup runs.
    if (failures == 0) {
        std::printf("ALL PASS\n");
        return 0;
    }
    std::fprintf(stderr, "%d failures\n", failures);
    return 1;
}
