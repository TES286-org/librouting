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

    // Router goes out of scope — RAII cleanup runs.
    if (failures == 0) {
        std::printf("ALL PASS\n");
        return 0;
    }
    std::fprintf(stderr, "%d failures\n", failures);
    return 1;
}
