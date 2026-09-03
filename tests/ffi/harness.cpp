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

    // Originate a route: 203.0.113.0/24 via 192.0.2.1
    {
        const std::uint8_t prefix[4] = {203, 0, 113, 0};
        const std::uint8_t nh[4] = {192, 0, 2, 1};
        int rc = lr_router_originate_v4(r.get(), prefix, 24, nh);
        check(rc == 0, "originate_v4");
    }

    // Loc-RIB must now hold exactly one route.
    int64_t n = lr_router_rib_len(r.get());
    check(n == 1, "rib_len == 1 after originate");

    // RIB dump renders the route.
    {
        auto out = std::make_unique<lr_bytes_t>();
        int rc = lr_router_rib_dump(r.get(), out.get());
        check(rc == 0, "rib_dump");
        check(lr_bytes_len(out.get()) > 0, "rib_dump non-empty");
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

    // Router goes out of scope — RAII cleanup runs.
    if (failures == 0) {
        std::printf("ALL PASS\n");
        return 0;
    }
    std::fprintf(stderr, "%d failures\n", failures);
    return 1;
}
