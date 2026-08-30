/* lr_harness.c — minimal C test that exercises the lr_ffi C ABI surface.
 * Build (sources BEFORE -l: `ld --as-needed` drops libs that precede the
 * objects referencing them):
 *   cc -Iinclude tests/ffi/harness.c -Ltarget/release -llr_ffi \
 *      -o /tmp/lr_harness
 * Run:
 *   LD_LIBRARY_PATH=target/release /tmp/lr_harness
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lr_ffi.h"

static int failures = 0;
static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    } else {
        printf("ok: %s\n", what);
    }
}

int main(void) {
    /* ABI version */
    uint32_t v = lr_abi_version();
    check(v != 0, "abi_version > 0");

    /* Router lifecycle */
    lr_router_t r = lr_router_new();
    check(r != NULL, "router_new");
    uint64_t h = 0;
    int rc = lr_router_add_bgp_session(r, 64512, 64513, 0x0a000001u, 90, 0, 1, &h);
    check(rc == 0, "add_bgp_session");
    check(h == 1, "session_handle == 1");

    /* Extended session creation (RFC 4724 GR + RFC 9494 LLGR knobs) */
    uint64_t h2 = 0;
    rc = lr_router_add_bgp_session_ext(r, 64512, 64513, 0x0a000001u, 90, 0, 1,
                                       1, 120, 1, 3600, 0, &h2);
    check(rc == 0, "add_bgp_session_ext (GR 120s + LLGR 3600s)");
    check(h2 == 2, "ext session_handle == 2");
    /* A second router to complete a full LLGR handshake against. */
    lr_router_t peer = lr_router_new();
    check(peer != NULL, "peer router_new");
    uint64_t ph = 0;
    rc = lr_router_add_bgp_session_ext(peer, 64513, 64512, 0x0a000002u, 90, 0, 1,
                                       1, 90, 1, 1800, 0, &ph);
    check(rc == 0, "peer add_bgp_session_ext");
    /* Drive the OPEN/KEEPALIVE exchange byte-by-byte. */
    rc = lr_router_start_session(r, h2);
    check(rc == 0, "start ext session");
    rc = lr_router_start_session(peer, ph);
    check(rc == 0, "start peer session");
    lr_bytes_t a_open = {0}, b_open = {0};
    rc = lr_router_drain_output(r, h2, &a_open);
    check(rc == 0, "drain ext OPEN");
    rc = lr_router_drain_output(peer, ph, &b_open);
    check(rc == 0, "drain peer OPEN");
    /* The OPEN must carry the LLGR capability (code 71, RFC 9494). */
    {
        const uint8_t *o = lr_bytes_ptr(&a_open);
        size_t len = lr_bytes_len(&a_open), i;
        int has_llgr = 0;
        for (i = 19; i + 1 < len; i++) {
            if (o[i] == 71 && o[i + 1] == 7) { /* cap 71, len 7 (one tuple) */
                has_llgr = 1;
                break;
            }
        }
        check(has_llgr, "OPEN advertises LLGR capability (code 71)");
    }
    rc = lr_router_feed_input(r, h2, lr_bytes_ptr(&b_open), (size_t)lr_bytes_len(&b_open));
    check(rc == 0, "feed peer OPEN");
    rc = lr_router_feed_input(peer, ph, lr_bytes_ptr(&a_open), (size_t)lr_bytes_len(&a_open));
    check(rc == 0, "feed ext OPEN");
    lr_bytes_free(&a_open);
    lr_bytes_free(&b_open);
    lr_bytes_t a_ka = {0}, b_ka = {0};
    rc = lr_router_drain_output(r, h2, &a_ka);
    check(rc == 0, "drain ext KEEPALIVE");
    rc = lr_router_drain_output(peer, ph, &b_ka);
    check(rc == 0, "drain peer KEEPALIVE");
    rc = lr_router_feed_input(r, h2, lr_bytes_ptr(&b_ka), (size_t)lr_bytes_len(&b_ka));
    check(rc == 0, "feed peer KEEPALIVE");
    rc = lr_router_feed_input(peer, ph, lr_bytes_ptr(&a_ka), (size_t)lr_bytes_len(&a_ka));
    check(rc == 0, "feed ext KEEPALIVE");
    lr_bytes_free(&a_ka);
    lr_bytes_free(&b_ka);
    lr_router_destroy(peer);

    /* Tick once */
    rc = lr_router_tick(r, 0);
    check(rc == 0, "tick");

    /* Keepalive encode — pass a lr_bytes_t storage struct, not a pointer. */
    lr_bytes_t b = {0};
    rc = lr_bgp_encode_keepalive(&b);
    check(rc == 0, "encode_keepalive");
    check(lr_bytes_len(&b) == 19, "keepalive is 19 bytes");
    const uint8_t *p = lr_bytes_ptr(&b);
    check(p != NULL, "keepalive ptr non-null");
    check(p[18] == 4, "keepalive type=4");
    lr_bytes_free(&b);

    /* Drain output — should be empty since we didn't feed input */
    lr_bytes_t out = {0};
    rc = lr_router_drain_output(r, h, &out);
    check(rc == 0, "drain_output");
    lr_bytes_free(&out);

    /* Start session (drives BGP ManualStart + TransportOpen) */
    rc = lr_router_start_session(r, h);
    check(rc == 0, "start_session");

    /* The OPEN message must now be queued for the peer */
    lr_bytes_t open_msg = {0};
    rc = lr_router_drain_output(r, h, &open_msg);
    check(rc == 0, "drain_output after start");
    check(lr_bytes_len(&open_msg) >= 29, "OPEN message queued (>=29 bytes)");
    if (lr_bytes_ptr(&open_msg) != NULL && lr_bytes_len(&open_msg) >= 19) {
        check(lr_bytes_ptr(&open_msg)[18] == 1, "queued message type == OPEN");
    }
    lr_bytes_free(&open_msg);

    /* Originate a route: 203.0.113.0/24 via 192.0.2.1 */
    const uint8_t prefix[4] = {203, 0, 113, 0};
    const uint8_t nh[4] = {192, 0, 2, 1};
    rc = lr_router_originate_v4(r, prefix, 24, nh);
    check(rc == 0, "originate_v4");

    /* RFC 8277 labelled-unicast origination (AFI=1, SAFI=4).
     * Originates 198.51.100.0/24 with label 100, next-hop 192.0.2.1. */
    const uint8_t lu_prefix[4] = {198, 51, 100, 0};
    const uint32_t labels[1] = {100};
    rc = lr_router_originate_labeled_v4(r, lu_prefix, 24, labels, 1, nh);
    check(rc == 0, "originate_labeled_v4 (RFC 8277, label=100)");

    /* A multi-label stack with the implicit-null terminator. */
    const uint32_t stack[3] = {100, 200, 3 /* implicit-null */};
    const uint8_t lu2_prefix[4] = {10, 0, 0, 0};
    rc = lr_router_originate_labeled_v4(r, lu2_prefix, 8, stack, 3, nh);
    check(rc == 0, "originate_labeled_v4 (3-label stack)");

    /* An out-of-range label value (>20 bits) is rejected. */
    const uint32_t bad_labels[1] = {0x100000u /* 2^20 */};
    rc = lr_router_originate_labeled_v4(r, lu_prefix, 24, bad_labels, 1, nh);
    check(rc == -3, "originate_labeled_v4 rejects label > 20 bits");

    /* MPLS platform-labels query (Linux: 0 in CI; lab: 16/20). */
    uint32_t mpls = lr_mpls_platform_labels();
    check(mpls == 0 || mpls == 16 || mpls == 20,
          "lr_mpls_platform_labels returns a known value");

    /* Loc-RIB must now hold exactly three routes (1 plain + 2 labelled). */
    int64_t n = lr_router_rib_len(r);
    check(n == 3, "rib_len == 3 after originate + 2 labelled");

    /* RIB dump renders the route */
    lr_bytes_t dump = {0};
    rc = lr_router_rib_dump(r, &dump);
    check(rc == 0, "rib_dump");
    check(lr_bytes_len(&dump) > 0, "rib_dump non-empty");
    lr_bytes_free(&dump);

    /* Session summary dump: one line per session, machine-parsable */
    lr_bytes_t sdump = {0};
    rc = lr_router_sessions_dump(r, &sdump);
    check(rc == 0, "sessions_dump");
    check(lr_bytes_len(&sdump) > 0, "sessions_dump non-empty");
    lr_bytes_free(&sdump);

    /* No UPDATE is queued for the peer yet: the session has not completed
     * its OPEN/KEEPALIVE handshake, so the route is held in Loc-RIB and
     * will be advertised when the session reaches Established (initial
     * table dump). Egress only to established peers is RFC 4271 behavior. */
    lr_bytes_t upd = {0};
    rc = lr_router_drain_output(r, h, &upd);
    check(rc == 0, "drain_output after originate");
    check(lr_bytes_len(&upd) == 0, "no UPDATE while session unestablished");
    lr_bytes_free(&upd);

    /* RFC 8212 ABI: mode toggle + per-session policy presence. The
     * library default is accept-all (RFC 4271); the mode is opt-in. */
    rc = lr_router_set_ebgp_requires_policy(r, 1);
    check(rc == 0, "set_ebgp_requires_policy(on)");
    rc = lr_router_set_session_policy(r, h, 1, 1);
    check(rc == 0, "set_session_policy(valid handle)");
    rc = lr_router_set_session_policy(r, 999, 1, 1);
    check(rc == -2, "set_session_policy(unknown handle) fails closed");
    rc = lr_router_set_ebgp_requires_policy(r, 0);
    check(rc == 0, "set_ebgp_requires_policy(off)");

    /* FRR `bgp enforce-first-as` (W2.2): router-wide toggle for the
     * leftmost-AS check on eBGP UPDATEs. Library default is off. */
    rc = lr_router_set_enforce_first_as(r, 1);
    check(rc == 0, "set_enforce_first_as(on)");
    rc = lr_router_set_enforce_first_as(r, 0);
    check(rc == 0, "set_enforce_first_as(off)");

    /* FRR `bgp default ipv4-unicast` (W2.1): per-session toggle for
     * implicit IPv4 unicast activation. Library default is on. */
    rc = lr_router_set_default_ipv4_unicast(r, h, 0);
    check(rc == 0, "set_default_ipv4_unicast(off) on valid handle");
    rc = lr_router_set_default_ipv4_unicast(r, h, 1);
    check(rc == 0, "set_default_ipv4_unicast(on) on valid handle");
    rc = lr_router_set_default_ipv4_unicast(r, 999, 1);
    check(rc == -2, "set_default_ipv4_unicast on unknown handle fails closed");

    /* FRR `neighbor X allowas-in N` / BIRD `allow local as` (W2.3):
     * per-session tolerance for the local AS in a received AS_PATH.
     * Library default is 0 (reject any). */
    rc = lr_router_set_local_as_tolerance(r, h, 1);
    check(rc == 0, "set_local_as_tolerance(1) on valid handle");
    rc = lr_router_set_local_as_tolerance(r, h, 0);
    check(rc == 0, "set_local_as_tolerance(0) on valid handle");
    rc = lr_router_set_local_as_tolerance(r, 999, 1);
    check(rc == -2, "set_local_as_tolerance on unknown handle fails closed");

    /* FRR `neighbor X soft-reconfiguration inbound` (W2.4):
     * per-session toggle for pre-policy Adj-RIB-In retention.
     * Library default is off. */
    rc = lr_router_set_soft_reconfig_inbound(r, h, 1);
    check(rc == 0, "set_soft_reconfig_inbound(on) on valid handle");
    rc = lr_router_set_soft_reconfig_inbound(r, h, 0);
    check(rc == 0, "set_soft_reconfig_inbound(off) on valid handle");
    rc = lr_router_set_soft_reconfig_inbound(r, 999, 1);
    check(rc == -2, "set_soft_reconfig_inbound on unknown handle fails closed");

    /* soft_reconfig_inbound on a session with the flag off is a
     * no-op (returns 0). An unknown session is also a no-op (returns
     * 0) — the pre-policy RIB is empty for that origin. */
    int64_t soft_n = lr_router_soft_reconfig_inbound(r, h);
    check(soft_n == 0, "soft_reconfig_inbound no-op when flag is off");
    soft_n = lr_router_soft_reconfig_inbound(r, 999);
    check(soft_n == 0, "soft_reconfig_inbound no-op on unknown handle");

    lr_router_destroy(r);
    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "%d failures\n", failures);
    return 1;
}
