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

    /* Loc-RIB must now hold exactly one route */
    int64_t n = lr_router_rib_len(r);
    check(n == 1, "rib_len == 1 after originate");

    /* RIB dump renders the route */
    lr_bytes_t dump = {0};
    rc = lr_router_rib_dump(r, &dump);
    check(rc == 0, "rib_dump");
    check(lr_bytes_len(&dump) > 0, "rib_dump non-empty");
    lr_bytes_free(&dump);

    /* No UPDATE is queued for the peer yet: the session has not completed
     * its OPEN/KEEPALIVE handshake, so the route is held in Loc-RIB and
     * will be advertised when the session reaches Established (initial
     * table dump). Egress only to established peers is RFC 4271 behavior. */
    lr_bytes_t upd = {0};
    rc = lr_router_drain_output(r, h, &upd);
    check(rc == 0, "drain_output after originate");
    check(lr_bytes_len(&upd) == 0, "no UPDATE while session unestablished");
    lr_bytes_free(&upd);

    lr_router_destroy(r);
    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "%d failures\n", failures);
    return 1;
}
