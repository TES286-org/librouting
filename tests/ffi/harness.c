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

/* ROA-state override used by the filter-context callback table
 * (D5.2): pretend every route is RFC 6811 invalid. */
static uint8_t roa_always_invalid(void *ud, lr_route_t r) {
    (void)ud; (void)r;
    return LR_ROA_INVALID;
}
static lr_filter_context_t roa_invalid_ctx = {
    .user_data = NULL,
    .roa_state = roa_always_invalid,
};
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

    /* D5.4 encoder surface: OPEN / NOTIFICATION / UPDATE. */
    lr_bytes_t enc = {0};
    const uint8_t rid[4] = {10, 0, 0, 1};
    rc = lr_bgp_encode_open(64512, 90, rid, 1, &enc);
    check(rc == 0, "encode_open");
    check(lr_bytes_ptr(&enc)[18] == 1, "open type=1");
    check(lr_bytes_len(&enc) > 29, "open carries optional parameters");
    lr_bytes_free(&enc);
    rc = lr_bgp_encode_open(4200000000u, 90, rid, 0, &enc);
    check(rc == -3, "encode_open rejects a 4-byte AS with as4 off");
    rc = lr_bgp_encode_open(64512, 1, rid, 0, &enc);
    check(rc == -3, "encode_open rejects hold time 1");

    rc = lr_bgp_encode_notification(6, 3, NULL, 0, &enc);
    check(rc == 0, "encode_notification");
    check(lr_bytes_ptr(&enc)[18] == 3, "notification type=3");
    check(lr_bytes_len(&enc) == 21, "notification without data is 21 bytes");
    lr_bytes_free(&enc);
    const uint8_t notif_data[2] = {1, 2};
    rc = lr_bgp_encode_notification(2, 4, notif_data, 2, &enc);
    check(rc == 0, "encode_notification with data");
    check(lr_bytes_len(&enc) == 23, "notification data rides the body");
    lr_bytes_free(&enc);

    struct lr_prefix_t w[2];
    memset(w, 0, sizeof(w));
    w[0].addr[0] = 203; w[0].addr[1] = 0; w[0].addr[2] = 113; w[0].addr[3] = 0;
    w[0].prefix_len = 24;
    w[1].addr[0] = 198; w[1].addr[1] = 51; w[1].addr[2] = 100; w[1].addr[3] = 0;
    w[1].prefix_len = 24;
    rc = lr_bgp_encode_update_withdraw_v4(w, 2, &enc);
    check(rc == 0, "encode_update_withdraw_v4");
    check(lr_bytes_ptr(&enc)[18] == 2, "update type=2");
    check(lr_bytes_len(&enc) == 31, "withdraw update: 2 prefixes, no attrs");
    lr_bytes_free(&enc);
    rc = lr_bgp_encode_update_withdraw_v4(NULL, 0, &enc);
    check(rc == 0, "encode_update_withdraw_v4 with zero prefixes");
    lr_bytes_free(&enc);

    struct lr_prefix_t ann[1];
    memset(ann, 0, sizeof(ann));
    ann[0].addr[0] = 203; ann[0].addr[1] = 0; ann[0].addr[2] = 113; ann[0].addr[3] = 0;
    ann[0].prefix_len = 24;
    const uint8_t enc_nh[4] = {192, 0, 2, 1};
    const uint32_t ases[2] = {64513, 64512};
    rc = lr_bgp_encode_update_announce_v4(ann, 1, enc_nh, ases, 2, 0, 0, &enc);
    check(rc == 0, "encode_update_announce_v4");
    check(lr_bytes_ptr(&enc)[18] == 2, "announce update type=2");
    check(lr_bytes_len(&enc) > 31, "announce update carries attributes + NLRI");
    lr_bytes_free(&enc);
    rc = lr_bgp_encode_update_announce_v4(ann, 1, enc_nh, NULL, 0, 3, 0, &enc);
    check(rc == -3, "announce rejects ORIGIN 3");
    struct lr_prefix_t v6p;
    memset(&v6p, 0, sizeof(v6p));
    v6p.addr[0] = 0x20; v6p.addr[1] = 0x01; v6p.addr[2] = 0x0d; v6p.addr[3] = 0xb8;
    v6p.is_ipv6 = 1;
    v6p.prefix_len = 32;
    rc = lr_bgp_encode_update_withdraw_v4(&v6p, 1, &enc);
    check(rc == -3, "withdraw rejects IPv6 in the legacy NLRI section");

    /* Structured BGP message inspection — decode the encoded bytes
     * back into an owned lr_bgp_message_t and read the variant
     * fields. Mirrors tests/ffi/harness.cpp's RAII test block. */
    {
        /* OPEN with 4-byte AS: reader must surface the real AS. */
        rc = lr_bgp_encode_open(4200000000u, 180, rid, 1, &enc);
        check(rc == 0, "encode_open for inspection");
        lr_bgp_message_t m = lr_bgp_decode_message(lr_bytes_ptr(&enc), lr_bytes_len(&enc));
        check(m != NULL, "decode_message OPEN returns non-null handle");
        uint8_t kind = 0;
        check(lr_bgp_message_type(m, &kind) == 0, "lr_bgp_message_type OPEN");
        check(kind == LR_BGP_MSG_OPEN, "decoded kind == OPEN");
        uint8_t ver = 0;
        check(lr_bgp_message_open_version(m, &ver) == 0, "open_version");
        check(ver == 4, "OPEN version 4");
        uint32_t asn = 0;
        check(lr_bgp_message_open_my_as(m, &asn) == 0, "open_my_as");
        check(asn == 4200000000u, "OPEN my_as unwraps AS_TRANS → 4-byte AS");
        uint16_t hold = 0;
        check(lr_bgp_message_open_hold_time(m, &hold) == 0, "open_hold_time");
        check(hold == 180, "OPEN hold time 180");
        uint8_t id[4] = {0};
        check(lr_bgp_message_open_bgp_id(m, id) == 0, "open_bgp_id");
        check(id[0] == 10 && id[1] == 0 && id[2] == 0 && id[3] == 1,
              "OPEN bgp_id == 10.0.0.1");
        /* Exactly one optional parameter — the capabilities TLV
         * carrying the Four-Octet-AS capability (code 65, len 4). */
        check(lr_bgp_message_open_param_count(m) == 1, "OPEN has one optional parameter");
        uint8_t ptype = 0;
        lr_bytes_t pval = {0};
        check(lr_bgp_message_open_param_at(m, 0, &ptype, &pval) == 0, "open_param_at(0)");
        check(ptype == 2, "OPEN param type 2 (capabilities, RFC 5492)");
        check(lr_bytes_len(&pval) >= 6, "OPEN capabilities payload >= 6 bytes");
        check(lr_bytes_ptr(&pval)[0] == 65, "OPEN capability code 65 (Four-Octet-AS)");
        check(lr_bytes_ptr(&pval)[1] == 4, "OPEN capability length 4");
        uint32_t cap_as = ((uint32_t)lr_bytes_ptr(&pval)[2] << 24) |
                         ((uint32_t)lr_bytes_ptr(&pval)[3] << 16) |
                         ((uint32_t)lr_bytes_ptr(&pval)[4] << 8) |
                         (uint32_t)lr_bytes_ptr(&pval)[5];
        check(cap_as == 4200000000u, "OPEN capability carries the real 4-byte AS");
        lr_bytes_free(&pval);
        /* Out-of-range param returns LR_ERR_OTHER (-6). */
        check(lr_bgp_message_open_param_at(m, 99, &ptype, &pval) == -6,
              "open_param_at(99) returns LR_ERR_OTHER");
        /* Variant mismatch reader returns LR_ERR_INVALID_HANDLE (-2). */
        check(lr_bgp_message_notification_code(m, &ver) == -2,
              "notification_code on OPEN returns LR_ERR_INVALID_HANDLE");
        lr_bgp_message_free(m);
        lr_bytes_free(&enc);

        /* NOTIFICATION with diagnostic data. */
        const uint8_t notif_data2[4] = {0xde, 0xad, 0xbe, 0xef};
        rc = lr_bgp_encode_notification(1, 2, notif_data2, 4, &enc);
        check(rc == 0, "encode_notification for inspection");
        lr_bgp_message_t nm = lr_bgp_decode_message(lr_bytes_ptr(&enc), lr_bytes_len(&enc));
        check(nm != NULL, "decode_message NOTIFICATION returns non-null");
        check(lr_bgp_message_type(nm, &kind) == 0, "lr_bgp_message_type NOTIFICATION");
        check(kind == LR_BGP_MSG_NOTIFICATION, "decoded kind == NOTIFICATION");
        uint8_t code = 0, sub = 0;
        check(lr_bgp_message_notification_code(nm, &code) == 0, "notification_code");
        check(lr_bgp_message_notification_subcode(nm, &sub) == 0, "notification_subcode");
        check(code == 1, "NOTIFICATION code 1 (Header)");
        check(sub == 2, "NOTIFICATION subcode 2 (Conn-Not-Sync)");
        lr_bytes_t ndata = {0};
        check(lr_bgp_message_notification_data(nm, &ndata) == 0, "notification_data");
        check(lr_bytes_len(&ndata) == 4, "NOTIFICATION data 4 bytes");
        check(lr_bytes_ptr(&ndata)[0] == 0xde && lr_bytes_ptr(&ndata)[3] == 0xef,
              "NOTIFICATION data round-trips");
        lr_bytes_free(&ndata);
        lr_bgp_message_free(nm);
        lr_bytes_free(&enc);

        /* Withdraw-only UPDATE: two prefixes, zero attributes. */
        rc = lr_bgp_encode_update_withdraw_v4(w, 2, &enc);
        check(rc == 0, "encode_update_withdraw_v4 for inspection");
        lr_bgp_message_t um = lr_bgp_decode_message(lr_bytes_ptr(&enc), lr_bytes_len(&enc));
        check(um != NULL, "decode_message UPDATE returns non-null");
        check(lr_bgp_message_type(um, &kind) == 0, "lr_bgp_message_type UPDATE");
        check(kind == LR_BGP_MSG_UPDATE, "decoded kind == UPDATE");
        check(lr_bgp_message_update_withdrawn_count(um) == 2, "UPDATE 2 withdrawn");
        check(lr_bgp_message_update_nlri_count(um) == 0, "UPDATE withdraw-only no NLRI");
        check(lr_bgp_message_update_attr_count(um) == 0, "UPDATE withdraw-only 0 attrs");
        lr_prefix_t got = {0};
        check(lr_bgp_message_update_withdrawn_at(um, 0, &got) == 0, "withdrawn_at(0)");
        check(got.addr[0] == 203 && got.prefix_len == 24, "withdrawn[0] = 203.0.113.0/24");
        check(lr_bgp_message_update_withdrawn_at(um, 1, &got) == 0, "withdrawn_at(1)");
        check(got.addr[0] == 198 && got.prefix_len == 24, "withdrawn[1] = 198.51.100.0/24");
        check(lr_bgp_message_update_withdrawn_at(um, 99, &got) == -6,
              "withdrawn_at(99) returns LR_ERR_OTHER");
        lr_bgp_message_free(um);
        lr_bytes_free(&enc);

        /* KEEPALIVE: variant tag only. */
        rc = lr_bgp_encode_keepalive(&enc);
        check(rc == 0, "encode_keepalive for inspection");
        lr_bgp_message_t km = lr_bgp_decode_message(lr_bytes_ptr(&enc), lr_bytes_len(&enc));
        check(km != NULL, "decode_message KEEPALIVE returns non-null");
        check(lr_bgp_message_type(km, &kind) == 0, "lr_bgp_message_type KEEPALIVE");
        check(kind == LR_BGP_MSG_KEEPALIVE, "decoded kind == KEEPALIVE");
        lr_bgp_message_free(km);
        lr_bytes_free(&enc);
    }

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

    /* IPv6 origination (AFI=2, SAFI=1) + the withdraw lifecycle
     * (ROADMAP-v3 D5.6/D5.7). */
    const uint8_t v6_prefix[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t v6_nh[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0x01};
    rc = lr_router_withdraw_v6(r, v6_prefix, 32);
    check(rc == 1, "withdraw_v6 on a non-originated prefix is a no-op (rc=1)");
    rc = lr_router_originate_v6(r, v6_prefix, 32, v6_nh);
    check(rc == 0, "originate_v6 (2001:db8::/32)");
    rc = lr_router_withdraw_v4(r, prefix, 24);
    check(rc == 0, "withdraw_v4 of the plain origination");
    rc = lr_router_withdraw_v4(r, prefix, 24);
    check(rc == 1, "repeat withdraw_v4 is a no-op (rc=1)");
    rc = lr_router_withdraw_v6(r, v6_prefix, 32);
    check(rc == 0, "withdraw_v6 of the v6 origination");
    rc = lr_router_withdraw_v6(r, v6_prefix, 129);
    check(rc == -3, "withdraw_v6 rejects prefix length 129");

    /* Static routes (BIRD `protocol static`, FRR `ip route`). */
    /* install_static_v4 with a real next-hop. */
    rc = lr_router_install_static_v4(r, prefix, 24, nh, 10, 0);
    check(rc == 0, "install_static_v4 203.0.113.0/24 via 192.0.2.1 metric=10");
    /* install_static_v4 as a blackhole (NULL next-hop). */
    const uint8_t bh_prefix[4] = {10, 0, 0, 0};
    rc = lr_router_install_static_v4(r, bh_prefix, 8, NULL, 0, 65000);
    check(rc == 0, "install_static_v4 10.0.0.0/8 blackhole metric=0 tag=65000");
    /* install_static_v6 with a real next-hop. */
    rc = lr_router_install_static_v6(r, v6_prefix, 32, v6_nh, 0, 0);
    check(rc == 0, "install_static_v6 2001:db8::/32 via fe80::1");
    /* Bad prefix length is rejected before the Loc-RIB is touched. */
    rc = lr_router_install_static_v4(r, prefix, 33, nh, 0, 0);
    check(rc == -3, "install_static_v4 rejects prefix length 33");
    rc = lr_router_install_static_v6(r, v6_prefix, 129, v6_nh, 0, 0);
    check(rc == -3, "install_static_v6 rejects prefix length 129");
    /* NULL prefix pointer is rejected. */
    rc = lr_router_install_static_v4(r, NULL, 24, nh, 0, 0);
    check(rc == -1, "install_static_v4 rejects NULL prefix");
    /* uninstall_static_v4 of an installed route succeeds (rc=0). */
    rc = lr_router_uninstall_static_v4(r, prefix, 24);
    check(rc == 0, "uninstall_static_v4 of an installed route");
    /* uninstall_static_v4 of a never-installed prefix is a no-op (rc=1). */
    const uint8_t absent[4] = {198, 51, 100, 0};
    rc = lr_router_uninstall_static_v4(r, absent, 24);
    check(rc == 1, "uninstall_static_v4 of an absent prefix is a no-op (rc=1)");
    /* uninstall_static_v6 of an installed route succeeds (rc=0). */
    rc = lr_router_uninstall_static_v6(r, v6_prefix, 32);
    check(rc == 0, "uninstall_static_v6 of an installed route");
    /* uninstall_static_v4 of the blackhole route (left for last). */
    rc = lr_router_uninstall_static_v4(r, bh_prefix, 8);
    check(rc == 0, "uninstall_static_v4 of the blackhole route");
    /* uninstall_static_v4 of the already-removed v4 route is a no-op. */
    rc = lr_router_uninstall_static_v4(r, prefix, 24);
    check(rc == 1, "uninstall_static_v4 of an already-removed route (rc=1)");

    /* MPLS platform-labels query (Linux: 0 in CI; lab: 16/20). */
    uint32_t mpls = lr_mpls_platform_labels();
    check(mpls == 0 || mpls == 16 || mpls == 20,
          "lr_mpls_platform_labels returns a known value");

    /* Loc-RIB must now hold exactly the two labelled routes (the plain
     * v4 and v6 origins were withdrawn above). */
    int64_t n = lr_router_rib_len(r);
    check(n == 2, "rib_len == 2 after the withdraw lifecycle");

    /* D5.5 event polling: the whole originate/withdraw lifecycle
     * surfaces as events. Drain in batches of 8 — the queue is longer
     * than one batch (4 installs + 2 withdraws + advertisements), which
     * exercises the requeue path implicitly. */
    {
        lr_event_t ev[8];
        int saw_installed = 0, saw_withdrawn = 0, sane_plen = 1;
        int total = 0, nev;
        while ((nev = lr_router_poll_events(r, ev, 8)) > 0) {
            for (int i = 0; i < nev; i++) {
                total++;
                if (ev[i].kind == LR_EVENT_ROUTE_INSTALLED) {
                    saw_installed = 1;
                    if (ev[i].prefix_len > 32) sane_plen = 0;
                }
                if (ev[i].kind == LR_EVENT_ROUTE_WITHDRAWN) saw_withdrawn = 1;
            }
        }
        check(total >= 6, "the lifecycle produced >= 6 events");
        check(saw_installed, "RouteInstalled event observed");
        check(saw_withdrawn, "RouteWithdrawn event observed");
        check(sane_plen, "installed events carry sane prefix lengths");
        /* The queue is now empty. */
        check(lr_router_poll_events(r, ev, 8) == 0, "poll_events empty after drain");
        /* cap 0 with NULL is a legal no-op poll. */
        check(lr_router_poll_events(r, NULL, 0) == 0, "poll_events cap=0 is a no-op");
        /* Negative capacity / NULL buffer are rejected. */
        check(lr_router_poll_events(r, NULL, -1) == -3, "poll_events rejects negative cap");
        check(lr_router_poll_events(r, NULL, 4) == -1, "poll_events rejects NULL buffer");
        /* Requeue semantics: generate two events, poll one at a time. */
        const uint8_t more1[4] = {198, 51, 100, 0};
        const uint8_t more2[4] = {203, 0, 113, 0};
        rc = lr_router_originate_v4(r, more1, 24, NULL);
        check(rc == 0, "originate for requeue test 1");
        rc = lr_router_originate_v4(r, more2, 24, NULL);
        check(rc == 0, "originate for requeue test 2");
        lr_event_t slot[1];
        check(lr_router_poll_events(r, slot, 1) == 1, "one slot takes one event");
        uint8_t first_prefix[4] = {slot[0].prefix[0], slot[0].prefix[1],
                                    slot[0].prefix[2], slot[0].prefix[3]};
        int drained = 1;
        while (lr_router_poll_events(r, slot, 1) > 0) drained++;
        check(drained >= 2, "the requeued remainder arrives on later polls");
        check(first_prefix[0] != 0 || first_prefix[1] != 0,
              "the first polled event carried a prefix");
    }

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

    /* ---- ROA store (RFC 6482 / RFC 6811 / RFC 8210, ROADMAP-v3
     * D2.3): a live, thread-safe ROA database with static + RTR
     * layers and atomic snapshot swaps. ---- */
    {
        lr_roa_store_t s = lr_roa_store_new();
        check(s != NULL, "roa_store_new");
        check(lr_roa_store_len(s) == 0, "roa_store empty at start");

        /* Static layer: 198.51.100.0/24-24 AS64513 exact and
         * 203.0.113.0/24-26 AS64512 (max_length authorizes /25-/26). */
        lr_roa_entry_t entries[2];
        memset(entries, 0, sizeof(entries));
        /* 198.51.100.0 */
        entries[0].addr[0] = 198; entries[0].addr[1] = 51;
        entries[0].addr[2] = 100; entries[0].addr[3] = 0;
        entries[0].is_ipv6 = 0;
        entries[0].prefix_len = 24; entries[0].max_length = 24;
        entries[0].asn = 64513;
        /* 203.0.113.0 */
        entries[1].addr[0] = 203; entries[1].addr[1] = 0;
        entries[1].addr[2] = 113; entries[1].addr[3] = 0;
        entries[1].is_ipv6 = 0;
        entries[1].prefix_len = 24; entries[1].max_length = 26;
        entries[1].asn = 64512;
        rc = lr_roa_store_replace_static(s, entries, 2);
        check(rc == 0, "roa_store_replace_static");
        check(lr_roa_store_len(s) == 2, "roa_store_len == 2 after replace");

        /* RFC 6811 §2 validation outcomes. */
        uint8_t v4a[4] = {198, 51, 100, 0};
        uint8_t v4b[4] = {203, 0, 113, 0};
        uint8_t state = 255;
        rc = lr_roa_store_validate(s, v4a, NULL, 24, 64513, 1, &state);
        check(rc == 0 && state == LR_ROA_VALID, "roa_validate valid origin");
        rc = lr_roa_store_validate(s, v4a, NULL, 24, 64512, 1, &state);
        check(rc == 0 && state == LR_ROA_INVALID, "roa_validate wrong origin");
        rc = lr_roa_store_validate(s, v4b, NULL, 27, 64512, 1, &state);
        check(rc == 0 && state == LR_ROA_INVALID,
              "roa_validate prefix longer than max_length");
        rc = lr_roa_store_validate(s, v4b, NULL, 26, 64512, 1, &state);
        check(rc == 0 && state == LR_ROA_VALID,
              "roa_validate max_length authorizes more-specific");
        rc = lr_roa_store_validate(s, v4b, NULL, 24, 0, 0, &state);
        check(rc == 0 && state == LR_ROA_NOT_FOUND,
              "roa_validate without origin AS is not-found");

        /* RTR layer: one announce delta (192.0.2.0/24-24 AS64512) +
         * a duplicate that must coalesce (RFC 8210 §5.6). */
        lr_roa_delta_t deltas[2];
        memset(deltas, 0, sizeof(deltas));
        deltas[0].announce = 1;
        deltas[0].entry.addr[0] = 192; deltas[0].entry.addr[1] = 0;
        deltas[0].entry.addr[2] = 2;   deltas[0].entry.addr[3] = 0;
        deltas[0].entry.is_ipv6 = 0;
        deltas[0].entry.prefix_len = 24; deltas[0].entry.max_length = 24;
        deltas[0].entry.asn = 64512;
        deltas[1] = deltas[0];
        rc = lr_roa_store_apply_deltas(s, deltas, 2);
        check(rc == 0, "roa_store_apply_deltas");
        check(lr_roa_store_len(s) == 3, "roa_store_len == 3 (2 static + 1 rtr)");

        /* Data expiry (RFC 8210 §6): the cache layer goes, the
         * static layer survives. */
        rc = lr_roa_store_clear_rtr(s);
        check(rc == 0, "roa_store_clear_rtr");
        check(lr_roa_store_len(s) == 2, "roa_store_len == 2 after clear_rtr");

        /* A malformed entry fails the whole batch atomically. */
        lr_roa_delta_t bad = deltas[0];
        bad.entry.max_length = 4; /* < prefix_len 24 (RFC 6482 §3.3) */
        rc = lr_roa_store_apply_deltas(s, &bad, 1);
        check(rc != 0, "roa_store_apply_deltas rejects max_length < prefix_len");
        check(lr_roa_store_len(s) == 2, "roa_store unchanged after failed batch");

        lr_roa_store_free(s);
        lr_roa_store_free(NULL); /* no-op */
        check(1, "roa_store_free");
    }

    /* ===== D4.4 — redistribution / aggregation / damping ===== */
    {
        /* Redistribution pipe: OSPF -> BGP, fixed metric, tag, and
         * an allow-list covering 10.0.0.0/8. */
        lr_prefix_t allow;
        memset(&allow, 0, sizeof(allow));
        allow.addr[0] = 10;
        allow.is_ipv6 = 0;
        allow.prefix_len = 8;
        rc = lr_router_add_redistribution_pipe(
            r, LR_PROTO_OSPF, LR_PROTO_BGP, LR_METRIC_FIXED, 100, 1, 65000, &allow, 1);
        check(rc == 0, "add_redistribution_pipe ospf->bgp");
        rc = lr_router_add_redistribution_pipe(
            r, 99, LR_PROTO_BGP, LR_METRIC_INHERIT, 0, 0, 0, NULL, 0);
        check(rc == -3, "add_redistribution_pipe rejects unknown protocol id");

        /* Aggregates: add, remove, malformed length rejected. */
        lr_prefix_t agg;
        memset(&agg, 0, sizeof(agg));
        agg.addr[0] = 203; agg.addr[1] = 0; agg.addr[2] = 113;
        agg.prefix_len = 24;
        rc = lr_router_add_aggregate(r, &agg);
        check(rc == 0, "add_aggregate");
        rc = lr_router_remove_aggregate(r, &agg);
        check(rc == 0, "remove_aggregate");
        lr_prefix_t badp;
        memset(&badp, 0, sizeof(badp));
        badp.prefix_len = 33;
        rc = lr_router_add_aggregate(r, &badp);
        check(rc == -3, "add_aggregate rejects prefix_len > 32");
        rc = lr_router_add_aggregate(r, NULL);
        check(rc == -1, "add_aggregate rejects NULL");
    }
    {
        /* Damping: install with RFC 2439 defaults, decay an idle
         * table, then destroy the handle. */
        lr_damping_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.additive_incr = 1000;
        cfg.suppress_threshold = 2000;
        cfg.reuse_threshold = 750;
        cfg.upper_limit = 60000;
        cfg.decay_interval_s = 30;
        cfg.decay_factor_active = 0.97;
        cfg.decay_factor_withdrawn = 0.5;
        lr_damping_t d = lr_router_set_damping(r, &cfg);
        check(d != NULL, "set_damping returns handle");
        int32_t reemerged = lr_damping_decay(d, 1000);
        check(reemerged == 0, "damping decay on idle table");
        lr_damping_destroy(d);
        lr_damping_destroy(NULL); /* no-op */
        check(1, "damping_destroy");
    }
    {
        /* OSPFv2/OSPFv3/Babel session management (ROADMAP-v3 D5.1):
         * defaults, the full ext knob set, the enum rejection matrix
         * and a Babel interface in both address families. */
        uint64_t oh = 0;
        rc = lr_router_add_ospf_session(r, 0x0a000001u, 0, &oh);
        check(rc == 0, "add_ospf_session defaults");
        check(oh != 0, "ospf session handle assigned");

        uint64_t oh3 = 0;
        rc = lr_router_add_ospfv3_session(r, 0x0a000001u, 3, &oh3);
        check(rc == 0, "add_ospfv3_session defaults (area 3: areas are version-exclusive)");

        /* A second OSPF router-id is rejected by the router. */
        uint64_t ohbad = 0;
        rc = lr_router_add_ospf_session(r, 0x0a000002u, 5, &ohbad);
        check(rc == -3, "add_ospf_session rejects router-id mismatch");

        /* Full knobs: totally-NSSA area 1 with the segment identities,
         * broadcast network type. */
        uint64_t ohx = 0;
        rc = lr_router_add_ospf_session_ext(r, LR_OSPF_V2, 0x0a000001u, 1,
                                            LR_AREA_NSSA_NO_SUMMARY, 1000, 1500,
                                            LR_NET_BROADCAST, 1, 0x0a000101u,
                                            1, 0x0a000102u, &ohx);
        check(rc == 0, "add_ospf_session_ext totally-NSSA + broadcast");

        /* RFC 2328 §3.6: the backbone can never be a stub. */
        rc = lr_router_add_ospf_session_ext(r, LR_OSPF_V2, 0x0a000001u, 0,
                                            LR_AREA_STUB, 1000, 1500, LR_NET_PTP,
                                            0, 0, 0, 0, &ohbad);
        check(rc == -3, "add_ospf_session_ext rejects backbone stub");

        /* Unknown enums fail closed. */
        rc = lr_router_add_ospf_session_ext(r, 4, 1, 0, LR_AREA_NORMAL, 0, 1500,
                                            LR_NET_PTP, 0, 0, 0, 0, &ohbad);
        check(rc == -3, "add_ospf_session_ext rejects version 4");
        rc = lr_router_add_ospf_session_ext(r, LR_OSPF_V3, 1, 3, 9, 0, 1500,
                                            LR_NET_PTP, 0, 0, 0, 0, &ohbad);
        check(rc == -3, "add_ospf_session_ext rejects area kind 9");
        rc = lr_router_add_ospf_session_ext(r, LR_OSPF_V3, 1, 3, LR_AREA_NORMAL, 0,
                                            1500, 7, 0, 0, 0, 0, &ohbad);
        check(rc == -3, "add_ospf_session_ext rejects network type 7");
        rc = lr_router_add_ospf_session_ext(r, LR_OSPF_V3, 1, 3, LR_AREA_NORMAL, 0,
                                            1500, LR_NET_PTP, 0, 0, 0, 0, NULL);
        check(rc == -1, "add_ospf_session_ext rejects NULL out_handle");

        /* Babel: one IPv6 link-local interface and one IPv4 interface
         * (v4 in the first four bytes, is_ipv6 = 0). */
        uint64_t bh = 0;
        const unsigned char ll6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                       0,    0,    0, 0, 0, 0, 0, 1};
        rc = lr_router_add_babel_session(r, ll6, 1, &bh);
        check(rc == 0, "add_babel_session v6");
        const unsigned char v4[4] = {192, 0, 2, 1};
        rc = lr_router_add_babel_session(r, v4, 0, &bh);
        check(rc == 0, "add_babel_session v4");
        rc = lr_router_add_babel_session(r, ll6, 1, NULL);
        check(rc == -1, "add_babel_session rejects NULL out_handle");

        /* The new sessions surface in the session dump. */
        lr_bytes_t dump = {0};
        rc = lr_router_sessions_dump(r, &dump);
        check(rc == 0, "sessions_dump");
        const char *text = (const char *)lr_bytes_ptr(&dump);
        check(strstr(text, "ospf") != NULL && strstr(text, "babel") != NULL,
              "session dump lists ospf + babel");
        lr_bytes_free(&dump);
    }
    {
        /* Policy objects (ROADMAP-v3 D5.3): route handle round trip,
         * prefix-list first-match semantics, the FRR route-map flow
         * (resolver + match + set + verdict) and the rejection
         * matrix. */
        const unsigned char p4[4] = {203, 0, 113, 0};
        lr_route_t rt = lr_route_new_v4(p4, 24, LR_PROTO_BGP);
        check(rt != NULL, "route_new_v4");

        /* Attribute round trip. */
        unsigned char nh[16] = {0};
        nh[0] = 192; nh[1] = 0; nh[2] = 2; nh[3] = 1;
        check(lr_route_set_next_hop(rt, nh, 0) == 0, "route_set_next_hop v4");
        unsigned char got[16] = {0};
        int32_t is_v6 = -1;
        check(lr_route_next_hop(rt, got, &is_v6) == 0 && is_v6 == 0,
              "route_next_hop reads back");
        check(lr_route_set_local_pref(rt, 250) == 0, "route_set_local_pref");
        uint32_t lp = 0;
        check(lr_route_local_pref(rt, &lp) == 0 && lp == 250, "local_pref round trip");
        check(lr_route_set_origin(rt, LR_ORIGIN_IGP) == 0, "route_set_origin");
        check(lr_route_set_origin(rt, 7) == -3, "route_set_origin rejects 7");

        /* AS_PATH: probe-then-read. */
        const uint32_t path[3] = {64513, 65010, 64512};
        check(lr_route_set_as_path(rt, path, 3) == 0, "route_set_as_path");
        check(lr_route_as_path(rt, NULL, 0) == 3, "as_path length probe");
        uint32_t gp[3] = {0};
        check(lr_route_as_path(rt, gp, 2) == -3, "as_path rejects a short buffer");
        check(lr_route_as_path(rt, gp, 3) == 3 && gp[1] == 65010, "as_path round trip");

        /* Standard communities, packed asn<<16|val. */
        const uint64_t comms[2] = {(64512ull << 16) | 100, (65000ull << 16) | 7};
        check(lr_route_set_communities(rt, comms, 2) == 0, "route_set_communities");
        check(lr_route_add_community(rt, 4294967295u, 1) == -3,
              "add_community rejects a 4-byte ASN");
        check(lr_route_communities(rt, NULL, 0) == 2, "communities length probe");

        /* Prefix-list: 10.0.0.0/8 ge 16 le 24 permit. */
        lr_prefix_list_t pl = lr_prefix_list_new();
        check(pl != NULL, "prefix_list_new");
        lr_prefix_t p8;
        memset(&p8, 0, sizeof(p8));
        p8.addr[0] = 10;
        p8.prefix_len = 8;
        check(lr_prefix_list_add(pl, &p8, 16, 24, 1) == 0, "prefix_list_add");
        lr_prefix_t inside;
        memset(&inside, 0, sizeof(inside));
        inside.addr[0] = 10; inside.addr[1] = 1; inside.prefix_len = 24;
        lr_prefix_t shorter = inside; shorter.prefix_len = 8;
        lr_prefix_t longer = inside; longer.prefix_len = 25;
        check(lr_prefix_list_match(pl, &inside) == 1, "prefix_list permits in-range");
        check(lr_prefix_list_match(pl, &shorter) == 0, "prefix_list ge gate");
        check(lr_prefix_list_match(pl, &longer) == 0, "prefix_list le gate");
        lr_prefix_list_free(pl);

        /* Resolver: "all-v4" prefix-list (id 0). */
        lr_resolver_t res = lr_resolver_new();
        check(res != NULL, "resolver_new");
        lr_prefix_list_t all4 = lr_prefix_list_new();
        lr_prefix_t any;
        memset(&any, 0, sizeof(any));
        any.addr[0] = 10;
        any.prefix_len = 0;
        check(lr_prefix_list_add(all4, &any, 0, 32, 1) == 0, "prefix_list_add any");
        int32_t list_id = lr_resolver_add_prefix_list(
            res, "all-v4", all4);
        check(list_id == 0, "resolver_add_prefix_list returns id 0");
        lr_prefix_list_free(all4); /* copied into the resolver */

        /* Route-map: match prefix-list 0 -> set local-pref 300, permit. */
        lr_route_map_t map = lr_route_map_new();
        check(map != NULL, "route_map_new");
        const lr_match_t m = {LR_MATCH_PREFIX_IN, 0, 0};
        const lr_set_t s = {LR_SET_LOCAL_PREF, 0, {0}, 300, 0};
        check(lr_route_map_add_entry(map, &m, 1, &s, 1, LR_VERDICT_PERMIT) == 0,
              "route_map_add_entry");
        int32_t verdict = 9;
        check(lr_route_map_evaluate(map, rt, res, &verdict) == 0,
              "route_map_evaluate");
        check(verdict == LR_EVAL_PERMIT, "route_map permits");
        check(lr_route_local_pref(rt, &lp) == 0 && lp == 300,
              "route_map set applied to the route");

        /* Fallthrough on an empty map. */
        lr_route_map_t empty = lr_route_map_new();
        check(lr_route_map_evaluate(empty, rt, res, &verdict) == 0 &&
                  verdict == LR_EVAL_FALLTHROUGH,
              "empty route-map falls through");
        lr_route_map_free(empty);

        /* A NULL resolver fails the list-backed match (fail closed):
         * the permit-only entry therefore falls through instead of
         * admitting the route. */
        lr_route_map_t nomatch = lr_route_map_new();
        check(lr_route_map_add_entry(nomatch, &m, 1, NULL, 0, LR_VERDICT_PERMIT) == 0,
              "route_map_add_entry no-set");
        check(lr_route_map_evaluate(nomatch, rt, NULL, &verdict) == 0 &&
                  verdict == LR_EVAL_FALLTHROUGH,
              "NULL resolver: list match fails, entry falls through");
        lr_route_map_free(nomatch);

        /* An explicit deny entry with a matching list really denies. */
        lr_route_map_t deny = lr_route_map_new();
        check(lr_route_map_add_entry(deny, &m, 1, NULL, 0, LR_VERDICT_DENY) == 0,
              "route_map_add_entry deny");
        check(lr_route_map_evaluate(deny, rt, res, &verdict) == 0 &&
                  verdict == LR_EVAL_DENY,
              "explicit deny entry denies via resolver");
        lr_route_map_free(deny);

        /* Rejection matrix. */
        const lr_match_t badm = {99, 0, 0};
        check(lr_route_map_add_entry(map, &badm, 1, NULL, 0, LR_VERDICT_PERMIT) == -3,
              "unknown match kind rejected");
        const lr_set_t bads = {99, 0, {0}, 0, 0};
        check(lr_route_map_add_entry(map, NULL, 0, &bads, 1, LR_VERDICT_PERMIT) == -3,
              "unknown set kind rejected");
        check(lr_route_map_add_entry(map, NULL, 0, NULL, 0, 5) == -3,
              "unknown verdict rejected");

        lr_route_map_free(map);
        lr_resolver_free(res);
        lr_route_free(rt);
        lr_route_free(NULL);
    }
    {
        /* Route attribute readers (D5.4 surface, RFC 4271 §5.1 /
         * RFC 4456 §8 / RFC 6514 §5 / RFC 7311 / RFC 9231 §4 /
         * RFC 8966 §3.2/§4.6.9 / RFC 2328 §16 / RFC 5340 §4.1):
         * a fresh route starts with every attribute absent; setting
         * one attribute and reading it back exercises the full
         * has_X / get_X matrix. */
        const unsigned char p4[4] = {203, 0, 113, 0};
        lr_route_t rt = lr_route_new_v4(p4, 24, LR_PROTO_BGP);
        check(rt != NULL, "route_new_v4 for attrs");

        /* ATOMIC_AGGREGATE: starts false (no attribute). */
        uint8_t aa = 2;
        check(lr_route_atomic_aggregate(rt, &aa) == 0 && aa == 0,
              "atomic_aggregate absent is false");

        /* ORIGINATOR_ID: absent on a fresh route. */
        unsigned char oid[4] = {0};
        uint8_t present = 2;
        check(lr_route_originator_id(rt, oid, &present) == 0 && present == 0,
              "originator_id absent is not present");

        /* CLUSTER_LIST: absent on a fresh route. */
        uint8_t hcl = 2;
        check(lr_route_has_cluster_list(rt, &hcl) == 0 && hcl == 0,
              "has_cluster_list absent is false");
        uintptr_t cl_len = 99;
        check(lr_route_cluster_list_len(rt, &cl_len) == 0 && cl_len == 0,
              "cluster_list_len absent is 0");

        /* OTC, AIGP, AGGREGATOR, PMSI_TUNNEL: absent on a fresh route. */
        uint8_t hotc = 2, haigp = 2, hagg = 2, hpmsi = 2;
        check(lr_route_has_otc(rt, &hotc) == 0 && hotc == 0,
              "has_otc absent is false");
        uint32_t otc = 99; uint8_t otc_p = 2;
        check(lr_route_otc(rt, &otc, &otc_p) == 0 && otc_p == 0,
              "otc absent is not present");
        check(lr_route_has_aigp(rt, &haigp) == 0 && haigp == 0,
              "has_aigp absent is false");
        uint64_t aigp = 99; uint8_t aigp_p = 2;
        check(lr_route_aigp(rt, &aigp, &aigp_p) == 0 && aigp_p == 0,
              "aigp absent is not present");
        check(lr_route_has_aggregator(rt, &hagg) == 0 && hagg == 0,
              "has_aggregator absent is false");
        uint32_t agg_asn = 99; uint8_t agg_p = 2;
        check(lr_route_aggregator_asn(rt, &agg_asn, &agg_p) == 0 && agg_p == 0,
              "aggregator_asn absent is not present");
        check(lr_route_has_pmsi_tunnel(rt, &hpmsi) == 0 && hpmsi == 0,
              "has_pmsi_tunnel absent is false");
        uint8_t pmsi_flags = 99; uint8_t pmsi_p = 2;
        check(lr_route_pmsi_tunnel_flags(rt, &pmsi_flags, &pmsi_p) == 0 &&
                  pmsi_p == 0, "pmsi_tunnel_flags absent is not present");

        /* AS_SEQUENCE round trip via set_as_sequence. */
        const uint32_t seq[3] = {64512, 64513, 65001};
        check(lr_route_set_as_sequence(rt, seq, 3) == 0, "set_as_sequence");
        uintptr_t seq_len = 0;
        check(lr_route_as_sequence_len(rt, &seq_len) == 0 && seq_len == 3,
              "as_sequence_len round trip");
        uint32_t got0 = 0;
        check(lr_route_as_sequence_at(rt, 0, &got0) == 0 && got0 == 64512,
              "as_sequence_at 0");
        check(lr_route_as_sequence_at(rt, 3, &got0) == -2,
              "as_sequence_at out-of-range is -2");
        /* prepend_as adds at the head. */
        check(lr_route_prepend_as(rt, 64500) == 0, "prepend_as");
        check(lr_route_as_sequence_at(rt, 0, &got0) == 0 && got0 == 64500,
              "as_sequence_at 0 after prepend");

        /* COMMUNITIES add + remove round trip. */
        check(lr_route_add_community(rt, 64512, 100) == 0, "add_community");
        check(lr_route_communities(rt, NULL, 0) == 1, "communities has 1");
        check(lr_route_remove_community(rt, 64512, 100) == 0, "remove_community");
        check(lr_route_communities(rt, NULL, 0) == 0, "communities now empty");
        /* remove_community is a no-op on an absent community. */
        check(lr_route_remove_community(rt, 65000, 999) == 0,
              "remove_community no-op on absent");

        /* Babel / OSPF attributes: absent on a fresh BGP route. */
        uint8_t hbm = 2, hbs = 2, hbr = 2;
        check(lr_route_has_babel_metric(rt, &hbm) == 0 && hbm == 0,
              "has_babel_metric absent is false");
        check(lr_route_has_babel_seqno(rt, &hbs) == 0 && hbs == 0,
              "has_babel_seqno absent is false");
        check(lr_route_has_babel_router_id(rt, &hbr) == 0 && hbr == 0,
              "has_babel_router_id absent is false");
        uint8_t hom1 = 2, hom2 = 2, hot = 2, hor = 2;
        check(lr_route_has_ospf_metric1(rt, &hom1) == 0 && hom1 == 0,
              "has_ospf_metric1 absent is false");
        check(lr_route_has_ospf_metric2(rt, &hom2) == 0 && hom2 == 0,
              "has_ospf_metric2 absent is false");
        check(lr_route_has_ospf_tag(rt, &hot) == 0 && hot == 0,
              "has_ospf_tag absent is false");
        check(lr_route_has_ospf_router_id(rt, &hor) == 0 && hor == 0,
              "has_ospf_router_id absent is false");

        /* NULL handle / NULL out-pointer rejection. */
        check(lr_route_atomic_aggregate(NULL, &aa) == -1, "atomic_aggregate NULL handle");
        check(lr_route_atomic_aggregate(rt, NULL) == -1, "atomic_aggregate NULL out");

        lr_route_free(rt);
    }
    {
        /* Filter DSL (ROADMAP-v3 D5.2): compile, accept/reject with
         * the built-in context, ROA override through the callback
         * table, and the reject reason buffer. */
        lr_filter_t f = lr_filter_compile("c-f", "if bgp.local_pref >= 200 then { accept; } else { reject with \"too low\"; }");
        check(f != NULL, "filter_compile");
        lr_filter_t bad = lr_filter_compile("c-bad", "if bgp.local_pref = ");
        check(bad == NULL, "filter_compile rejects a parse error");

        const unsigned char p4[4] = {203, 0, 113, 0};
        lr_route_t rt = lr_route_new_v4(p4, 24, LR_PROTO_BGP);
        check(lr_route_set_local_pref(rt, 250) == 0, "route_set_local_pref for filter");

        int32_t verdict = -9;
        check(lr_filter_evaluate(f, rt, NULL, &verdict, NULL) == 0, "filter_evaluate");
        check(verdict == LR_FILTER_ACCEPT, "filter accepts local_pref 250");

        check(lr_route_set_local_pref(rt, 100) == 0, "route_set_local_pref low");
        check(lr_filter_evaluate(f, rt, NULL, &verdict, NULL) == 0, "filter_evaluate low");
        check(verdict == LR_FILTER_REJECT, "filter rejects local_pref 100");

        /* Reject reason comes back as an owned NUL-terminated buffer. */
        lr_bytes_t reason = {0};
        check(lr_filter_evaluate(f, rt, NULL, &verdict, &reason) == 0,
              "filter_evaluate with reason out");
        check(verdict == LR_FILTER_REJECT && reason.ptr != NULL &&
                  strcmp((const char *)lr_bytes_ptr(&reason), "too low") == 0,
              "reject reason carried");
        lr_bytes_free(&reason);

        /* ROA override: the built-in context has no RPKI data, the
         * table's roa_state callback injects invalid. */
        lr_filter_t rf = lr_filter_compile("c-roa", "if roa.state == \"invalid\" then { reject; } accept;");
        check(rf != NULL, "filter_compile roa");
        check(lr_filter_evaluate(rf, rt, NULL, &verdict, NULL) == 0 &&
                  verdict == LR_FILTER_ACCEPT,
              "built-in context: roa not-found accepts");
        int32_t rc2 = lr_filter_evaluate(rf, rt, &roa_invalid_ctx, &verdict, NULL);
        check(rc2 == 0 && verdict == LR_FILTER_REJECT,
              "callback table overrides roa.state");

        /* Name probe-then-read. */
        int64_t need = lr_filter_name(rf, NULL, 0);
        check(need == 6, "filter_name length probe");
        char nb[8] = {0};
        check(lr_filter_name(rf, (uint8_t *)nb, sizeof(nb)) == need &&
                  strcmp(nb, "c-roa") == 0,
              "filter_name reads back");

        lr_filter_free(f);
        lr_filter_free(rf);
        lr_filter_free(NULL);
        lr_route_free(rt);
    }

    /* ===== Structured inspection surface (issue #92) ===== */
    {
        lr_router_t r2 = lr_router_new();
        check(r2 != NULL, "router_new for inspection");

        /* Fresh router: zero sessions, zero areas. */
        check(lr_router_session_count(r2) == 0,
              "session_count: 0 on fresh router");
        check(lr_router_ospf_area_count(r2) == 0,
              "ospf_area_count: 0 on fresh router");

        /* Add one BGP session and verify the summary surface. */
        uint64_t h = 0;
        int rc = lr_router_add_bgp_session(r2, 64512, 64513, 0x0a000001u,
                                            90, 0, 1, &h);
        check(rc == 0 && h != 0, "add_bgp_session for inspection");
        check(lr_router_session_count(r2) == 1,
              "session_count: 1 after BGP session");
        lr_session_summary_t s;
        check(lr_router_session_summary_at(r2, 0, &s) == 0,
              "session_summary_at(0): success");
        check(s.handle == h, "session_summary_at: handle matches");
        check(s.kind == LR_SESSION_KIND_BGP, "session_summary_at: kind is BGP");
        check(s.local_as == 64512, "session_summary_at: local_as");
        check(s.peer_as == 64513, "session_summary_at: peer_as");
        check(strcmp((const char *)s.kind_text, "bgp") == 0,
              "session_summary_at: kind_text is 'bgp'");

        /* Out-of-range index returns LR_ERR_OTHER (-6). */
        lr_session_summary_t s2;
        check(lr_router_session_summary_at(r2, 99, &s2) == -6,
              "session_summary_at(99): out-of-range returns -6");

        /* OSPF area IDs: fresh router has zero; unknown area returns
         * LR_ERR_OTHER (-6). */
        check(lr_router_ospf_area_count(r2) == 0,
              "ospf_area_count: still 0 after BGP session");
        uint64_t tv = 0;
        check(lr_router_ospf_area_topology_version(r2, 99, &tv) == -6,
              "ospf_area_topology_version(99): unknown returns -6");

        /* OSPF LSA: unknown area/LSA returns -6. */
        lr_ospf_lsa_t lsa;
        check(lr_router_ospf_area_lsa(r2, 0, 1, 1, 1, &lsa) == -6,
              "ospf_area_lsa: unknown returns -6");

        /* bgp_session_identity_hash returns a u64 (always succeeds). */
        uint64_t hash = lr_router_bgp_session_identity_hash(r2);
        check(hash <= 0xFFFFFFFFFFFFFFFFULL,
              "bgp_session_identity_hash: fits in u64");

        /* drain_ospf_grace_events returns 0 events on a fresh router. */
        lr_ospf_grace_event_t ev;
        intptr_t n = lr_router_drain_ospf_grace_events(r2, &ev, 1);
        check(n == 0, "drain_ospf_grace_events: 0 events on fresh router");

        lr_router_destroy(r2);
    }

    /* ---- MPLS Label / LabelStack (RFC 3032 §2.1, RFC 8277 §2.2/§2.3) ---- */
    {
        lr_mpls_label_t l = lr_mpls_label_new(100);
        check(l != NULL, "lr_mpls_label_new returns non-NULL");
        check(lr_mpls_label_value(l) == 100, "lr_mpls_label_value = 100");
        check(lr_mpls_label_tc(l) == 0, "lr_mpls_label_tc defaults to 0");
        check(lr_mpls_label_ttl(l) == 64, "lr_mpls_label_ttl defaults to 64");
        check(lr_mpls_label_is_reserved(l) == 0, "label 100 is not reserved");
        lr_mpls_label_free(l);

        lr_mpls_label_t r0 = lr_mpls_label_new(0);
        check(lr_mpls_label_is_reserved(r0) == 1, "label 0 is reserved");
        lr_mpls_label_free(r0);

        /* checked constructor rejects oversize value. */
        check(lr_mpls_label_new_checked(0x100000) == NULL,
              "lr_mpls_label_new_checked rejects 1<<20");

        /* with_tc / with_ttl chain (consumes the receiver). */
        lr_mpls_label_t l2 = lr_mpls_label_new(0xFFFFF);
        l2 = lr_mpls_label_with_tc(l2, 7);
        l2 = lr_mpls_label_with_ttl(l2, 255);
        check(lr_mpls_label_tc(l2) == 7, "with_tc(7)");
        check(lr_mpls_label_ttl(l2) == 255, "with_ttl(255)");
        lr_mpls_label_free(l2);

        /* with_tc masks high bits. */
        lr_mpls_label_t l3 = lr_mpls_label_new(16);
        l3 = lr_mpls_label_with_tc(l3, 0xFF);
        check(lr_mpls_label_tc(l3) == 0x07, "with_tc masks to 3 bits");
        lr_mpls_label_free(l3);

        /* encode_3octet / encode_4octet on label 100 (TC=0, TTL=64). */
        lr_mpls_label_t l4 = lr_mpls_label_new(100);
        l4 = lr_mpls_label_with_tc(l4, 0);
        l4 = lr_mpls_label_with_ttl(l4, 64);
        uint8_t out3[3] = {0};
        check(lr_mpls_label_encode_3octet(l4, 1, out3) == 0,
              "encode_3octet returns 0");
        check(out3[0] == 0x00 && out3[1] == 0x06 && out3[2] == 0x41,
              "encode_3octet(100, bottom) = 00 06 41");
        uint8_t out4[4] = {0};
        check(lr_mpls_label_encode_4octet(l4, 1, out4) == 0,
              "encode_4octet returns 0");
        check(out4[0] == 0x00 && out4[1] == 0x06 && out4[2] == 0x41 && out4[3] == 0x40,
              "encode_4octet(100, bottom) = 00 06 41 40");
        lr_mpls_label_free(l4);

        /* Stack from values — round-trip through 4-octet wire form. */
        uint32_t values[3] = {16, 240, 1048575};
        lr_mpls_label_stack_t s =
            lr_mpls_label_stack_from_values(values, 3);
        check(s != NULL, "label_stack_from_values returns non-NULL");
        check(lr_mpls_label_stack_len(s) == 3, "label_stack_len = 3");
        check(lr_mpls_label_stack_is_empty(s) == 0, "label_stack not empty");

        uint32_t v = 0;
        uint8_t tc = 0, ttl = 0;
        check(lr_mpls_label_stack_at(s, 1, &v, &tc, &ttl) == 0,
              "label_stack_at(1) returns 0");
        check(v == 240, "label_stack_at(1).value = 240");

        lr_bytes_t enc = {NULL, 0, 0};
        check(lr_mpls_label_stack_encode_4octet(s, &enc) == 0,
              "label_stack_encode_4octet returns 0");
        check(enc.len == 12, "label_stack_encode_4octet = 12 bytes");

        lr_mpls_label_stack_t dec = NULL;
        check(lr_mpls_label_stack_decode_4octet(enc.ptr, enc.len, &dec) == 0,
              "label_stack_decode_4octet returns 0");
        check(dec != NULL, "label_stack_decode_4octet sets *out");
        check(lr_mpls_label_stack_len(dec) == 3, "decoded len = 3");

        uint32_t last_v = 0;
        check(lr_mpls_label_stack_at(dec, 2, &last_v, &tc, &ttl) == 0,
              "label_stack_at(2) returns 0");
        check(last_v == 1048575, "decoded At(2).value = 1048575");

        lr_bytes_free(&enc);
        lr_mpls_label_stack_free(s);
        lr_mpls_label_stack_free(dec);

        /* Stack from labels — round-trip through 3-octet NLRI form. */
        lr_mpls_label_spec_t specs[2] = {
            {16, 0, 0},
            {240, 0, 0},
        };
        lr_mpls_label_stack_t s2 =
            lr_mpls_label_stack_from_labels(specs, 2);
        check(s2 != NULL, "label_stack_from_labels returns non-NULL");
        lr_bytes_t enc2 = {NULL, 0, 0};
        check(lr_mpls_label_stack_encode_3octet(s2, &enc2) == 0,
              "label_stack_encode_3octet returns 0");
        check(enc2.len == 6, "label_stack_encode_3octet = 6 bytes");

        lr_mpls_label_stack_t dec2 = NULL;
        check(lr_mpls_label_stack_decode_3octet(enc2.ptr, enc2.len, &dec2) == 0,
              "label_stack_decode_3octet returns 0");
        check(lr_mpls_label_stack_len(dec2) == 2, "decoded 3-octet len = 2");

        lr_bytes_free(&enc2);
        lr_mpls_label_stack_free(s2);
        lr_mpls_label_stack_free(dec2);

        /* push / pop semantics. */
        lr_mpls_label_stack_t s3 = lr_mpls_label_stack_new();
        lr_mpls_label_t top = lr_mpls_label_new(100);
        check(lr_mpls_label_stack_push(s3, top) == 0, "push(top) returns 0");
        lr_mpls_label_t bot = lr_mpls_label_new(200);
        check(lr_mpls_label_stack_push_bottom(s3, bot) == 0, "push_bottom returns 0");
        check(lr_mpls_label_stack_len(s3) == 2, "after push: len = 2");

        check(lr_mpls_label_stack_at(s3, 0, &v, &tc, &ttl) == 0, "At(0) returns 0");
        check(v == 100, "top is 100");

        check(lr_mpls_label_stack_pop(s3) == 1, "pop top returns 1");
        check(lr_mpls_label_stack_len(s3) == 1, "after pop: len = 1");
        check(lr_mpls_label_stack_at(s3, 0, &v, &tc, &ttl) == 0, "At(0) returns 0");
        check(v == 200, "bottom is now at 0");

        check(lr_mpls_label_stack_pop(s3) == 1, "pop bottom returns 1");
        check(lr_mpls_label_stack_is_empty(s3) == 1, "after 2 pops: empty");
        check(lr_mpls_label_stack_pop(s3) == 0, "pop on empty returns 0");

        /* At() out of range returns LR_ERR_INVALID_HANDLE. */
        check(lr_mpls_label_stack_at(s3, 0, &v, &tc, &ttl) == -2,
              "At(0) on empty returns -2 (InvalidHandle)");

        /* decode_4octet rejects uneven-length input. */
        uint8_t bad[3] = {0, 1, 2};
        lr_mpls_label_stack_t bad_out = NULL;
        check(lr_mpls_label_stack_decode_4octet(bad, 3, &bad_out) == -6,
              "decode_4octet rejects uneven length");

        /* free handles NULL safely. */
        lr_mpls_label_free(NULL);
        lr_mpls_label_stack_free(NULL);

        lr_mpls_label_stack_free(s3);
    }

    /* ---- BFD Control packet (RFC 5880 §4.1) ---- */
    {
        lr_bfd_packet_t p = lr_bfd_packet_new();
        check(p != NULL, "lr_bfd_packet_new returns non-NULL");
        check(lr_bfd_packet_version(p) == 1, "BFD version = 1");
        check(lr_bfd_packet_state(p) == LR_BFD_STATE_DOWN, "default state = Down");
        check(lr_bfd_packet_detect_mult(p) == 3, "default detect_mult = 3");
        check(lr_bfd_packet_desired_min_tx_interval(p) == 1000000,
              "default tx_interval = 1s");
        check(lr_bfd_packet_length(p) == 24, "default length = 24");
        lr_bfd_packet_free(p);

        lr_bfd_packet_t hb = lr_bfd_packet_heartbeat(0xDEADBEEF, 0xCAFEBABE);
        check(hb != NULL, "heartbeat returns non-NULL");
        check(lr_bfd_packet_state(hb) == LR_BFD_STATE_UP, "heartbeat state = Up");
        check(lr_bfd_packet_my_discriminator(hb) == 0xDEADBEEF, "heartbeat my_disc");
        check(lr_bfd_packet_your_discriminator(hb) == 0xCAFEBABE, "heartbeat your_disc");

        /* Setters mutate in place. */
        check(lr_bfd_packet_set_diag(hb, LR_BFD_DIAG_CTRL_EXPIRED) == 0, "set_diag");
        check(lr_bfd_packet_set_state(hb, LR_BFD_STATE_UP) == 0, "set_state");
        check(lr_bfd_packet_set_flags(hb, 0x20) == 0, "set_flags (Poll)");
        check(lr_bfd_packet_set_detect_mult(hb, 5) == 0, "set_detect_mult");
        check(lr_bfd_packet_set_my_discriminator(hb, 0xAABBCCDD) == 0, "set_my_disc");
        check(lr_bfd_packet_diag(hb) == LR_BFD_DIAG_CTRL_EXPIRED, "diag = CtrlExpired");
        check(lr_bfd_packet_state(hb) == LR_BFD_STATE_UP, "state = Up");
        check(lr_bfd_packet_flags(hb) == 0x20, "flags = Poll");
        check(lr_bfd_packet_detect_mult(hb) == 5, "detect_mult = 5");
        check(lr_bfd_packet_my_discriminator(hb) == 0xAABBCCDD, "my_disc = 0xAABBCCDD");

        /* SetState clamps invalid values to AdminDown. */
        check(lr_bfd_packet_set_state(hb, 99) == 0, "set_state(99) returns 0");
        check(lr_bfd_packet_state(hb) == LR_BFD_STATE_ADMIN_DOWN,
              "invalid state clamps to AdminDown");

        /* SetFlags masks reserved bits (M|D|A|C|F|P only). */
        check(lr_bfd_packet_set_flags(hb, 0xFF) == 0, "set_flags(0xFF) returns 0");
        check(lr_bfd_packet_flags(hb) == 0x3F, "reserved bits masked to 0x3F");

        /* Encode/decode roundtrip. */
        lr_bfd_packet_t hb2 = lr_bfd_packet_heartbeat(0xDEADBEEF, 0xCAFEBABE);
        lr_bytes_t enc = {NULL, 0, 0};
        check(lr_bfd_encode(hb2, &enc) == 0, "lr_bfd_encode returns 0");
        check(enc.len == 24, "encoded length = 24");

        lr_bfd_packet_t dec = NULL;
        check(lr_bfd_decode(enc.ptr, enc.len, &dec) == 0, "lr_bfd_decode returns 0");
        check(dec != NULL, "decode sets *out");
        check(lr_bfd_packet_state(dec) == LR_BFD_STATE_UP, "decoded state = Up");
        check(lr_bfd_packet_my_discriminator(dec) == 0xDEADBEEF, "decoded my_disc");
        check(lr_bfd_packet_your_discriminator(dec) == 0xCAFEBABE, "decoded your_disc");

        lr_bytes_free(&enc);
        lr_bfd_packet_free(hb);
        lr_bfd_packet_free(hb2);
        lr_bfd_packet_free(dec);

        /* free handles NULL safely. */
        lr_bfd_packet_free(NULL);

        /* decode rejects too-short input. */
        uint8_t bad[3] = {0, 1, 2};
        lr_bfd_packet_t bad_out = NULL;
        check(lr_bfd_decode(bad, 3, &bad_out) < 0, "decode rejects too-short");
        check(bad_out == NULL, "decode sets *out to NULL on failure");
    }

    /* ---- lr_loc_rib / lr_adj_rib / lr_rib_mux / lr_route_selector ---- */
    {
        lr_loc_rib_t rib = lr_loc_rib_new();
        check(rib != NULL, "lr_loc_rib_new returns non-NULL");
        check(lr_loc_rib_is_empty(rib) == 1, "fresh Loc-RIB is empty");
        check(lr_loc_rib_len(rib) == 0, "fresh Loc-RIB len = 0");
        lr_loc_rib_free(rib);
        lr_loc_rib_free(NULL); /* safe on NULL */

        lr_adj_rib_in_t in = lr_adj_rib_in_new();
        check(in != NULL, "lr_adj_rib_in_new returns non-NULL");
        check(lr_adj_rib_in_is_empty(in) == 1, "fresh Adj-RIB-In is empty");
        lr_adj_rib_in_free(in);

        lr_adj_rib_out_t out = lr_adj_rib_out_new();
        check(out != NULL, "lr_adj_rib_out_new returns non-NULL");
        check(lr_adj_rib_out_is_empty(out) == 1, "fresh Adj-RIB-Out is empty");
        lr_adj_rib_out_free(out);

        lr_rib_mux_t mux = lr_rib_mux_new();
        check(mux != NULL, "lr_rib_mux_new returns non-NULL");
        check(lr_rib_mux_is_empty(mux) == 1, "fresh RibMux is empty");
        lr_rib_mux_free(mux);

        /* RouteSelector on an empty array returns -1. */
        check(lr_route_selector_select(NULL, 0) == -1,
              "RouteSelector returns -1 on empty input");
    }

    /* ---- lr_ospf_lsdb + lr_ospf_lsa ---- */
    {
        lr_ospf_lsdb_t lsdb = lr_ospf_lsdb_new();
        check(lsdb != NULL, "lr_ospf_lsdb_new returns non-NULL");
        check(lr_ospf_lsdb_is_empty(lsdb) == 1, "fresh LSDB is empty");

        /* Construct an LSA header + body. */
        lr_ospf_lsa_hdr_box_t hdr = lr_ospf_lsa_header_new(
            1, 0, 1, 0x01020304, 0x01020304, 0x80000001, 0xabcd, 24);
        check(hdr != NULL, "lr_ospf_lsa_header_new returns non-NULL");

        uint8_t body[] = {0xde, 0xad, 0xbe, 0xef};
        lr_ospf_lsa_box_t lsa = lr_ospf_lsa_new(hdr, body, 4);
        check(lsa != NULL, "lr_ospf_lsa_new returns non-NULL");

        /* Install — should be New (returns 1). */
        int rc = lr_ospf_lsdb_install(lsdb, lsa, 0);
        check(rc == 1, "lr_ospf_lsdb_install returns 1 (New)");

        check(lr_ospf_lsdb_len(lsdb) == 1, "LSDB has 1 LSA");
        check(lr_ospf_lsdb_is_empty(lsdb) == 0, "LSDB not empty");

        /* Get it back. */
        lr_ospf_lsa_box_t got = NULL;
        rc = lr_ospf_lsdb_get(lsdb, 1, 0x01020304, 0x01020304, &got);
        check(rc == 0, "lr_ospf_lsdb_get returns 0");
        check(got != NULL, "lr_ospf_lsdb_get sets *out");

        /* Read the header back. */
        lr_ospf_lsa_hdr_t got_hdr;
        rc = lr_ospf_lsa_header_get(got, &got_hdr);
        check(rc == 0, "lr_ospf_lsa_header_get returns 0");
        check(got_hdr.ls_type == 1, "got ls_type = 1");
        check(got_hdr.link_state_id == 0x01020304, "got link_state_id");

        /* Read the body back. */
        lr_bytes_t got_body = {NULL, 0, 0};
        rc = lr_ospf_lsa_body(got, &got_body);
        check(rc == 0, "lr_ospf_lsa_body returns 0");
        check(got_body.len == 4, "got body len = 4");
        lr_bytes_free(&got_body);

        /* Encode as wire form. */
        lr_bytes_t wire = {NULL, 0, 0};
        rc = lr_ospf_lsa_to_wire(got, &wire);
        check(rc == 0, "lr_ospf_lsa_to_wire returns 0");
        check(wire.len == 24, "wire len = 20-byte header + 4-byte body");
        lr_bytes_free(&wire);

        lr_ospf_lsa_free(got);

        /* Remove. */
        rc = lr_ospf_lsdb_remove(lsdb, 1, 0x01020304, 0x01020304);
        check(rc == 1, "lr_ospf_lsdb_remove returns 1");

        /* NULL safety. */
        check(lr_ospf_lsdb_len(NULL) == 0, "lsdb_len on NULL = 0");
        lr_ospf_lsdb_free(NULL);
        lr_ospf_lsa_free(NULL);
        lr_ospf_lsa_header_free(NULL);

        lr_ospf_lsdb_free(lsdb);
    }

    /* ---- lr_ospf_neighbor (FSM) ---- */
    {
        lr_ospf_neighbor_t n = lr_ospf_neighbor_new(0x01020304);
        check(n != NULL, "lr_ospf_neighbor_new returns non-NULL");
        check(lr_ospf_neighbor_state(n) == LR_OSPF_NEIGHBOR_STATE_DOWN,
              "fresh neighbor is Down");

        int st = lr_ospf_neighbor_step_hello_seen(n, 0, 0, 1);
        check(st == LR_OSPF_NEIGHBOR_STATE_INIT,
              "HelloSeen transitions Down → Init");

        st = lr_ospf_neighbor_step_hello_seen(n, 0, 0, 1);
        check(st == LR_OSPF_NEIGHBOR_STATE_TWO_WAY,
              "second HelloSeen transitions Init → TwoWay");

        st = lr_ospf_neighbor_step_adj_ok(n, 1);
        check(st == LR_OSPF_NEIGHBOR_STATE_EX_START,
              "AdjOk { proceed } transitions TwoWay → ExStart");

        st = lr_ospf_neighbor_step_kill(n);
        check(st == LR_OSPF_NEIGHBOR_STATE_DOWN,
              "Kill transitions back to Down");

        lr_ospf_neighbor_free(n);
    }

    /* ---- lr_bgp_peer (FSM) ---- */
    {
        lr_bgp_peer_t p = lr_bgp_peer_new(64512, 64513, 0x0a000001, 90, 30, 1);
        check(p != NULL, "lr_bgp_peer_new returns non-NULL");
        check(lr_bgp_peer_state(p) == LR_BGP_STATE_IDLE, "fresh peer is Idle");
        check(lr_bgp_peer_is_established(p) == 0, "fresh peer not established");

        /* ManualStart transitions Idle → Connect. */
        int rc = lr_bgp_peer_step_manual_start(p);
        check(rc == 0, "step_manual_start returns 0");
        check(lr_bgp_peer_state(p) == LR_BGP_STATE_CONNECT,
              "ManualStart transitions Idle → Connect");

        /* No OPEN received yet — peer_bgp_id returns 0 (absent). */
        uint32_t id = 0;
        check(lr_bgp_peer_peer_bgp_id(p, &id) == 0, "no peer_bgp_id yet");

        lr_bgp_peer_free(p);
    }

    /* ---- lr_babel_neighbor + lr_babel_route_table ---- */
    {
        uint8_t v4[4] = {10, 0, 0, 1};
        lr_babel_neighbor_t n = lr_babel_neighbor_new(v4, NULL, 1000);
        check(n != NULL, "lr_babel_neighbor_new (v4) returns non-NULL");

        int rc = lr_babel_neighbor_hello(n, 1, 100, 1100);
        check(rc == 0, "lr_babel_neighbor_hello returns 0");
        rc = lr_babel_neighbor_ihu(n, 96, 100, 1100);
        check(rc == 0, "lr_babel_neighbor_ihu returns 0");

        check(lr_babel_neighbor_rtt_valid(n, 1200) == 0,
              "rtt not valid (no timestamped Hello)");
        check(lr_babel_neighbor_rtt_us(n, 1200) == 0,
              "rtt_us = 0 when no valid sample");

        lr_babel_neighbor_free(n);

        lr_babel_route_table_t t = lr_babel_route_table_new();
        check(t != NULL, "lr_babel_route_table_new returns non-NULL");
        check(lr_babel_route_table_is_empty(t) == 1, "fresh route table is empty");
        check(lr_babel_route_table_len(t) == 0, "fresh route table len = 0");
        lr_babel_route_table_free(t);
    }

    /* ---- lr_ldp_session ---- */
    {
        lr_ldp_session_t s = lr_ldp_session_new(
            0x0a000001, 0, 0x0a000002, 0, 0, 0);
        check(s != NULL, "lr_ldp_session_new returns non-NULL");
        check(lr_ldp_session_state(s) == LR_LDP_SESSION_STATE_NON_EXISTENT,
              "fresh session is NonExistent");
        check(lr_ldp_session_is_operational(s) == 0, "fresh session not operational");

        int rc = lr_ldp_session_start(s, 0);
        check(rc == 0, "lr_ldp_session_start returns 0");

        int st = lr_ldp_session_state(s);
        check(st == LR_LDP_SESSION_STATE_OPEN_SENT ||
                  st == LR_LDP_SESSION_STATE_INITIALIZED,
              "state after start is OpenSent or Initialized");

        lr_ldp_session_free(s);
    }

    /* ---- lr_safety_net ---- */
    {
        lr_safety_net_t sn = lr_safety_net_new(64512);
        check(sn != NULL, "lr_safety_net_new returns non-NULL");

        /* A v4 local address. */
        uint8_t v4[4] = {10, 0, 0, 1};
        lr_safety_net_t sn2 = lr_safety_net_with_local_addr(sn, v4, NULL);
        check(sn2 != NULL, "lr_safety_net_with_local_addr returns non-NULL");
        lr_safety_net_free(sn2);
        /* The original handle was consumed by with_local_addr — do not
         * free it. */

        /* NULL-handle check returns LR_ERR_NULL. */
        check(lr_safety_net_check(NULL, NULL, 1) == -1, "check on NULL = -1");
    }

    /* ---- lr_seg6_route_* / lr_seg6_local_route_* / lr_seg6_netlink_* (issue #92) ---- */
    {
        /* SID + SRH construction (raw C ABI). */
        uint8_t sid_octets[16] = {
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1};
        lr_srv6_sid_t sid = lr_srv6_sid_new(sid_octets);
        check(sid != NULL, "lr_srv6_sid_new returns non-NULL");

        /* SRH from a single 16-byte segment. */
        lr_srv6_srh_t srh = lr_srv6_srh_new(sid_octets, 1);
        check(srh != NULL, "lr_srv6_srh_new returns non-NULL");

        /* IPv6 prefix for the seg6 encap route. */
        lr_prefix_t v6_prefix;
        memset(&v6_prefix, 0, sizeof(v6_prefix));
        v6_prefix.is_ipv6 = 1;
        v6_prefix.prefix_len = 64;
        v6_prefix.addr[0] = 0x20; v6_prefix.addr[1] = 0x01;
        v6_prefix.addr[2] = 0x0d; v6_prefix.addr[3] = 0xb8;

        lr_seg6_route_t route = lr_seg6_route_new(v6_prefix, srh);
        check(route != NULL, "lr_seg6_route_new returns non-NULL");

        /* Set mode round-trip. */
        check(lr_seg6_route_set_mode(route, LR_SEG6_ENCAP_INLINE) == 0,
              "lr_seg6_route_set_mode(Inline) returns 0");
        check(lr_seg6_route_set_mode(route, LR_SEG6_ENCAP_ENCAP) == 0,
              "lr_seg6_route_set_mode(Encap) returns 0");
        check(lr_seg6_route_set_mode(route, 0xFFFFFFFFu) != 0,
              "lr_seg6_route_set_mode(unknown) returns non-zero");

        /* Set if_index round-trip. */
        check(lr_seg6_route_set_if_index(route, 7) == 0,
              "lr_seg6_route_set_if_index(7) returns 0");

        /* NULL handle returns LR_ERR_NULL. */
        check(lr_seg6_route_set_mode(NULL, LR_SEG6_ENCAP_INLINE) == -1,
              "lr_seg6_route_set_mode(NULL) returns -1");

        lr_seg6_route_free(route);

        /* IPv4 prefix should be rejected — srh_new returns NULL. */
        lr_prefix_t v4_prefix;
        memset(&v4_prefix, 0, sizeof(v4_prefix));
        v4_prefix.is_ipv6 = 0;
        v4_prefix.prefix_len = 24;
        v4_prefix.addr[0] = 203; v4_prefix.addr[1] = 0;
        v4_prefix.addr[2] = 113; v4_prefix.addr[3] = 0;
        check(lr_seg6_route_new(v4_prefix, srh) == NULL,
              "lr_seg6_route_new(IPv4) returns NULL");

        /* NULL srh is rejected. */
        check(lr_seg6_route_new(v6_prefix, NULL) == NULL,
              "lr_seg6_route_new(NULL srh) returns NULL");

        /* ---- Seg6LocalRoute ---- */
        lr_seg6_local_route_t local =
            lr_seg6_local_route_new(sid, 1 /* End behavior */);
        check(local != NULL,
              "lr_seg6_local_route_new(End) returns non-NULL");

        /* All builder setters return 0 on a valid handle. */
        check(lr_seg6_local_route_set_if_index(local, 1) == 0,
              "lr_seg6_local_route_set_if_index(1) returns 0");

        uint8_t nh4[4] = {203, 0, 113, 1};
        check(lr_seg6_local_route_set_nh4(local, nh4) == 0,
              "lr_seg6_local_route_set_nh4 returns 0");

        uint8_t nh6[16];
        memset(nh6, 0xfe, 16);
        check(lr_seg6_local_route_set_nh6(local, nh6) == 0,
              "lr_seg6_local_route_set_nh6 returns 0");

        check(lr_seg6_local_route_set_iif(local, 2) == 0,
              "lr_seg6_local_route_set_iif(2) returns 0");
        check(lr_seg6_local_route_set_oif(local, 3) == 0,
              "lr_seg6_local_route_set_oif(3) returns 0");
        check(lr_seg6_local_route_set_table(local, 254) == 0,
              "lr_seg6_local_route_set_table(254) returns 0");
        check(lr_seg6_local_route_set_vrf_table(local, 100) == 0,
              "lr_seg6_local_route_set_vrf_table(100) returns 0");
        check(lr_seg6_local_route_set_srh(local, srh) == 0,
              "lr_seg6_local_route_set_srh returns 0");

        /* NULL pointers on set_nh4 / set_nh6 return LR_ERR_NULL. */
        check(lr_seg6_local_route_set_nh4(local, NULL) == -1,
              "lr_seg6_local_route_set_nh4(NULL) returns -1");
        check(lr_seg6_local_route_set_nh6(local, NULL) == -1,
              "lr_seg6_local_route_set_nh6(NULL) returns -1");

        /* NULL handle returns LR_ERR_NULL. */
        check(lr_seg6_local_route_set_if_index(NULL, 1) == -1,
              "lr_seg6_local_route_set_if_index(NULL) returns -1");

        lr_seg6_local_route_free(local);

        /* Unknown behavior wire value (0xFFFF) is rejected. */
        check(lr_seg6_local_route_new(sid, 0xFFFF) == NULL,
              "lr_seg6_local_route_new(0xFFFF) returns NULL");

        /* ---- Seg6Netlink ---- */
        lr_seg6_netlink_t nl = lr_seg6_netlink_connect();
        if (nl == NULL) {
            /* On a CI runner without SRv6 enabled the connect call
             * fails — the discriminant is recorded in the last-error
             * string and must be either NotEnabled or Unsupported. */
            int32_t code = lr_seg6_route_err_code();
            check(code == LR_SEG6_ERR_NOT_ENABLED ||
                      code == LR_SEG6_ERR_UNSUPPORTED,
                  "lr_seg6_netlink_connect sets NotEnabled or Unsupported");
        } else {
            /* On a kernel with SRv6 enabled the handle is non-NULL. */
            lr_seg6_netlink_free(nl);
        }

        /* ---- Error helpers ---- */
        /* lr_seg6_route_err_name lookup on every known code. */
        const char* name_unsup = lr_seg6_route_err_name(LR_SEG6_ERR_UNSUPPORTED);
        check(name_unsup != NULL && strcmp(name_unsup, "unsupported") == 0,
              "lr_seg6_route_err_name(Unsupported) returns 'unsupported'");
        const char* name_not_enabled = lr_seg6_route_err_name(LR_SEG6_ERR_NOT_ENABLED);
        check(name_not_enabled != NULL && strcmp(name_not_enabled, "not-enabled") == 0,
              "lr_seg6_route_err_name(NotEnabled) returns 'not-enabled'");
        const char* name_unknown = lr_seg6_route_err_name(999);
        check(name_unknown != NULL && strcmp(name_unknown, "unknown") == 0,
              "lr_seg6_route_err_name(999) returns 'unknown'");

        /* Add seg6 route on NULL handle returns LR_ERR_NULL. */
        check(lr_seg6_netlink_add_seg6_route(NULL, NULL) == -1,
              "lr_seg6_netlink_add_seg6_route(NULL) returns -1");

        /* Free is safe on NULL. */
        lr_seg6_netlink_free(NULL);
        lr_seg6_route_free(NULL);
        lr_seg6_local_route_free(NULL);

        lr_srv6_srh_free(srh);
        lr_srv6_sid_free(sid);
    }

    lr_router_destroy(r);
    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    fprintf(stderr, "%d failures\n", failures);
    return 1;
}
