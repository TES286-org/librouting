# C binding guide

`include/lr_ffi.h` is the C ABI for librouting: opaque handles, `int32_t`
return codes and `lr_bytes_t` for owned buffers. Read this if you are
embedding the library in a C program and you own the transport and the
event loop.

The design behind the ABI — the panic barrier, the buffer ownership
model and the locking rules — is in [`../ffi_design.md`](../ffi_design.md).
The header is generated; do not edit it. Regenerate it with
`cargo build -p lr-ffi` after any change to `crates/lr-ffi`.

Build the shared library once:

```sh
cargo build --release -p lr-ffi
```

## A first program

The program below creates a router, adds an eBGP session, originates a
prefix, drains the OPEN the session produces, and cleans up.

```c
/* lr_quickstart.c — build with:
 *   cc -Iinclude lr_quickstart.c -Ltarget/release -llr_ffi \
 *      -o lr_quickstart
 * Run with:
 *   LD_LIBRARY_PATH=target/release ./lr_quickstart
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "lr_ffi.h"

int main(void) {
    printf("lr ABI version %u\n", lr_abi_version());

    lr_router_t r = lr_router_new();
    if (!r) {
        fprintf(stderr, "router allocation failed\n");
        return 1;
    }

    uint64_t session = 0;
    if (lr_router_add_bgp_session(r, 64512, 64513, 0x0A000001,
                                  90, 0, 1, &session) != 0) {
        fprintf(stderr, "add_bgp_session: %s\n", lr_last_error());
        return 1;
    }

    /* next-hop-self for the eBGP advertisement. */
    uint8_t local_addr[4] = {192, 0, 2, 1};
    lr_router_set_local_address(r, session, 1 /* AF_INET */,
                                local_addr, 4);

    if (lr_router_start_session(r, session) != 0) {
        fprintf(stderr, "start_session: %s\n", lr_last_error());
        return 1;
    }

    /* Originate 203.0.113.0/24 with next-hop 192.0.2.1. */
    uint8_t prefix[4] = {203, 0, 113, 0};
    uint8_t next_hop[4] = {192, 0, 2, 1};
    if (lr_router_originate_v4(r, prefix, 24, next_hop) != 0) {
        fprintf(stderr, "originate_v4: %s\n", lr_last_error());
        return 1;
    }

    /* Drain the bytes the session wants on the wire. */
    lr_bytes_t out = {0};
    if (lr_router_drain_output(r, session, &out) == 0 &&
        lr_bytes_len(&out) > 0) {
        printf("wire bytes:");
        for (uintptr_t i = 0; i < lr_bytes_len(&out); i++) {
            printf(" %02x", lr_bytes_ptr(&out)[i]);
        }
        printf("\n");
    }
    lr_bytes_free(&out);

    /* Drive timers with a monotonic millisecond clock. */
    lr_router_tick(r, 0);

    lr_router_destroy(r);
    return 0;
}
```

Note the link order in the build command: sources come before `-llr_ffi`.
With `ld --as-needed` (the default on Ubuntu) a library listed before the
objects that reference its symbols is dropped.

## Error handling

Every entry point returns `int32_t` or `int64_t`: `0` on success and a
negative value on failure. Check the code before you touch an output
parameter, then read `lr_last_error()` for the human-readable reason.

```c
uint64_t session = 0;
int32_t rc = lr_router_add_bgp_session(r, 64512, 64513, 0x0A000001,
                                       90, 0, 1, &session);
if (rc != 0) {
    /* lr_last_error() is valid until the next FFI call on this thread. */
    fprintf(stderr, "add_bgp_session failed (rc=%d): %s\n",
            rc, lr_last_error());
    lr_router_destroy(r);
    return 1;
}
```

Two details that trip up C callers:

- **A positive return is not always an error.** `lr_router_withdraw_v4`
  and `lr_router_uninstall_static_v4` return `1` when the prefix was not
  locally originated or was not static; `lr_router_request_route_refresh`
  returns `1` when a refresh was queued. Test for `< 0` when the doc
  comment says so, and for `!= 0` otherwise.
- **The last-error string is thread-local.** `lr_last_error()` reports the
  most recent failure on the calling thread and is invalidated by the
  next call on that thread, so copy the text before you call anything
  else.

The header defines `LR_ERR_OK`, `LR_ERR_NULL`, `LR_ERR_INVALID_HANDLE`,
`LR_ERR_BAD_UTF8`, `LR_ERR_PANIC` and `LR_ERR_OTHER` for the codes a
caller is likely to branch on; an entry point whose doc comment names a
different value is authoritative for that call.
[`../ffi_design.md`](../ffi_design.md) §10 lists every value and notes
where the Rust variant names do not match the practice — `-5` in
particular has no macro, because the SRv6 codec entry points use it for
their own failures rather than as a general error code.

## The event loop

The library performs no I/O. Per iteration: call `lr_router_tick` with
your monotonic millisecond clock, drain each session with
`lr_router_drain_output` and send the bytes, push inbound bytes back with
`lr_router_feed_input`, and collect events with `lr_router_poll_events`.
[`../ffi_design.md`](../ffi_design.md) §7 has a worked loop.

`lr_router_poll_events` requeues events that did not fit the buffer, so
polling with a small array loses nothing.

## Installation check

`tests/ffi/harness.c` is the maintained smoke test for this surface;
building and running it is the quickest way to confirm a working
installation:

```sh
cc -Iinclude tests/ffi/harness.c -Ltarget/release -llr_ffi \
   -o /tmp/lr_harness
LD_LIBRARY_PATH=target/release /tmp/lr_harness
```

It runs in the `ffi-bindings` job of
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) after
`cargo build --release -p lr-ffi`.

## API map

The header is the complete list. The groups an embedder reaches for
first:

| Area | Entry points |
| --- | --- |
| Router lifecycle | `lr_router_new`, `lr_router_destroy` |
| BGP sessions | `lr_router_add_bgp_session`, `lr_router_add_bgp_session_ext`, `lr_router_start_session` |
| Data plane | `lr_router_feed_input`, `lr_router_drain_output`, `lr_router_tick`, `lr_router_poll_events` |
| Session policy | `lr_router_set_session_policy`, `lr_router_set_ebgp_requires_policy`, `lr_router_set_enforce_first_as` |
| MP-BGP | `lr_router_set_mp_families`, `lr_router_set_extended_next_hop`, `lr_router_set_add_path` |
| Local routes | `lr_router_originate_v4`/`_v6`, `lr_router_originate_labeled_v4`/`_v6`, `lr_router_withdraw_v4`/`_v6`, `lr_router_install_static_v4`/`_v6` |
| Policy objects | `lr_prefix_list_*`, `lr_route_map_*`, `lr_resolver_*`, `lr_filter_*` |
| ROA | `lr_roa_store_*`, `lr_router_add_roa_entry`, `lr_router_set_roa_validate` |
| Observability | `lr_router_rib_len`, `lr_router_rib_dump`, `lr_router_sessions_dump` |

Every buffer the ABI hands you is owned: release it with
`lr_bytes_free`. Every handle you create is yours: release it with the
matching `lr_*_free` / `lr_*_destroy`. Neither is done for you in C.
