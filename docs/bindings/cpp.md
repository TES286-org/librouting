# C++ binding guide

`include/librouting.hpp` is a header-only RAII wrapper over the C ABI.
`librouting::Router`, `librouting::Bytes`, `librouting::RoaStore` and
`librouting::Damping` are `std::unique_ptr` aliases with custom deleters,
and every fallible function throws `librouting::Error`. Read this if you
are embedding the library in C++17 or later and want the C ABI's
ownership rules handled for you.

[`c.md`](c.md) documents the ABI the wrapper delegates to, and
[`../ffi_design.md`](../ffi_design.md) documents the locking, panic and
buffer-ownership contracts that the wrapper does not hide.

Build the shared library once:

```sh
cargo build --release -p lr-ffi
```

## A first program

The program below creates a router, adds an eBGP session, originates a
prefix and drains the OPEN the session produces.

```cpp
// lr_quickstart.cpp — build with:
//   c++ -std=c++17 -Iinclude lr_quickstart.cpp \
//       -Ltarget/release -llr_ffi -o lr_quickstart
// Run with:
//   LD_LIBRARY_PATH=target/release ./lr_quickstart
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#include "librouting.hpp"

int main() {
    auto r = librouting::make_router();

    // Defaults: hold 90 s, ASN4 on, graceful restart (RFC 4724) on.
    auto session = librouting::add_bgp_session(
        r, 64512, 64513, 0x0A000001);

    // next-hop-self for the eBGP advertisement.
    const std::vector<std::uint8_t> local_addr = {192, 0, 2, 1};
    librouting::set_local_address(r, session, local_addr);

    // The wrapper has no start_session helper; this one line is the ABI.
    if (lr_router_start_session(r.get(), session) != 0) {
        std::cerr << "start_session: " << lr_last_error() << '\n';
        return 1;
    }

    // Originate 203.0.113.0/24 with next-hop 192.0.2.1.
    const std::array<std::uint8_t, 4> prefix = {203, 0, 113, 0};
    const std::uint8_t next_hop[4] = {192, 0, 2, 1};
    librouting::originate_v4(r, prefix, 24, next_hop);

    // Drain the bytes the session wants on the wire. `Bytes` frees
    // itself; `to_vec` copies into a plain vector.
    auto out = librouting::drain_output(r, session);
    std::cout << "wire bytes:";
    for (std::uint8_t b : librouting::to_vec(out)) {
        std::cout << ' ' << std::hex << static_cast<int>(b);
    }
    std::cout << '\n';

    // Drive timers with a monotonic millisecond clock.
    librouting::tick(r, 0);

    return 0;
    // The Router's unique_ptr deleter calls lr_router_destroy.
}
```

The header wraps `lr_ffi.h` in `extern "C"`, so there is no link-time
dependency beyond `liblr_ffi` itself and no generated source to track.

## Error handling

Every fallible wrapper function throws `librouting::Error`, which derives
from `std::runtime_error`:

```cpp
class Error : public std::runtime_error {
public:
    explicit Error(std::string msg) : std::runtime_error(msg) {}
};
```

The message carries the failing C function and the C-side last error, so
`what()` is the whole diagnostic. Catch it by reference:

```cpp
try {
    auto session = librouting::add_bgp_session(r, 64512, 64513, 0x0A000001);
    librouting::originate_v4(r, prefix, 24, next_hop);
} catch (const librouting::Error& e) {
    std::cerr << "librouting: " << e.what() << '\n';
    return 1;
}
```

Three properties are worth knowing:

- **`Error` has no error-code accessor.** It is constructed from a message
  string, so the `int32_t` code is not preserved. If you need to branch on
  the code, call the C ABI and test the return value yourself.
- **The exception is not the source of the message.** It is built from
  `lr_last_error()`, which is thread-local and valid only until the next
  FFI call on that thread. `what()` copies it, so the string in the
  exception stays valid.
- **`check_rc(int32_t, const char*)` is the one-liner behind most
  wrappers.** It throws `Error` when `rc != 0`. The wrappers that need a
  distinguishing return value — `withdraw_v4`, `uninstall_static_v4`,
  `damping_decay`, `resolver_add_prefix_list` — test the code themselves.

A corrupted or destroyed handle is a programming error, not an
exception: the wrapper's deleters are `noexcept`, and using a moved-from
handle is undefined behaviour in the same way as any `unique_ptr`.

## What the wrapper covers

The wrapper is a convenience layer, not a mirror of the header. This is
the real surface; [`include/lr_ffi.h`](../../include/lr_ffi.h) is the
complete ABI, and `r.get()` reaches all of it.

| Area | Wrapper names |
| --- | --- |
| Ownership | `Router`, `Bytes`, `RoaStore`, `Damping` |
| Router + sessions | `make_router`, `add_bgp_session`, `add_bgp_session_ext` |
| OSPF / Babel | `add_ospf_session`, `add_ospfv3_session`, `add_ospf_session_ext`, `add_babel_session` |
| Data plane | `feed_input`, `drain_output`, `tick`, `poll_events`, `Event`, `EventKind` |
| Local routes | `originate_v4`/`_v6`, `withdraw_v4`/`_v6`, `install_static_v4`/`_v6`, `uninstall_static_v4`/`_v6` |
| Session knobs | `set_mp_families`, `set_extended_next_hop`, `set_local_address` |
| Redistribution | `add_redistribution_pipe`, `add_aggregate`, `remove_aggregate`, `make_prefix` |
| Damping | `set_damping`, `damping_decay` |
| ROA | `make_roa_store`, `roa_store_replace_static`, `roa_store_apply_deltas`, `roa_store_validate` |
| Policy objects | `make_route_v4`/`_v6`, `make_prefix_list`, `make_route_map`, `make_resolver`, `make_filter` and their setters/evaluators |
| BGP encoders | `encode_keepalive`, `encode_open`, `encode_notification`, `encode_update_withdraw_v4`, `encode_update_announce_v4` |
| Buffer helper | `to_vec` |

Functions the header exports that the wrapper does **not** cover include
`lr_router_start_session`, `lr_router_rib_len`, `lr_router_rib_dump`,
`lr_router_sessions_dump`, `lr_router_add_roa_entry`,
`lr_router_set_roa_validate`, `lr_router_set_add_path`,
`lr_router_request_route_refresh`, `lr_router_set_soft_reconfig_inbound`,
`lr_router_soft_reconfig_inbound`, `lr_router_set_local_as_tolerance`,
`lr_router_set_enforce_first_as`,
`lr_router_set_ebgp_requires_policy`, `lr_router_originate_labeled_v4`
and `_v6`, `lr_bgp_decode`, `lr_ospf_decode_v2`, `lr_babel_decode`, the
`lr_srv6_*` pair and `lr_mpls_platform_labels`. They return `int32_t` or
fill an `lr_bytes_t`; combine `r.get()` with the row you need and the
patterns in [`c.md`](c.md).

## CI coverage

`tests/ffi/harness.cpp` exercises the wrapper end to end — RAII
lifecycle, the throwing path, an OPEN/KEEPALIVE round trip with the LLGR
capability check, the setter helpers, and the error-path throws. The
`ffi-bindings` job of
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) builds it
with `c++ -std=c++17` against `liblr_ffi.so`; a failure fails the build.
