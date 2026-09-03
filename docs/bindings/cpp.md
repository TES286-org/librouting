# C++ binding guide

The C++ surface (`include/librouting.hpp`) is a header-only RAII
wrapper over the C ABI: `librouting::Router` owns the native router
via `std::unique_ptr` with a custom deleter, `librouting::Bytes`
owns returned buffers, and errors throw `librouting::Error`. Inline
helpers cover the common calls; anything the wrapper does not cover
yet is one `r.get()` away from the plain C ABI.

Build the shared library once:

```sh
cargo build --release -p lr-ffi
```

A complete program — create a router, add an eBGP session, originate
a prefix, drain the wire bytes:

```cpp
// lr_quickstart.cpp — build with:
//   c++ -std=c++17 -Iinclude lr_quickstart.cpp \
//       -Ltarget/release -llr_ffi -o lr_quickstart
// Run with:
//   LD_LIBRARY_PATH=target/release ./lr_quickstart
#include <cstdint>
#include <iostream>
#include <vector>

#include "librouting.hpp"

int main() {
    auto r = librouting::make_router();

    // Defaults: hold 90s, ASN4 on, graceful restart (RFC 4724) on.
    auto session = librouting::add_bgp_session(
        r, 64512, 64513, 0x0A000001);

    // next-hop-self for the eBGP advertisement (wrapper helper).
    const std::vector<std::uint8_t> local_addr = {192, 0, 2, 1};
    librouting::set_local_address(r, session, local_addr);

    // The wrapper does not cover start/originate yet — use the ABI.
    if (lr_router_start_session(r.get(), session) != 0) {
        std::cerr << "start_session failed\n";
        return 1;
    }
    const std::uint8_t prefix[4] = {203, 0, 113, 0};
    const std::uint8_t next_hop[4] = {192, 0, 2, 1};
    if (lr_router_originate_v4(r.get(), prefix, 24, next_hop) != 0) {
        std::cerr << "originate_v4 failed\n";
        return 1;
    }

    // Drain the bytes the session wants on the wire. `Bytes` frees
    // itself; `to_vec` copies into a plain vector.
    auto out = librouting::drain_output(r, session);
    std::cout << "wire bytes:";
    for (std::uint8_t b : librouting::to_vec(out)) {
        std::cout << ' ' << std::hex << static_cast<int>(b);
    }
    std::cout << '\n';

    // Drive timers with a monotonic millisecond clock (wrapper helper).
    librouting::tick(r, 0);

    return 0;
    // The Router's unique_ptr deleter calls lr_router_destroy.
}
```

The header compiles as `extern "C" { #include "lr_ffi.h" }` — no
link-time dependency beyond `liblr_ffi` itself, and no generated
sources to track.

API map: `add_bgp_session_ext` exposes the RFC 4724/9494 knobs
(`graceful_restart`, `gr_restart_time`, `long_lived_gr`,
`llgr_stale_time`, `llgr_max_stale_time`); `set_mp_families` /
`set_extended_next_hop` (RFC 5549) gate the multi-protocol families
before `start_session`; the RFC 8212 posture, `allowas-in`, soft
reconfiguration, RFC 8277 labelled origination and the Loc-RIB dump
are available through the C ABI directly
(`lr_router_set_ebgp_requires_policy`,
`lr_router_set_local_as_tolerance`,
`lr_router_set_soft_reconfig_inbound`,
`lr_router_originate_labeled_v4/v6`, `lr_router_rib_dump`) — each
throwing nothing and returning `int32_t` codes, so wrap them in a
helper that converts to `librouting::Error` when the wrapper grows
one.
