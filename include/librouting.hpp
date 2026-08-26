// librouting.hpp — header-only RAII C++ wrapper around lr_ffi.h.
//
// Provides `librouting::Router`, `librouting::Bytes` and friends that own
// C ABI handles via std::unique_ptr with custom deleters. Throws
// `librouting::Error` (a std::runtime_error subclass) on FFI errors.
#pragma once

#include "lr_ffi.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace librouting {

class Error : public std::runtime_error {
public:
    explicit Error(std::string msg) : std::runtime_error(msg) {}
};

namespace detail {

struct RouterDeleter {
    void operator()(lr_router_t r) const noexcept {
        if (r) lr_router_destroy(r);
    }
};

struct BytesDeleter {
    void operator()(lr_bytes_t* b) const noexcept {
        if (b) lr_bytes_free(b);
    }
};

} // namespace detail

using Router = std::unique_ptr<OpaqueRouter, detail::RouterDeleter>;
using Bytes = std::unique_ptr<lr_bytes_t, detail::BytesDeleter>;

inline Router make_router() {
    auto r = lr_router_new();
    if (!r) throw Error("lr_router_new returned null");
    return Router(r);
}

inline std::uint64_t add_bgp_session(Router& r,
                                     std::uint32_t local_as,
                                     std::uint32_t peer_as,
                                     std::uint32_t local_bgp_id,
                                     std::uint16_t hold_time = 90,
                                     std::uint16_t keepalive = 0,
                                     bool asn4 = true) {
    // RFC 4724 graceful restart on (120 s), RFC 9494 LLGR off.
    return add_bgp_session_ext(r, local_as, peer_as, local_bgp_id, hold_time,
                               keepalive, asn4, true, 120, false, 0, 0);
}

/// Extended session creation with graceful-restart knobs.
///
/// - `graceful_restart` / `gr_restart_time`: RFC 4724 (seconds).
/// - `long_lived_gr` / `llgr_stale_time`: RFC 9494 long-lived graceful
///   restart. LLGR requires GR (RFC 9494 §4.1); it is not advertised
///   when `graceful_restart` is false.
/// - `llgr_max_stale_time`: local cap (seconds) on the stale time
///   received from the peer; 0 honours the peer's value.
inline std::uint64_t add_bgp_session_ext(Router& r,
                                         std::uint32_t local_as,
                                         std::uint32_t peer_as,
                                         std::uint32_t local_bgp_id,
                                         std::uint16_t hold_time,
                                         std::uint16_t keepalive,
                                         bool asn4,
                                         bool graceful_restart,
                                         std::uint16_t gr_restart_time,
                                         bool long_lived_gr,
                                         std::uint32_t llgr_stale_time,
                                         std::uint32_t llgr_max_stale_time) {
    std::uint64_t h = 0;
    int rc = lr_router_add_bgp_session_ext(
        r.get(), local_as, peer_as, local_bgp_id, hold_time, keepalive,
        asn4 ? 1 : 0, graceful_restart ? 1 : 0, gr_restart_time,
        long_lived_gr ? 1 : 0, llgr_stale_time, llgr_max_stale_time, &h);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_add_bgp_session_ext failed: " +
                    std::string(err ? err : "unknown"));
    }
    return h;
}

inline void feed_input(Router& r, std::uint64_t session, const std::uint8_t* data, std::size_t len) {
    int rc = lr_router_feed_input(r.get(), session, data, len);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_feed_input failed: " + std::string(err ? err : "unknown"));
    }
}

inline Bytes drain_output(Router& r, std::uint64_t session) {
    lr_bytes_t* out = nullptr;
    int rc = lr_router_drain_output(r.get(), session, &out);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_drain_output failed: " + std::string(err ? err : "unknown"));
    }
    return Bytes(out);
}

inline void tick(Router& r, std::uint64_t now_ms) {
    int rc = lr_router_tick(r.get(), now_ms);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_tick failed: " + std::string(err ? err : "unknown"));
    }
}

inline std::vector<std::uint8_t> to_vec(const Bytes& b) {
    if (!b) return {};
    auto len = lr_bytes_len(b.get());
    auto* ptr = lr_bytes_ptr(b.get());
    return std::vector<std::uint8_t>(ptr, ptr + len);
}

} // namespace librouting
