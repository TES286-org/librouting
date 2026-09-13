// librouting.hpp — header-only RAII C++ wrapper around lr_ffi.h.
//
// Provides `librouting::Router`, `librouting::Bytes` and friends that own
// C ABI handles via std::unique_ptr with custom deleters. Throws
// `librouting::Error` (a std::runtime_error subclass) on FFI errors.
#pragma once

extern "C" {
#include "lr_ffi.h"
}

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

/// RAII handle to a live ROA store (RFC 6482 / RFC 6811 / RFC 8210;
/// ROADMAP-v3 D2.3) — static + RTR provenance layers with atomic
/// snapshot swaps.
struct RoaStoreDeleter {
    void operator()(lr_roa_store_t s) const noexcept {
        if (s) lr_roa_store_free(s);
    }
};
using RoaStore = std::unique_ptr<OpaqueRoaStore, RoaStoreDeleter>;

inline Router make_router() {
    auto r = lr_router_new();
    if (!r) throw Error("lr_router_new returned null");
    return Router(r);
}

inline RoaStore make_roa_store() {
    auto s = lr_roa_store_new();
    if (!s) throw Error("lr_roa_store_new returned null");
    return RoaStore(s);
}

/// Atomically replace the store's static (configuration) layer.
inline void roa_store_replace_static(RoaStore& s, const std::vector<lr_roa_entry_t>& entries) {
    int rc = lr_roa_store_replace_static(s.get(), entries.data(), entries.size());
    if (rc != 0) {
        throw Error(std::string("lr_roa_store_replace_static: ") + lr_last_error());
    }
}

/// Apply one completed RTR sync's delta batch atomically.
inline void roa_store_apply_deltas(RoaStore& s, const std::vector<lr_roa_delta_t>& deltas) {
    int rc = lr_roa_store_apply_deltas(s.get(), deltas.data(), deltas.size());
    if (rc != 0) {
        throw Error(std::string("lr_roa_store_apply_deltas: ") + lr_last_error());
    }
}

/// RFC 6811 §2 validation against the current snapshot.
inline std::uint8_t roa_store_validate(RoaStore& s,
                                       const std::uint8_t* addr_v4,
                                       const std::uint8_t* addr_v6,
                                       std::uint8_t prefix_len,
                                       std::uint32_t origin_as,
                                       bool has_origin_as) {
    std::uint8_t state = 0;
    int rc = lr_roa_store_validate(s.get(), addr_v4, addr_v6, prefix_len, origin_as,
                                   has_origin_as ? 1 : 0, &state);
    if (rc != 0) {
        throw Error(std::string("lr_roa_store_validate: ") + lr_last_error());
    }
    return state;
}

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
                                         std::uint32_t llgr_max_stale_time);

/// Create a BGP session with the defaults an operator expects:
/// graceful restart on (120 s), RFC 9494 LLGR off.
inline std::uint64_t add_bgp_session(Router& r,
                                     std::uint32_t local_as,
                                     std::uint32_t peer_as,
                                     std::uint32_t local_bgp_id,
                                     std::uint16_t hold_time = 90,
                                     std::uint16_t keepalive = 0,
                                     bool asn4 = true) {
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
    // The FFI writes the bytes into a caller-provided struct and expects
    // it to be freed with lr_bytes_free (which drops the struct itself),
    // so allocate it on the heap and hand ownership to Bytes.
    auto out = std::make_unique<lr_bytes_t>();
    int rc = lr_router_drain_output(r.get(), session, out.get());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_drain_output failed: " + std::string(err ? err : "unknown"));
    }
    return Bytes(out.release());
}

inline void tick(Router& r, std::uint64_t now_ms) {
    int rc = lr_router_tick(r.get(), now_ms);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_tick failed: " + std::string(err ? err : "unknown"));
    }
}

/// RFC 5549 Extended Next-Hop tuple: `(NLRI AFI, NLRI SAFI, Nexthop AFI)`.
/// The canonical entry `{1, 1, 2}` advertises IPv4 unicast over an IPv6
/// next-hop.
struct ExtNextHopTuple {
    std::uint16_t nlri_afi;
    std::uint8_t  nlri_safi;
    std::uint16_t nexthop_afi;
};

/// Configure RFC 5549 Extended Next-Hop on a BGP session. Must be called
/// after `add_bgp_session` and before `start_session`.
inline void set_extended_next_hop(Router& r, std::uint64_t session,
                                  const std::vector<ExtNextHopTuple>& tuples) {
    std::vector<std::uint8_t> buf;
    buf.reserve(tuples.size() * 5);
    for (const auto& t : tuples) {
        buf.push_back(static_cast<std::uint8_t>(t.nlri_afi >> 8));
        buf.push_back(static_cast<std::uint8_t>(t.nlri_afi));
        buf.push_back(t.nlri_safi);
        buf.push_back(static_cast<std::uint8_t>(t.nexthop_afi >> 8));
        buf.push_back(static_cast<std::uint8_t>(t.nexthop_afi));
    }
    int rc = lr_router_set_extended_next_hop(
        r.get(), session,
        buf.empty() ? nullptr : buf.data(),
        tuples.size());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_set_extended_next_hop failed: " +
                    std::string(err ? err : "unknown"));
    }
}

/// RFC 4760 MP-BGP family: `(AFI, SAFI)`. `{1, 1}` is IPv4 unicast,
/// `{2, 1}` is IPv6 unicast.
struct MPFamily {
    std::uint16_t afi;
    std::uint8_t  safi;
};

/// Override the MP-BGP address families advertised in OPEN. Must be
/// called before `start_session`.
inline void set_mp_families(Router& r, std::uint64_t session,
                            const std::vector<MPFamily>& families) {
    std::vector<std::uint8_t> buf;
    buf.reserve(families.size() * 4);
    for (const auto& f : families) {
        buf.push_back(static_cast<std::uint8_t>(f.afi >> 8));
        buf.push_back(static_cast<std::uint8_t>(f.afi));
        buf.push_back(0); // reserved
        buf.push_back(f.safi);
    }
    int rc = lr_router_set_mp_families(
        r.get(), session,
        buf.empty() ? nullptr : buf.data(),
        families.size());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_set_mp_families failed: " +
                    std::string(err ? err : "unknown"));
    }
}

/// Set the local source address for next-hop-self egress. `addr` must be
/// 4 bytes (IPv4) or 16 bytes (IPv6). For RFC 5549 ENH egress over IPv6
/// pass a 16-byte IPv6 address.
inline void set_local_address(Router& r, std::uint64_t session,
                              const std::vector<std::uint8_t>& addr) {
    std::uint16_t afi;
    if (addr.size() == 4) {
        afi = 1;
    } else if (addr.size() == 16) {
        afi = 2;
    } else {
        throw Error("set_local_address: bad address length (want 4 or 16)");
    }
    int rc = lr_router_set_local_address(
        r.get(), session, afi, addr.data(), addr.size());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_set_local_address failed: " +
                    std::string(err ? err : "unknown"));
    }
}

inline std::vector<std::uint8_t> to_vec(const Bytes& b) {
    if (!b) return {};
    auto len = lr_bytes_len(b.get());
    auto* ptr = lr_bytes_ptr(b.get());
    return std::vector<std::uint8_t>(ptr, ptr + len);
}

} // namespace librouting
