// librouting.hpp — header-only RAII C++ wrapper around lr_ffi.h.
//
// Provides `librouting::Router`, `librouting::Bytes` and friends that own
// C ABI handles via std::unique_ptr with custom deleters. Throws
// `librouting::Error` (a std::runtime_error subclass) on FFI errors.
#pragma once

extern "C" {
#include "lr_ffi.h"
}

#include <algorithm>
#include <array>
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

/// RAII handle to a shared RFC 2439 damping table (ROADMAP-v3 D4.4).
/// The router's import hook holds its own reference, so destroying
/// this handle releases only the embedder's decay access.
struct DampingDeleter {
    void operator()(lr_damping_t d) const noexcept {
        if (d) lr_damping_destroy(d);
    }
};
using Damping = std::unique_ptr<OpaqueDamping, DampingDeleter>;

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

// ===== Local route lifecycle =====

/// Originate a local IPv4 route into Loc-RIB and advertise it (FRR
/// `network ...`).
inline void originate_v4(Router& r, const std::array<std::uint8_t, 4>& prefix,
                         std::uint8_t prefix_len, const std::uint8_t* next_hop = nullptr) {
    int rc = lr_router_originate_v4(r.get(), prefix.data(), prefix_len, next_hop);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_originate_v4 failed: " + std::string(err ? err : "unknown"));
    }
}

/// Originate a local IPv6 route (AFI=2, SAFI=1; MP_REACH_NLRI on egress).
inline void originate_v6(Router& r, const std::array<std::uint8_t, 16>& prefix,
                         std::uint8_t prefix_len, const std::uint8_t* next_hop = nullptr) {
    int rc = lr_router_originate_v6(r.get(), prefix.data(), prefix_len, next_hop);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_originate_v6 failed: " + std::string(err ? err : "unknown"));
    }
}

/// Withdraw a locally originated IPv4 route (FRR `no network ...`).
/// Returns true when a route was withdrawn; false when the prefix was
/// not locally originated (idempotent no-op).
inline bool withdraw_v4(Router& r, const std::array<std::uint8_t, 4>& prefix,
                        std::uint8_t prefix_len) {
    int rc = lr_router_withdraw_v4(r.get(), prefix.data(), prefix_len);
    if (rc < 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_withdraw_v4 failed: " + std::string(err ? err : "unknown"));
    }
    return rc == 0;
}

/// Withdraw a locally originated IPv6 route (FRR `no network ...`).
inline bool withdraw_v6(Router& r, const std::array<std::uint8_t, 16>& prefix,
                       std::uint8_t prefix_len) {
    int rc = lr_router_withdraw_v6(r.get(), prefix.data(), prefix_len);
    if (rc < 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_withdraw_v6 failed: " + std::string(err ? err : "unknown"));
    }
    return rc == 0;
}

// ===== D4.4 — redistribution / aggregation / damping =====

/// Wire protocol identifiers for redistribution pipes. Mirrors
/// `LrProtocol` in lr_ffi.h.
enum class Protocol : std::int32_t {
    Bgp = 0,
    Ospf = 1,
    Ospf3 = 2,
    Babel = 3,
    Static = 4,
    Connected = 5,
};

/// Metric transformation for a redistribution pipe.
enum class MetricPolicy : std::int32_t {
    Inherit = 0,
    Fixed = 1,
    Add = 2,
};

/// One IPv4/IPv6 prefix. IPv4 goes in the first four bytes of `addr`.
inline lr_prefix_t make_prefix(const std::vector<std::uint8_t>& addr, std::uint8_t prefix_len) {
    if (addr.size() != 4 && addr.size() != 16) {
        throw Error("make_prefix: bad address length (want 4 or 16)");
    }
    lr_prefix_t p{};
    std::copy(addr.begin(), addr.end(), p.addr);
    p.is_ipv6 = addr.size() == 16 ? 1 : 0;
    p.prefix_len = prefix_len;
    return p;
}

/// Install a redistribution pipe (BIRD `pipe` / FRR `redistribute`):
/// routes from `source` are re-originated into `target` with the
/// configured metric policy, optional tag and optional allow-list.
inline void add_redistribution_pipe(Router& r,
                                    Protocol source,
                                    Protocol target,
                                    MetricPolicy metric_policy,
                                    std::uint32_t metric,
                                    bool has_tag,
                                    std::uint32_t tag,
                                    const std::vector<lr_prefix_t>& allow = {}) {
    int rc = lr_router_add_redistribution_pipe(
        r.get(), static_cast<std::int32_t>(source), static_cast<std::int32_t>(target),
        static_cast<std::int32_t>(metric_policy), metric, has_tag ? 1 : 0, tag,
        allow.empty() ? nullptr : allow.data(), allow.size());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_add_redistribution_pipe failed: " +
                    std::string(err ? err : "unknown"));
    }
}

/// Register an RFC 4271 §9.2.2.2 aggregate (zeroed AS_PATH +
/// ATOMIC_AGGREGATE + AGGREGATOR while a more-specific exists).
inline void add_aggregate(Router& r, const lr_prefix_t& prefix) {
    int rc = lr_router_add_aggregate(r.get(), &prefix);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_add_aggregate failed: " + std::string(err ? err : "unknown"));
    }
}

/// Withdraw a previously registered aggregate (unknown prefixes are
/// a no-op).
inline void remove_aggregate(Router& r, const lr_prefix_t& prefix) {
    int rc = lr_router_remove_aggregate(r.get(), &prefix);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_remove_aggregate failed: " + std::string(err ? err : "unknown"));
    }
}

/// RFC 2439 damping tunables (mirrors `lr_damping_config_t`).
inline Damping set_damping(Router& r, const lr_damping_config_t& cfg) {
    lr_damping_t d = lr_router_set_damping(r.get(), &cfg);
    if (!d) {
        const char* err = lr_last_error();
        throw Error("lr_router_set_damping failed: " + std::string(err ? err : "unknown"));
    }
    return Damping(d);
}

/// Drive one damping decay pass; returns the number of prefixes that
/// re-emerged from suppression.
inline std::int32_t damping_decay(Damping& d, std::uint64_t now_s) {
    std::int32_t rc = lr_damping_decay(d.get(), now_s);
    if (rc < 0) {
        const char* err = lr_last_error();
        throw Error("lr_damping_decay failed: " + std::string(err ? err : "unknown"));
    }
    return rc;
}

inline std::vector<std::uint8_t> to_vec(const Bytes& b) {
    if (!b) return {};
    auto len = lr_bytes_len(b.get());
    auto* ptr = lr_bytes_ptr(b.get());
    return std::vector<std::uint8_t>(ptr, ptr + len);
}

} // namespace librouting
