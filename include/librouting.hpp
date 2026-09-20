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
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace librouting {

class Error : public std::runtime_error {
public:
    explicit Error(std::string msg) : std::runtime_error(msg) {}
};

/// Throw `Error(what + ": " + last_error)` when `rc != 0` — the
/// throwing one-liner behind the D5.3 policy-object wrappers.
inline void check_rc(std::int32_t rc, const char* what) {
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string(what) + " failed: " + std::string(err ? err : "unknown"));
    }
}

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

// ===== D5.1 — OSPF / OSPFv3 / Babel session management =====

/// OSPF protocol version selector (LR_OSPF_V2 / LR_OSPF_V3).
enum class OspfVersion : std::int32_t { V2 = 2, V3 = 3 };

/// OSPF area kind (LR_AREA_*): Normal, RFC 2328 §3.6 stub and the
/// "totally stubby" variant, RFC 3101 NSSA and the "totally NSSA"
/// variant. The stub/NSSA kinds inject a default route with the
/// configured metric on the area border router.
enum class OspfAreaKind : std::int32_t {
    Normal = 0,
    Stub = 1,
    StubNoSummary = 2,
    Nssa = 3,
    NssaNoSummary = 4,
};

/// OSPF interface network type (RFC 2328 §9.1): point-to-point always
/// becomes adjacent; broadcast elects a DR/BDR (§9.4, §10.4).
enum class OspfNetType : std::int32_t { Ptp = 0, Broadcast = 1 };

/// Add an OSPFv2 session with the library defaults (MTU 1500,
/// point-to-point, Normal area). Returns the session handle.
inline std::uint64_t add_ospf_session(Router& r,
                                      std::uint32_t router_id,
                                      std::uint32_t area_id) {
    std::uint64_t h = 0;
    int rc = lr_router_add_ospf_session(r.get(), router_id, area_id, &h);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_add_ospf_session failed: " +
                    std::string(err ? err : "unknown"));
    }
    return h;
}

/// Add an OSPFv3 session (RFC 5340) with the library defaults.
inline std::uint64_t add_ospfv3_session(Router& r,
                                        std::uint32_t router_id,
                                        std::uint32_t area_id) {
    std::uint64_t h = 0;
    int rc = lr_router_add_ospfv3_session(r.get(), router_id, area_id, &h);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_add_ospfv3_session failed: " +
                    std::string(err ? err : "unknown"));
    }
    return h;
}

/// Add an OSPF session with the full knob set: area kind + default
/// metric, MTU (§10.6), network type (§9.1) and the §10.4 segment
/// identities (`has_interface_ip` / `has_neighbor_ip` gate the
/// addresses; v2 uses the IPv4 interface address, v3 the Router ID).
inline std::uint64_t add_ospf_session_ext(Router& r,
                                          OspfVersion version,
                                          std::uint32_t router_id,
                                          std::uint32_t area_id,
                                          OspfAreaKind area_kind,
                                          std::uint32_t default_metric,
                                          std::uint16_t mtu,
                                          OspfNetType network_type,
                                          bool has_interface_ip,
                                          std::uint32_t interface_ip,
                                          bool has_neighbor_ip,
                                          std::uint32_t neighbor_ip) {
    std::uint64_t h = 0;
    int rc = lr_router_add_ospf_session_ext(
        r.get(), static_cast<std::int32_t>(version), router_id, area_id,
        static_cast<std::int32_t>(area_kind), default_metric, mtu,
        static_cast<std::int32_t>(network_type), has_interface_ip ? 1 : 0,
        interface_ip, has_neighbor_ip ? 1 : 0, neighbor_ip, &h);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_add_ospf_session_ext failed: " +
                    std::string(err ? err : "unknown"));
    }
    return h;
}

/// Add one Babel interface session (RFC 8966 §4.2.1). `addr` is the
/// 4-byte IPv4 or 16-byte IPv6 local address announced in Hellos.
inline std::uint64_t add_babel_session(Router& r,
                                       const std::vector<std::uint8_t>& addr) {
    if (addr.size() != 4 && addr.size() != 16) {
        throw Error("add_babel_session: bad address length (want 4 or 16)");
    }
    std::uint64_t h = 0;
    int rc = lr_router_add_babel_session(r.get(), addr.data(),
                                         addr.size() == 16 ? 1 : 0, &h);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_add_babel_session failed: " +
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

// ===== Static routes (BIRD `protocol static`, FRR `ip route`) =====

/// Install a static IPv4 route into the Loc-RIB. The route's protocol
/// is `Protocol::Static` and its admin distance is 1, so it wins over
/// every dynamic protocol except Connected. Pass `nullptr` for
/// `next_hop` to install a blackhole route (FRR `Null0`, BIRD
/// `blackhole`). `metric` is the per-route metric within the static
/// protocol (lower wins); `tag` is an optional 32-bit route tag
/// carried through redistribution pipes (pass 0 when not set).
inline void install_static_v4(Router& r,
                              const std::array<std::uint8_t, 4>& prefix,
                              std::uint8_t prefix_len,
                              const std::uint8_t* next_hop,
                              std::uint32_t metric = 0,
                              std::uint32_t tag = 0) {
    int rc = lr_router_install_static_v4(r.get(), prefix.data(), prefix_len,
                                         next_hop, metric, tag);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_install_static_v4 failed: " +
                    std::string(err ? err : "unknown"));
    }
}

/// Install a static IPv6 route into the Loc-RIB. See `install_static_v4`
/// for the semantics.
inline void install_static_v6(Router& r,
                              const std::array<std::uint8_t, 16>& prefix,
                              std::uint8_t prefix_len,
                              const std::uint8_t* next_hop,
                              std::uint32_t metric = 0,
                              std::uint32_t tag = 0) {
    int rc = lr_router_install_static_v6(r.get(), prefix.data(), prefix_len,
                                         next_hop, metric, tag);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_install_static_v6 failed: " +
                    std::string(err ? err : "unknown"));
    }
}

/// Withdraw a previously-installed static IPv4 route. Returns true when
/// a static route was removed; false when the prefix was not a static
/// route (idempotent no-op, matching `withdraw_v4`'s contract).
inline bool uninstall_static_v4(Router& r,
                                const std::array<std::uint8_t, 4>& prefix,
                                std::uint8_t prefix_len) {
    int rc = lr_router_uninstall_static_v4(r.get(), prefix.data(), prefix_len);
    if (rc < 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_uninstall_static_v4 failed: " +
                    std::string(err ? err : "unknown"));
    }
    return rc == 0;
}

/// Withdraw a previously-installed static IPv6 route. See
/// `uninstall_static_v4` for the semantics and the return value.
inline bool uninstall_static_v6(Router& r,
                                const std::array<std::uint8_t, 16>& prefix,
                                std::uint8_t prefix_len) {
    int rc = lr_router_uninstall_static_v6(r.get(), prefix.data(), prefix_len);
    if (rc < 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_uninstall_static_v6 failed: " +
                    std::string(err ? err : "unknown"));
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

// ===== D5.5 — event polling =====

/// Event kind constants (mirror lr_event_kind_t / LR_EVENT_*).
enum class EventKind : std::int32_t {
    PeerState = 1,
    RouteInstalled = 2,
    RouteWithdrawn = 3,
    Log = 4,
    PrefixAdvertised = 5,
    PrefixRetracted = 6,
    ProtocolError = 7,
    MaxPrefixExceeded = 8,
    MaxPrefixThreshold = 9,
};

/// One serialized router event. Only the fields meaningful for `kind`
/// are populated (see lr_event_t in lr_ffi.h).
struct Event {
    EventKind kind;
    std::uint64_t session = 0;
    std::vector<std::uint8_t> prefix; // 4 bytes (IPv4) or 16 (IPv6)
    std::uint8_t prefix_len = 0;
    bool is_ipv6 = false;
    std::uint32_t path_id = 0;
    std::uint32_t count = 0;
    std::uint32_t limit = 0;
    std::uint32_t pct = 0;
    std::int32_t action = 0;
    std::string text;
};

/// Poll up to `capacity` pending router events. Events beyond the
/// buffer are requeued (nothing is lost); transport-plane events never
/// surface — outgoing bytes ride the drain-output data plane.
inline std::vector<Event> poll_events(Router& r, std::size_t capacity = 32) {
    if (capacity == 0) {
        throw Error("poll_events: capacity must be positive");
    }
    std::vector<lr_event_t> raw(capacity);
    std::int32_t n = lr_router_poll_events(r.get(), raw.data(),
                                           static_cast<std::int32_t>(capacity));
    if (n < 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_poll_events failed: " + std::string(err ? err : "unknown"));
    }
    std::vector<Event> out;
    out.reserve(static_cast<std::size_t>(n));
    for (std::int32_t i = 0; i < n; ++i) {
        const auto& e = raw[static_cast<std::size_t>(i)];
        Event ev;
        ev.kind = static_cast<EventKind>(e.kind);
        ev.session = e.session;
        ev.is_ipv6 = e.is_ipv6 != 0;
        const std::size_t plen = e.is_ipv6 ? 16 : 4;
        ev.prefix.assign(e.prefix, e.prefix + plen);
        ev.prefix_len = e.prefix_len;
        ev.path_id = e.path_id;
        ev.count = e.count;
        ev.limit = e.limit;
        ev.pct = e.pct;
        ev.action = e.action;
        ev.text.assign(reinterpret_cast<const char*>(e.text), strnlen(reinterpret_cast<const char*>(e.text), sizeof(e.text)));
        out.push_back(std::move(ev));
    }
    return out;
}

// ===== D5.4 — BGP message encoders =====

/// Encode a KEEPALIVE message (RFC 4271 §4.4).
inline Bytes encode_keepalive() {
    auto b = std::make_unique<lr_bytes_t>();
    if (lr_bgp_encode_keepalive(b.get()) != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bgp_encode_keepalive failed: " + std::string(err ? err : "unknown"));
    }
    return Bytes(b.release());
}

/// Encode an OPEN message (RFC 4271 §4.2). With as4 the RFC 6793
/// four-octet-AS capability (code 65) is appended; an AS above 65535
/// then travels as AS_TRANS (23456) in the 16-bit field.
inline Bytes encode_open(std::uint32_t my_as, std::uint16_t hold_time,
                         const std::array<std::uint8_t, 4>& bgp_id, bool as4) {
    auto b = std::make_unique<lr_bytes_t>();
    if (lr_bgp_encode_open(my_as, hold_time, bgp_id.data(), as4 ? 1 : 0, b.get()) != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bgp_encode_open failed: " + std::string(err ? err : "unknown"));
    }
    return Bytes(b.release());
}

/// Encode a NOTIFICATION message (RFC 4271 §4.5): code + subcode and
/// an optional data payload.
inline Bytes encode_notification(std::uint8_t code, std::uint8_t subcode,
                                 const std::vector<std::uint8_t>& data = {}) {
    auto b = std::make_unique<lr_bytes_t>();
    if (lr_bgp_encode_notification(code, subcode, data.empty() ? nullptr : data.data(),
                                    data.size(), b.get()) != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bgp_encode_notification failed: " + std::string(err ? err : "unknown"));
    }
    return Bytes(b.release());
}

/// Encode a withdraw-only UPDATE (RFC 4271 §4.3): every listed IPv4
/// prefix goes into the withdrawn-routes section. IPv6 entries are
/// rejected (the legacy NLRI section carries IPv4 only).
inline Bytes encode_update_withdraw_v4(const std::vector<lr_prefix_t>& prefixes) {
    auto b = std::make_unique<lr_bytes_t>();
    if (lr_bgp_encode_update_withdraw_v4(prefixes.empty() ? nullptr : prefixes.data(),
                                          prefixes.size(), b.get()) != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bgp_encode_update_withdraw_v4 failed: " +
                    std::string(err ? err : "unknown"));
    }
    return Bytes(b.release());
}

/// Encode an announcement UPDATE (RFC 4271 §4.3): ORIGIN + AS_PATH +
/// NEXT_HOP attributes and the IPv4 NLRI. origin selects the ORIGIN
/// value (0=IGP, 1=EGP, 2=INCOMPLETE); as_path is an AS_SEQUENCE in
/// wire order (the origin AS first; empty for a locally originated
/// route); with as4 the segments use the RFC 6793 four-octet encoding.
inline Bytes encode_update_announce_v4(const std::vector<lr_prefix_t>& prefixes,
                                       const std::array<std::uint8_t, 4>& next_hop,
                                       const std::vector<std::uint32_t>& as_path = {},
                                       std::uint8_t origin = 0, bool as4 = true) {
    if (origin > 2) {
        throw Error("encode_update_announce_v4: origin must be 0 (IGP), 1 (EGP) or 2 (INCOMPLETE)");
    }
    auto b = std::make_unique<lr_bytes_t>();
    if (lr_bgp_encode_update_announce_v4(
            prefixes.empty() ? nullptr : prefixes.data(), prefixes.size(), next_hop.data(),
            as_path.empty() ? nullptr : as_path.data(), as_path.size(), origin, as4 ? 1 : 0,
            b.get()) != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bgp_encode_update_announce_v4 failed: " +
                    std::string(err ? err : "unknown"));
    }
    return Bytes(b.release());
}

inline std::vector<std::uint8_t> to_vec(const Bytes& b) {
    if (!b) return {};
    auto len = lr_bytes_len(b.get());
    auto* ptr = lr_bytes_ptr(b.get());
    return std::vector<std::uint8_t>(ptr, ptr + len);
}

// ===== D5.3 — policy objects: route handle, prefix-list, route-map,
// resolver =====

/// Verdict encoding for route-map entries.
enum class MapVerdict : std::int32_t { Continue = 0, Permit = 1, Deny = 2 };

/// `lr_route_map_evaluate` outcomes.
enum class EvalVerdict : std::int32_t {
    Fallthrough = -1,
    Deny = 0,
    Permit = 1,
};

struct RouteDeleter {
    void operator()(lr_route_t r) const noexcept { lr_route_free(r); }
};
/// An owned route handle (a boxed `lr_core::rib::Route`).
using Route = std::unique_ptr<OpaqueRoute, RouteDeleter>;

struct PrefixListDeleter {
    void operator()(lr_prefix_list_t l) const noexcept { lr_prefix_list_free(l); }
};
using PrefixListHandle = std::unique_ptr<OpaquePrefixList, PrefixListDeleter>;

struct RouteMapDeleter {
    void operator()(lr_route_map_t m) const noexcept { lr_route_map_free(m); }
};
using RouteMapHandle = std::unique_ptr<OpaqueRouteMap, RouteMapDeleter>;

struct ResolverDeleter {
    void operator()(lr_resolver_t r) const noexcept { lr_resolver_free(r); }
};
using ResolverHandle = std::unique_ptr<OpaqueResolver, ResolverDeleter>;

inline Route make_route_v4(const std::array<std::uint8_t, 4>& octets, std::uint8_t prefix_len,
                           Protocol proto) {
    auto r = lr_route_new_v4(octets.data(), prefix_len, static_cast<std::int32_t>(proto));
    if (!r) {
        const char* err = lr_last_error();
        throw Error("lr_route_new_v4 failed: " + std::string(err ? err : "unknown"));
    }
    return Route(r);
}

inline Route make_route_v6(const std::array<std::uint8_t, 16>& octets, std::uint8_t prefix_len,
                           Protocol proto) {
    auto r = lr_route_new_v6(octets.data(), prefix_len, static_cast<std::int32_t>(proto));
    if (!r) {
        const char* err = lr_last_error();
        throw Error("lr_route_new_v6 failed: " + std::string(err ? err : "unknown"));
    }
    return Route(r);
}

inline void set_next_hop(Route& r, const std::vector<std::uint8_t>& addr) {
    if (addr.size() != 4 && addr.size() != 16) {
        throw Error("set_next_hop: bad address length (want 4 or 16)");
    }
    check_rc(lr_route_set_next_hop(r.get(), addr.data(), addr.size() == 16 ? 1 : 0),
             "lr_route_set_next_hop");
}

/// Reads the next hop; `false` when absent. IPv4 comes back in the
/// first four bytes.
inline bool next_hop(Route& r, std::vector<std::uint8_t>& out, bool& is_ipv6) {
    std::uint8_t buf[16];
    std::int32_t v6 = 0;
    std::int32_t rc = lr_route_next_hop(r.get(), buf, &v6);
    if (rc == 1) return false;
    if (rc != 0) {
        throw Error("lr_route_next_hop failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    out.assign(buf, buf + (v6 ? 16 : 4));
    is_ipv6 = v6 != 0;
    return true;
}

inline void set_local_pref(Route& r, std::uint32_t value) {
    check_rc(lr_route_set_local_pref(r.get(), value), "lr_route_set_local_pref");
}

inline std::optional<std::uint32_t> local_pref(Route& r) {
    std::uint32_t v = 0;
    std::int32_t rc = lr_route_local_pref(r.get(), &v);
    if (rc == 1) return std::nullopt;
    if (rc != 0) {
        throw Error("lr_route_local_pref failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return v;
}

inline void set_med(Route& r, std::uint32_t value) {
    check_rc(lr_route_set_med(r.get(), value), "lr_route_set_med");
}

inline std::optional<std::uint32_t> med(Route& r) {
    std::uint32_t v = 0;
    std::int32_t rc = lr_route_med(r.get(), &v);
    if (rc == 1) return std::nullopt;
    if (rc != 0) {
        throw Error("lr_route_med failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return v;
}

/// ORIGIN values (RFC 4271 §5.1.1).
inline void set_origin(Route& r, std::uint8_t origin) {
    check_rc(lr_route_set_origin(r.get(), origin), "lr_route_set_origin");
}

inline std::optional<std::uint8_t> origin(Route& r) {
    std::uint8_t v = 0;
    std::int32_t rc = lr_route_origin(r.get(), &v);
    if (rc == 1) return std::nullopt;
    if (rc != 0) {
        throw Error("lr_route_origin failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return v;
}

/// Replace the AS_PATH with a flat sequence (empty drops the attribute).
inline void set_as_path(Route& r, const std::vector<std::uint32_t>& asns) {
    check_rc(lr_route_set_as_path(r.get(), asns.empty() ? nullptr : asns.data(), asns.size()),
             "lr_route_set_as_path");
}

inline std::vector<std::uint32_t> as_path(Route& r) {
    // These getters return the element count (>= 0) on success, so
    // only a negative rc is an error.
    std::int64_t n = lr_route_as_path(r.get(), nullptr, 0);
    if (n < 0) return {};
    std::vector<std::uint32_t> out(static_cast<std::size_t>(n));
    if (n > 0 && lr_route_as_path(r.get(), out.data(), out.size()) < 0) {
        throw Error("lr_route_as_path failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return out;
}

inline void add_community(Route& r, std::uint32_t asn, std::uint16_t value) {
    check_rc(lr_route_add_community(r.get(), asn, value), "lr_route_add_community");
}

/// Replace the standard communities from packed `asn << 16 | value`.
inline void set_communities(Route& r, const std::vector<std::uint64_t>& packed) {
    check_rc(lr_route_set_communities(r.get(), packed.empty() ? nullptr : packed.data(), packed.size()),
             "lr_route_set_communities");
}

inline std::vector<std::uint64_t> communities(Route& r) {
    std::int64_t n = lr_route_communities(r.get(), nullptr, 0);
    if (n < 0) return {};
    std::vector<std::uint64_t> out(static_cast<std::size_t>(n));
    if (n > 0 && lr_route_communities(r.get(), out.data(), out.size()) < 0) {
        throw Error("lr_route_communities failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return out;
}

inline void add_large_community(Route& r, std::uint32_t g, std::uint32_t d1, std::uint32_t d2) {
    check_rc(lr_route_add_large_community(r.get(), g, d1, d2), "lr_route_add_large_community");
}

/// Replace the large communities from flat triples.
inline void set_large_communities(Route& r, const std::vector<std::uint32_t>& triples) {
    if (triples.size() % 3 != 0) {
        throw Error("set_large_communities: triples must come in groups of three");
    }
    check_rc(lr_route_set_large_communities(r.get(), triples.empty() ? nullptr : triples.data(),
                                            triples.size() / 3),
             "lr_route_set_large_communities");
}

inline std::vector<std::uint32_t> large_communities(Route& r) {
    std::int64_t n = lr_route_large_communities(r.get(), nullptr, 0);
    if (n < 0) return {};
    std::vector<std::uint32_t> out(static_cast<std::size_t>(n));
    if (n > 0 && lr_route_large_communities(r.get(), out.data(), out.size()) < 0) {
        throw Error("lr_route_large_communities failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return out;
}

inline void add_ext_community(Route& r, std::uint8_t kind, std::uint8_t subtype,
                              std::uint32_t global, std::uint16_t local) {
    check_rc(lr_route_add_ext_community(r.get(), kind, subtype, global, local),
             "lr_route_add_ext_community");
}

inline std::vector<lr_ext_comm_t> ext_communities(Route& r) {
    std::int64_t n = lr_route_ext_communities(r.get(), nullptr, 0);
    if (n < 0) return {};
    std::vector<lr_ext_comm_t> out(static_cast<std::size_t>(n));
    if (n > 0 && lr_route_ext_communities(r.get(), out.data(), out.size()) < 0) {
        throw Error("lr_route_ext_communities failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return out;
}

inline void set_metric(Route& r, std::uint32_t value) {
    check_rc(lr_route_set_metric(r.get(), value), "lr_route_set_metric");
}

inline std::uint32_t metric(Route& r) {
    std::uint32_t v = 0;
    check_rc(lr_route_metric(r.get(), &v), "lr_route_metric");
    return v;
}

/// `std::nullopt` clears the tag.
inline void set_tag(Route& r, std::optional<std::uint32_t> tag) {
    check_rc(lr_route_set_tag(r.get(), tag ? 1 : 0, tag.value_or(0)), "lr_route_set_tag");
}

inline std::optional<std::uint32_t> tag(Route& r) {
    std::uint32_t v = 0;
    std::int32_t rc = lr_route_tag(r.get(), &v);
    if (rc == 1) return std::nullopt;
    if (rc != 0) {
        throw Error("lr_route_tag failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return v;
}

inline PrefixListHandle make_prefix_list() {
    auto l = lr_prefix_list_new();
    if (!l) throw Error("lr_prefix_list_new returned null");
    return PrefixListHandle(l);
}

inline void prefix_list_add(PrefixListHandle& l, const lr_prefix_t& prefix, std::uint8_t ge,
                            std::uint8_t le, bool permit) {
    check_rc(lr_prefix_list_add(l.get(), &prefix, ge, le, permit ? 1 : 0), "lr_prefix_list_add");
}

/// First-match evaluation; `false` covers deny + implicit deny.
inline bool prefix_list_match(PrefixListHandle& l, const lr_prefix_t& prefix) {
    std::int32_t rc = lr_prefix_list_match(l.get(), &prefix);
    if (rc < 0) {
        throw Error("lr_prefix_list_match failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return rc == 1;
}

inline RouteMapHandle make_route_map() {
    auto m = lr_route_map_new();
    if (!m) throw Error("lr_route_map_new returned null");
    return RouteMapHandle(m);
}

inline void route_map_add_entry(RouteMapHandle& m, const std::vector<lr_match_t>& matches,
                                const std::vector<lr_set_t>& sets, MapVerdict verdict) {
    check_rc(lr_route_map_add_entry(m.get(),
                                    matches.empty() ? nullptr : matches.data(), matches.size(),
                                    sets.empty() ? nullptr : sets.data(), sets.size(),
                                    static_cast<std::int32_t>(verdict)),
             "lr_route_map_add_entry");
}

inline EvalVerdict route_map_evaluate(RouteMapHandle& m, Route& r, ResolverHandle* resolver) {
    std::int32_t verdict = 0;
    lr_resolver_t res = resolver ? resolver->get() : nullptr;
    check_rc(lr_route_map_evaluate(m.get(), r.get(), res, &verdict), "lr_route_map_evaluate");
    return static_cast<EvalVerdict>(verdict);
}

inline ResolverHandle make_resolver() {
    auto r = lr_resolver_new();
    if (!r) throw Error("lr_resolver_new returned null");
    return ResolverHandle(r);
}

/// Register a prefix-list under `name`; the list is copied in. Returns
/// the numeric list id for `lr_match_t::list_id`.
inline std::int32_t resolver_add_prefix_list(ResolverHandle& res, const char* name,
                                             PrefixListHandle& list) {
    std::int32_t id = lr_resolver_add_prefix_list(res.get(), name, list.get());
    if (id < 0) {
        throw Error("lr_resolver_add_prefix_list failed: " +
                    std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return id;
}

inline std::int32_t resolver_add_as_path_list(ResolverHandle& res, const char* name,
                                              const std::vector<lr_as_path_filter_t>& filters) {
    std::int32_t id = lr_resolver_add_as_path_list(
        res.get(), name, filters.empty() ? nullptr : filters.data(), filters.size());
    if (id < 0) {
        throw Error("lr_resolver_add_as_path_list failed: " +
                    std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return id;
}

inline std::int32_t resolver_add_community_list(ResolverHandle& res, const char* name,
                                                const std::vector<lr_community_entry_t>& entries) {
    std::int32_t id = lr_resolver_add_community_list(
        res.get(), name, entries.empty() ? nullptr : entries.data(), entries.size());
    if (id < 0) {
        throw Error("lr_resolver_add_community_list failed: " +
                    std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    return id;
}

// ===== D5.2 — Filter DSL: compile / evaluate / free =====

/// `lr_filter_evaluate` verdicts.
enum class FilterVerdict : std::int32_t { Accept = 0, Reject = 1, Fallthrough = 2 };

struct FilterDeleter {
    void operator()(lr_filter_t f) const noexcept { lr_filter_free(f); }
};
/// An owned compiled filter (the D3.7 stack VM).
using Filter = std::unique_ptr<OpaqueFilter, FilterDeleter>;

inline Filter make_filter(const std::string& name, const std::string& body) {
    auto f = lr_filter_compile(name.c_str(), body.c_str());
    if (!f) {
        const char* err = lr_last_error();
        throw Error("lr_filter_compile failed: " + std::string(err ? err : "unknown"));
    }
    return Filter(f);
}

inline std::string filter_name(const Filter& f) {
    std::int64_t need = lr_filter_name(f.get(), nullptr, 0);
    if (need < 0) {
        throw Error("lr_filter_name failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    std::string out(static_cast<std::size_t>(need), '\0');
    if (lr_filter_name(f.get(), reinterpret_cast<std::uint8_t*>(out.data()),
                       static_cast<std::size_t>(need)) < 0) {
        throw Error("lr_filter_name failed: " + std::string(lr_last_error() ? lr_last_error() : "unknown"));
    }
    out.resize(static_cast<std::size_t>(need) - 1);
    return out;
}

/// Run the filter against the route. `ctx` may be nullptr (built-in
/// route-backed context). `reason` (optional) receives the
/// `reject with` payload.
inline FilterVerdict filter_evaluate(const Filter& f, Route& r,
                                     const lr_filter_context_t* ctx = nullptr,
                                     std::string* reason = nullptr) {
    std::int32_t verdict = 0;
    auto buf = std::make_unique<lr_bytes_t>();
    std::int32_t rc = lr_filter_evaluate(f.get(), r.get(), ctx, &verdict,
                                         reason ? buf.get() : nullptr);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_filter_evaluate failed: " + std::string(err ? err : "unknown"));
    }
    if (reason && buf->ptr) {
        *reason = std::string(reinterpret_cast<const char*>(lr_bytes_ptr(buf.get())),
                              lr_bytes_len(buf.get()));
        // The FFI hands back a NUL-terminated buffer; strip the NUL.
        while (!reason->empty() && reason->back() == '\0') reason->pop_back();
    }
    return static_cast<FilterVerdict>(verdict);
}

} // namespace librouting
