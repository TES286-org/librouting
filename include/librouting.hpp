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

// ===== Structured inspection surface (issue #92) =====
//
// Mirrors the Rust pub API of DefaultRouter::session_summaries /
// ospf_area_ids / ospf_area_topology_version / ospf_area_lsa /
// bgp_session_identity_hash / drain_ospf_grace_events so the
// embedder no longer has to parse the text-form
// `sessions_dump` / `rib_dump` JSON.

/// Session protocol kind (mirrors LR_SESSION_KIND_*).
enum class SessionKind : std::int32_t {
    Bgp   = 1,
    Ospf  = 2,
    Ospf3 = 3,
    Babel = 4,
};

/// Lower-case ASCII name for the kind — same form as Rust's
/// `SessionSummary::kind`.
inline const char* session_kind_name(SessionKind k) {
    switch (k) {
        case SessionKind::Bgp:   return "bgp";
        case SessionKind::Ospf:  return "ospf";
        case SessionKind::Ospf3: return "ospf3";
        case SessionKind::Babel: return "babel";
    }
    return "unknown";
}

/// One session's operational summary (mirrors lr_router::SessionSummary).
struct SessionSummary {
    std::uint64_t handle = 0;
    SessionKind kind = SessionKind::Bgp;
    std::string kind_text;
    std::uint32_t local_as = 0;
    std::uint32_t peer_as = 0;
    std::string state;
    bool established = false;
    bool peer_bgp_id_present = false;
    std::uint32_t peer_bgp_id = 0;
    std::uint16_t negotiated_hold_time = 0;
    std::uint64_t adj_rib_in_len = 0;
    std::uint64_t updates_received = 0;
    std::uint64_t updates_sent = 0;
};

/// Decode a fixed-size NUL-terminated uint8 array as a std::string.
/// The C struct field is `uint8_t arr[N]`; the caller passes the
/// array decayed to a pointer plus its declared size.
inline std::string decode_c_text(const std::uint8_t* p, std::size_t cap) {
    std::size_t n = 0;
    while (n < cap && p[n] != 0) ++n;
    return std::string(reinterpret_cast<const char*>(p), n);
}

/// Number of sessions currently registered on the router. Mirrors
/// `DefaultRouter::session_summaries().len()`.
inline std::size_t session_count(Router& r) {
    return lr_router_session_count(r.get());
}

/// Read one session summary by index. Mirrors
/// `DefaultRouter::session_summaries()[index]`. Throws `Error` when
/// the index is out of range.
inline SessionSummary session_summary_at(Router& r, std::size_t index) {
    lr_session_summary_t raw{};
    int rc = lr_router_session_summary_at(r.get(), index, &raw);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_session_summary_at failed: " +
                    std::string(err ? err : "unknown"));
    }
    SessionSummary s;
    s.handle = raw.handle;
    s.kind = static_cast<SessionKind>(raw.kind);
    s.kind_text = decode_c_text(raw.kind_text, sizeof(raw.kind_text));
    s.local_as = raw.local_as;
    s.peer_as = raw.peer_as;
    s.state = decode_c_text(raw.state_text, sizeof(raw.state_text));
    s.established = raw.established != 0;
    s.peer_bgp_id_present = raw.peer_bgp_id_present != 0;
    s.peer_bgp_id = raw.peer_bgp_id;
    s.negotiated_hold_time = raw.negotiated_hold_time;
    s.adj_rib_in_len = raw.adj_rib_in_len;
    s.updates_received = raw.updates_received;
    s.updates_sent = raw.updates_sent;
    return s;
}

/// Snapshot of every session's operational summary. Convenience
/// wrapper around `session_count` + `session_summary_at`.
inline std::vector<SessionSummary> session_summaries(Router& r) {
    std::size_t n = session_count(r);
    std::vector<SessionSummary> out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(session_summary_at(r, i));
    }
    return out;
}

/// Number of OSPF areas the router currently holds. Mirrors
/// `DefaultRouter::ospf_area_ids().len()`.
inline std::size_t ospf_area_count(Router& r) {
    return lr_router_ospf_area_count(r.get());
}

/// Read one OSPF area ID by index. Mirrors
/// `DefaultRouter::ospf_area_ids()[index]`. The order is ascending
/// (BTreeMap iteration).
inline std::uint32_t ospf_area_id_at(Router& r, std::size_t index) {
    std::uint32_t id = 0;
    int rc = lr_router_ospf_area_id_at(r.get(), index, &id);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_ospf_area_id_at failed: " +
                    std::string(err ? err : "unknown"));
    }
    return id;
}

/// Snapshot of every OSPF area ID. Convenience wrapper around
/// `ospf_area_count` + `ospf_area_id_at`.
inline std::vector<std::uint32_t> ospf_area_ids(Router& r) {
    std::size_t n = ospf_area_count(r);
    std::vector<std::uint32_t> out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(ospf_area_id_at(r, i));
    }
    return out;
}

/// OSPF area topology version — a monotonic counter bumped on every
/// *content* change of a topology LSA (types 1-5, 7). Mirrors
/// `DefaultRouter::ospf_area_topology_version`. Throws `Error` when
/// the area is unknown.
inline std::uint64_t ospf_area_topology_version(Router& r, std::uint32_t area_id) {
    std::uint64_t v = 0;
    int rc = lr_router_ospf_area_topology_version(r.get(), area_id, &v);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_ospf_area_topology_version failed: " +
                    std::string(err ? err : "unknown"));
    }
    return v;
}

/// One OSPF LSA projection — fixed-layout header plus the body bytes
/// owned by the caller (RAII through `Bytes`).
struct OspfLsa {
    std::uint16_t ls_age = 0;
    std::uint8_t options = 0;
    std::uint16_t ls_type = 0;
    std::uint32_t link_state_id = 0;
    std::uint32_t advertising_router = 0;
    std::uint32_t ls_sequence_number = 0;
    std::uint16_t ls_checksum = 0;
    std::uint16_t length = 0;
    std::vector<std::uint8_t> body;
};

/// Read one LSA out of an area's LSDB by its exact key
/// (ls_type, link_state_id, advertising_router). Mirrors
/// `DefaultRouter::ospf_area_lsa`. Throws `Error` when the area or
/// LSA is unknown.
inline OspfLsa ospf_area_lsa(Router& r,
                             std::uint32_t area_id,
                             std::uint16_t ls_type,
                             std::uint32_t link_state_id,
                             std::uint32_t advertising_router) {
    lr_ospf_lsa_t raw{};
    int rc = lr_router_ospf_area_lsa(r.get(), area_id, ls_type,
                                     link_state_id, advertising_router, &raw);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_ospf_area_lsa failed: " +
                    std::string(err ? err : "unknown"));
    }
    OspfLsa out;
    out.ls_age = raw.ls_age;
    out.options = raw.options;
    out.ls_type = raw.ls_type;
    out.link_state_id = raw.link_state_id;
    out.advertising_router = raw.advertising_router;
    out.ls_sequence_number = raw.ls_sequence_number;
    out.ls_checksum = raw.ls_checksum;
    out.length = raw.length;
    if (raw.body.len > 0 && raw.body.ptr != nullptr) {
        out.body.assign(raw.body.ptr, raw.body.ptr + raw.body.len);
    }
    lr_bytes_free(&raw.body);
    return out;
}

/// Stable, content-derived hash that changes when the set of BGP
/// sessions changes structurally (session added/removed, peer
/// address changed, ASN4 mode flipped). Mirrors
/// `DefaultRouter::bgp_session_identity_hash`.
inline std::uint64_t bgp_session_identity_hash(Router& r) {
    return lr_router_bgp_session_identity_hash(r.get());
}

/// One OSPF Graceful-Restart event (RFC 3623 §3 / RFC 5187 §2).
/// Mirrors lr_router::OspfGraceEvent.
struct OspfGraceEvent {
    std::uint32_t area = 0;
    std::uint32_t advertising_router = 0;
    std::uint32_t grace_period_secs = 0;
    std::uint8_t reason = 0;
    std::optional<std::array<std::uint8_t, 4>> interface_addr_v4;
    std::optional<std::array<std::uint8_t, 16>> interface_addr_v6;
    std::uint16_t ls_age_secs = 0;
    bool purged = false;
};

/// Drain pending OSPF Graceful-Restart events (RFC 3623 §3 / RFC
/// 5187 §2). Mirrors `DefaultRouter::drain_ospf_grace_events`.
/// Events past `capacity` stay queued for the next call.
inline std::vector<OspfGraceEvent> drain_ospf_grace_events(Router& r,
                                                            std::size_t capacity = 32) {
    if (capacity == 0) {
        throw Error("drain_ospf_grace_events: capacity must be positive");
    }
    std::vector<lr_ospf_grace_event_t> raw(capacity);
    std::intptr_t n = lr_router_drain_ospf_grace_events(
        r.get(), raw.data(), static_cast<std::uintptr_t>(capacity));
    if (n < 0) {
        const char* err = lr_last_error();
        throw Error("lr_router_drain_ospf_grace_events failed: " +
                    std::string(err ? err : "unknown"));
    }
    std::vector<OspfGraceEvent> out;
    out.reserve(static_cast<std::size_t>(n));
    for (std::intptr_t i = 0; i < n; ++i) {
        const auto& e = raw[static_cast<std::size_t>(i)];
        OspfGraceEvent ev;
        ev.area = e.area;
        ev.advertising_router = e.advertising_router;
        ev.grace_period_secs = e.grace_period_secs;
        ev.reason = e.reason;
        if (e.interface_addr_v4_present) {
            std::array<std::uint8_t, 4> a{};
            std::copy(e.interface_addr_v4, e.interface_addr_v4 + 4, a.begin());
            ev.interface_addr_v4 = a;
        }
        if (e.interface_addr_v6_present) {
            std::array<std::uint8_t, 16> a{};
            std::copy(e.interface_addr_v6, e.interface_addr_v6 + 16, a.begin());
            ev.interface_addr_v6 = a;
        }
        ev.ls_age_secs = e.ls_age_secs;
        ev.purged = e.purged != 0;
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

// ===== BGP message inspection (parsed-form readers) =====
//
// `lr_bgp_decode` returns the canonical re-encoded bytes — useful for
// differential checks but not for reading a message's fields. The
// handles + readers below mirror the `BgpMessage` enum so an embedder
// can decode a message once and walk its variant fields in C++.

struct BgpMessageDeleter {
    void operator()(lr_bgp_message_t m) const noexcept {
        if (m) lr_bgp_message_free(m);
    }
};
/// An owned BGP-message handle. Decoded from wire bytes via
/// `decode_bgp_message`; release is automatic via the deleter.
using BgpMessage = std::unique_ptr<OpaqueBgpMessage, BgpMessageDeleter>;

/// Decode one BGP message and return an owned handle to the parsed
/// form. Throws `Error` on a decode failure (the underlying last-error
/// string is preserved in the exception message).
inline BgpMessage decode_bgp_message(const std::uint8_t* data, std::size_t len) {
    auto m = lr_bgp_decode_message(data, len);
    if (!m) {
        const char* err = lr_last_error();
        throw Error("lr_bgp_decode_message failed: " + std::string(err ? err : "unknown"));
    }
    return BgpMessage(m);
}
inline BgpMessage decode_bgp_message(const std::vector<std::uint8_t>& bytes) {
    return decode_bgp_message(bytes.data(), bytes.size());
}

/// Variant tag (mirrors `LR_BGP_MSG_*`).
enum class BgpMessageKind : std::uint8_t {
    Open = LR_BGP_MSG_OPEN,
    Update = LR_BGP_MSG_UPDATE,
    Notification = LR_BGP_MSG_NOTIFICATION,
    Keepalive = LR_BGP_MSG_KEEPALIVE,
    RouteRefresh = LR_BGP_MSG_ROUTE_REFRESH,
};

inline BgpMessageKind message_kind(const BgpMessage& m) {
    std::uint8_t k = 0;
    check_rc(lr_bgp_message_type(m.get(), &k), "lr_bgp_message_type");
    return static_cast<BgpMessageKind>(k);
}

/// OPEN reader: version (always 4 on a well-formed message).
inline std::uint8_t open_version(const BgpMessage& m) {
    std::uint8_t v = 0;
    check_rc(lr_bgp_message_open_version(m.get(), &v), "lr_bgp_message_open_version");
    return v;
}

/// OPEN reader: sender AS. Unwraps AS_TRANS (23456) when the RFC 6793
/// four-octet-AS capability is present, returning the real 32-bit AS.
inline std::uint32_t open_my_as(const BgpMessage& m) {
    std::uint32_t v = 0;
    check_rc(lr_bgp_message_open_my_as(m.get(), &v), "lr_bgp_message_open_my_as");
    return v;
}

/// OPEN reader: hold time in seconds.
inline std::uint16_t open_hold_time(const BgpMessage& m) {
    std::uint16_t v = 0;
    check_rc(lr_bgp_message_open_hold_time(m.get(), &v), "lr_bgp_message_open_hold_time");
    return v;
}

/// OPEN reader: 4-byte BGP identifier (network order).
inline std::array<std::uint8_t, 4> open_bgp_id(const BgpMessage& m) {
    std::array<std::uint8_t, 4> id{};
    check_rc(lr_bgp_message_open_bgp_id(m.get(), id.data()), "lr_bgp_message_open_bgp_id");
    return id;
}

/// OPEN reader: number of optional parameters (RFC 5492 capabilities).
inline std::size_t open_param_count(const BgpMessage& m) {
    return lr_bgp_message_open_param_count(m.get());
}

/// One OPEN optional parameter: type byte + raw capability payload
/// (RFC 5492 §3 — `(code:1, length:1, value:length)` triples).
struct OpenParam {
    std::uint8_t param_type;
    std::vector<std::uint8_t> value;
};

inline OpenParam open_param_at(const BgpMessage& m, std::size_t idx) {
    OpenParam out;
    auto b = std::make_unique<lr_bytes_t>();
    check_rc(lr_bgp_message_open_param_at(m.get(), idx, &out.param_type, b.get()),
             "lr_bgp_message_open_param_at");
    out.value = to_vec(Bytes(b.release()));
    return out;
}

/// NOTIFICATION reader: error code (RFC 4271 §4.5).
inline std::uint8_t notification_code(const BgpMessage& m) {
    std::uint8_t v = 0;
    check_rc(lr_bgp_message_notification_code(m.get(), &v),
             "lr_bgp_message_notification_code");
    return v;
}

/// NOTIFICATION reader: error subcode.
inline std::uint8_t notification_subcode(const BgpMessage& m) {
    std::uint8_t v = 0;
    check_rc(lr_bgp_message_notification_subcode(m.get(), &v),
             "lr_bgp_message_notification_subcode");
    return v;
}

/// NOTIFICATION reader: variable-length diagnostic data (often empty).
inline std::vector<std::uint8_t> notification_data(const BgpMessage& m) {
    auto b = std::make_unique<lr_bytes_t>();
    check_rc(lr_bgp_message_notification_data(m.get(), b.get()),
             "lr_bgp_message_notification_data");
    return to_vec(Bytes(b.release()));
}

/// ROUTE-REFRESH reader: AFI (RFC 4271 address-family identifier).
inline std::uint16_t route_refresh_afi(const BgpMessage& m) {
    std::uint16_t v = 0;
    check_rc(lr_bgp_message_route_refresh_afi(m.get(), &v),
             "lr_bgp_message_route_refresh_afi");
    return v;
}

/// ROUTE-REFRESH reader: SAFI (sub-address-family identifier).
inline std::uint8_t route_refresh_safi(const BgpMessage& m) {
    std::uint8_t v = 0;
    check_rc(lr_bgp_message_route_refresh_safi(m.get(), &v),
             "lr_bgp_message_route_refresh_safi");
    return v;
}

/// ROUTE-REFRESH reader: RFC 7313 subtype (0 = Normal, 1 = BoRR,
/// 2 = EoRR, 0xff = unknown — RFC 7313 §3.2 requires the message be
/// silently ignored, so the decoder maps unrecognized values here).
inline std::uint8_t route_refresh_subtype(const BgpMessage& m) {
    std::uint8_t v = 0;
    check_rc(lr_bgp_message_route_refresh_subtype(m.get(), &v),
             "lr_bgp_message_route_refresh_subtype");
    return v;
}

/// UPDATE reader: number of withdrawn routes.
inline std::size_t update_withdrawn_count(const BgpMessage& m) {
    return lr_bgp_message_update_withdrawn_count(m.get());
}

/// UPDATE reader: number of NLRI entries (IPv4 unicast legacy NLRI only;
/// MP-BGP NLRI lives inside the MpReach/MpUnreach path attributes).
inline std::size_t update_nlri_count(const BgpMessage& m) {
    return lr_bgp_message_update_nlri_count(m.get());
}

/// UPDATE reader: number of path attributes.
inline std::size_t update_attr_count(const BgpMessage& m) {
    return lr_bgp_message_update_attr_count(m.get());
}

/// One path attribute: type code, flags byte and raw value bytes.
struct PathAttr {
    std::uint8_t attr_type;
    std::uint8_t flags;
    std::vector<std::uint8_t> value;
};

inline PathAttr update_attr_at(const BgpMessage& m, std::size_t idx) {
    PathAttr out;
    auto b = std::make_unique<lr_bytes_t>();
    check_rc(lr_bgp_message_update_attr_at(m.get(), idx, &out.attr_type, &out.flags, b.get()),
             "lr_bgp_message_update_attr_at");
    out.value = to_vec(Bytes(b.release()));
    return out;
}

/// Read the withdrawn route at `idx` as a `lr_prefix_t`. Throws on
/// out-of-range or variant mismatch (the C ABI returns distinct error
/// codes that surface through `check_rc`'s last-error string).
inline lr_prefix_t update_withdrawn_at(const BgpMessage& m, std::size_t idx) {
    lr_prefix_t p{};
    check_rc(lr_bgp_message_update_withdrawn_at(m.get(), idx, &p),
             "lr_bgp_message_update_withdrawn_at");
    return p;
}

/// Read the NLRI entry at `idx` as a `lr_prefix_t`.
inline lr_prefix_t update_nlri_at(const BgpMessage& m, std::size_t idx) {
    lr_prefix_t p{};
    check_rc(lr_bgp_message_update_nlri_at(m.get(), idx, &p),
             "lr_bgp_message_update_nlri_at");
    return p;
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

// ---------------------------------------------------------------------------
// MPLS Label / LabelStack (RFC 3032 §2.1, RFC 8277 §2.2/§2.3)
//
// Mirrors the public Rust API of `lr_mpls::{Label, LabelStack}` and the
// `lr_mpls_*` C ABI surface in `lr_ffi.h`. Each handle is RAII-owned
// via `std::unique_ptr` with a deleter that calls the matching
// `lr_mpls_*_free` function.
// ---------------------------------------------------------------------------

struct MplsLabelDeleter {
    void operator()(lr_mpls_label_t l) const noexcept {
        if (l) lr_mpls_label_free(l);
    }
};
struct MplsLabelStackDeleter {
    void operator()(lr_mpls_label_stack_t s) const noexcept {
        if (s) lr_mpls_label_stack_free(s);
    }
};

/// RAII handle to a single MPLS label value with TC + TTL fields.
using MplsLabel = std::unique_ptr<OpaqueMplsLabel, MplsLabelDeleter>;
/// RAII handle to an ordered MPLS label stack.
using MplsLabelStack = std::unique_ptr<OpaqueMplsLabelStack, MplsLabelStackDeleter>;

/// One fully-specified label `(value, tc, ttl)`. Used by
/// `make_label_stack_from_labels` to build a stack from a flat vector of
/// label specs without round-tripping through individual `MplsLabel`
/// handles. Mirrors `lr_mpls_label_spec_t`.
struct MplsLabelSpec {
    std::uint32_t value;
    std::uint8_t tc;
    std::uint8_t ttl;
};

/// Construct a Label with default TC=0 and TTL=64 (RFC 3032 §2.1).
/// Infallible — the value is masked to 20 bits on encode.
inline MplsLabel make_label(std::uint32_t value) {
    auto l = lr_mpls_label_new(value);
    if (!l) throw Error("lr_mpls_label_new returned null");
    return MplsLabel(l);
}

/// Checked constructor — throws `Error` when `value` exceeds the 20-bit
/// label range (RFC 3032 §2.1).
inline MplsLabel make_label_checked(std::uint32_t value) {
    auto l = lr_mpls_label_new_checked(value);
    if (!l) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_new_checked failed: " + std::string(err ? err : "unknown"));
    }
    return MplsLabel(l);
}

/// Read the 20-bit label value.
inline std::uint32_t label_value(const MplsLabel& l) {
    return lr_mpls_label_value(l.get());
}
/// Read the 3-bit Traffic Class.
inline std::uint8_t label_tc(const MplsLabel& l) {
    return lr_mpls_label_tc(l.get());
}
/// Read the 8-bit TTL.
inline std::uint8_t label_ttl(const MplsLabel& l) {
    return lr_mpls_label_ttl(l.get());
}
/// True when the label value is in the reserved range 0–15 (RFC 3032 §2.1).
inline bool label_is_reserved(const MplsLabel& l) {
    return lr_mpls_label_is_reserved(l.get()) != 0;
}

/// Set the Traffic Class (3 bits, RFC 5462). The lower 3 bits of `tc`
/// are taken; the rest are masked. Returns a NEW handle (the input
/// handle is consumed and freed).
inline MplsLabel label_with_tc(MplsLabel& l, std::uint8_t tc) {
    auto out = lr_mpls_label_with_tc(l.release(), tc);
    if (!out) throw Error("lr_mpls_label_with_tc returned null");
    return MplsLabel(out);
}

/// Set the TTL. Returns a NEW handle; the input is consumed.
inline MplsLabel label_with_ttl(MplsLabel& l, std::uint8_t ttl) {
    auto out = lr_mpls_label_with_ttl(l.release(), ttl);
    if (!out) throw Error("lr_mpls_label_with_ttl returned null");
    return MplsLabel(out);
}

/// Encode as a single 3-octet NLRI entry (RFC 8277 §2.2/§2.3:
/// `Label(20) | Rsrv(3) | S(1)`, no TTL and no TC field). `bottom`
/// sets the S bit. Returns 3 bytes.
inline std::array<std::uint8_t, 3> label_encode_3octet(const MplsLabel& l, bool bottom) {
    std::array<std::uint8_t, 3> out{};
    std::int32_t rc = lr_mpls_label_encode_3octet(l.get(), bottom ? 1 : 0, out.data());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_encode_3octet failed: " + std::string(err ? err : "unknown"));
    }
    return out;
}

/// Encode as a single 4-octet wire entry (RFC 3032 §2.1: label + TC
/// + S + TTL). `bottom` sets the S bit. Returns 4 bytes.
inline std::array<std::uint8_t, 4> label_encode_4octet(const MplsLabel& l, bool bottom) {
    std::array<std::uint8_t, 4> out{};
    std::int32_t rc = lr_mpls_label_encode_4octet(l.get(), bottom ? 1 : 0, out.data());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_encode_4octet failed: " + std::string(err ? err : "unknown"));
    }
    return out;
}

/// Construct an empty LabelStack (RFC 3032 §2.1). Useful as a builder
/// starting point; not a valid wire value (an MPLS frame must carry
/// at least one label).
inline MplsLabelStack make_label_stack() {
    auto s = lr_mpls_label_stack_new();
    if (!s) throw Error("lr_mpls_label_stack_new returned null");
    return MplsLabelStack(s);
}

/// Build a stack from a vector of label values (TC=0, TTL=64).
inline MplsLabelStack make_label_stack_from_values(const std::vector<std::uint32_t>& values) {
    auto s = lr_mpls_label_stack_from_values(values.data(), values.size());
    if (!s) throw Error("lr_mpls_label_stack_from_values returned null");
    return MplsLabelStack(s);
}

/// Build a stack from a vector of fully-specified labels.
inline MplsLabelStack make_label_stack_from_labels(const std::vector<MplsLabelSpec>& labels) {
    // Translate the C++ struct to the C struct — same memory layout,
    // but `std::vector<MplsLabelSpec>` is not directly usable as a
    // `const lr_mpls_label_spec_t*` because the C struct may carry
    // padding the C++ struct does not (or vice versa). Copy into a
    // C-typed buffer to be safe across ABIs.
    std::vector<lr_mpls_label_spec_t> c_specs;
    c_specs.reserve(labels.size());
    for (const auto& l : labels) {
        c_specs.push_back(lr_mpls_label_spec_t{l.value, l.tc, l.ttl});
    }
    auto s = lr_mpls_label_stack_from_labels(c_specs.data(), c_specs.size());
    if (!s) throw Error("lr_mpls_label_stack_from_labels returned null");
    return MplsLabelStack(s);
}

/// Decode the 4-octet-per-entry wire form (RFC 3032 §2.1). The S bit
/// must mark the bottom entry only.
inline MplsLabelStack decode_label_stack_4octet(const std::uint8_t* data, std::size_t len) {
    lr_mpls_label_stack_t s = nullptr;
    std::int32_t rc = lr_mpls_label_stack_decode_4octet(data, len, &s);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_decode_4octet failed: " + std::string(err ? err : "unknown"));
    }
    if (!s) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_decode_4octet returned null: " + std::string(err ? err : "unknown"));
    }
    return MplsLabelStack(s);
}
inline MplsLabelStack decode_label_stack_4octet(const std::vector<std::uint8_t>& bytes) {
    return decode_label_stack_4octet(bytes.data(), bytes.size());
}

/// Decode the 3-octet-per-entry NLRI form (RFC 8277 §2.2/§2.3). TTL
/// is not carried in this form and defaults to 0.
inline MplsLabelStack decode_label_stack_3octet(const std::uint8_t* data, std::size_t len) {
    lr_mpls_label_stack_t s = nullptr;
    std::int32_t rc = lr_mpls_label_stack_decode_3octet(data, len, &s);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_decode_3octet failed: " + std::string(err ? err : "unknown"));
    }
    if (!s) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_decode_3octet returned null: " + std::string(err ? err : "unknown"));
    }
    return MplsLabelStack(s);
}
inline MplsLabelStack decode_label_stack_3octet(const std::vector<std::uint8_t>& bytes) {
    return decode_label_stack_3octet(bytes.data(), bytes.size());
}

/// Number of labels in the stack.
inline std::size_t label_stack_len(const MplsLabelStack& s) {
    return lr_mpls_label_stack_len(s.get());
}
/// True when the stack holds no labels.
inline bool label_stack_is_empty(const MplsLabelStack& s) {
    return lr_mpls_label_stack_is_empty(s.get()) != 0;
}

/// Read one label by index as a fully-specified `MplsLabelSpec`.
/// Throws `Error` when the index is out of range.
inline MplsLabelSpec label_stack_at(const MplsLabelStack& s, std::size_t index) {
    std::uint32_t v = 0;
    std::uint8_t tc = 0, ttl = 0;
    std::int32_t rc = lr_mpls_label_stack_at(s.get(), index, &v, &tc, &ttl);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_at failed: " + std::string(err ? err : "unknown"));
    }
    return MplsLabelSpec{v, tc, ttl};
}

/// Return the full vector of label specs in stack order (top first).
inline std::vector<MplsLabelSpec> label_stack_labels(const MplsLabelStack& s) {
    std::vector<MplsLabelSpec> out;
    out.reserve(label_stack_len(s));
    for (std::size_t i = 0; i < out.capacity(); ++i) {
        out.push_back(label_stack_at(s, i));
    }
    return out;
}

/// Push a label onto the top of the stack. The label handle is
/// consumed and freed.
inline void label_stack_push(MplsLabelStack& s, MplsLabel& label) {
    std::int32_t rc = lr_mpls_label_stack_push(s.get(), label.release());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_push failed: " + std::string(err ? err : "unknown"));
    }
}

/// Push a label onto the bottom of the stack. The label handle is
/// consumed and freed.
inline void label_stack_push_bottom(MplsLabelStack& s, MplsLabel& label) {
    std::int32_t rc = lr_mpls_label_stack_push_bottom(s.get(), label.release());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_push_bottom failed: " + std::string(err ? err : "unknown"));
    }
}

/// Pop the top label. Returns true when a label was popped, false
/// when the stack was already empty.
inline bool label_stack_pop(MplsLabelStack& s) {
    std::int32_t rc = lr_mpls_label_stack_pop(s.get());
    if (rc < 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_pop failed: " + std::string(err ? err : "unknown"));
    }
    return rc == 1;
}

/// Encode the stack as the 4-octet-per-entry wire form (RFC 3032 §2.1).
/// The S bit is set on the last entry.
inline Bytes label_stack_encode_4octet(const MplsLabelStack& s) {
    auto out = std::make_unique<lr_bytes_t>();
    std::int32_t rc = lr_mpls_label_stack_encode_4octet(s.get(), out.get());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_encode_4octet failed: " + std::string(err ? err : "unknown"));
    }
    return Bytes(out.release());
}

/// Encode the stack as the 3-octet-per-entry NLRI form (RFC 8277
/// §2.2/§2.3).
inline Bytes label_stack_encode_3octet(const MplsLabelStack& s) {
    auto out = std::make_unique<lr_bytes_t>();
    std::int32_t rc = lr_mpls_label_stack_encode_3octet(s.get(), out.get());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_mpls_label_stack_encode_3octet failed: " + std::string(err ? err : "unknown"));
    }
    return Bytes(out.release());
}

// ---------------------------------------------------------------------------
// BFD Control packet (RFC 5880 §4.1)
//
// Mirrors the public Rust API of lr_bfd::{BfdCodec, BfdPacket, State,
// Diagnostic, PacketFlags} and the lr_bfd_* C ABI surface.
// ---------------------------------------------------------------------------

namespace bfd_state {
constexpr std::uint8_t kAdminDown = LR_BFD_STATE_ADMIN_DOWN;
constexpr std::uint8_t kDown = LR_BFD_STATE_DOWN;
constexpr std::uint8_t kInit = LR_BFD_STATE_INIT;
constexpr std::uint8_t kUp = LR_BFD_STATE_UP;
}  // namespace bfd_state

namespace bfd_diag {
constexpr std::uint8_t kNone = LR_BFD_DIAG_NONE;
constexpr std::uint8_t kCtrlExpired = LR_BFD_DIAG_CTRL_EXPIRED;
constexpr std::uint8_t kEchoFailed = LR_BFD_DIAG_ECHO_FAILED;
constexpr std::uint8_t kNeighborSignaled = LR_BFD_DIAG_NEIGHBOR_SIGNALLED;
constexpr std::uint8_t kFwdReset = LR_BFD_DIAG_FWD_RESET;
constexpr std::uint8_t kPathDown = LR_BFD_DIAG_PATH_DOWN;
constexpr std::uint8_t kConcatPathDown = LR_BFD_DIAG_CONCAT_PATH_DOWN;
constexpr std::uint8_t kAdminDown = LR_BFD_DIAG_ADMIN_DOWN;
constexpr std::uint8_t kRevPathDown = LR_BFD_DIAG_REV_PATH_DOWN;
constexpr std::uint8_t kMisConnDefect = LR_BFD_DIAG_MISCONN_DEFECT;
}  // namespace bfd_diag

struct BfdPacketDeleter {
    void operator()(lr_bfd_packet_t p) const noexcept {
        if (p) lr_bfd_packet_free(p);
    }
};

/// RAII handle to a BFD Control packet.
using BfdPacket = std::unique_ptr<OpaqueBfdPacket, BfdPacketDeleter>;

/// Construct an empty BFD packet with sensible defaults (state=Down,
/// diag=None, detect_mult=3, intervals=1s, no auth).
inline BfdPacket make_bfd_packet() {
    auto p = lr_bfd_packet_new();
    if (!p) throw Error("lr_bfd_packet_new returned null");
    return BfdPacket(p);
}

/// Construct an "Up" heartbeat packet.
inline BfdPacket make_bfd_heartbeat(std::uint32_t my_disc, std::uint32_t your_disc) {
    auto p = lr_bfd_packet_heartbeat(my_disc, your_disc);
    if (!p) throw Error("lr_bfd_packet_heartbeat returned null");
    return BfdPacket(p);
}

inline std::uint8_t bfd_packet_version(const BfdPacket& p) {
    return lr_bfd_packet_version(p.get());
}
inline std::uint8_t bfd_packet_diag(const BfdPacket& p) {
    return lr_bfd_packet_diag(p.get());
}
inline std::uint8_t bfd_packet_state(const BfdPacket& p) {
    return lr_bfd_packet_state(p.get());
}
inline std::uint8_t bfd_packet_flags(const BfdPacket& p) {
    return lr_bfd_packet_flags(p.get());
}
inline std::uint8_t bfd_packet_detect_mult(const BfdPacket& p) {
    return lr_bfd_packet_detect_mult(p.get());
}
inline std::uint32_t bfd_packet_my_discriminator(const BfdPacket& p) {
    return lr_bfd_packet_my_discriminator(p.get());
}
inline std::uint32_t bfd_packet_your_discriminator(const BfdPacket& p) {
    return lr_bfd_packet_your_discriminator(p.get());
}
inline std::uint32_t bfd_packet_desired_min_tx_interval(const BfdPacket& p) {
    return lr_bfd_packet_desired_min_tx_interval(p.get());
}
inline std::uint32_t bfd_packet_required_min_rx_interval(const BfdPacket& p) {
    return lr_bfd_packet_required_min_rx_interval(p.get());
}
inline std::uint32_t bfd_packet_required_min_echo_interval(const BfdPacket& p) {
    return lr_bfd_packet_required_min_echo_interval(p.get());
}
inline std::uint8_t bfd_packet_length(const BfdPacket& p) {
    return lr_bfd_packet_length(p.get());
}

inline void bfd_packet_set_diag(BfdPacket& p, std::uint8_t diag) {
    std::int32_t rc = lr_bfd_packet_set_diag(p.get(), diag);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_diag failed: " + std::string(err ? err : "unknown"));
    }
}
inline void bfd_packet_set_state(BfdPacket& p, std::uint8_t state) {
    std::int32_t rc = lr_bfd_packet_set_state(p.get(), state);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_state failed: " + std::string(err ? err : "unknown"));
    }
}
inline void bfd_packet_set_flags(BfdPacket& p, std::uint8_t flags) {
    std::int32_t rc = lr_bfd_packet_set_flags(p.get(), flags);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_flags failed: " + std::string(err ? err : "unknown"));
    }
}
inline void bfd_packet_set_detect_mult(BfdPacket& p, std::uint8_t mult) {
    std::int32_t rc = lr_bfd_packet_set_detect_mult(p.get(), mult);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_detect_mult failed: " + std::string(err ? err : "unknown"));
    }
}
inline void bfd_packet_set_my_discriminator(BfdPacket& p, std::uint32_t disc) {
    std::int32_t rc = lr_bfd_packet_set_my_discriminator(p.get(), disc);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_my_discriminator failed: " + std::string(err ? err : "unknown"));
    }
}
inline void bfd_packet_set_your_discriminator(BfdPacket& p, std::uint32_t disc) {
    std::int32_t rc = lr_bfd_packet_set_your_discriminator(p.get(), disc);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_your_discriminator failed: " + std::string(err ? err : "unknown"));
    }
}
inline void bfd_packet_set_desired_min_tx_interval(BfdPacket& p, std::uint32_t interval) {
    std::int32_t rc = lr_bfd_packet_set_desired_min_tx_interval(p.get(), interval);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_desired_min_tx_interval failed: " + std::string(err ? err : "unknown"));
    }
}
inline void bfd_packet_set_required_min_rx_interval(BfdPacket& p, std::uint32_t interval) {
    std::int32_t rc = lr_bfd_packet_set_required_min_rx_interval(p.get(), interval);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_required_min_rx_interval failed: " + std::string(err ? err : "unknown"));
    }
}
inline void bfd_packet_set_required_min_echo_interval(BfdPacket& p, std::uint32_t interval) {
    std::int32_t rc = lr_bfd_packet_set_required_min_echo_interval(p.get(), interval);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_packet_set_required_min_echo_interval failed: " + std::string(err ? err : "unknown"));
    }
}

/// Encode the packet to its wire form (24 bytes + auth).
inline Bytes bfd_packet_encode(const BfdPacket& p) {
    auto out = std::make_unique<lr_bytes_t>();
    std::int32_t rc = lr_bfd_encode(p.get(), out.get());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_encode failed: " + std::string(err ? err : "unknown"));
    }
    return Bytes(out.release());
}

/// Decode one BFD Control packet from raw bytes.
inline BfdPacket decode_bfd_packet(const std::uint8_t* data, std::size_t len) {
    lr_bfd_packet_t p = nullptr;
    std::int32_t rc = lr_bfd_decode(data, len, &p);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_decode failed: " + std::string(err ? err : "unknown"));
    }
    if (!p) {
        const char* err = lr_last_error();
        throw Error("lr_bfd_decode returned null: " + std::string(err ? err : "unknown"));
    }
    return BfdPacket(p);
}
inline BfdPacket decode_bfd_packet(const std::vector<std::uint8_t>& bytes) {
    return decode_bfd_packet(bytes.data(), bytes.size());
}

// =========================================================================
// SRv6 structured types — Sid / Locator / Srh / Behavior
// (RFC 8754 / RFC 8986). Mirrors `lr_srv6::{Sid, Locator, Srh, Behavior}`.
// =========================================================================

namespace detail {

struct Srv6SidDeleter {
    void operator()(lr_srv6_sid_t s) const noexcept {
        if (s) lr_srv6_sid_free(s);
    }
};

struct Srv6LocatorDeleter {
    void operator()(lr_srv6_locator_t l) const noexcept {
        if (l) lr_srv6_locator_free(l);
    }
};

struct Srv6SrhDeleter {
    void operator()(lr_srv6_srh_t s) const noexcept {
        if (s) lr_srv6_srh_free(s);
    }
};

} // namespace detail

/// RAII handle to a 128-bit SRv6 Segment Identifier (RFC 8754 §3).
using Srv6Sid = std::unique_ptr<OpaqueSrv6Sid, detail::Srv6SidDeleter>;

/// RAII handle to a locator block (RFC 8754 §3.1).
using Srv6Locator = std::unique_ptr<OpaqueSrv6Locator, detail::Srv6LocatorDeleter>;

/// RAII handle to a Segment Routing Header (RFC 8754 §2).
using Srv6Srh = std::unique_ptr<OpaqueSrv6Srh, detail::Srv6SrhDeleter>;

/// SRv6 SRH error discriminant (mirrors `lr_srv6::SrhError`).
enum class Srv6SrhError : std::int32_t {
    TooShort = 0,
    LengthMismatch = 1,
    EmptySegmentList = 2,
    TooManySegments = 3,
    LastEntryOutOfRange = 4,
    SegmentsLeftOutOfRange = 5,
    WrongRoutingType = 6,
    ReservedFlagBits = 7,
    Unknown = -1,
};

/// Sid parse-error discriminant (mirrors `lr_srv6::SidParseError`).
/// Values match `lr_srv6_sid_parse_error_name`'s mapping.
enum class Srv6SidParseError : std::int32_t {
    Empty = 1,
    DoubleDoubleColon = 2,
    BadHextet = 3,
    WrongLength = 4,
};

/// Locator parse-error discriminant (mirrors `lr_srv6::LocatorParseError`).
enum class Srv6LocatorParseError : std::int32_t {
    MissingPrefixLen = 1,
    BadAddr = 2,
    BadPrefixLen = 3,
};

/// Exception thrown on SRv6 SRH encode/decode failure.
class Srv6SrhErrorException : public Error {
public:
    Srv6SrhErrorException(Srv6SrhError code, std::string msg)
        : Error(std::string("SrhError(") + srh_error_name(code) + "): " + msg),
          code_(code) {}
    Srv6SrhError code() const noexcept { return code_; }
private:
    static const char* srh_error_name(Srv6SrhError c) {
        switch (c) {
            case Srv6SrhError::TooShort: return "TooShort";
            case Srv6SrhError::LengthMismatch: return "LengthMismatch";
            case Srv6SrhError::EmptySegmentList: return "EmptySegmentList";
            case Srv6SrhError::TooManySegments: return "TooManySegments";
            case Srv6SrhError::LastEntryOutOfRange: return "LastEntryOutOfRange";
            case Srv6SrhError::SegmentsLeftOutOfRange: return "SegmentsLeftOutOfRange";
            case Srv6SrhError::WrongRoutingType: return "WrongRoutingType";
            case Srv6SrhError::ReservedFlagBits: return "ReservedFlagBits";
            case Srv6SrhError::Unknown: return "Unknown";
        }
        return "Unknown";
    }
    Srv6SrhError code_;
};

/// Exception thrown on SID parse failure.
class Srv6SidParseException : public Error {
public:
    Srv6SidParseException(Srv6SidParseError code, std::string msg)
        : Error(std::string("SidParseError: ") + msg), code_(code) {}
    Srv6SidParseError code() const noexcept { return code_; }
private:
    Srv6SidParseError code_;
};

/// Exception thrown on Locator parse failure.
class Srv6LocatorParseException : public Error {
public:
    Srv6LocatorParseException(Srv6LocatorParseError code, std::string msg)
        : Error(std::string("LocatorParseError: ") + msg), code_(code) {}
    Srv6LocatorParseError code() const noexcept { return code_; }
private:
    Srv6LocatorParseError code_;
};

// ---- Srv6Sid construction ----

/// Construct a SID from 16 raw bytes (network byte order).
inline Srv6Sid make_srv6_sid(const std::array<std::uint8_t, 16>& octets) {
    lr_srv6_sid_t s = lr_srv6_sid_new(octets.data());
    if (!s) {
        throw Error("lr_srv6_sid_new returned null: " + std::string(lr_last_error()));
    }
    return Srv6Sid(s);
}

/// Construct a SID from a 16-byte vector.
inline Srv6Sid make_srv6_sid(const std::vector<std::uint8_t>& octets) {
    if (octets.size() != 16) {
        throw Error("Sid must be 16 bytes, got " + std::to_string(octets.size()));
    }
    std::array<std::uint8_t, 16> arr{};
    std::copy(octets.begin(), octets.end(), arr.begin());
    return make_srv6_sid(arr);
}

/// Construct the all-zeros SID (`::`).
inline Srv6Sid make_srv6_sid_unspecified() {
    return make_srv6_sid(std::array<std::uint8_t, 16>{});
}

/// Parse a SID from the canonical IPv6 textual form (RFC 5952 §4).
inline Srv6Sid parse_srv6_sid(std::string_view s) {
    std::array<std::uint8_t, 16> out{};
    std::int32_t rc = lr_srv6_sid_from_str(s.data(), out.data());
    if (rc == 0) {
        return make_srv6_sid(out);
    }
    if (rc > 0) {
        auto code = static_cast<Srv6SidParseError>(rc);
        throw Srv6SidParseException(code, std::string(s));
    }
    throw Error("lr_srv6_sid_from_str failed (rc=" + std::to_string(rc) + "): "
                + std::string(lr_last_error()));
}

/// Construct a SID by concatenating a locator byte string and a
/// function/argument tail (RFC 8754 §3.1).
inline Srv6Sid make_srv6_sid_from_locator_tail(
    const std::vector<std::uint8_t>& locator,
    const std::vector<std::uint8_t>& tail,
    std::uint8_t locator_block_bits) {
    lr_srv6_sid_t s = lr_srv6_sid_from_locator_tail(
        locator.data(), locator.size(),
        tail.data(), tail.size(),
        locator_block_bits);
    if (!s) {
        throw Error("lr_srv6_sid_from_locator_tail returned null: "
                    + std::string(lr_last_error()));
    }
    return Srv6Sid(s);
}

// ---- Srv6Sid accessors ----

/// Read the 16 raw bytes.
inline std::array<std::uint8_t, 16> srv6_sid_octets(const Srv6Sid& s) {
    std::array<std::uint8_t, 16> out{};
    std::int32_t rc = lr_srv6_sid_octets(s.get(), out.data());
    if (rc != 0) {
        throw Error("lr_srv6_sid_octets failed: " + std::string(lr_last_error()));
    }
    return out;
}

/// True when the SID is the all-zeros SID (`::`).
inline bool srv6_sid_is_unspecified(const Srv6Sid& s) {
    return lr_srv6_sid_is_unspecified(s.get()) != 0;
}

/// Slice the locator prefix out of the SID (RFC 8754 §3.1).
/// Returns `(offset, length)` so the caller can borrow the slice via
/// `srv6_sid_octets(s)[offset..offset+length]`. Returns `std::nullopt`
/// when `locator_block_bits` exceeds 128 or is not a multiple of 8.
inline std::optional<std::pair<std::size_t, std::size_t>>
srv6_sid_locator_slice(const Srv6Sid& s, std::uint8_t locator_block_bits) {
    std::size_t off = 0, len = 0;
    if (lr_srv6_sid_locator_slice(s.get(), locator_block_bits, &off, &len)) {
        return std::make_pair(off, len);
    }
    return std::nullopt;
}

/// True when the SID falls inside the given locator block (RFC 8754 §3.1).
inline bool srv6_sid_is_inside_locator(
    const Srv6Sid& s,
    const std::vector<std::uint8_t>& locator,
    std::uint8_t locator_block_bits) {
    return lr_srv6_sid_is_inside_locator(
        s.get(), locator.data(), locator.size(), locator_block_bits) != 0;
}

/// Render a SID as the canonical IPv6 textual form (RFC 5952 §4).
inline std::string srv6_sid_to_string(const Srv6Sid& s) {
    auto octets = srv6_sid_octets(s);
    const char* p = lr_srv6_sid_to_str(octets.data());
    if (!p) return {};
    return std::string(p);
}

// ---- Srv6Locator construction ----

/// Construct a Locator from a 16-byte address and a bit length.
/// The address is masked so host bits are zero (RFC 8754 §3.1).
inline Srv6Locator make_srv6_locator(
    const std::array<std::uint8_t, 16>& addr, std::uint8_t block_bits) {
    if (block_bits > 128) {
        throw Error("block_bits must be <= 128, got " + std::to_string(block_bits));
    }
    lr_srv6_locator_t l = lr_srv6_locator_new(addr.data(), block_bits);
    if (!l) {
        throw Error("lr_srv6_locator_new returned null: " + std::string(lr_last_error()));
    }
    return Srv6Locator(l);
}

/// Build a Locator from a Sid's high `block_bits` bits.
inline Srv6Locator make_srv6_locator_from_sid(const Srv6Sid& sid, std::uint8_t block_bits) {
    lr_srv6_locator_t l = lr_srv6_locator_from_sid(sid.get(), block_bits);
    if (!l) {
        throw Error("lr_srv6_locator_from_sid returned null: " + std::string(lr_last_error()));
    }
    return Srv6Locator(l);
}

/// Parse "fcbb:bb00::/48" (RFC 5952 §4 + a /prefix suffix).
inline Srv6Locator parse_srv6_locator(std::string_view s) {
    std::array<std::uint8_t, 16> addr{};
    std::uint8_t bits = 0;
    std::int32_t rc = lr_srv6_locator_from_str(s.data(), addr.data(), &bits);
    if (rc == 0) {
        return make_srv6_locator(addr, bits);
    }
    if (rc > 0) {
        auto code = static_cast<Srv6LocatorParseError>(rc);
        throw Srv6LocatorParseException(code, std::string(s));
    }
    throw Error("lr_srv6_locator_from_str failed (rc=" + std::to_string(rc) + "): "
                + std::string(lr_last_error()));
}

// ---- Srv6Locator accessors ----

/// The raw 16-byte address (host bits zeroed).
inline std::array<std::uint8_t, 16> srv6_locator_addr(const Srv6Locator& l) {
    std::array<std::uint8_t, 16> out{};
    std::int32_t rc = lr_srv6_locator_addr(l.get(), out.data());
    if (rc != 0) {
        throw Error("lr_srv6_locator_addr failed: " + std::string(lr_last_error()));
    }
    return out;
}

/// The locator prefix length in bits.
inline std::uint8_t srv6_locator_block_bits(const Srv6Locator& l) {
    return lr_srv6_locator_block_bits(l.get());
}

/// The locator's byte length (rounded up).
inline std::size_t srv6_locator_block_bytes(const Srv6Locator& l) {
    return lr_srv6_locator_block_bytes(l.get());
}

/// True when `sid` falls inside this locator.
inline bool srv6_locator_contains_sid(const Srv6Locator& l, const Srv6Sid& sid) {
    return lr_srv6_locator_contains_sid(l.get(), sid.get()) != 0;
}

/// Build a Sid under this locator by appending the 16-byte `tail`.
inline Srv6Sid srv6_locator_sid_with_tail(
    const Srv6Locator& l, const std::array<std::uint8_t, 16>& tail) {
    lr_srv6_sid_t s = lr_srv6_locator_sid_with_tail(l.get(), tail.data());
    if (!s) {
        throw Error("lr_srv6_locator_sid_with_tail returned null: "
                    + std::string(lr_last_error()));
    }
    return Srv6Sid(s);
}

/// Allocate a Sid at a given function index inside this locator.
/// Returns `nullptr` (an empty `Srv6Sid`) when the locator leaves
/// no room for a 4-byte function.
inline Srv6Sid srv6_locator_sid_with_index(
    const Srv6Locator& l, std::uint32_t function_index) {
    lr_srv6_sid_t s = lr_srv6_locator_sid_with_index(l.get(), function_index);
    return Srv6Sid(s);  // may be nullptr
}

/// Render a Locator as "<addr>/<bits>" (RFC 5952 §4 + RFC 8754 §3.1).
inline std::string srv6_locator_to_string(const Srv6Locator& l) {
    auto addr = srv6_locator_addr(l);
    const char* p = lr_srv6_locator_to_str(addr.data(), srv6_locator_block_bits(l));
    if (!p) return {};
    return std::string(p);
}

// ---- Srv6Srh construction ----

/// Build an SRH from a segment list. `segments_left` defaults to
/// `segments.size() - 1` (RFC 8754 §4.2 — the sender's view).
inline Srv6Srh make_srv6_srh(const std::vector<std::array<std::uint8_t, 16>>& segments) {
    if (segments.empty()) {
        throw Srv6SrhErrorException(Srv6SrhError::EmptySegmentList, "segment list is empty");
    }
    // Flatten the segment list into a single buffer (16 bytes per SID).
    std::vector<std::uint8_t> flat;
    flat.reserve(segments.size() * 16);
    for (const auto& s : segments) {
        flat.insert(flat.end(), s.begin(), s.end());
    }
    lr_srv6_srh_t s = lr_srv6_srh_new(flat.data(), segments.size());
    if (!s) {
        throw Error("lr_srv6_srh_new returned null: " + std::string(lr_last_error()));
    }
    return Srv6Srh(s);
}

/// Like `make_srv6_srh` but with an explicit `segments_left`.
inline Srv6Srh make_srv6_srh_with_segments_left(
    const std::vector<std::array<std::uint8_t, 16>>& segments,
    std::uint8_t segments_left) {
    if (segments.empty()) {
        throw Srv6SrhErrorException(Srv6SrhError::EmptySegmentList, "segment list is empty");
    }
    std::vector<std::uint8_t> flat;
    flat.reserve(segments.size() * 16);
    for (const auto& s : segments) {
        flat.insert(flat.end(), s.begin(), s.end());
    }
    lr_srv6_srh_t s = lr_srv6_srh_new_with_segments_left(
        flat.data(), segments.size(), segments_left, /*segments_left_present=*/1);
    if (!s) {
        throw Error("lr_srv6_srh_new_with_segments_left returned null: "
                    + std::string(lr_last_error()));
    }
    return Srv6Srh(s);
}

// ---- Srv6Srh builder setters ----

inline Srv6Srh& srv6_srh_set_next_header(Srv6Srh& s, std::uint8_t next_header) {
    if (lr_srv6_srh_set_next_header(s.get(), next_header) != 0) {
        throw Error("lr_srv6_srh_set_next_header failed: " + std::string(lr_last_error()));
    }
    return s;
}

inline Srv6Srh& srv6_srh_set_flags(Srv6Srh& s, std::uint8_t flags) {
    if (lr_srv6_srh_set_flags(s.get(), flags) != 0) {
        throw Error("lr_srv6_srh_set_flags failed: " + std::string(lr_last_error()));
    }
    return s;
}

inline Srv6Srh& srv6_srh_set_tag(Srv6Srh& s, std::uint16_t tag) {
    if (lr_srv6_srh_set_tag(s.get(), tag) != 0) {
        throw Error("lr_srv6_srh_set_tag failed: " + std::string(lr_last_error()));
    }
    return s;
}

inline Srv6Srh& srv6_srh_set_tlvs(Srv6Srh& s, const std::vector<std::uint8_t>& tlvs) {
    if (lr_srv6_srh_set_tlvs(s.get(), tlvs.data(), tlvs.size()) != 0) {
        throw Error("lr_srv6_srh_set_tlvs failed: " + std::string(lr_last_error()));
    }
    return s;
}

// ---- Srv6Srh accessors ----

inline std::uint8_t srv6_srh_next_header(const Srv6Srh& s) {
    return lr_srv6_srh_next_header(s.get());
}

inline std::uint8_t srv6_srh_segments_left(const Srv6Srh& s) {
    return lr_srv6_srh_segments_left(s.get());
}

inline std::uint8_t srv6_srh_last_entry(const Srv6Srh& s) {
    return lr_srv6_srh_last_entry(s.get());
}

inline std::uint8_t srv6_srh_flags(const Srv6Srh& s) {
    return lr_srv6_srh_flags(s.get());
}

inline std::uint16_t srv6_srh_tag(const Srv6Srh& s) {
    return lr_srv6_srh_tag(s.get());
}

inline std::size_t srv6_srh_segment_count(const Srv6Srh& s) {
    return lr_srv6_srh_segment_count(s.get());
}

/// Number of segments — mirrors Rust's `Srh::len`.
inline std::size_t srv6_srh_len(const Srv6Srh& s) {
    return lr_srv6_srh_len(s.get());
}

inline bool srv6_srh_is_empty(const Srv6Srh& s) {
    return lr_srv6_srh_is_empty(s.get()) != 0;
}

inline std::uint8_t srv6_srh_hdr_ext_len(const Srv6Srh& s) {
    return lr_srv6_srh_hdr_ext_len(s.get());
}

/// Segment at `index` (16 raw bytes). Throws on out-of-range.
inline std::array<std::uint8_t, 16> srv6_srh_segment_at(
    const Srv6Srh& s, std::size_t index) {
    std::array<std::uint8_t, 16> out{};
    if (lr_srv6_srh_segment_at(s.get(), index, out.data()) != 0) {
        throw Error("lr_srv6_srh_segment_at: out of range");
    }
    return out;
}

/// All segments as a vector of 16-byte arrays.
inline std::vector<std::array<std::uint8_t, 16>> srv6_srh_segments(const Srv6Srh& s) {
    std::vector<std::array<std::uint8_t, 16>> out;
    out.reserve(srv6_srh_segment_count(s));
    for (std::size_t i = 0; i < out.capacity(); ++i) {
        out.push_back(srv6_srh_segment_at(s, i));
    }
    return out;
}

/// Segment List[0] — the destination address at the sender (RFC 8754 §4.1).
inline std::array<std::uint8_t, 16> srv6_srh_first_segment(const Srv6Srh& s) {
    std::array<std::uint8_t, 16> out{};
    if (lr_srv6_srh_first_segment(s.get(), out.data()) != 0) {
        throw Error("lr_srv6_srh_first_segment: empty SRH");
    }
    return out;
}

/// Segment List[Segments Left] — the current destination (RFC 8754 §4.1).
inline std::array<std::uint8_t, 16> srv6_srh_current_destination(const Srv6Srh& s) {
    std::array<std::uint8_t, 16> out{};
    if (lr_srv6_srh_current_destination(s.get(), out.data()) != 0) {
        throw Error("lr_srv6_srh_current_destination: empty SRH");
    }
    return out;
}

/// The TLV bytes following the segment list (RFC 8754 §2.6).
inline std::vector<std::uint8_t> srv6_srh_tlvs(const Srv6Srh& s) {
    auto b = std::make_unique<lr_bytes_t>();
    if (lr_srv6_srh_tlvs(s.get(), b.get()) != 0) {
        throw Error("lr_srv6_srh_tlvs failed: " + std::string(lr_last_error()));
    }
    const std::uint8_t* p = lr_bytes_ptr(b.get());
    std::size_t n = lr_bytes_len(b.get());
    return std::vector<std::uint8_t>(p, p + n);
}

/// Encode the SRH into wire bytes (RFC 8754 §2 — auto-padded to a
/// multiple of 8 octets). Throws `Srv6SrhErrorException` on encode failure.
inline Bytes srv6_srh_encode(const Srv6Srh& s) {
    auto out = std::make_unique<lr_bytes_t>();
    std::int32_t rc = lr_srv6_srh_encode(s.get(), out.get());
    if (rc != 0) {
        std::int32_t code = lr_srv6_srh_last_err_code();
        if (code != -1) {
            throw Srv6SrhErrorException(static_cast<Srv6SrhError>(code),
                                        std::string(lr_last_error()));
        }
        throw Error("lr_srv6_srh_encode failed: " + std::string(lr_last_error()));
    }
    return Bytes(out.release());
}

// ---- SRv6 Behavior (RFC 8986 §4 — endpoint behaviors) ----

/// Parse a 16-bit wire value into `(canonical_wire, name)`.
/// Returns `std::nullopt` when the wire value does not name a known behavior.
inline std::optional<std::pair<std::uint16_t, std::string>>
srv6_behavior_from_wire(std::uint16_t wire) {
    std::uint16_t out_value = 0;
    std::array<char, 64> buf{};
    if (lr_srv6_behavior_from_wire(wire, &out_value, buf.data(), buf.size())) {
        return std::make_pair(out_value, std::string(buf.data()));
    }
    return std::nullopt;
}

/// Canonical wire value for `wire` (strips reserved bits).
inline std::uint16_t srv6_behavior_wire_value(std::uint16_t wire) {
    return lr_srv6_behavior_wire_value(wire);
}

/// The IANA-registered behavior name (e.g. "End", "End.X", "End.DX6").
inline std::string srv6_behavior_name(std::uint16_t wire) {
    auto r = srv6_behavior_from_wire(wire);
    if (r) return r->second;
    return "Unknown(0x" + std::to_string(wire) + ")";
}

inline bool srv6_behavior_is_psp(std::uint16_t wire) {
    return lr_srv6_behavior_is_psp(wire) != 0;
}

inline bool srv6_behavior_is_usp(std::uint16_t wire) {
    return lr_srv6_behavior_is_usp(wire) != 0;
}

inline bool srv6_behavior_is_usd(std::uint16_t wire) {
    return lr_srv6_behavior_is_usd(wire) != 0;
}

inline bool srv6_behavior_is_decap(std::uint16_t wire) {
    return lr_srv6_behavior_is_decap(wire) != 0;
}

inline bool srv6_behavior_is_cross_connect(std::uint16_t wire) {
    return lr_srv6_behavior_is_cross_connect(wire) != 0;
}

inline bool srv6_behavior_is_table_lookup(std::uint16_t wire) {
    return lr_srv6_behavior_is_table_lookup(wire) != 0;
}

// =========================================================================
// ===== lr-ospf — Link State Retransmission List / LSDB / LSA / External ===
// =========================================================================
//
// Mirrors the `lr_ospf` Rust crate's pub modules (RFC 2328 §13 / §13.5 /
// §13.6 / §13.7) and the C ABI surface `lr_ospf_retransmit_*`,
// `lr_ospf_lsdb_*`, `lr_ospf_lsa_*`, `lr_ospf_external_*` in lr_ffi.h.
// Each RAII handle owns its underlying `Box<T>` and frees it via the
// matching `lr_*_free` in its deleter — matches the layering the rest
// of this header uses for BGP message / route / filter handles.

namespace detail {

struct OspfRetransmitListDeleter {
    void operator()(lr_ospf_retransmit_t p) const noexcept {
        if (p) lr_ospf_retransmit_free(p);
    }
};
struct OspfLsdbDeleter {
    void operator()(lr_ospf_lsdb_t p) const noexcept {
        if (p) lr_ospf_lsdb_free(p);
    }
};
struct OspfLsaDeleter {
    void operator()(lr_ospf_lsa_box_t p) const noexcept {
        if (p) lr_ospf_lsa_free(p);
    }
};
struct OspfExternalDestDeleter {
    void operator()(lr_ospf_external_dest_t p) const noexcept {
        if (p) lr_ospf_external_dest_free(p);
    }
};

} // namespace detail

/// Fixed-layout 20-byte OSPF LSA header (RFC 2328 §A.4.1 for v2,
/// RFC 5340 §A.4.2 for v3). Mirrors lr_ospf::lsa::LsaHeader.
struct OspfLsaHeader {
    std::uint16_t ls_age;
    std::uint8_t options;
    std::uint16_t ls_type;
    std::uint32_t link_state_id;
    std::uint32_t advertising_router;
    std::uint32_t ls_sequence_number;
    std::uint16_t ls_checksum;
    std::uint16_t length;
};

/// LSA identity tuple used by the LSDB and the retransmission list:
/// (ls_type, link_state_id, advertising_router). Mirrors
/// lr_ospf::lsa::LsaKey.
struct OspfLsaKey {
    std::uint16_t ls_type;
    std::uint32_t link_state_id;
    std::uint32_t advertising_router;
};

/// RAII handle to one lr_ospf::lsa::Lsa instance (header + body).
/// Default-constructed handles and handles returned by `OspfLsaArray::at`
/// (a borrow) do NOT own the underlying C pointer — their destructors
/// are no-ops. Handles constructed via `make()` or `release()`-ed from
/// an owning handle DO own the pointer and free it on destruction.
class OspfLsaHandle {
public:
    OspfLsaHandle() = default;
    /// Owning constructor — the destructor will call lr_ospf_lsa_free.
    explicit OspfLsaHandle(lr_ospf_lsa_box_t ptr) : ptr_(ptr), owns_(true) {}

    /// Construct a new LSA from a header and a body byte vector.
    /// Throws std::runtime_error on allocation failure.
    static OspfLsaHandle make(const OspfLsaHeader& hdr,
                        const unsigned char* body, std::size_t body_len) {
        lr_ospf_lsa_hdr_box_t hdr_box = lr_ospf_lsa_header_new(
            hdr.ls_age, hdr.options, hdr.ls_type,
            hdr.link_state_id, hdr.advertising_router,
            hdr.ls_sequence_number, hdr.ls_checksum, hdr.length);
        if (!hdr_box) throw Error("lr_ospf_lsa_header_new returned null");
        lr_ospf_lsa_box_t p = lr_ospf_lsa_new(hdr_box, body, body_len);
        if (!p) throw Error("lr_ospf_lsa_new returned null");
        return OspfLsaHandle(p);
    }
    static OspfLsaHandle make(const OspfLsaHeader& hdr) {
        return make(hdr, nullptr, 0);
    }

    /// True when this handle owns the underlying C pointer (will free
    /// it on destruction). Borrowing handles return false.
    bool owns() const noexcept { return owns_; }

    /// Release ownership (the C side owns the handle after this call).
    /// After release(), owns() returns false and the destructor is a
    /// no-op. Calling release() on a non-owning handle returns nullptr
    /// and is a no-op.
    lr_ospf_lsa_box_t release() noexcept {
        auto p = ptr_;
        owns_ = false;
        ptr_ = nullptr;
        return p;
    }

    /// Read the LSA header.
    OspfLsaHeader header() const {
        lr_ospf_lsa_hdr_t c{};
        int rc = lr_ospf_lsa_header_get(ptr_, &c);
        if (rc != 0) throw Error(std::string("lr_ospf_lsa_header_get: ") + lr_last_error());
        return OspfLsaHeader{c.ls_age, c.options, c.ls_type, c.link_state_id,
                             c.advertising_router, c.ls_sequence_number,
                             c.ls_checksum, c.length};
    }
    /// Read the body bytes into a std::vector.
    std::vector<unsigned char> body() const {
        lr_bytes_t b{};
        int rc = lr_ospf_lsa_body(ptr_, &b);
        if (rc != 0) throw Error(std::string("lr_ospf_lsa_body: ") + lr_last_error());
        std::vector<unsigned char> out;
        if (b.len > 0) {
            out.assign(b.ptr, b.ptr + b.len);
            lr_bytes_free(&b);
        }
        return out;
    }
    /// Encode the LSA as 20-byte header + body (RFC 2328 §A.4 wire form).
    std::vector<unsigned char> to_wire() const {
        lr_bytes_t b{};
        int rc = lr_ospf_lsa_to_wire(ptr_, &b);
        if (rc != 0) throw Error(std::string("lr_ospf_lsa_to_wire: ") + lr_last_error());
        std::vector<unsigned char> out;
        if (b.len > 0) {
            out.assign(b.ptr, b.ptr + b.len);
            lr_bytes_free(&b);
        }
        return out;
    }
    /// Compute and store the LSA checksum and length in place
    /// (RFC 2328 §12.1).
    void finalize() {
        int rc = lr_ospf_lsa_finalize(ptr_);
        if (rc != 0) throw Error(std::string("lr_ospf_lsa_finalize: ") + lr_last_error());
    }
    /// True when the LSA's checksum field validates against the body.
    bool checksum_ok() const {
        return lr_ospf_lsa_handle_checksum_ok(ptr_) != 0;
    }
    /// Read the LSA identity tuple.
    OspfLsaKey key() const {
        std::uint16_t ls_type = 0;
        std::uint32_t ls_id = 0, adv = 0;
        int rc = lr_ospf_lsa_key(ptr_, &ls_type, &ls_id, &adv);
        if (rc != 0) throw Error(std::string("lr_ospf_lsa_key: ") + lr_last_error());
        return OspfLsaKey{ls_type, ls_id, adv};
    }

    /// Underlying C pointer (raw, no transfer of ownership).
    lr_ospf_lsa_box_t raw() const noexcept { return ptr_; }

    ~OspfLsaHandle() {
        if (ptr_ && owns_) {
            lr_ospf_lsa_free(ptr_);
        }
    }

    OspfLsaHandle(const OspfLsaHandle&) = delete;
    OspfLsaHandle& operator=(const OspfLsaHandle&) = delete;
    OspfLsaHandle(OspfLsaHandle&& other) noexcept
        : ptr_(other.ptr_), owns_(other.owns_) {
        other.ptr_ = nullptr;
        other.owns_ = false;
    }
    OspfLsaHandle& operator=(OspfLsaHandle&& other) noexcept {
        if (this != &other) {
            if (ptr_ && owns_) lr_ospf_lsa_free(ptr_);
            ptr_ = other.ptr_;
            owns_ = other.owns_;
            other.ptr_ = nullptr;
            other.owns_ = false;
        }
        return *this;
    }

private:
    lr_ospf_lsa_box_t ptr_ = nullptr;
    bool owns_ = false;

    /// Internal borrow constructor — used by OspfLsaArray::at() to alias
    /// array storage without claiming ownership. The destructor is a
    /// no-op because owns_ stays false.
    struct BorrowTag {};
    OspfLsaHandle(lr_ospf_lsa_box_t ptr, BorrowTag)
        : ptr_(ptr), owns_(false) {}

    friend class OspfLsaArray;
};

/// RAII handle to a flat C array of LSA handles returned by poll /
/// refresh_due / age_out. Frees the array AND every contained LSA on
/// destruction (lr_ospf_lsa_array_free does both). Use at() to borrow
/// individual LSAs — borrowed LSAs alias the array storage and must
/// NOT be freed separately.
class OspfLsaArray {
public:
    OspfLsaArray() = default;
    OspfLsaArray(lr_ospf_lsa_box_t* ptr, std::size_t count)
        : ptr_(ptr), count_(count) {}

    ~OspfLsaArray() { reset(); }

    OspfLsaArray(const OspfLsaArray&) = delete;
    OspfLsaArray& operator=(const OspfLsaArray&) = delete;
    OspfLsaArray(OspfLsaArray&& other) noexcept
        : ptr_(other.ptr_), count_(other.count_) {
        other.ptr_ = nullptr;
        other.count_ = 0;
    }
    OspfLsaArray& operator=(OspfLsaArray&& other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = other.ptr_;
            count_ = other.count_;
            other.ptr_ = nullptr;
            other.count_ = 0;
        }
        return *this;
    }

    std::size_t size() const noexcept { return count_; }
    bool empty() const noexcept { return count_ == 0; }

    /// Borrow the LSA at index i (no allocation, no transfer of
    /// ownership). The returned OspfLsaHandle aliases the array storage —
    /// the caller must NOT call release() or otherwise transfer
    /// ownership of the borrowed handle. Out-of-bounds indices
    /// return a default-constructed (empty) OspfLsaHandle. The
    /// destructor of the returned handle is a no-op (owns()==false).
    OspfLsaHandle at(std::size_t i) const {
        if (i >= count_ || !ptr_) return OspfLsaHandle{};
        return OspfLsaHandle(ptr_[i], OspfLsaHandle::BorrowTag{});
    }

    /// Release ownership without freeing (advanced use).
    lr_ospf_lsa_box_t* release() noexcept {
        auto p = ptr_;
        ptr_ = nullptr;
        count_ = 0;
        return p;
    }

private:
    void reset() noexcept {
        if (ptr_) {
            lr_ospf_lsa_array_free(ptr_, count_);
            ptr_ = nullptr;
            count_ = 0;
        }
    }

    lr_ospf_lsa_box_t* ptr_ = nullptr;
    std::size_t count_ = 0;
};

/// RAII handle to one lr_ospf::lsdb::Lsdb area link-state database.
class OspfLsdb {
public:
    OspfLsdb() : ptr_(lr_ospf_lsdb_new()) {
        if (!ptr_) throw Error("lr_ospf_lsdb_new returned null");
    }

    std::size_t size() const noexcept { return lr_ospf_lsdb_len(ptr_.get()); }
    bool empty() const noexcept { return lr_ospf_lsdb_is_empty(ptr_.get()) != 0; }

    /// Install `lsa` (transfers ownership). Returns 1=New, 2=Replaced,
    /// 0=Ignored, 3=Purged.
    int install(OspfLsaHandle lsa, std::uint64_t now_ms = 0) {
        int rc = lr_ospf_lsdb_install(ptr_.get(), lsa.release(), now_ms);
        if (rc < 0) throw Error(std::string("lr_ospf_lsdb_install: ") + lr_last_error());
        return rc;
    }
    bool remove(const OspfLsaKey& k) {
        int rc = lr_ospf_lsdb_remove(ptr_.get(), k.ls_type,
                                    k.link_state_id, k.advertising_router);
        if (rc < 0) throw Error(std::string("lr_ospf_lsdb_remove: ") + lr_last_error());
        return rc != 0;
    }
    /// Get a *clone* of the LSA identified by `k` (caller owns the
    /// returned handle). Returns std::nullopt when absent.
    std::optional<OspfLsaHandle> get(const OspfLsaKey& k) const {
        lr_ospf_lsa_box_t out = nullptr;
        int rc = lr_ospf_lsdb_get(ptr_.get(), k.ls_type, k.link_state_id,
                                  k.advertising_router, &out);
        if (rc < 0) throw Error(std::string("lr_ospf_lsdb_get: ") + lr_last_error());
        if (!out) return std::nullopt;
        return OspfLsaHandle(out);
    }
    /// Every LSA header in the LSDB (copied into a std::vector).
    std::vector<OspfLsaHeader> headers() const {
        lr_ospf_lsa_hdr_t* p = nullptr;
        std::uintptr_t n = 0;
        int rc = lr_ospf_lsdb_headers(ptr_.get(), &p, &n);
        if (rc != 0) throw Error(std::string("lr_ospf_lsdb_headers: ") + lr_last_error());
        std::vector<OspfLsaHeader> out;
        if (!p || n == 0) return out;
        out.reserve(n);
        for (std::uintptr_t i = 0; i < n; ++i) {
            out.push_back(OspfLsaHeader{
                p[i].ls_age, p[i].options, p[i].ls_type, p[i].link_state_id,
                p[i].advertising_router, p[i].ls_sequence_number,
                p[i].ls_checksum, p[i].length});
        }
        lr_ospf_lsa_hdr_array_free(p, n);
        return out;
    }
    /// LSAs whose LS age has crossed LSRefreshTime (RFC 2328 §14.1).
    OspfLsaArray refresh_due(std::uint32_t router_id, std::uint64_t now_ms) const {
        lr_ospf_lsa_box_t* p = nullptr;
        std::uintptr_t n = 0;
        int rc = lr_ospf_lsdb_refresh_due(ptr_.get(), router_id, now_ms, &p, &n);
        if (rc != 0) throw Error(std::string("lr_ospf_lsdb_refresh_due: ") + lr_last_error());
        return OspfLsaArray(p, n);
    }
    /// LSAs whose age crossed MaxAge and were flushed (RFC 2328 §14.4).
    OspfLsaArray age_out(std::uint64_t now_ms) const {
        lr_ospf_lsa_box_t* p = nullptr;
        std::uintptr_t n = 0;
        int rc = lr_ospf_lsdb_age_out(ptr_.get(), now_ms, &p, &n);
        if (rc != 0) throw Error(std::string("lr_ospf_lsdb_age_out: ") + lr_last_error());
        return OspfLsaArray(p, n);
    }

private:
    std::unique_ptr<std::remove_pointer_t<lr_ospf_lsdb_t>,
                    detail::OspfLsdbDeleter> ptr_;
};

/// RAII handle to one per-neighbor LSA retransmission list
/// (RFC 2328 §13.5). The flood path adds LSAs; the LS-Acknowledgment
/// handler drains them (§13.7); the poll loop re-floods aged entries
/// (§13.6).
class OspfRetransmitList {
public:
    OspfRetransmitList() : ptr_(lr_ospf_retransmit_new()) {
        if (!ptr_) throw Error("lr_ospf_retransmit_new returned null");
    }

    std::size_t size() const noexcept { return lr_ospf_retransmit_len(ptr_.get()); }
    bool empty() const noexcept { return lr_ospf_retransmit_is_empty(ptr_.get()) != 0; }

    bool contains(const OspfLsaKey& k) const {
        return lr_ospf_retransmit_contains(ptr_.get(), k.ls_type,
                                            k.link_state_id,
                                            k.advertising_router) != 0;
    }
    /// Record `lsa` on the list stamped at `now_ms` (§13.5 step 5).
    /// Transfers ownership of the LSA handle.
    void record_flood(OspfLsaHandle lsa, std::uint64_t now_ms) {
        int rc = lr_ospf_retransmit_record_flood(ptr_.get(), lsa.release(), now_ms);
        if (rc != 0) throw Error(std::string("lr_ospf_retransmit_record_flood: ") + lr_last_error());
    }
    bool remove(const OspfLsaKey& k) {
        return lr_ospf_retransmit_remove(ptr_.get(), k.ls_type,
                                         k.link_state_id,
                                         k.advertising_router) != 0;
    }
    void clear() { lr_ospf_retransmit_clear(ptr_.get()); }

    /// Drain `acks` from the list (§13.7). Returns the number of
    /// entries actually removed — useful for stray-ack diagnostics.
    std::size_t apply_acks(const std::vector<OspfLsaHeader>& acks) {
        if (acks.empty()) return 0;
        return lr_ospf_retransmit_apply_acks(ptr_.get(),
            reinterpret_cast<const lr_ospf_lsa_hdr_t*>(acks.data()),
            acks.size());
    }
    /// Return LSAs whose now_ms - last_sent_ms >= rxmt_interval_ms
    /// (§13.6). The returned LSAs are NOT removed from the list; their
    /// last_sent_ms is bumped to now_ms.
    OspfLsaArray poll(std::uint64_t now_ms, std::uint64_t rxmt_interval_ms) {
        lr_ospf_lsa_box_t* p = nullptr;
        std::uintptr_t n = 0;
        int rc = lr_ospf_retransmit_poll(ptr_.get(), now_ms,
                                         rxmt_interval_ms, &p, &n);
        if (rc != 0) throw Error(std::string("lr_ospf_retransmit_poll: ") + lr_last_error());
        return OspfLsaArray(p, n);
    }

private:
    std::unique_ptr<std::remove_pointer_t<lr_ospf_retransmit_t>,
                    detail::OspfRetransmitListDeleter> ptr_;
};

/// External-LSA metric type — RFC 2328 §2.3.
enum class OspfExternalMetricType : std::int32_t {
    Type1 = 1,  ///< metric is added to the internal cost.
    Type2 = 2,  ///< metric is compared only against other Type-2 routes.
};

/// RAII handle to one AS-external-LSA destination (RFC 2328 §2.3 / §A.4.5).
class OspfExternalDest {
public:
    OspfExternalDest(const unsigned char* prefix_v4,
                     const unsigned char* prefix_v6,
                     std::uint8_t prefix_len, std::uint32_t metric,
                     OspfExternalMetricType mt)
        : ptr_(lr_ospf_external_dest_new(prefix_v4, prefix_v6, prefix_len,
                                         metric,
                                         static_cast<std::int32_t>(mt))) {
        if (!ptr_) throw Error("lr_ospf_external_dest_new returned null");
    }
    static OspfExternalDest v4(const unsigned char prefix[4],
                               std::uint8_t prefix_len, std::uint32_t metric,
                               OspfExternalMetricType mt = OspfExternalMetricType::Type1) {
        return OspfExternalDest(prefix, nullptr, prefix_len, metric, mt);
    }
    static OspfExternalDest v6(const unsigned char prefix[16],
                               std::uint8_t prefix_len, std::uint32_t metric,
                               OspfExternalMetricType mt = OspfExternalMetricType::Type1) {
        return OspfExternalDest(nullptr, prefix, prefix_len, metric, mt);
    }

    void set_forwarding_addr_v4(std::uint32_t addr) {
        int rc = lr_ospf_external_dest_set_forwarding_addr(ptr_.get(), addr);
        if (rc != 0) throw Error(std::string("lr_ospf_external_dest_set_forwarding_addr: ") + lr_last_error());
    }
    void set_route_tag(std::uint32_t tag) {
        int rc = lr_ospf_external_dest_set_route_tag(ptr_.get(), tag);
        if (rc != 0) throw Error(std::string("lr_ospf_external_dest_set_route_tag: ") + lr_last_error());
    }
    void set_p_bit(std::uint8_t p) {
        int rc = lr_ospf_external_dest_set_p_bit(ptr_.get(), p);
        if (rc != 0) throw Error(std::string("lr_ospf_external_dest_set_p_bit: ") + lr_last_error());
    }

    std::uint32_t metric() const { return lr_ospf_external_dest_metric(ptr_.get()); }
    OspfExternalMetricType metric_type() const {
        return static_cast<OspfExternalMetricType>(
            lr_ospf_external_dest_metric_type(ptr_.get()));
    }
    std::uint32_t forwarding_addr() const {
        return lr_ospf_external_dest_forwarding_addr(ptr_.get());
    }
    std::uint32_t route_tag() const {
        return lr_ospf_external_dest_route_tag(ptr_.get());
    }
    std::uint8_t p_bit() const { return lr_ospf_external_dest_p_bit(ptr_.get()); }

private:
    std::unique_ptr<std::remove_pointer_t<lr_ospf_external_dest_t>,
                    detail::OspfExternalDestDeleter> ptr_;
};

// =========================================================================
// ===== lr-osroute::seg6_route — Seg6Route / Seg6LocalRoute / Seg6Netlink ==
// =========================================================================
//
// Mirrors `lr_osroute::seg6_route` (RFC 8754 §2 + RFC 8986 §4 + the
// Linux `seg6` / `seg6local` lwtunnel netlink surface). Same
// hierarchy as the Rust crate's module split:
//   - Seg6Route       — lr_osroute::seg6_route::Seg6Route       (RFC 8754 §2)
//   - Seg6LocalRoute  — lr_osroute::seg6_route::Seg6LocalRoute  (RFC 8986 §4)
//   - Seg6Netlink     — lr_osroute::seg6_route::Seg6Netlink     (NETLINK_ROUTE)
//   - Seg6EncapMode   — lr_osroute::seg6_route::Seg6EncapMode
//   - Seg6RouteError  — lr_osroute::seg6_route::Seg6RouteError

namespace detail {

struct Seg6RouteDeleter {
    void operator()(lr_seg6_route_t r) const noexcept {
        if (r) lr_seg6_route_free(r);
    }
};

struct Seg6LocalRouteDeleter {
    void operator()(lr_seg6_local_route_t r) const noexcept {
        if (r) lr_seg6_local_route_free(r);
    }
};

struct Seg6NetlinkDeleter {
    void operator()(lr_seg6_netlink_t n) const noexcept {
        if (n) lr_seg6_netlink_free(n);
    }
};

} // namespace detail

/// RAII handle to a `seg6` encap route (RFC 8754 §2).
using Seg6Route = std::unique_ptr<OpaqueSeg6Route, detail::Seg6RouteDeleter>;

/// RAII handle to a `seg6local` endpoint route (RFC 8986 §4).
using Seg6LocalRoute = std::unique_ptr<OpaqueSeg6LocalRoute, detail::Seg6LocalRouteDeleter>;

/// RAII handle to a `NETLINK_ROUTE` backend for SRv6 route installation.
using Seg6Netlink = std::unique_ptr<OpaqueSeg6Netlink, detail::Seg6NetlinkDeleter>;

/// Seg6EncapMode (mirrors `uapi/linux/seg6_iptunnel.h`).
enum class Seg6EncapMode : std::uint32_t {
    Inline = LR_SEG6_ENCAP_INLINE,
    Encap = LR_SEG6_ENCAP_ENCAP,
};

/// Seg6RouteError discriminant (mirrors `lr_osroute::Seg6RouteError`).
/// Positive integers; the global `LR_ERR_*` codes remain negative.
enum class Seg6RouteError : std::int32_t {
    Unsupported = LR_SEG6_ERR_UNSUPPORTED,
    NotEnabled = LR_SEG6_ERR_NOT_ENABLED,
    Syscall = LR_SEG6_ERR_SYSCALL,
    Kernel = LR_SEG6_ERR_KERNEL,
    BadSrh = LR_SEG6_ERR_BAD_SRH,
    UnsupportedAction = LR_SEG6_ERR_UNSUPPORTED_ACTION,
    Unknown = LR_SEG6_ERR_UNKNOWN,
};

/// Exception thrown on seg6 route failure (carries the discriminant
/// and the human-readable last-error message).
class Seg6RouteErrorException : public Error {
public:
    Seg6RouteErrorException(Seg6RouteError code, std::string msg)
        : Error(std::string("Seg6RouteError(") + name(code) + "): " + msg),
          code_(code) {}
    Seg6RouteError code() const noexcept { return code_; }

    static const char* name(Seg6RouteError c) {
        switch (c) {
            case Seg6RouteError::Unsupported: return "unsupported";
            case Seg6RouteError::NotEnabled: return "not-enabled";
            case Seg6RouteError::Syscall: return "syscall";
            case Seg6RouteError::Kernel: return "kernel";
            case Seg6RouteError::BadSrh: return "bad-srh";
            case Seg6RouteError::UnsupportedAction: return "unsupported-action";
            case Seg6RouteError::Unknown: return "unknown";
        }
        return "unknown";
    }
private:
    Seg6RouteError code_;
};

/// Throw `Seg6RouteErrorException` when the C ABI recorded a
/// `Seg6RouteError` in the last-error string (peeked via
/// `lr_seg6_route_err_code`). Falls back to a generic `Error` when
/// no seg6 error is recorded (the rc was negative — `LR_ERR_*`).
inline void throw_seg6_err(const char* what) {
    auto code_int = lr_seg6_route_err_code();
    const char* err = lr_last_error();
    std::string msg = err ? std::string(err) : std::string("unknown");
    if (code_int == LR_SEG6_ERR_UNKNOWN) {
        throw Error(std::string(what) + std::string(" failed: ") + msg);
    }
    throw Seg6RouteErrorException(
        static_cast<Seg6RouteError>(code_int),
        std::move(msg));
}

// ---- Seg6Route construction + mutators ----

/// Construct a `seg6` encap route (RFC 8754 §2 — the LSP head-end:
/// push an SRH on packets matching `prefix`). The default encap
/// mode is `Encap`. The SRH handle is borrowed — the constructor
/// clones the inner SRH.
inline Seg6Route make_seg6_route(lr_prefix_t prefix, lr_srv6_srh_t srh) {
    if (!srh) {
        throw Error("make_seg6_route: srh is null");
    }
    if (prefix.is_ipv6 == 0) {
        throw Error("make_seg6_route: prefix must be IPv6 (seg6 lwtunnel is IPv6-only)");
    }
    auto r = lr_seg6_route_new(prefix, srh);
    if (!r) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_route_new: ") + (err ? err : "unknown"));
    }
    return Seg6Route(r);
}

/// Set the encap mode. Builder-style.
inline Seg6Route& seg6_route_set_mode(Seg6Route& r, Seg6EncapMode mode) {
    auto rc = lr_seg6_route_set_mode(r.get(), static_cast<std::uint32_t>(mode));
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_route_set_mode: ") + (err ? err : "unknown"));
    }
    return r;
}

/// Set the output interface index. Builder-style.
inline Seg6Route& seg6_route_set_if_index(Seg6Route& r, std::uint32_t if_index) {
    auto rc = lr_seg6_route_set_if_index(r.get(), if_index);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_route_set_if_index: ") + (err ? err : "unknown"));
    }
    return r;
}

// ---- Seg6LocalRoute construction + mutators ----

/// Construct a `seg6local` endpoint route (RFC 8986 §4 — the LSP
/// tail-end: run `behavior` when a packet arrives addressed to
/// `sid`). `behavior_wire` is an IANA behavior wire value (one of
/// the `lr_srv6::Behavior` wire codes — End=1, End.X=5, End.T=9,
/// ...). The SID handle is borrowed — the constructor reads the 16
/// octets and rebuilds the `Sid`.
inline Seg6LocalRoute make_seg6_local_route(lr_srv6_sid_t sid, std::uint16_t behavior_wire) {
    if (!sid) {
        throw Error("make_seg6_local_route: sid is null");
    }
    auto r = lr_seg6_local_route_new(sid, behavior_wire);
    if (!r) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_new: ") + (err ? err : "unknown"));
    }
    return Seg6LocalRoute(r);
}

/// Set the route-level egress interface index. Builder-style.
inline Seg6LocalRoute& seg6_local_route_set_if_index(Seg6LocalRoute& r, std::uint32_t if_index) {
    auto rc = lr_seg6_local_route_set_if_index(r.get(), if_index);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_set_if_index: ") + (err ? err : "unknown"));
    }
    return r;
}

/// Set the IPv4 next-hop (SEG6_LOCAL_NH4 — the End.DX4 parameter).
inline Seg6LocalRoute& seg6_local_route_set_nh4(Seg6LocalRoute& r, const std::array<std::uint8_t, 4>& nh4) {
    auto rc = lr_seg6_local_route_set_nh4(r.get(), nh4.data());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_set_nh4: ") + (err ? err : "unknown"));
    }
    return r;
}

/// Set the IPv6 next-hop (SEG6_LOCAL_NH6 — the End.X / End.DX6
/// parameter).
inline Seg6LocalRoute& seg6_local_route_set_nh6(Seg6LocalRoute& r, const std::array<std::uint8_t, 16>& nh6) {
    auto rc = lr_seg6_local_route_set_nh6(r.get(), nh6.data());
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_set_nh6: ") + (err ? err : "unknown"));
    }
    return r;
}

/// Set the input interface index. Builder-style. Note: no mainline
/// kernel `seg6local` action consumes the IIF parameter today —
/// the install will fail with a descriptive error until a kernel
/// action adopts it.
inline Seg6LocalRoute& seg6_local_route_set_iif(Seg6LocalRoute& r, std::uint32_t iif) {
    auto rc = lr_seg6_local_route_set_iif(r.get(), iif);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_set_iif: ") + (err ? err : "unknown"));
    }
    return r;
}

/// Set the output interface index. Builder-style.
inline Seg6LocalRoute& seg6_local_route_set_oif(Seg6LocalRoute& r, std::uint32_t oif) {
    auto rc = lr_seg6_local_route_set_oif(r.get(), oif);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_set_oif: ") + (err ? err : "unknown"));
    }
    return r;
}

/// Set the routing table ID. Mutually exclusive with
/// `seg6_local_route_set_vrf_table`. Builder-style.
inline Seg6LocalRoute& seg6_local_route_set_table(Seg6LocalRoute& r, std::uint32_t table) {
    auto rc = lr_seg6_local_route_set_table(r.get(), table);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_set_table: ") + (err ? err : "unknown"));
    }
    return r;
}

/// Set the VRF table ID. Mutually exclusive with
/// `seg6_local_route_set_table`. Builder-style.
inline Seg6LocalRoute& seg6_local_route_set_vrf_table(Seg6LocalRoute& r, std::uint32_t vrf_table) {
    auto rc = lr_seg6_local_route_set_vrf_table(r.get(), vrf_table);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_set_vrf_table: ") + (err ? err : "unknown"));
    }
    return r;
}

/// Set the SRv6 Routing Header (SEG6_LOCAL_SRH — the End.B6.Insert /
/// End.B6.Encaps parameter). The SRH handle is borrowed — the
/// setter clones the inner SRH. Builder-style.
inline Seg6LocalRoute& seg6_local_route_set_srh(Seg6LocalRoute& r, lr_srv6_srh_t srh) {
    if (!srh) {
        throw Error("seg6_local_route_set_srh: srh is null");
    }
    auto rc = lr_seg6_local_route_set_srh(r.get(), srh);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_local_route_set_srh: ") + (err ? err : "unknown"));
    }
    return r;
}

// ---- Seg6Netlink ----

/// Open a `NETLINK_ROUTE` socket for SRv6 route installation.
/// Throws `Seg6RouteErrorException` when the kernel's `seg6_enabled`
/// sysctl is 0 (Code = `NotEnabled`) or the platform has no SRv6
/// (Code = `Unsupported`).
inline Seg6Netlink make_seg6_netlink() {
    auto n = lr_seg6_netlink_connect();
    if (!n) {
        throw_seg6_err("lr_seg6_netlink_connect");
    }
    return Seg6Netlink(n);
}

/// Install a `seg6` encap route (RFC 8754 §2 — the LSP head-end:
/// push an SRH on packets matching `prefix`).
inline void seg6_netlink_add_seg6_route(Seg6Netlink& n, const Seg6Route& route) {
    if (!route) {
        throw Error("seg6_netlink_add_seg6_route: route is null");
    }
    auto rc = lr_seg6_netlink_add_seg6_route(n.get(), route.get());
    if (rc != 0) {
        throw_seg6_err("lr_seg6_netlink_add_seg6_route");
    }
}

/// Delete a `seg6` encap route by prefix (the minimal prefix-shaped
/// delete iproute2 sends: `ip route del PREFIX`).
inline void seg6_netlink_delete_seg6_route(Seg6Netlink& n, lr_prefix_t prefix) {
    auto rc = lr_seg6_netlink_delete_seg6_route(n.get(), prefix);
    if (rc != 0) {
        throw_seg6_err("lr_seg6_netlink_delete_seg6_route");
    }
}

/// Install a `seg6local` endpoint route (RFC 8986 §4 — the LSP
/// tail-end: run `behavior` when a packet arrives addressed to
/// `sid`).
inline void seg6_netlink_add_seg6local_route(Seg6Netlink& n, const Seg6LocalRoute& route) {
    if (!route) {
        throw Error("seg6_netlink_add_seg6local_route: route is null");
    }
    auto rc = lr_seg6_netlink_add_seg6local_route(n.get(), route.get());
    if (rc != 0) {
        throw_seg6_err("lr_seg6_netlink_add_seg6local_route");
    }
}

/// Delete a `seg6local` endpoint route by SID (the same minimal
/// prefix-shaped delete as `seg6_netlink_delete_seg6_route`, against
/// the local table — seg6local rows are /128 SIDs).
inline void seg6_netlink_delete_seg6local_route(Seg6Netlink& n, lr_srv6_sid_t sid) {
    if (!sid) {
        throw Error("seg6_netlink_delete_seg6local_route: sid is null");
    }
    auto rc = lr_seg6_netlink_delete_seg6local_route(n.get(), sid);
    if (rc != 0) {
        throw_seg6_err("lr_seg6_netlink_delete_seg6local_route");
    }
}

/// Read the most recent request bytes (the diagnostic for "the
/// kernel rejected this and I need to see what \"this\" was" —
/// hex-dump it on failure and compare against a reference
/// implementation's bytes). Returns an empty vector when no
/// request has been sent yet.
inline std::vector<std::uint8_t> seg6_netlink_last_request_bytes(Seg6Netlink& n) {
    lr_bytes_t out{};
    auto rc = lr_seg6_netlink_last_request_bytes(n.get(), &out);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_netlink_last_request_bytes: ") + (err ? err : "unknown"));
    }
    std::vector<std::uint8_t> buf;
    if (out.ptr && out.len > 0) {
        buf.assign(out.ptr, out.ptr + out.len);
    }
    lr_bytes_free(&out);
    return buf;
}

/// Read the most recent response bytes (the raw NAK, extack
/// attributes included, for the same purpose as
/// `seg6_netlink_last_request_bytes`). Returns an empty vector when
/// no response has been received yet.
inline std::vector<std::uint8_t> seg6_netlink_last_response_bytes(Seg6Netlink& n) {
    lr_bytes_t out{};
    auto rc = lr_seg6_netlink_last_response_bytes(n.get(), &out);
    if (rc != 0) {
        const char* err = lr_last_error();
        throw Error(std::string("lr_seg6_netlink_last_response_bytes: ") + (err ? err : "unknown"));
    }
    std::vector<std::uint8_t> buf;
    if (out.ptr && out.len > 0) {
        buf.assign(out.ptr, out.ptr + out.len);
    }
    lr_bytes_free(&out);
    return buf;
}

} // namespace librouting

