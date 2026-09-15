"""Low-level CFFI loader for librouting."""

from __future__ import annotations

import os
from cffi import FFI

# Define the C ABI surface we want to consume. This must match `include/lr_ffi.h`.
# Note: FFI functions take `lr_bytes_t*` (single pointer); the caller
# declares a stack-allocated `lr_bytes_t` struct and passes its address.
_HEADER = r"""
typedef struct lr_bytes_t {
    uint8_t *ptr;
    uintptr_t len;
    uintptr_t cap;
} lr_bytes_t;

typedef struct OpaqueRouter OpaqueRouter;
typedef struct OpaqueRouter *lr_router_t;

const char *lr_last_error(void);
uint32_t lr_abi_version(void);

void lr_bytes_free(lr_bytes_t *b);
uintptr_t lr_bytes_len(const lr_bytes_t *b);
const uint8_t *lr_bytes_ptr(const lr_bytes_t *b);

lr_router_t lr_router_new(void);
void lr_router_destroy(lr_router_t r);
int32_t lr_router_add_bgp_session(lr_router_t r,
                                  uint32_t local_as,
                                  uint32_t peer_as,
                                  uint32_t local_bgp_id,
                                  uint16_t hold_time,
                                  uint16_t keepalive,
                                  uint8_t asn4,
                                  uint64_t *out_handle);
int32_t lr_router_add_bgp_session_ext(lr_router_t r,
                                      uint32_t local_as,
                                      uint32_t peer_as,
                                      uint32_t local_bgp_id,
                                      uint16_t hold_time,
                                      uint16_t keepalive,
                                      uint8_t asn4,
                                      uint8_t graceful_restart,
                                      uint16_t gr_restart_time,
                                      uint8_t long_lived_gr,
                                      uint32_t llgr_stale_time,
                                      uint32_t llgr_max_stale_time,
                                      uint64_t *out_handle);
int32_t lr_router_add_ospf_session(lr_router_t r,
                                   uint32_t router_id,
                                   uint32_t area_id,
                                   uint64_t *out_handle);
int32_t lr_router_add_ospfv3_session(lr_router_t r,
                                     uint32_t router_id,
                                     uint32_t area_id,
                                     uint64_t *out_handle);
int32_t lr_router_add_ospf_session_ext(lr_router_t r,
                                       int32_t version,
                                       uint32_t router_id,
                                       uint32_t area_id,
                                       int32_t area_kind,
                                       uint32_t default_metric,
                                       uint16_t mtu,
                                       int32_t network_type,
                                       int32_t has_interface_ip,
                                       uint32_t interface_ip,
                                       int32_t has_neighbor_ip,
                                       uint32_t neighbor_ip,
                                       uint64_t *out_handle);
int32_t lr_router_add_babel_session(lr_router_t r,
                                    const uint8_t *local_addr,
                                    int32_t is_ipv6,
                                    uint64_t *out_handle);
int32_t lr_router_feed_input(lr_router_t r,
                             uint64_t session,
                             const uint8_t *bytes,
                             uintptr_t len);
int32_t lr_router_drain_output(lr_router_t r,
                                uint64_t session,
                                lr_bytes_t *out);
int32_t lr_router_tick(lr_router_t r, uint64_t now_ms);
int32_t lr_router_start_session(lr_router_t r, uint64_t session);
int32_t lr_router_set_mrai(lr_router_t r, uint64_t session, uint64_t interval_ms);
int32_t lr_router_set_add_path(lr_router_t r, uint64_t session, uint8_t enabled);
int32_t lr_router_set_add_path_max_paths(lr_router_t r, uint32_t max_paths);
int32_t lr_router_set_ebgp_requires_policy(lr_router_t r, uint8_t enabled);
int32_t lr_router_set_enforce_first_as(lr_router_t r, uint8_t enabled);
int32_t lr_router_set_session_policy(lr_router_t r, uint64_t session,
                                     uint8_t import_, uint8_t export);
int32_t lr_router_set_extended_next_hop(lr_router_t r,
                                        uint64_t session,
                                        const uint8_t *tuples,
                                        uintptr_t count);
int32_t lr_router_set_mp_families(lr_router_t r,
                                  uint64_t session,
                                  const uint8_t *families,
                                  uintptr_t count);
int32_t lr_router_set_local_address(lr_router_t r,
                                    uint64_t session,
                                    uint16_t addr_family,
                                    const uint8_t *addr_bytes,
                                    uintptr_t addr_len);
int32_t lr_router_set_default_ipv4_unicast(lr_router_t r,
                                           uint64_t session,
                                           uint8_t enabled);
int32_t lr_router_set_local_as_tolerance(lr_router_t r,
                                         uint64_t session,
                                         uint32_t tolerance);
int32_t lr_router_set_soft_reconfig_inbound(lr_router_t r,
                                            uint64_t session,
                                            uint8_t enabled);
int64_t lr_router_soft_reconfig_inbound(lr_router_t r,
                                        uint64_t session);
int32_t lr_router_request_route_refresh(lr_router_t r,
                                        uint64_t session,
                                        uint16_t afi,
                                        uint8_t safi);
int32_t lr_router_originate_v4(lr_router_t r,
                               const uint8_t *prefix_addr,
                               uint8_t prefix_len,
                               const uint8_t *next_hop);
int32_t lr_router_originate_v6(lr_router_t r,
                               const uint8_t *prefix_addr,
                               uint8_t prefix_len,
                               const uint8_t *next_hop);
int32_t lr_router_withdraw_v4(lr_router_t r,
                               const uint8_t *prefix_addr,
                               uint8_t prefix_len);
int32_t lr_router_withdraw_v6(lr_router_t r,
                               const uint8_t *prefix_addr,
                               uint8_t prefix_len);
int32_t lr_router_originate_labeled_v4(lr_router_t r,
                                       const uint8_t *prefix_addr,
                                       uint8_t prefix_len,
                                       const uint32_t *labels,
                                       uintptr_t n_labels,
                                       const uint8_t *next_hop);
int32_t lr_router_originate_labeled_v6(lr_router_t r,
                                       const uint8_t *prefix_addr,
                                       uint8_t prefix_len,
                                       const uint32_t *labels,
                                       uintptr_t n_labels,
                                       const uint8_t *next_hop);
uint32_t lr_mpls_platform_labels(void);
typedef struct lr_event_t {
    int32_t kind;
    uint64_t session;
    uint8_t prefix[16];
    uint8_t prefix_len;
    uint8_t is_ipv6;
    uint32_t path_id;
    uint32_t count;
    uint32_t limit;
    uint32_t pct;
    int32_t action;
    char text[128];
} lr_event_t;
int32_t lr_router_poll_events(lr_router_t r, struct lr_event_t *out, int32_t cap);
int64_t lr_router_rib_len(lr_router_t r);
int32_t lr_router_rib_dump(lr_router_t r, lr_bytes_t *out);
int32_t lr_router_sessions_dump(lr_router_t r, lr_bytes_t *out);

int32_t lr_bgp_decode(const uint8_t *data, uintptr_t len, lr_bytes_t *out);
int32_t lr_bgp_encode_keepalive(lr_bytes_t *out);
int32_t lr_bgp_encode_open(uint32_t my_as,
                           uint16_t hold_time,
                           const uint8_t *bgp_id,
                           uint8_t as4,
                           lr_bytes_t *out);
int32_t lr_bgp_encode_notification(uint8_t error_code,
                                   uint8_t error_subcode,
                                   const uint8_t *data,
                                   uintptr_t data_len,
                                   lr_bytes_t *out);
int32_t lr_bgp_encode_update_withdraw_v4(const struct lr_prefix_t *prefixes,
                                         uintptr_t n_prefixes,
                                         lr_bytes_t *out);
int32_t lr_bgp_encode_update_announce_v4(const struct lr_prefix_t *prefixes,
                                         uintptr_t n_prefixes,
                                         const uint8_t *next_hop,
                                         const uint32_t *as_path,
                                         uintptr_t as_path_len,
                                         uint8_t origin,
                                         uint8_t as4,
                                         lr_bytes_t *out);
int32_t lr_ospf_decode_v2(const uint8_t *data, uintptr_t len, lr_bytes_t *out);
int32_t lr_babel_decode(const uint8_t *data, uintptr_t len, lr_bytes_t *out);
int32_t lr_srv6_encode_srh(const uint8_t *data, uintptr_t len, lr_bytes_t *out);
int32_t lr_srv6_decode_srh(const uint8_t *data, uintptr_t len, lr_bytes_t *out);

typedef struct OpaqueRoaStore OpaqueRoaStore;
typedef struct OpaqueRoaStore *lr_roa_store_t;

typedef struct lr_roa_entry_t {
    uint8_t addr[16];
    uint8_t is_ipv6;
    uint8_t prefix_len;
    uint8_t max_length;
    uint32_t asn;
} lr_roa_entry_t;

typedef struct lr_roa_delta_t {
    uint8_t announce;
    lr_roa_entry_t entry;
} lr_roa_delta_t;

lr_roa_store_t lr_roa_store_new(void);
void lr_roa_store_free(lr_roa_store_t s);
int32_t lr_roa_store_replace_static(lr_roa_store_t s,
                                    const lr_roa_entry_t *entries,
                                    uintptr_t len);
int32_t lr_roa_store_apply_deltas(lr_roa_store_t s,
                                  const lr_roa_delta_t *deltas,
                                  uintptr_t len);
int32_t lr_roa_store_clear_rtr(lr_roa_store_t s);
uintptr_t lr_roa_store_len(lr_roa_store_t s);
int32_t lr_roa_store_validate(lr_roa_store_t s,
                              const uint8_t *addr_v4,
                              const uint8_t *addr_v6,
                              uint8_t prefix_len,
                              uint32_t origin_as,
                              uint8_t has_origin_as,
                              uint8_t *out_state);

typedef struct lr_prefix_t {
    uint8_t addr[16];
    uint8_t is_ipv6;
    uint8_t prefix_len;
} lr_prefix_t;

typedef struct lr_damping_config_t {
    uint32_t additive_incr;
    uint32_t suppress_threshold;
    uint32_t reuse_threshold;
    uint32_t upper_limit;
    uint64_t decay_interval_s;
    double decay_factor_active;
    double decay_factor_withdrawn;
} lr_damping_config_t;

typedef struct OpaqueDamping OpaqueDamping;
typedef struct OpaqueDamping *lr_damping_t;

int32_t lr_router_add_redistribution_pipe(lr_router_t r,
                                          int32_t source,
                                          int32_t target,
                                          int32_t metric_policy,
                                          uint32_t metric,
                                          int32_t has_tag,
                                          uint32_t tag,
                                          const lr_prefix_t *allow,
                                          uintptr_t allow_count);
int32_t lr_router_add_aggregate(lr_router_t r, const lr_prefix_t *prefix);
int32_t lr_router_remove_aggregate(lr_router_t r, const lr_prefix_t *prefix);
lr_damping_t lr_router_set_damping(lr_router_t r, const lr_damping_config_t *cfg);
int32_t lr_damping_decay(lr_damping_t d, uint64_t now_s);
void lr_damping_destroy(lr_damping_t d);
"""


def _find_library():
    if path := os.environ.get("LIBROUTING_LIB"):
        return path
    candidates = []
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        here = os.path.dirname(here)
        candidates.append(os.path.join(here, "target", "release", "liblr_ffi.so"))
        candidates.append(os.path.join(here, "target", "release", "liblr_ffi.dylib"))
        candidates.append(os.path.join(here, "target", "release", "liblr_ffi.a"))
        candidates.append(os.path.join(here, "target", "debug", "liblr_ffi.so"))
        candidates.append(os.path.join(here, "target", "debug", "liblr_ffi.dylib"))
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


ffi = FFI()
ffi.cdef(_HEADER)

_lib = None

def get_lib():
    global _lib
    if _lib is None:
        path = _find_library()
        if path is None:
            raise RuntimeError("librouting shared library not found. Set LIBROUTING_LIB.")
        _lib = ffi.dlopen(path)
    return _lib


def alloc_bytes():
    """Allocate a zero-initialized lr_bytes_t on the C side; returns the
    new ffi.newp handle that the caller passes to lr_* functions."""
    return ffi.new("lr_bytes_t*")


def free_bytes(b) -> None:
    if b is None:
        return
    get_lib().lr_bytes_free(b)


def copy_bytes(b) -> bytes:
    """Copy the contents of an lr_bytes_t into Python bytes."""
    n = int(get_lib().lr_bytes_len(b))
    if n == 0:
        return b""
    ptr = get_lib().lr_bytes_ptr(b)
    return ffi.buffer(ptr, n)[:]
