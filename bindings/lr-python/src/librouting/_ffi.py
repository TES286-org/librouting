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
typedef struct OpaqueFilter OpaqueFilter;
typedef struct OpaqueFilter *lr_filter_t;

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
int32_t lr_router_add_roa_entry(lr_router_t r,
                                 const uint8_t *prefix_v4,
                                 const uint8_t *prefix_v6,
                                 uint8_t prefix_len,
                                 uint8_t max_length,
                                 uint32_t asn);
int32_t lr_router_set_roa_validate(lr_router_t r, uint8_t enable);
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
int32_t lr_router_install_static_v4(lr_router_t r,
                                    const uint8_t *prefix_addr,
                                    uint8_t prefix_len,
                                    const uint8_t *next_hop,
                                    uint32_t metric,
                                    uint32_t tag);
int32_t lr_router_install_static_v6(lr_router_t r,
                                    const uint8_t *prefix_addr,
                                    uint8_t prefix_len,
                                    const uint8_t *next_hop,
                                    uint32_t metric,
                                    uint32_t tag);
int32_t lr_router_uninstall_static_v4(lr_router_t r,
                                      const uint8_t *prefix_addr,
                                      uint8_t prefix_len);
int32_t lr_router_uninstall_static_v6(lr_router_t r,
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

/* ===== Structured inspection surface (issue #92) =====
 *
 * Mirrors the Rust pub API of DefaultRouter::session_summaries /
 * ospf_area_ids / ospf_area_topology_version / ospf_area_lsa /
 * bgp_session_identity_hash / drain_ospf_grace_events so the
 * embedder no longer has to parse the JSON-form dumps above. */
#define LR_SESSION_TEXT_MAX 32
#define LR_SESSION_KIND_BGP 1
#define LR_SESSION_KIND_OSPF 2
#define LR_SESSION_KIND_OSPF3 3
#define LR_SESSION_KIND_BABEL 4

typedef struct lr_session_summary_t {
    uint64_t handle;
    int32_t kind;
    uint8_t kind_text[LR_SESSION_TEXT_MAX];
    uint32_t local_as;
    uint32_t peer_as;
    uint8_t state_text[LR_SESSION_TEXT_MAX];
    uint8_t established;
    uint8_t peer_bgp_id_present;
    uint32_t peer_bgp_id;
    uint16_t negotiated_hold_time;
    uint64_t adj_rib_in_len;
    uint64_t updates_received;
    uint64_t updates_sent;
} lr_session_summary_t;

typedef struct lr_ospf_lsa_t {
    uint16_t ls_age;
    uint8_t options;
    uint16_t ls_type;
    uint32_t link_state_id;
    uint32_t advertising_router;
    uint32_t ls_sequence_number;
    uint16_t ls_checksum;
    uint16_t length;
    lr_bytes_t body;
} lr_ospf_lsa_t;

typedef struct lr_ospf_grace_event_t {
    uint32_t area;
    uint32_t advertising_router;
    uint32_t grace_period_secs;
    uint8_t reason;
    uint8_t interface_addr_v4_present;
    uint8_t interface_addr_v4[4];
    uint8_t interface_addr_v6_present;
    uint8_t interface_addr_v6[16];
    uint16_t ls_age_secs;
    uint8_t purged;
} lr_ospf_grace_event_t;

/* OSPF structured-type opaque handles (issue #92 — mirror lr_ospf
 * crate's pub modules: retransmit / lsdb / lsa / external). */
typedef struct OpaqueOspfRetransmitList OpaqueOspfRetransmitList;
typedef struct OpaqueOspfRetransmitList *lr_ospf_retransmit_t;
typedef struct OpaqueOspfLsdb OpaqueOspfLsdb;
typedef struct OpaqueOspfLsdb *lr_ospf_lsdb_t;
typedef struct OpaqueOspfLsaBox OpaqueOspfLsaBox;
typedef struct OpaqueOspfLsaBox *lr_ospf_lsa_box_t;
typedef struct OpaqueOspfLsaHdrBox OpaqueOspfLsaHdrBox;
typedef struct OpaqueOspfLsaHdrBox *lr_ospf_lsa_hdr_box_t;
typedef struct OpaqueOspfExternalDest OpaqueOspfExternalDest;
typedef struct OpaqueOspfExternalDest *lr_ospf_external_dest_t;

/* OSPF LSA header — fixed-layout 20-byte struct (RFC 2328 §A.4.1). */
typedef struct lr_ospf_lsa_hdr_t {
    uint16_t ls_age;
    uint8_t options;
    uint16_t ls_type;
    uint32_t link_state_id;
    uint32_t advertising_router;
    uint32_t ls_sequence_number;
    uint16_t ls_checksum;
    uint16_t length;
} lr_ospf_lsa_hdr_t;

/* OSPF retransmit list surface (RFC 2328 §13.5/§13.6/§13.7). */
lr_ospf_retransmit_t lr_ospf_retransmit_new(void);
void lr_ospf_retransmit_free(lr_ospf_retransmit_t r);
uintptr_t lr_ospf_retransmit_len(lr_ospf_retransmit_t r);
uint8_t lr_ospf_retransmit_is_empty(lr_ospf_retransmit_t r);
uint8_t lr_ospf_retransmit_contains(lr_ospf_retransmit_t r,
                                    uint16_t ls_type,
                                    uint32_t link_state_id,
                                    uint32_t advertising_router);
int32_t lr_ospf_retransmit_record_flood(lr_ospf_retransmit_t r,
                                        lr_ospf_lsa_box_t lsa,
                                        uint64_t now_ms);
uint8_t lr_ospf_retransmit_remove(lr_ospf_retransmit_t r,
                                  uint16_t ls_type,
                                  uint32_t link_state_id,
                                  uint32_t advertising_router);
void lr_ospf_retransmit_clear(lr_ospf_retransmit_t r);
uintptr_t lr_ospf_retransmit_apply_acks(lr_ospf_retransmit_t r,
                                       const lr_ospf_lsa_hdr_t *acks,
                                       uintptr_t count);
int32_t lr_ospf_retransmit_poll(lr_ospf_retransmit_t r,
                                uint64_t now_ms,
                                uint64_t rxmt_interval_ms,
                                lr_ospf_lsa_box_t **out,
                                uintptr_t *out_count);

/* OSPF LSDB surface (RFC 2328 §12). */
lr_ospf_lsdb_t lr_ospf_lsdb_new(void);
void lr_ospf_lsdb_free(lr_ospf_lsdb_t r);
int32_t lr_ospf_lsdb_install(lr_ospf_lsdb_t r,
                              lr_ospf_lsa_box_t lsa,
                              uint64_t now_ms);
int32_t lr_ospf_lsdb_remove(lr_ospf_lsdb_t r,
                             uint16_t ls_type,
                             uint32_t link_state_id,
                             uint32_t advertising_router);
int32_t lr_ospf_lsdb_get(lr_ospf_lsdb_t r,
                         uint16_t ls_type,
                         uint32_t link_state_id,
                         uint32_t advertising_router,
                         lr_ospf_lsa_box_t *out);
uintptr_t lr_ospf_lsdb_len(lr_ospf_lsdb_t r);
uint8_t lr_ospf_lsdb_is_empty(lr_ospf_lsdb_t r);
int32_t lr_ospf_lsdb_headers(lr_ospf_lsdb_t r,
                             lr_ospf_lsa_hdr_t **out,
                             uintptr_t *out_count);
void lr_ospf_lsa_hdr_array_free(lr_ospf_lsa_hdr_t *ptr, uintptr_t count);
int32_t lr_ospf_lsdb_refresh_due(lr_ospf_lsdb_t r,
                                 uint32_t advertising_router,
                                 uint64_t now_ms,
                                 lr_ospf_lsa_box_t **out,
                                 uintptr_t *out_count);
int32_t lr_ospf_lsdb_age_out(lr_ospf_lsdb_t r,
                             uint64_t now_ms,
                             lr_ospf_lsa_box_t **out,
                             uintptr_t *out_count);

/* OSPF LSA handle surface (lr_ospf::lsa::Lsa + LsaHeader). */
lr_ospf_lsa_hdr_box_t lr_ospf_lsa_header_new(uint16_t ls_age,
                                             uint8_t options,
                                             uint16_t ls_type,
                                             uint32_t link_state_id,
                                             uint32_t advertising_router,
                                             uint32_t ls_sequence_number,
                                             uint16_t ls_checksum,
                                             uint16_t length);
lr_ospf_lsa_box_t lr_ospf_lsa_new(lr_ospf_lsa_hdr_box_t header,
                                  const uint8_t *body,
                                  uintptr_t body_len);
void lr_ospf_lsa_free(lr_ospf_lsa_box_t lsa);
int32_t lr_ospf_lsa_header_get(lr_ospf_lsa_box_t lsa,
                               lr_ospf_lsa_hdr_t *out);
int32_t lr_ospf_lsa_body(lr_ospf_lsa_box_t lsa, lr_bytes_t *out);
int32_t lr_ospf_lsa_to_wire(lr_ospf_lsa_box_t lsa, lr_bytes_t *out);
int32_t lr_ospf_lsa_finalize(lr_ospf_lsa_box_t lsa);
uint8_t lr_ospf_lsa_handle_checksum_ok(lr_ospf_lsa_box_t lsa);
int32_t lr_ospf_lsa_key(lr_ospf_lsa_box_t lsa,
                        uint16_t *out_ls_type,
                        uint32_t *out_link_state_id,
                        uint32_t *out_advertising_router);
void lr_ospf_lsa_array_free(lr_ospf_lsa_box_t *ptr, uintptr_t count);

/* OSPF external-LSA origination surface (lr_ospf::external). */
lr_ospf_external_dest_t lr_ospf_external_dest_new(const uint8_t *prefix_v4,
                                                  const uint8_t *prefix_v6,
                                                  uint8_t prefix_len,
                                                  uint32_t metric,
                                                  int32_t metric_type);
void lr_ospf_external_dest_free(lr_ospf_external_dest_t d);
int32_t lr_ospf_external_dest_set_forwarding_addr(lr_ospf_external_dest_t d,
                                                  uint32_t forwarding_addr);
int32_t lr_ospf_external_dest_set_route_tag(lr_ospf_external_dest_t d,
                                            uint32_t tag);
int32_t lr_ospf_external_dest_set_p_bit(lr_ospf_external_dest_t d,
                                        uint8_t p);
uint32_t lr_ospf_external_dest_metric(lr_ospf_external_dest_t d);
int32_t lr_ospf_external_dest_metric_type(lr_ospf_external_dest_t d);
uint32_t lr_ospf_external_dest_forwarding_addr(lr_ospf_external_dest_t d);
uint32_t lr_ospf_external_dest_route_tag(lr_ospf_external_dest_t d);
uint8_t lr_ospf_external_dest_p_bit(lr_ospf_external_dest_t d);

uintptr_t lr_router_session_count(lr_router_t r);
int32_t lr_router_session_summary_at(lr_router_t r,
                                     uintptr_t index,
                                     struct lr_session_summary_t *out);
uintptr_t lr_router_ospf_area_count(lr_router_t r);
int32_t lr_router_ospf_area_id_at(lr_router_t r,
                                  uintptr_t index,
                                  uint32_t *out);
int32_t lr_router_ospf_area_topology_version(lr_router_t r,
                                             uint32_t area_id,
                                             uint64_t *out);
int32_t lr_router_ospf_area_lsa(lr_router_t r,
                                uint32_t area_id,
                                uint16_t ls_type,
                                uint32_t link_state_id,
                                uint32_t advertising_router,
                                struct lr_ospf_lsa_t *out);
uint64_t lr_router_bgp_session_identity_hash(lr_router_t r);
intptr_t lr_router_drain_ospf_grace_events(lr_router_t r,
                                           struct lr_ospf_grace_event_t *out,
                                           uintptr_t cap);

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

/* Structured BGP message inspection — opaque handle + variant readers
 * (mirrors lr_bgp::BgpMessage). */
typedef struct OpaqueBgpMessage OpaqueBgpMessage;
typedef struct OpaqueBgpMessage *lr_bgp_message_t;

lr_bgp_message_t lr_bgp_decode_message(const uint8_t *data, uintptr_t len);
void lr_bgp_message_free(lr_bgp_message_t m);
int32_t lr_bgp_message_type(lr_bgp_message_t m, uint8_t *out);

int32_t lr_bgp_message_open_version(lr_bgp_message_t m, uint8_t *out);
int32_t lr_bgp_message_open_my_as(lr_bgp_message_t m, uint32_t *out);
int32_t lr_bgp_message_open_hold_time(lr_bgp_message_t m, uint16_t *out);
int32_t lr_bgp_message_open_bgp_id(lr_bgp_message_t m, uint8_t *out);
uintptr_t lr_bgp_message_open_param_count(lr_bgp_message_t m);
int32_t lr_bgp_message_open_param_at(lr_bgp_message_t m,
                                     uintptr_t idx,
                                     uint8_t *out_type,
                                     lr_bytes_t *out_value);

int32_t lr_bgp_message_notification_code(lr_bgp_message_t m, uint8_t *out);
int32_t lr_bgp_message_notification_subcode(lr_bgp_message_t m, uint8_t *out);
int32_t lr_bgp_message_notification_data(lr_bgp_message_t m, lr_bytes_t *out);

int32_t lr_bgp_message_route_refresh_afi(lr_bgp_message_t m, uint16_t *out);
int32_t lr_bgp_message_route_refresh_safi(lr_bgp_message_t m, uint8_t *out);
int32_t lr_bgp_message_route_refresh_subtype(lr_bgp_message_t m, uint8_t *out);

uintptr_t lr_bgp_message_update_withdrawn_count(lr_bgp_message_t m);
uintptr_t lr_bgp_message_update_nlri_count(lr_bgp_message_t m);
uintptr_t lr_bgp_message_update_attr_count(lr_bgp_message_t m);
int32_t lr_bgp_message_update_withdrawn_at(lr_bgp_message_t m,
                                           uintptr_t idx,
                                           struct lr_prefix_t *out);
int32_t lr_bgp_message_update_nlri_at(lr_bgp_message_t m,
                                       uintptr_t idx,
                                       struct lr_prefix_t *out);
int32_t lr_bgp_message_update_attr_at(lr_bgp_message_t m,
                                      uintptr_t idx,
                                      uint8_t *out_type,
                                      uint8_t *out_flags,
                                      lr_bytes_t *out_value);

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

typedef struct lr_ext_comm_t {
    uint8_t kind;
    uint8_t subtype;
    uint32_t global;
    uint16_t local;
} lr_ext_comm_t;

typedef struct lr_match_t {
    uint8_t kind;
    uint32_t list_id;
    uint8_t protocol;
} lr_match_t;

typedef struct lr_set_t {
    uint8_t kind;
    uint8_t is_ipv6;
    uint8_t addr[16];
    uint32_t value;
    uint16_t value2;
} lr_set_t;

typedef struct lr_as_path_filter_t {
    const char *pattern;
    uint8_t permit;
} lr_as_path_filter_t;

typedef struct lr_community_entry_t {
    const uint64_t *communities;
    uintptr_t count;
    uint8_t permit;
} lr_community_entry_t;

typedef struct lr_filter_context_t {
    void *user_data;
    /* Every field may be NULL (built-in route-backed behaviour). The
     * Python binding uses the built-in context; the raw table is
     * available for advanced embedders. */
    void *unused_padding[19];
} lr_filter_context_t;

typedef struct OpaqueRoute OpaqueRoute;
typedef struct OpaqueRoute *lr_route_t;
typedef struct OpaquePrefixList OpaquePrefixList;
typedef struct OpaquePrefixList *lr_prefix_list_t;
typedef struct OpaqueRouteMap OpaqueRouteMap;
typedef struct OpaqueRouteMap *lr_route_map_t;
typedef struct OpaqueResolver OpaqueResolver;
typedef struct OpaqueResolver *lr_resolver_t;

lr_route_t lr_route_new_v4(const uint8_t *octets,
                           uint8_t prefix_len,
                           int32_t protocol);
lr_route_t lr_route_new_v6(const uint8_t *octets,
                           uint8_t prefix_len,
                           int32_t protocol);
void lr_route_free(lr_route_t route);
int32_t lr_route_set_next_hop(lr_route_t route, const uint8_t *addr, int32_t is_ipv6);
int32_t lr_route_next_hop(lr_route_t route, uint8_t *out, int32_t *out_is_ipv6);
int32_t lr_route_set_local_pref(lr_route_t route, uint32_t value);
int32_t lr_route_local_pref(lr_route_t route, uint32_t *out);
int32_t lr_route_set_med(lr_route_t route, uint32_t value);
int32_t lr_route_med(lr_route_t route, uint32_t *out);
int32_t lr_route_set_origin(lr_route_t route, uint8_t origin);
int32_t lr_route_origin(lr_route_t route, uint8_t *out);
int32_t lr_route_set_as_path(lr_route_t route, const uint32_t *asns, uintptr_t count);
int64_t lr_route_as_path(lr_route_t route, uint32_t *out, uintptr_t cap);
int32_t lr_route_add_community(lr_route_t route, uint32_t asn, uint16_t value);
int32_t lr_route_set_communities(lr_route_t route, const uint64_t *items, uintptr_t count);
int64_t lr_route_communities(lr_route_t route, uint64_t *out, uintptr_t cap);
int32_t lr_route_add_large_community(lr_route_t route, uint32_t global_admin,
                                     uint32_t local_data1, uint32_t local_data2);
int32_t lr_route_set_large_communities(lr_route_t route, const uint32_t *triples,
                                       uintptr_t count);
int64_t lr_route_large_communities(lr_route_t route, uint32_t *out, uintptr_t cap);
int32_t lr_route_add_ext_community(lr_route_t route, uint8_t kind, uint8_t subtype,
                                   uint32_t global, uint16_t local);
int32_t lr_route_set_ext_communities(lr_route_t route, const struct lr_ext_comm_t *items,
                                     uintptr_t count);
int64_t lr_route_ext_communities(lr_route_t route, struct lr_ext_comm_t *out, uintptr_t cap);
int32_t lr_route_set_metric(lr_route_t route, uint32_t value);
int32_t lr_route_metric(lr_route_t route, uint32_t *out);
int32_t lr_route_set_tag(lr_route_t route, int32_t has_tag, uint32_t tag);
int32_t lr_route_tag(lr_route_t route, uint32_t *out);

lr_prefix_list_t lr_prefix_list_new(void);
void lr_prefix_list_free(lr_prefix_list_t list);
int32_t lr_prefix_list_add(lr_prefix_list_t list, const struct lr_prefix_t *prefix,
                           uint8_t ge, uint8_t le, int32_t permit);
int32_t lr_prefix_list_match(lr_prefix_list_t list, const struct lr_prefix_t *prefix);

lr_route_map_t lr_route_map_new(void);
void lr_route_map_free(lr_route_map_t map);
int32_t lr_route_map_add_entry(lr_route_map_t map,
                               const struct lr_match_t *matches, uintptr_t n_matches,
                               const struct lr_set_t *sets, uintptr_t n_sets,
                               int32_t verdict);
int32_t lr_route_map_evaluate(lr_route_map_t map, lr_route_t route,
                              lr_resolver_t resolver, int32_t *out);

lr_resolver_t lr_resolver_new(void);
void lr_resolver_free(lr_resolver_t resolver);
int32_t lr_resolver_add_prefix_list(lr_resolver_t resolver, const char *name,
                                    lr_prefix_list_t list);
int32_t lr_resolver_add_as_path_list(lr_resolver_t resolver, const char *name,
                                     const struct lr_as_path_filter_t *filters,
                                     uintptr_t count);
int32_t lr_resolver_add_community_list(lr_resolver_t resolver, const char *name,
                                       const struct lr_community_entry_t *entries,
                                       uintptr_t count);

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

lr_filter_t lr_filter_compile(const char *name, const char *body);
void lr_filter_free(lr_filter_t filter);
int64_t lr_filter_name(lr_filter_t filter, uint8_t *out, uintptr_t cap);
int32_t lr_filter_evaluate(lr_filter_t filter,
                           lr_route_t route,
                           const struct lr_filter_context_t *ctx,
                           int32_t *out_verdict,
                           lr_bytes_t *out_reason);

/* MPLS label and label-stack codec (RFC 3032 §2.1, RFC 8277 §2.2/§2.3).
 * Mirrors the public Rust API of lr_mpls::{Label, LabelStack} and the
 * lr_mpls_* symbols in lr_ffi.h. */
typedef struct OpaqueMplsLabel OpaqueMplsLabel;
typedef struct OpaqueMplsLabel *lr_mpls_label_t;
typedef struct OpaqueMplsLabelStack OpaqueMplsLabelStack;
typedef struct OpaqueMplsLabelStack *lr_mpls_label_stack_t;

struct lr_mpls_label_spec_t {
    uint32_t value;
    uint8_t tc;
    uint8_t ttl;
};

lr_mpls_label_t lr_mpls_label_new(uint32_t value);
lr_mpls_label_t lr_mpls_label_new_checked(uint32_t value);
lr_mpls_label_t lr_mpls_label_with_tc(lr_mpls_label_t label, uint8_t tc);
lr_mpls_label_t lr_mpls_label_with_ttl(lr_mpls_label_t label, uint8_t ttl);
uint32_t lr_mpls_label_value(lr_mpls_label_t label);
uint8_t lr_mpls_label_tc(lr_mpls_label_t label);
uint8_t lr_mpls_label_ttl(lr_mpls_label_t label);
uint8_t lr_mpls_label_is_reserved(lr_mpls_label_t label);
int32_t lr_mpls_label_encode_3octet(lr_mpls_label_t label, uint8_t bottom, uint8_t *out);
int32_t lr_mpls_label_encode_4octet(lr_mpls_label_t label, uint8_t bottom, uint8_t *out);
void lr_mpls_label_free(lr_mpls_label_t label);

lr_mpls_label_stack_t lr_mpls_label_stack_new(void);
lr_mpls_label_stack_t lr_mpls_label_stack_from_values(const uint32_t *values, uintptr_t count);
lr_mpls_label_stack_t lr_mpls_label_stack_from_labels(const struct lr_mpls_label_spec_t *labels, uintptr_t count);
int32_t lr_mpls_label_stack_decode_4octet(const uint8_t *data, uintptr_t len, lr_mpls_label_stack_t *out);
int32_t lr_mpls_label_stack_decode_3octet(const uint8_t *data, uintptr_t len, lr_mpls_label_stack_t *out);
int32_t lr_mpls_label_stack_encode_4octet(lr_mpls_label_stack_t stack, lr_bytes_t *out);
int32_t lr_mpls_label_stack_encode_3octet(lr_mpls_label_stack_t stack, lr_bytes_t *out);
uintptr_t lr_mpls_label_stack_len(lr_mpls_label_stack_t stack);
uint8_t lr_mpls_label_stack_is_empty(lr_mpls_label_stack_t stack);
int32_t lr_mpls_label_stack_at(lr_mpls_label_stack_t stack,
                               uintptr_t index,
                               uint32_t *out_value,
                               uint8_t *out_tc,
                               uint8_t *out_ttl);
int32_t lr_mpls_label_stack_push(lr_mpls_label_stack_t stack, lr_mpls_label_t label);
int32_t lr_mpls_label_stack_push_bottom(lr_mpls_label_stack_t stack, lr_mpls_label_t label);
int32_t lr_mpls_label_stack_pop(lr_mpls_label_stack_t stack);
void lr_mpls_label_stack_free(lr_mpls_label_stack_t stack);

/* BFD Control packet wire codec (RFC 5880 §4.1). */
typedef struct OpaqueBfdPacket OpaqueBfdPacket;
typedef struct OpaqueBfdPacket *lr_bfd_packet_t;

#define LR_BFD_STATE_ADMIN_DOWN 0
#define LR_BFD_STATE_DOWN 1
#define LR_BFD_STATE_INIT 2
#define LR_BFD_STATE_UP 3
#define LR_BFD_DIAG_NONE 0
#define LR_BFD_DIAG_CTRL_EXPIRED 1
#define LR_BFD_DIAG_ECHO_FAILED 2
#define LR_BFD_DIAG_NEIGHBOR_SIGNALLED 3
#define LR_BFD_DIAG_FWD_RESET 4
#define LR_BFD_DIAG_PATH_DOWN 5
#define LR_BFD_DIAG_CONCAT_PATH_DOWN 6
#define LR_BFD_DIAG_ADMIN_DOWN 7
#define LR_BFD_DIAG_REV_PATH_DOWN 8
#define LR_BFD_DIAG_MISCONN_DEFECT 9

int32_t lr_bfd_decode(const uint8_t *data, uintptr_t len, lr_bfd_packet_t *out);
int32_t lr_bfd_encode(lr_bfd_packet_t packet, lr_bytes_t *out);
lr_bfd_packet_t lr_bfd_packet_new(void);
lr_bfd_packet_t lr_bfd_packet_heartbeat(uint32_t my_disc, uint32_t your_disc);
uint8_t lr_bfd_packet_version(lr_bfd_packet_t packet);
uint8_t lr_bfd_packet_diag(lr_bfd_packet_t packet);
uint8_t lr_bfd_packet_state(lr_bfd_packet_t packet);
uint8_t lr_bfd_packet_flags(lr_bfd_packet_t packet);
uint8_t lr_bfd_packet_detect_mult(lr_bfd_packet_t packet);
uint32_t lr_bfd_packet_my_discriminator(lr_bfd_packet_t packet);
uint32_t lr_bfd_packet_your_discriminator(lr_bfd_packet_t packet);
uint32_t lr_bfd_packet_desired_min_tx_interval(lr_bfd_packet_t packet);
uint32_t lr_bfd_packet_required_min_rx_interval(lr_bfd_packet_t packet);
uint32_t lr_bfd_packet_required_min_echo_interval(lr_bfd_packet_t packet);
uint8_t lr_bfd_packet_length(lr_bfd_packet_t packet);
int32_t lr_bfd_packet_set_diag(lr_bfd_packet_t packet, uint8_t diag);
int32_t lr_bfd_packet_set_state(lr_bfd_packet_t packet, uint8_t state);
int32_t lr_bfd_packet_set_flags(lr_bfd_packet_t packet, uint8_t flags);
int32_t lr_bfd_packet_set_detect_mult(lr_bfd_packet_t packet, uint8_t detect_mult);
int32_t lr_bfd_packet_set_my_discriminator(lr_bfd_packet_t packet, uint32_t disc);
int32_t lr_bfd_packet_set_your_discriminator(lr_bfd_packet_t packet, uint32_t disc);
int32_t lr_bfd_packet_set_desired_min_tx_interval(lr_bfd_packet_t packet, uint32_t interval);
int32_t lr_bfd_packet_set_required_min_rx_interval(lr_bfd_packet_t packet, uint32_t interval);
int32_t lr_bfd_packet_set_required_min_echo_interval(lr_bfd_packet_t packet, uint32_t interval);
void lr_bfd_packet_free(lr_bfd_packet_t packet);

/* ----- SRv6 structured types (RFC 8754 / RFC 8986) -----
 * Mirrors lr_srv6::{Sid, Locator, Srh, Behavior}. Each type is exposed
 * as an opaque handle that owns its heap allocation; the Python wrapper
 * (bindings/lr-python/src/librouting/srv6.py) provides the idiomatic
 * class surface on top. */
typedef struct OpaqueSrv6Sid OpaqueSrv6Sid;
typedef struct OpaqueSrv6Sid *lr_srv6_sid_t;
typedef struct OpaqueSrv6Locator OpaqueSrv6Locator;
typedef struct OpaqueSrv6Locator *lr_srv6_locator_t;
typedef struct OpaqueSrv6Srh OpaqueSrv6Srh;
typedef struct OpaqueSrv6Srh *lr_srv6_srh_t;

/* Sid — 128-bit SRv6 Segment Identifier (RFC 8754 §3). */
lr_srv6_sid_t lr_srv6_sid_new(const uint8_t *octets);
int32_t lr_srv6_sid_octets(lr_srv6_sid_t sid, uint8_t *out_octets);
uint8_t lr_srv6_sid_is_unspecified(lr_srv6_sid_t sid);
const uint8_t *lr_srv6_sid_as_ptr(lr_srv6_sid_t sid);
uint8_t lr_srv6_sid_locator_slice(lr_srv6_sid_t sid,
                                   uint8_t locator_block_bits,
                                   uintptr_t *out_offset,
                                   uintptr_t *out_len);
lr_srv6_sid_t lr_srv6_sid_from_locator_tail(const uint8_t *locator,
                                             uintptr_t locator_len,
                                             const uint8_t *tail,
                                             uintptr_t tail_len,
                                             uint8_t locator_block_bits);
uint8_t lr_srv6_sid_is_inside_locator(lr_srv6_sid_t sid,
                                       const uint8_t *locator,
                                       uintptr_t locator_len,
                                       uint8_t locator_block_bits);
void lr_srv6_sid_free(lr_srv6_sid_t sid);

/* Sid text round-trip (RFC 5952 §4 canonical form). */
int32_t lr_srv6_sid_from_str(const char *s, uint8_t *out);
const char *lr_srv6_sid_to_str(const uint8_t *sid);
const char *lr_srv6_sid_parse_error_name(int32_t v);

/* Locator — IPv6 prefix that owns a SID block (RFC 8754 §3.1). */
lr_srv6_locator_t lr_srv6_locator_new(const uint8_t *addr, uint8_t block_bits);
void lr_srv6_locator_free(lr_srv6_locator_t loc);
int32_t lr_srv6_locator_addr(lr_srv6_locator_t loc, uint8_t *out_addr);
uint8_t lr_srv6_locator_block_bits(lr_srv6_locator_t loc);
uintptr_t lr_srv6_locator_block_bytes(lr_srv6_locator_t loc);
uint8_t lr_srv6_locator_contains_sid(lr_srv6_locator_t loc, lr_srv6_sid_t sid);
lr_srv6_sid_t lr_srv6_locator_sid_with_tail(lr_srv6_locator_t loc, const uint8_t *tail);
lr_srv6_locator_t lr_srv6_locator_from_sid(lr_srv6_sid_t sid, uint8_t block_bits);
lr_srv6_sid_t lr_srv6_locator_sid_with_index(lr_srv6_locator_t loc, uint32_t function_index);

int32_t lr_srv6_locator_from_str(const char *s,
                                  uint8_t *out_addr,
                                  uint8_t *out_block_bits);
const char *lr_srv6_locator_to_str(const uint8_t *addr, uint8_t block_bits);
const char *lr_srv6_locator_parse_error_name(int32_t v);

/* Srh — Segment Routing Header (RFC 8754 §2). */
lr_srv6_srh_t lr_srv6_srh_new(const uint8_t *data, uintptr_t count);
lr_srv6_srh_t lr_srv6_srh_new_with_segments_left(const uint8_t *data,
                                                  uintptr_t count,
                                                  uint8_t segments_left);
int32_t lr_srv6_srh_set_next_header(lr_srv6_srh_t srh, uint8_t next_header);
int32_t lr_srv6_srh_set_flags(lr_srv6_srh_t srh, uint8_t flags);
int32_t lr_srv6_srh_set_tag(lr_srv6_srh_t srh, uint16_t tag);
int32_t lr_srv6_srh_set_tlvs(lr_srv6_srh_t srh,
                              const uint8_t *tlvs,
                              uintptr_t tlvs_len);
uint8_t lr_srv6_srh_next_header(lr_srv6_srh_t srh);
uint8_t lr_srv6_srh_segments_left(lr_srv6_srh_t srh);
uint8_t lr_srv6_srh_last_entry(lr_srv6_srh_t srh);
uint8_t lr_srv6_srh_flags(lr_srv6_srh_t srh);
uint16_t lr_srv6_srh_tag(lr_srv6_srh_t srh);
uintptr_t lr_srv6_srh_segment_count(lr_srv6_srh_t srh);
int32_t lr_srv6_srh_segment_at(lr_srv6_srh_t srh, uintptr_t index, uint8_t *out);
int32_t lr_srv6_srh_tlvs(lr_srv6_srh_t srh, lr_bytes_t *out);
int32_t lr_srv6_srh_first_segment(lr_srv6_srh_t srh, uint8_t *out);
int32_t lr_srv6_srh_current_destination(lr_srv6_srh_t srh, uint8_t *out);
int32_t lr_srv6_srh_encode(lr_srv6_srh_t srh, lr_bytes_t *out);
uintptr_t lr_srv6_srh_len(lr_srv6_srh_t srh);
uint8_t lr_srv6_srh_is_empty(lr_srv6_srh_t srh);
uint8_t lr_srv6_srh_hdr_ext_len(lr_srv6_srh_t srh);
void lr_srv6_srh_free(lr_srv6_srh_t srh);

/* SrhError discriminant (mirrors lr_srv6::SrhError). */
int32_t lr_srv6_srh_err_code(void);
int32_t lr_srv6_srh_last_err_code(void);

/* Behavior — RFC 8986 endpoint behavior registry. */
uint8_t lr_srv6_behavior_from_wire(uint16_t wire,
                                    uint16_t *out_value,
                                    char *out_name,
                                    uintptr_t name_cap);
uint16_t lr_srv6_behavior_wire_value(uint16_t wire);
uint8_t lr_srv6_behavior_is_psp(uint16_t wire);
uint8_t lr_srv6_behavior_is_usp(uint16_t wire);
uint8_t lr_srv6_behavior_is_usd(uint16_t wire);
uint8_t lr_srv6_behavior_is_decap(uint16_t wire);
uint8_t lr_srv6_behavior_is_cross_connect(uint16_t wire);
uint8_t lr_srv6_behavior_is_table_lookup(uint16_t wire);
uintptr_t lr_srv6_behavior_name(uint16_t wire, char *out_name, uintptr_t name_cap);

/* SRv6 netlink route-table — seg6 (encap) + seg6local (endpoint)
 * (mirrors lr_osroute::seg6_route pub API). */
#define LR_SEG6_ENCAP_INLINE 0
#define LR_SEG6_ENCAP_ENCAP 1
#define LR_SEG6_ERR_UNSUPPORTED 1
#define LR_SEG6_ERR_NOT_ENABLED 2
#define LR_SEG6_ERR_SYSCALL 3
#define LR_SEG6_ERR_KERNEL 4
#define LR_SEG6_ERR_BAD_SRH 5
#define LR_SEG6_ERR_UNSUPPORTED_ACTION 6
#define LR_SEG6_ERR_UNKNOWN -1

typedef struct OpaqueSeg6Route OpaqueSeg6Route;
typedef struct OpaqueSeg6Route *lr_seg6_route_t;
typedef struct OpaqueSeg6LocalRoute OpaqueSeg6LocalRoute;
typedef struct OpaqueSeg6LocalRoute *lr_seg6_local_route_t;
typedef struct OpaqueSeg6Netlink OpaqueSeg6Netlink;
typedef struct OpaqueSeg6Netlink *lr_seg6_netlink_t;

lr_seg6_route_t lr_seg6_route_new(struct lr_prefix_t prefix, lr_srv6_srh_t srh);
int32_t lr_seg6_route_set_mode(lr_seg6_route_t r, uint32_t mode);
int32_t lr_seg6_route_set_if_index(lr_seg6_route_t r, uint32_t if_index);
void lr_seg6_route_free(lr_seg6_route_t r);

lr_seg6_local_route_t lr_seg6_local_route_new(lr_srv6_sid_t sid,
                                               uint16_t behavior_wire);
int32_t lr_seg6_local_route_set_if_index(lr_seg6_local_route_t r,
                                          uint32_t if_index);
int32_t lr_seg6_local_route_set_nh4(lr_seg6_local_route_t r,
                                    const uint8_t *nh4);
int32_t lr_seg6_local_route_set_nh6(lr_seg6_local_route_t r,
                                    const uint8_t *nh6);
int32_t lr_seg6_local_route_set_iif(lr_seg6_local_route_t r, uint32_t iif);
int32_t lr_seg6_local_route_set_oif(lr_seg6_local_route_t r, uint32_t oif);
int32_t lr_seg6_local_route_set_table(lr_seg6_local_route_t r,
                                       uint32_t table);
int32_t lr_seg6_local_route_set_vrf_table(lr_seg6_local_route_t r,
                                           uint32_t vrf_table);
int32_t lr_seg6_local_route_set_srh(lr_seg6_local_route_t r,
                                    lr_srv6_srh_t srh);
void lr_seg6_local_route_free(lr_seg6_local_route_t r);

lr_seg6_netlink_t lr_seg6_netlink_connect(void);
int32_t lr_seg6_netlink_add_seg6_route(lr_seg6_netlink_t nl,
                                       lr_seg6_route_t route);
int32_t lr_seg6_netlink_delete_seg6_route(lr_seg6_netlink_t nl,
                                          struct lr_prefix_t prefix);
int32_t lr_seg6_netlink_add_seg6local_route(lr_seg6_netlink_t nl,
                                            lr_seg6_local_route_t route);
int32_t lr_seg6_netlink_delete_seg6local_route(lr_seg6_netlink_t nl,
                                               lr_srv6_sid_t sid);
int32_t lr_seg6_netlink_last_request_bytes(lr_seg6_netlink_t nl,
                                            lr_bytes_t *out);
int32_t lr_seg6_netlink_last_response_bytes(lr_seg6_netlink_t nl,
                                             lr_bytes_t *out);
void lr_seg6_netlink_free(lr_seg6_netlink_t nl);

int32_t lr_seg6_route_err_code(void);
const char *lr_seg6_route_err_name(int32_t code);
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
