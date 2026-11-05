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
typedef struct OpaqueRoute OpaqueRoute;
typedef struct OpaqueRoute *lr_route_t;
typedef struct OpaqueAttributes OpaqueAttributes;
typedef struct OpaqueAttributes *lr_attributes_t;

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
typedef struct OpaqueOspfV3ExternalDest OpaqueOspfV3ExternalDest;
typedef struct OpaqueOspfV3ExternalDest *lr_ospf_v3_external_dest_t;

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

/* OSPFv3 external destination (RFC 5340 §4.4.3.6 / §A.4.7). */
lr_ospf_v3_external_dest_t lr_ospf_v3_external_dest_new(const uint8_t *prefix_v4,
                                                       const uint8_t *prefix_v6,
                                                       uint8_t prefix_len,
                                                       uint32_t metric,
                                                       uint8_t metric_type2);
int32_t lr_ospf_v3_external_dest_set_forwarding_addr(lr_ospf_v3_external_dest_t d,
                                                    const uint8_t *addr);
int32_t lr_ospf_v3_external_dest_clear_forwarding_addr(lr_ospf_v3_external_dest_t d);
int32_t lr_ospf_v3_external_dest_set_route_tag(lr_ospf_v3_external_dest_t d,
                                              uint32_t route_tag);
int32_t lr_ospf_v3_external_dest_clear_route_tag(lr_ospf_v3_external_dest_t d);
int32_t lr_ospf_v3_external_dest_prefix(lr_ospf_v3_external_dest_t d,
                                       struct lr_core_prefix_t *out);
uint32_t lr_ospf_v3_external_dest_metric(lr_ospf_v3_external_dest_t d);
uint8_t lr_ospf_v3_external_dest_type2(lr_ospf_v3_external_dest_t d);
int32_t lr_ospf_v3_external_dest_forwarding_addr(lr_ospf_v3_external_dest_t d,
                                                uint8_t *out_addr);
int32_t lr_ospf_v3_external_dest_route_tag(lr_ospf_v3_external_dest_t d,
                                          uint32_t *out_tag);
void lr_ospf_v3_external_dest_free(lr_ospf_v3_external_dest_t d);

/* OSPF runtime: virtual links + AS-external redistribution. */
int32_t lr_router_ospf_add_virtual_link(lr_router_t r,
                                        uint32_t transit_area,
                                        uint32_t endpoint);
int32_t lr_router_ospf_remove_virtual_link(lr_router_t r,
                                           uint32_t transit_area,
                                           uint32_t endpoint);
int32_t lr_router_ospf_virtual_link_up(lr_router_t r,
                                       uint32_t transit_area,
                                       uint32_t endpoint);
int32_t lr_router_ospf_virtual_link_session(lr_router_t r,
                                            uint32_t transit_area,
                                            uint32_t endpoint,
                                            uint64_t *out_handle);
int32_t lr_router_ospf_redistribute(lr_router_t r,
                                    lr_ospf_external_dest_t dest);
int32_t lr_router_ospf_unredistribute(lr_router_t r,
                                     struct lr_core_prefix_t prefix);
int32_t lr_router_ospf_redistribute_v3(lr_router_t r,
                                       lr_ospf_v3_external_dest_t dest);
int32_t lr_router_ospf_unredistribute_v3(lr_router_t r,
                                        struct lr_core_prefix_t prefix);
int32_t lr_router_ospf_is_asbr(lr_router_t r);

/* OSPF area type — value struct mirroring lr_router::OspfAreaType
 * (RFC 2328 §3.6 stub areas; RFC 3101 NSSA). Mirrors the Rust pub
 * API one-to-one: constructors, readers, router set/get entry
 * points. The struct is passed and returned by value. */
struct lr_ospf_area_type_t {
    int32_t kind;
    uint32_t default_metric;
};
struct lr_ospf_area_type_t lr_ospf_area_type_normal(void);
struct lr_ospf_area_type_t lr_ospf_area_type_stub(uint32_t default_metric);
struct lr_ospf_area_type_t lr_ospf_area_type_stub_no_summary(uint32_t default_metric);
struct lr_ospf_area_type_t lr_ospf_area_type_nssa(uint32_t default_metric);
struct lr_ospf_area_type_t lr_ospf_area_type_nssa_no_summary(uint32_t default_metric);
int32_t lr_ospf_area_type_kind(struct lr_ospf_area_type_t t);
uint8_t lr_ospf_area_type_is_stub(struct lr_ospf_area_type_t t);
uint8_t lr_ospf_area_type_is_nssa(struct lr_ospf_area_type_t t);
uint8_t lr_ospf_area_type_is_stubby(struct lr_ospf_area_type_t t);
uint8_t lr_ospf_area_type_no_summary(struct lr_ospf_area_type_t t);
uint8_t lr_ospf_area_type_default_metric(struct lr_ospf_area_type_t t,
                                         uint32_t *out_default_metric);
int32_t lr_router_ospf_set_area_type_ext(lr_router_t r,
                                         uint32_t area_id,
                                         struct lr_ospf_area_type_t t);
int32_t lr_router_ospf_area_type(lr_router_t r,
                                 uint32_t area_id,
                                 struct lr_ospf_area_type_t *out);

/* OSPF DR/BDR election reporting + Router-LSA flags reader (issue #92).
 * Mirrors DefaultRouter::set_ospf_dr_state (RFC 2328 §9.4 step 7) and
 * DefaultRouter::ospf_router_lsa_flags (§A.4.2 V/E/B bits). The setter
 * returns 0 on success with *out_changed written to 1/0; -2 invalid
 * handle; -6 unknown / non-OSPF session; -4 panic. The reader returns
 * 0 on success with the 3 boolean slots written; -2 invalid handle;
 * -6 unknown area; -1 NULL out pointer; -4 panic. */
int32_t lr_router_set_ospf_dr_state(lr_router_t r,
                                    uint64_t session,
                                    uint32_t dr,
                                    uint32_t bdr,
                                    uint8_t *out_changed);
int32_t lr_router_ospf_router_lsa_flags(lr_router_t r,
                                        uint32_t area_id,
                                        uint8_t *out_v,
                                        uint8_t *out_e,
                                        uint8_t *out_b);

/* Simple router-wide readers (issue #92). Mirrors
 * DefaultRouter::enforce_first_as / add_path_max_paths /
 * roa_validate_enabled — the reader side of the existing setters.
 * Each returns the router-wide configuration value; a NULL router
 * handle falls back to the documented default (0 / 1 / 0) so a panic
 * cannot be observed through these readers. */
uint8_t lr_router_enforce_first_as(lr_router_t r);
uint32_t lr_router_add_path_max_paths(lr_router_t r);
uint8_t lr_router_roa_validate_enabled(lr_router_t r);

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
    /* Every field may be NULL (built-in route-backed behaviour).
     * The full callback table mirrors the C ABI struct in
     * include/lr_ffi.h (lines 2877-2938) so Python embedders can
     * supply custom ROA / BGP attribute hooks. */
    int32_t (*bgp_local_pref)(void *user_data, lr_route_t route, uint32_t *out);
    int32_t (*bgp_med)(void *user_data, lr_route_t route, uint32_t *out);
    int32_t (*bgp_next_hop)(void *user_data, lr_route_t route,
                            int32_t *out_is_v6, uint8_t *out);
    int64_t (*bgp_as_path)(void *user_data, lr_route_t route,
                           uint32_t *out, uintptr_t cap);
    int64_t (*bgp_communities)(void *user_data, lr_route_t route,
                                uint64_t *out, uintptr_t cap);
    int64_t (*bgp_large_communities)(void *user_data, lr_route_t route,
                                     uint32_t *out, uintptr_t cap);
    int64_t (*bgp_ext_communities)(void *user_data, lr_route_t route,
                                    struct lr_ext_comm_t *out, uintptr_t cap);
    int32_t (*bgp_origin)(void *user_data, lr_route_t route, uint8_t *out);
    uint8_t (*roa_state)(void *user_data, lr_route_t route);
    void (*set_bgp_local_pref)(void *user_data, lr_route_t route, uint32_t value);
    void (*set_bgp_med)(void *user_data, lr_route_t route, uint32_t value);
    void (*set_bgp_next_hop)(void *user_data, lr_route_t route,
                              int32_t is_v6, const uint8_t *addr);
    void (*bgp_as_path_prepend)(void *user_data, lr_route_t route, uint32_t asn);
    void (*bgp_communities_add)(void *user_data, lr_route_t route,
                                 uint32_t asn, uint16_t value);
    void (*set_bgp_communities)(void *user_data, lr_route_t route,
                                 const uint64_t *items, uintptr_t count);
    void (*set_bgp_as_path)(void *user_data, lr_route_t route,
                             const uint32_t *seq, uintptr_t count);
    void (*set_bgp_large_communities)(void *user_data, lr_route_t route,
                                       const uint32_t *triples, uintptr_t count);
    void (*set_bgp_ext_communities)(void *user_data, lr_route_t route,
                                     const struct lr_ext_comm_t *items,
                                     uintptr_t count);
} lr_filter_context_t;

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

/* Attributes container (lr_core::attr::Attributes — the generic
 * ordered attribute set used by BGP path attributes and OSPF/Babel
 * extra metadata). Mirrors crates/lr-ffi/src/attributes.rs. */
lr_attributes_t lr_attributes_new(void);
void lr_attributes_free(lr_attributes_t a);
int32_t lr_attributes_insert(lr_attributes_t a,
                             uint8_t tag,
                             uint8_t flags,
                             const uint8_t *value,
                             uintptr_t value_len);
int64_t lr_attributes_get(lr_attributes_t a,
                          uint8_t tag,
                          uint8_t *out_flags,
                          uint8_t *out_value,
                          uintptr_t cap);
uint32_t lr_attributes_get_u32_be(lr_attributes_t a, uint8_t tag);
uint64_t lr_attributes_get_u64_be(lr_attributes_t a, uint8_t tag);
uint8_t lr_attributes_get_u8(lr_attributes_t a, uint8_t tag);
int32_t lr_attributes_remove(lr_attributes_t a, uint8_t tag);
uintptr_t lr_attributes_len(lr_attributes_t a);
uint8_t lr_attributes_is_empty(lr_attributes_t a);
int64_t lr_attributes_at(lr_attributes_t a,
                         uintptr_t index,
                         uint8_t *out_tag,
                         uint8_t *out_flags,
                         uint8_t *out_value,
                         uintptr_t cap);

/* ApplySetError helpers — apply a SetAction to a route via the
 * fail-closed apply_set_checked surface (lr-policy::action).
 * Mirrors crates/lr-ffi/src/policy_batch.rs. */
uint8_t lr_apply_set_checked(lr_route_t route,
                             uint8_t set_kind,
                             uint32_t arg1,
                             uint32_t arg2,
                             uint32_t arg3);
const char *lr_apply_set_error_name(uint8_t code);

/* Per-route BGP / Babel / OSPF attribute readers (RFC 4271 §5.1,
 * RFC 4456 §8, RFC 6514 §5, RFC 7311, RFC 9231 §4, RFC 8966 §3.2/§4.6.9,
 * RFC 2328 §16 / RFC 5340 §4.1). Mirrors the C ABI surface in
 * crates/lr-ffi/src/route_attrs.rs. */
int32_t lr_route_atomic_aggregate(lr_route_t route, uint8_t *out);
int32_t lr_route_originator_id(lr_route_t route, uint8_t *out_addr, uint8_t *out_present);
int32_t lr_route_has_cluster_list(lr_route_t route, uint8_t *out);
int32_t lr_route_cluster_list_len(lr_route_t route, uintptr_t *out);
int32_t lr_route_cluster_list_at(lr_route_t route, uintptr_t index, uint8_t *out_addr);
int32_t lr_route_has_otc(lr_route_t route, uint8_t *out);
int32_t lr_route_otc(lr_route_t route, uint32_t *out, uint8_t *out_present);
int32_t lr_route_has_aigp(lr_route_t route, uint8_t *out);
int32_t lr_route_aigp(lr_route_t route, uint64_t *out, uint8_t *out_present);
int32_t lr_route_has_aggregator(lr_route_t route, uint8_t *out);
int32_t lr_route_aggregator_asn(lr_route_t route, uint32_t *out, uint8_t *out_present);
int32_t lr_route_aggregator_speaker(lr_route_t route, uint8_t *out_addr, uint8_t *out_present);
int32_t lr_route_has_pmsi_tunnel(lr_route_t route, uint8_t *out);
int32_t lr_route_pmsi_tunnel_flags(lr_route_t route, uint8_t *out_flags, uint8_t *out_present);
int32_t lr_route_as_sequence_len(lr_route_t route, uintptr_t *out);
int32_t lr_route_as_sequence_at(lr_route_t route, uintptr_t index, uint32_t *out);
int32_t lr_route_set_as_sequence(lr_route_t route, const uint32_t *asns, uintptr_t count);
int32_t lr_route_prepend_as(lr_route_t route, uint32_t asn);
int32_t lr_route_remove_community(lr_route_t route, uint32_t asn, uint16_t value);
int32_t lr_route_has_babel_metric(lr_route_t route, uint8_t *out);
int32_t lr_route_babel_metric(lr_route_t route, uint32_t *out, uint8_t *out_present);
int32_t lr_route_has_babel_seqno(lr_route_t route, uint8_t *out);
int32_t lr_route_babel_seqno(lr_route_t route, uint16_t *out, uint8_t *out_present);
int32_t lr_route_has_babel_router_id(lr_route_t route, uint8_t *out);
int32_t lr_route_babel_router_id(lr_route_t route, uint8_t *out_router_id, uint8_t *out_present);
int32_t lr_route_has_ospf_metric1(lr_route_t route, uint8_t *out);
int32_t lr_route_ospf_metric1(lr_route_t route, uint32_t *out, uint8_t *out_present);
int32_t lr_route_has_ospf_metric2(lr_route_t route, uint8_t *out);
int32_t lr_route_ospf_metric2(lr_route_t route, uint32_t *out, uint8_t *out_present);
int32_t lr_route_has_ospf_tag(lr_route_t route, uint8_t *out);
int32_t lr_route_ospf_tag(lr_route_t route, uint32_t *out, uint8_t *out_present);
int32_t lr_route_has_ospf_router_id(lr_route_t route, uint8_t *out);
int32_t lr_route_ospf_router_id(lr_route_t route, uint32_t *out, uint8_t *out_present);

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

/* ----- BFD AuthType / AuthKey / AuthSection (RFC 5880 §4.2-§4.4) -----
 * Mirrors lr_bfd::auth::{AuthType, AuthKey, AuthSection}. Each type is
 * exposed as an opaque handle that owns its heap allocation; the
 * Python wrapper (bindings/lr-python/src/librouting/bfd.py) provides
 * the idiomatic class surface on top. */
typedef struct OpaqueBfdAuthKey OpaqueBfdAuthKey;
typedef struct OpaqueBfdAuthKey *lr_bfd_auth_key_t;
typedef struct OpaqueBfdAuthSection OpaqueBfdAuthSection;
typedef struct OpaqueBfdAuthSection *lr_bfd_auth_section_t;

/* AuthType free-function readers (RFC 5880 §8 IANA codes). */
intptr_t lr_bfd_auth_type_expected_digest_len(uint8_t auth_type);
uint8_t lr_bfd_auth_type_is_keyed_hash(uint8_t auth_type);
uint8_t lr_bfd_auth_type_is_meticulous(uint8_t auth_type);

/* AuthKey lifecycle + accessors. */
lr_bfd_auth_key_t lr_bfd_auth_key_new(uint8_t key_id, const uint8_t *secret, uintptr_t secret_len);
lr_bfd_auth_key_t lr_bfd_auth_key_simple_password(uint8_t key_id, const uint8_t *password, uintptr_t password_len);
void lr_bfd_auth_key_free(lr_bfd_auth_key_t k);
uint8_t lr_bfd_auth_key_key_id(lr_bfd_auth_key_t k);
uintptr_t lr_bfd_auth_key_data_len(lr_bfd_auth_key_t k);
int32_t lr_bfd_auth_key_data(lr_bfd_auth_key_t k, uint8_t *out_data, uintptr_t cap, uintptr_t *out_len);

/* AuthSection lifecycle (RFC 5880 §4.2-§4.4 — five type-specific
 * constructors matching the §8 IANA codes). */
lr_bfd_auth_section_t lr_bfd_auth_section_simple_password(const uint8_t *password, uintptr_t password_len, uint8_t key_id);
lr_bfd_auth_section_t lr_bfd_auth_section_keyed_md5(uint8_t key_id, uint32_t sequence, const uint8_t *digest, uintptr_t digest_len);
lr_bfd_auth_section_t lr_bfd_auth_section_meticulous_keyed_md5(uint8_t key_id, uint32_t sequence, const uint8_t *digest, uintptr_t digest_len);
lr_bfd_auth_section_t lr_bfd_auth_section_keyed_sha1(uint8_t key_id, uint32_t sequence, const uint8_t *digest, uintptr_t digest_len);
lr_bfd_auth_section_t lr_bfd_auth_section_meticulous_keyed_sha1(uint8_t key_id, uint32_t sequence, const uint8_t *digest, uintptr_t digest_len);
void lr_bfd_auth_section_free(lr_bfd_auth_section_t s);

/* AuthSection readers. */
uint8_t lr_bfd_auth_section_auth_type(lr_bfd_auth_section_t s);
uint8_t lr_bfd_auth_section_key_id(lr_bfd_auth_section_t s);
int32_t lr_bfd_auth_section_sequence(lr_bfd_auth_section_t s, uint32_t *out_sequence);
uintptr_t lr_bfd_auth_section_data_len(lr_bfd_auth_section_t s);
int32_t lr_bfd_auth_section_data(lr_bfd_auth_section_t s, uint8_t *out_data, uintptr_t cap, uintptr_t *out_len);
uintptr_t lr_bfd_auth_section_wire_len(lr_bfd_auth_section_t s);

/* BfdPacket auth integration (RFC 5880 §4.1 A bit). */
int32_t lr_bfd_packet_set_auth(lr_bfd_packet_t packet, lr_bfd_auth_section_t section);
uint8_t lr_bfd_packet_auth_present(lr_bfd_packet_t packet);
int32_t lr_bfd_packet_auth(lr_bfd_packet_t packet, lr_bfd_auth_section_t *out);

/* BfdKeyedAuth (RFC 5880 §6.7 / §6.8.5). */
typedef struct OpaqueBfdKeyedAuth OpaqueBfdKeyedAuth;
typedef struct OpaqueBfdKeyedAuth *lr_bfd_keyed_auth_t;
lr_bfd_keyed_auth_t lr_bfd_keyed_auth_new(int32_t algorithm, uint8_t key_id, const uint8_t *secret, uintptr_t secret_len);
void lr_bfd_keyed_auth_free(lr_bfd_keyed_auth_t a);
uint8_t lr_bfd_keyed_auth_key_id(lr_bfd_keyed_auth_t a);
int32_t lr_bfd_keyed_auth_algorithm(lr_bfd_keyed_auth_t a);
uint8_t lr_bfd_keyed_auth_auth_type_value(lr_bfd_keyed_auth_t a);
uintptr_t lr_bfd_keyed_auth_digest_len(lr_bfd_keyed_auth_t a);
uint8_t lr_bfd_keyed_auth_is_meticulous(lr_bfd_keyed_auth_t a);
uint32_t lr_bfd_keyed_auth_xmit_seq(lr_bfd_keyed_auth_t a);
uint8_t lr_bfd_keyed_auth_rcv_auth_seq_known(lr_bfd_keyed_auth_t a);
uint32_t lr_bfd_keyed_auth_rcv_auth_seq(lr_bfd_keyed_auth_t a);
int32_t lr_bfd_keyed_auth_advance_xmit_seq(lr_bfd_keyed_auth_t a);
lr_bfd_auth_section_t lr_bfd_keyed_auth_auth_section_for_tx(lr_bfd_keyed_auth_t a);
int32_t lr_bfd_keyed_auth_sign_packet(lr_bfd_keyed_auth_t a, uint8_t *packet, uintptr_t packet_len);
int32_t lr_bfd_keyed_auth_verify_inbound(lr_bfd_keyed_auth_t a, const uint8_t *packet, uintptr_t packet_len, lr_bfd_auth_section_t section, uint8_t detect_mult);

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

/* RTR client (RFC 8210 §6-§8) — transport-agnostic state machine.
 * Mirrors `lr_bgp::rtr::client::{RtrClient, ClientStep, RoaDelta}`. */
typedef struct OpaqueRtrClient OpaqueRtrClient;
typedef struct OpaqueRtrClient *lr_rtr_client_t;

typedef struct lr_rtr_client_step_t {
    lr_bytes_t send_bytes;
    uint8_t synced;
    uint8_t drop;
    uint8_t expired;
    uintptr_t roa_delta_count;
    uintptr_t log_count;
    lr_roa_delta_t *roa_deltas;
    char **logs;
} lr_rtr_client_step_t;

lr_rtr_client_t lr_rtr_client_new(void);
void lr_rtr_client_free(lr_rtr_client_t c);
uint8_t lr_rtr_client_version(lr_rtr_client_t c);
uint8_t lr_rtr_client_session_id(lr_rtr_client_t c, uint16_t *out_session);
uint8_t lr_rtr_client_serial(lr_rtr_client_t c, uint32_t *out_serial);
uintptr_t lr_rtr_client_phase_name(lr_rtr_client_t c,
                                    uint8_t *out_buf,
                                    uintptr_t cap);
int32_t lr_rtr_client_intervals(lr_rtr_client_t c,
                                 uint32_t *out_refresh,
                                 uint32_t *out_retry,
                                 uint32_t *out_expire);
int32_t lr_rtr_client_set_intervals(lr_rtr_client_t c,
                                     uint32_t refresh,
                                     uint32_t retry,
                                     uint32_t expire);
int32_t lr_rtr_client_on_connect(lr_rtr_client_t c, lr_bytes_t *out);
int32_t lr_rtr_client_poll(lr_rtr_client_t c,
                            uint64_t now_ms,
                            lr_rtr_client_step_t *out_step);
int32_t lr_rtr_client_on_pdu_raw(lr_rtr_client_t c,
                                 const uint8_t *data,
                                 uintptr_t len,
                                 uint64_t now_ms,
                                 lr_rtr_client_step_t *out_step);
uintptr_t lr_rtr_client_snapshot(lr_rtr_client_t c,
                                 lr_roa_entry_t *out_entries,
                                 uintptr_t cap);
int32_t lr_rtr_client_step_roa_delta_at(const lr_rtr_client_step_t *step,
                                        uintptr_t index,
                                        lr_roa_delta_t *out);
uintptr_t lr_rtr_client_step_log_at(const lr_rtr_client_step_t *step,
                                    uintptr_t index,
                                    uint8_t *out_buf,
                                    uintptr_t cap);
void lr_rtr_client_step_free(lr_rtr_client_step_t *step);

/* ---- Foundational types (lr-core mirror) ---- */

typedef struct lr_ip_addr_t {
  uint8_t is_ipv6;
  uint8_t octets[16];
} lr_ip_addr_t;

typedef struct lr_core_prefix_t {
  struct lr_ip_addr_t addr;
  uint8_t prefix_len;
} lr_core_prefix_t;

typedef struct lr_route_key_t {
  struct lr_core_prefix_t prefix;
  uint16_t afi_safi;
  uint8_t has_source;
  struct lr_core_prefix_t source_prefix;
} lr_route_key_t;

typedef struct lr_asn_t {
  uint32_t value;
} lr_asn_t;

typedef struct lr_router_id_t {
  uint32_t value;
} lr_router_id_t;

typedef struct lr_preference_t {
  uint32_t admin_distance;
  uint32_t metric;
} lr_preference_t;

typedef struct lr_afi_safi_t {
  uint16_t afi;
  uint8_t safi;
} lr_afi_safi_t;

typedef struct lr_afi_safi_t lr_nlri_family_t;

typedef struct lr_route_origin_t {
  uint8_t protocol;
  uint64_t peer;
} lr_route_origin_t;

typedef struct OpaqueIpAddr IpAddr;
typedef struct OpaqueReadBuf *lr_read_buf_t;
typedef struct OpaqueWriteBuf *lr_write_buf_t;
typedef struct OpaqueTimerQueue *lr_timer_queue_t;
typedef uint32_t lr_timer_id_t;
typedef struct lr_timer_spec_t {
  uint64_t after_ms;
  uint64_t periodic_ms;
} lr_timer_spec_t;
typedef struct OpaqueMemoryConn *lr_memory_conn_t;

struct lr_ip_addr_t lr_ip_addr_v4(const uint8_t *octets);
struct lr_ip_addr_t lr_ip_addr_v6(const uint8_t *octets);
uint8_t lr_ip_addr_is_ipv4(struct lr_ip_addr_t addr);
uint8_t lr_ip_addr_is_ipv6(struct lr_ip_addr_t addr);
uint8_t lr_ip_addr_is_unspecified(struct lr_ip_addr_t addr);
uint8_t lr_ip_addr_is_multicast(struct lr_ip_addr_t addr);
uintptr_t lr_ip_addr_octets(struct lr_ip_addr_t addr, uint8_t *out, uintptr_t cap);

struct lr_core_prefix_t lr_core_prefix_v4(const uint8_t *octets, uint8_t prefix_len);
struct lr_core_prefix_t lr_core_prefix_v6(const uint8_t *octets, uint8_t prefix_len);
uint8_t lr_core_prefix_is_ipv4(struct lr_core_prefix_t prefix);
uint8_t lr_core_prefix_is_ipv6(struct lr_core_prefix_t prefix);
uint8_t lr_core_prefix_contains(struct lr_core_prefix_t prefix, struct lr_ip_addr_t addr);
uint8_t lr_core_prefix_contains_prefix(struct lr_core_prefix_t outer,
                                        struct lr_core_prefix_t inner);
int32_t lr_core_prefix_network(struct lr_core_prefix_t prefix, struct lr_ip_addr_t *out);

struct lr_asn_t lr_asn_new(uint32_t value);
uint8_t lr_asn_is_private(struct lr_asn_t asn);
uint8_t lr_asn_is_as_trans(struct lr_asn_t asn);
uint8_t lr_asn_is_as23456(struct lr_asn_t asn);

struct lr_router_id_t lr_router_id_from_u32(uint32_t value);
struct lr_router_id_t lr_router_id_from_v4(const uint8_t *octets);
int32_t lr_router_id_to_v4_bytes(struct lr_router_id_t rid, uint8_t *out_octets);

uintptr_t lr_protocol_bird_name(uint8_t proto, char *out_name, uintptr_t name_cap);
uint32_t lr_protocol_default_admin_distance(uint8_t proto);

uint64_t lr_instant_from_millis(uint64_t millis);
uint64_t lr_instant_from_secs(uint64_t secs);
uint64_t lr_instant_as_millis(uint64_t instant);
uint64_t lr_instant_as_secs(uint64_t instant);
uint64_t lr_instant_saturating_sub(uint64_t earlier, uint64_t later);
uint64_t lr_instant_checked_add(uint64_t instant, uint64_t duration_ms);
int32_t lr_instant_checked_sub(uint64_t instant, uint64_t other, uint64_t *out);

uint64_t lr_duration_from_millis(uint64_t millis);
uint64_t lr_duration_from_secs(uint64_t secs);
uint64_t lr_duration_as_millis(uint64_t duration_ms);
uint64_t lr_duration_as_secs(uint64_t duration_ms);
uint64_t lr_duration_checked_add(uint64_t a, uint64_t b);

int32_t lr_route_key_new(struct lr_core_prefix_t prefix,
                         uint16_t afi_safi,
                         struct lr_route_key_t *out);
int32_t lr_route_key_with_source(struct lr_core_prefix_t prefix,
                                 uint16_t afi_safi,
                                 struct lr_core_prefix_t source,
                                 struct lr_route_key_t *out);
struct lr_preference_t lr_preference_new(uint32_t admin_distance, uint32_t metric);

lr_nlri_family_t lr_nlri_family_ipv4_unicast(void);
lr_nlri_family_t lr_nlri_family_ipv6_unicast(void);
lr_nlri_family_t lr_nlri_family_ipv4_multicast(void);
lr_nlri_family_t lr_nlri_family_ipv4_mpls_vpn(void);
lr_nlri_family_t lr_nlri_family_ipv6_mpls_vpn(void);
lr_nlri_family_t lr_nlri_family_ipv4_labeled_unicast(void);
lr_nlri_family_t lr_nlri_family_ipv6_labeled_unicast(void);
lr_nlri_family_t lr_nlri_family_bgp_ls(void);
lr_nlri_family_t lr_nlri_family_bgp_ls_vpn(void);
uint8_t lr_nlri_family_is_ipv4(lr_nlri_family_t f);
uint8_t lr_nlri_family_is_ipv6(lr_nlri_family_t f);
uint8_t lr_nlri_family_is_labeled_unicast(lr_nlri_family_t f);
uint8_t lr_nlri_family_is_bgp_ls(lr_nlri_family_t f);
uint8_t lr_nlri_family_is_bgp_ls_vpn(lr_nlri_family_t f);
int32_t lr_nlri_family_from_addr(const IpAddr *addr, lr_nlri_family_t *out);

IpAddr *lr_ip_addr_from_v4_bytes(const uint8_t *bytes);
IpAddr *lr_ip_addr_from_v6_bytes(const uint8_t *bytes);
IpAddr *lr_ip_addr_from_bytes(const uint8_t *bytes, uintptr_t len);
void lr_ip_addr_free(IpAddr *a);
uint8_t lr_ip_addr_is_ipv4_mapped_ipv6(const IpAddr *a);
IpAddr *lr_ip_addr_to_ipv4_mapped(const IpAddr *a);
uint32_t lr_asn_as_u32(uint32_t asn);
uint16_t lr_asn_as_u16(uint32_t asn);

uint16_t lr_crc16_arc(const uint8_t *bytes, uintptr_t len);
uint32_t lr_crc32c(const uint8_t *bytes, uintptr_t len);
uint16_t lr_ospf_lsa_checksum(const uint8_t *lsa, uintptr_t len);
uint8_t lr_ospf_lsa_checksum_ok(const uint8_t *lsa, uintptr_t len);
uint32_t lr_fletcher32(const uint8_t *bytes, uintptr_t len);

/* ReadBuf / WriteBuf */
lr_read_buf_t lr_read_buf_new(const uint8_t *data, uintptr_t len);
void lr_read_buf_free(lr_read_buf_t r);
uintptr_t lr_read_buf_remaining(lr_read_buf_t r);
uintptr_t lr_read_buf_position(lr_read_buf_t r);
int32_t lr_read_buf_advance(lr_read_buf_t r, uintptr_t n);
int32_t lr_read_buf_peek_u8(lr_read_buf_t r, uint8_t *out);
int32_t lr_read_buf_get_u8(lr_read_buf_t r, uint8_t *out);
int32_t lr_read_buf_get_u16_be(lr_read_buf_t r, uint16_t *out);
int32_t lr_read_buf_get_u32_be(lr_read_buf_t r, uint32_t *out);
int32_t lr_read_buf_get_u64_be(lr_read_buf_t r, uint64_t *out);
int32_t lr_read_buf_get_bytes(lr_read_buf_t r, uintptr_t n, lr_bytes_t *out);
int32_t lr_read_buf_chunk(lr_read_buf_t r, lr_bytes_t *out);

lr_write_buf_t lr_write_buf_new(uintptr_t cap);
void lr_write_buf_free(lr_write_buf_t w);
uintptr_t lr_write_buf_position(lr_write_buf_t w);
uintptr_t lr_write_buf_remaining_mut(lr_write_buf_t w);
int32_t lr_write_buf_put_u8(lr_write_buf_t w, uint8_t v);
int32_t lr_write_buf_put_bytes(lr_write_buf_t w, const uint8_t *b, uintptr_t len);
int32_t lr_write_buf_put_u16_be(lr_write_buf_t w, uint16_t v);
int32_t lr_write_buf_put_u32_be(lr_write_buf_t w, uint32_t v);
int32_t lr_write_buf_put_u64_be(lr_write_buf_t w, uint64_t v);
int32_t lr_write_buf_take_bytes(lr_write_buf_t w, lr_bytes_t *out);
int32_t lr_write_buf_patch(lr_write_buf_t w, uintptr_t at, const uint8_t *data, uintptr_t len);
int32_t lr_write_buf_reserve(lr_write_buf_t w, uintptr_t additional);
uintptr_t lr_write_buf_capacity(lr_write_buf_t w);
int32_t lr_write_buf_written(lr_write_buf_t w, lr_bytes_t *out);

/* TimerQueue */
lr_timer_queue_t lr_timer_queue_new(void);
void lr_timer_queue_free(lr_timer_queue_t q);
int32_t lr_timer_queue_arm(lr_timer_queue_t q,
                           uint64_t now_ms,
                           lr_timer_id_t id,
                           struct lr_timer_spec_t spec);
int32_t lr_timer_queue_cancel(lr_timer_queue_t q, lr_timer_id_t id);
int32_t lr_timer_queue_cancel_all(lr_timer_queue_t q);
int32_t lr_timer_queue_tick(lr_timer_queue_t q,
                            uint64_t now_ms,
                            lr_timer_id_t **out_array,
                            uintptr_t *out_count);
uint8_t lr_timer_queue_is_empty(lr_timer_queue_t q);
uintptr_t lr_timer_queue_len(lr_timer_queue_t q);
uint64_t lr_timer_queue_next_fire_ms(lr_timer_queue_t q);
void lr_timer_queue_drain_free(lr_timer_id_t *array, uintptr_t count);
struct lr_timer_spec_t lr_timer_spec_once(uint64_t after_ms);
struct lr_timer_spec_t lr_timer_spec_periodic(uint64_t after_ms, uint64_t periodic_ms);

/* MemoryConn */
lr_memory_conn_t lr_memory_conn_new(void);
int32_t lr_memory_conn_pair(lr_memory_conn_t *out_a, lr_memory_conn_t *out_b);
int32_t lr_memory_conn_push_input(lr_memory_conn_t c, const uint8_t *bytes, uintptr_t len);
int32_t lr_memory_conn_take_input(lr_memory_conn_t c, lr_bytes_t *out);
int32_t lr_memory_conn_put_output(lr_memory_conn_t c, const uint8_t *bytes, uintptr_t len);
int32_t lr_memory_conn_drain_output(lr_memory_conn_t c, lr_bytes_t *out);
void lr_memory_conn_free(lr_memory_conn_t c);

typedef struct OpaqueLocRib *lr_loc_rib_t;
typedef struct OpaqueAdjRibIn *lr_adj_rib_in_t;
typedef struct OpaqueAdjRibOut *lr_adj_rib_out_t;
typedef struct OpaqueRibMux *lr_rib_mux_t;

lr_loc_rib_t lr_loc_rib_new(void);
void lr_loc_rib_free(lr_loc_rib_t r);
int32_t lr_loc_rib_install(lr_loc_rib_t r, lr_route_t route);
int32_t lr_loc_rib_uninstall(lr_loc_rib_t r,
                             const struct lr_prefix_t *prefix,
                             uint16_t afi,
                             uint8_t safi,
                             const struct lr_prefix_t *source);
uintptr_t lr_loc_rib_len(lr_loc_rib_t r);
uint8_t lr_loc_rib_is_empty(lr_loc_rib_t r);
uintptr_t lr_loc_rib_paths_len(lr_loc_rib_t r);
uint64_t lr_loc_rib_generation(lr_loc_rib_t r);
uint8_t lr_loc_rib_best_present(lr_loc_rib_t r,
                                const struct lr_prefix_t *prefix,
                                uint16_t afi,
                                uint8_t safi,
                                const struct lr_prefix_t *source);
int32_t lr_loc_rib_best(lr_loc_rib_t r,
                        const struct lr_prefix_t *prefix,
                        uint16_t afi,
                        uint8_t safi,
                        const struct lr_prefix_t *source,
                        lr_route_t *out);
int32_t lr_loc_rib_install_set(lr_loc_rib_t r,
                               const struct lr_route_key_t *key,
                               const lr_route_t *routes,
                               uintptr_t count);
uintptr_t lr_loc_rib_paths(lr_loc_rib_t r, const struct lr_route_key_t *key);
int64_t lr_loc_rib_iter_best(lr_loc_rib_t r,
                              void (*cb)(lr_route_t route, void *user),
                              void *user);
int64_t lr_loc_rib_iter_paths(lr_loc_rib_t r,
                               void (*cb)(lr_route_t route, void *user),
                               void *user);
int64_t lr_loc_rib_iter_sets(lr_loc_rib_t r,
                              void (*cb)(uint8_t *prefix_out,
                                         uint8_t prefix_len,
                                         uint8_t is_ipv6,
                                         uintptr_t path_count,
                                         void *user),
                              void *user);
int32_t lr_loc_rib_diff_since(lr_loc_rib_t r,
                              uint64_t since_gen,
                              uintptr_t *out_added,
                              uintptr_t *out_modified,
                              uintptr_t *out_removed);

lr_adj_rib_in_t lr_adj_rib_in_new(void);
void lr_adj_rib_in_free(lr_adj_rib_in_t r);
int32_t lr_adj_rib_in_feed(lr_adj_rib_in_t r,
                            uint64_t origin_peer,
                            int32_t origin_proto,
                            lr_route_t route);
int32_t lr_adj_rib_in_withdraw(lr_adj_rib_in_t r,
                                uint64_t origin_peer,
                                int32_t origin_proto,
                                const struct lr_prefix_t *prefix,
                                uint16_t afi,
                                uint8_t safi,
                                const struct lr_prefix_t *source,
                                uint32_t path_id);
uintptr_t lr_adj_rib_in_len(lr_adj_rib_in_t r);
uint8_t lr_adj_rib_in_is_empty(lr_adj_rib_in_t r);
int32_t lr_adj_rib_in_get(lr_adj_rib_in_t r,
                          struct lr_route_origin_t origin,
                          const struct lr_route_key_t *key,
                          uint32_t path_id,
                          lr_route_t *out_route);
int32_t lr_adj_rib_in_origins_for(lr_adj_rib_in_t r,
                                   const struct lr_route_key_t *key,
                                   struct lr_route_origin_t *out_origins,
                                   uintptr_t cap,
                                   uintptr_t *out_count);
int32_t lr_adj_rib_in_clear(lr_adj_rib_in_t r);
int32_t lr_adj_rib_in_clear_for(lr_adj_rib_in_t r,
                                  struct lr_route_origin_t origin);
int64_t lr_adj_rib_in_iter_all(lr_adj_rib_in_t r,
                                void (*cb)(lr_route_t route, void *user),
                                void *user);
int64_t lr_adj_rib_in_iter_origin(lr_adj_rib_in_t r,
                                    uint64_t origin_peer,
                                    int32_t origin_proto,
                                    void (*cb)(lr_route_t route, void *user),
                                    void *user);

lr_adj_rib_out_t lr_adj_rib_out_new(void);
void lr_adj_rib_out_free(lr_adj_rib_out_t r);
int32_t lr_adj_rib_out_advertise(lr_adj_rib_out_t r,
                                  uint64_t dest_peer,
                                  int32_t dest_proto,
                                  lr_route_t route,
                                  uint32_t tx_path_id);
int32_t lr_adj_rib_out_suppress(lr_adj_rib_out_t r,
                                  uint64_t dest_peer,
                                  int32_t dest_proto,
                                  const struct lr_prefix_t *prefix,
                                  uint16_t afi,
                                  uint8_t safi,
                                  const struct lr_prefix_t *source,
                                  uint32_t tx_path_id);
uintptr_t lr_adj_rib_out_len(lr_adj_rib_out_t r);
uint8_t lr_adj_rib_out_is_empty(lr_adj_rib_out_t r);
int32_t lr_adj_rib_out_tx_path_ids(lr_adj_rib_out_t r,
                                     struct lr_route_origin_t dest,
                                     const struct lr_route_key_t *key,
                                     uint32_t *out_path_ids,
                                     uintptr_t cap,
                                     uintptr_t *out_count);
int64_t lr_adj_rib_out_paths_for(lr_adj_rib_out_t r,
                                   struct lr_route_origin_t dest,
                                   const struct lr_route_key_t *key,
                                   void (*cb)(uint32_t path_id,
                                              lr_route_t route,
                                              void *user),
                                   void *user);
int64_t lr_adj_rib_out_advertised_keys(lr_adj_rib_out_t r,
                                          struct lr_route_origin_t dest,
                                          uint16_t afi,
                                          uint8_t safi,
                                          void (*cb)(const struct lr_route_key_t *key,
                                                     const uint32_t *path_ids,
                                                     uintptr_t path_id_count,
                                                     void *user),
                                          void *user);
int32_t lr_adj_rib_out_clear(lr_adj_rib_out_t r);
int32_t lr_adj_rib_out_clear_for(lr_adj_rib_out_t r,
                                   struct lr_route_origin_t dest);
int64_t lr_adj_rib_out_iter_for(lr_adj_rib_out_t r,
                                  uint64_t origin_peer,
                                  int32_t origin_proto,
                                  void (*cb)(lr_route_t route, void *user),
                                  void *user);

lr_rib_mux_t lr_rib_mux_new(void);
void lr_rib_mux_free(lr_rib_mux_t r);
int32_t lr_rib_mux_install(lr_rib_mux_t r, lr_route_t route);
int32_t lr_rib_mux_uninstall(lr_rib_mux_t r,
                              const struct lr_prefix_t *prefix,
                              uint16_t afi,
                              uint8_t safi,
                              const struct lr_prefix_t *source);
int32_t lr_rib_mux_get(lr_rib_mux_t r,
                        const struct lr_prefix_t *prefix,
                        uint16_t afi,
                        uint8_t safi,
                        const struct lr_prefix_t *source,
                        lr_route_t *out);
uintptr_t lr_rib_mux_len(lr_rib_mux_t r);
uint8_t lr_rib_mux_is_empty(lr_rib_mux_t r);
int64_t lr_rib_mux_iter(lr_rib_mux_t r,
                          void (*cb)(lr_route_t route, void *user),
                          void *user);

int64_t lr_route_selector_select(const lr_route_t *routes, uintptr_t count);
int64_t lr_route_selector_select_bgp(const lr_route_t *routes, uintptr_t count);
int32_t lr_route_selector_compare(lr_route_t a, lr_route_t b);

/* Babel protocol surface — mirrors lr_babel::{BabelFrame, BabelNeighbor,
 * BabelRouteTable, BabelRoute, RouteKey, BabelCodec, tlv::Tlv} and the
 * auth::* helpers. Mirrors the C ABI in crates/lr-ffi/src/babel*.rs.
 * RFC 8966 §3 (Babel routing protocol) + RFC 8967 (authentication).
 */

/* Opaque handle types (one per Rust struct). */
typedef struct OpaqueBabelFrame OpaqueBabelFrame;
typedef struct OpaqueBabelFrame *lr_babel_frame_t;
typedef struct OpaqueBabelCodec OpaqueBabelCodec;
typedef struct OpaqueBabelCodec *lr_babel_codec_t;
typedef struct OpaqueBabelTlv OpaqueBabelTlv;
typedef struct OpaqueBabelTlv *lr_babel_tlv_t;
typedef struct OpaqueBabelRoute OpaqueBabelRoute;
typedef struct OpaqueBabelRoute *lr_babel_route_t;
typedef struct OpaqueBabelRouteKey OpaqueBabelRouteKey;
typedef struct OpaqueBabelRouteKey *lr_babel_route_key_t;
typedef struct OpaqueBabelRouteTable OpaqueBabelRouteTable;
typedef struct OpaqueBabelRouteTable *lr_babel_route_table_t;
typedef struct OpaqueBabelNeighbor OpaqueBabelNeighbor;
typedef struct OpaqueBabelNeighbor *lr_babel_neighbor_t;
typedef struct OpaqueBabelMacKey OpaqueBabelMacKey;
typedef struct OpaqueBabelMacKey *lr_babel_mac_key_t;
typedef struct OpaqueBabelPseudoHeader OpaqueBabelPseudoHeader;
typedef struct OpaqueBabelPseudoHeader *lr_babel_pseudo_header_t;
typedef struct OpaqueBabelPacketCounter OpaqueBabelPacketCounter;
typedef struct OpaqueBabelPacketCounter *lr_babel_packet_counter_t;
typedef struct OpaqueBabelReplayProtection OpaqueBabelReplayProtection;
typedef struct OpaqueBabelReplayProtection *lr_babel_replay_protection_t;
typedef struct OpaqueBabelHello OpaqueBabelHello;
typedef struct OpaqueBabelHello *lr_babel_hello_t;
typedef struct OpaqueBabelIhu OpaqueBabelIhu;
typedef struct OpaqueBabelIhu *lr_babel_ihu_t;
typedef struct OpaqueBabelAckReq OpaqueBabelAckReq;
typedef struct OpaqueBabelAckReq *lr_babel_ack_req_t;
typedef struct OpaqueBabelAck OpaqueBabelAck;
typedef struct OpaqueBabelAck *lr_babel_ack_t;
typedef struct OpaqueBabelNextHop OpaqueBabelNextHop;
typedef struct OpaqueBabelNextHop *lr_babel_next_hop_t;
typedef struct OpaqueBabelRouterId OpaqueBabelRouterId;
typedef struct OpaqueBabelRouterId *lr_babel_router_id_t;
typedef struct OpaqueBabelRouteRequest OpaqueBabelRouteRequest;
typedef struct OpaqueBabelRouteRequest *lr_babel_route_request_t;
typedef struct OpaqueBabelSeqnoRequest OpaqueBabelSeqnoRequest;
typedef struct OpaqueBabelSeqnoRequest *lr_babel_seqno_request_t;

/* Callback shape for lr_babel_route_table_iter / _best_routes_iter.
 * Returns 0 to continue iteration, non-zero to stop early. */
typedef int32_t (*lr_babel_route_iter_cb)(lr_babel_route_t route, void *user);

/* Babel codec + frame surface (RFC 8966 §4). */
lr_babel_codec_t lr_babel_codec_new(void);
void lr_babel_codec_free(lr_babel_codec_t c);
int32_t lr_babel_codec_decode_slice(lr_babel_codec_t c,
                                    const uint8_t *data,
                                    uintptr_t len,
                                    lr_babel_frame_t *out);
int32_t lr_babel_codec_encode_vec(lr_babel_codec_t c,
                                  lr_babel_frame_t frame,
                                  lr_bytes_t *out);
int32_t lr_babel_codec_decode_authenticated_slice(lr_babel_codec_t c,
                                                   const uint8_t *data,
                                                   uintptr_t len,
                                                   lr_babel_pseudo_header_t ph,
                                                   lr_bytes_t *out);
int32_t lr_babel_codec_encode_authenticated(lr_babel_codec_t c,
                                            lr_babel_frame_t frame,
                                            lr_babel_pseudo_header_t ph,
                                            const lr_babel_mac_key_t *keys,
                                            uintptr_t keys_len,
                                            lr_bytes_t *out);

int32_t lr_babel_decode_frame(const uint8_t *data, uintptr_t len, lr_babel_frame_t *out);
int32_t lr_babel_encode_frame(lr_babel_frame_t frame, lr_bytes_t *out);
lr_babel_frame_t lr_babel_frame_new_empty(void);
lr_babel_frame_t lr_babel_frame_new_from_tlvs(const lr_babel_tlv_t *tlvs, uintptr_t count);
int32_t lr_babel_frame_push_tlv(lr_babel_frame_t frame, lr_babel_tlv_t tlv);
uintptr_t lr_babel_frame_tlv_count(lr_babel_frame_t frame);
uint8_t lr_babel_frame_tlv_type_at(lr_babel_frame_t frame, uintptr_t index);
uintptr_t lr_babel_frame_tlv_value_len_at(lr_babel_frame_t frame, uintptr_t index);
uintptr_t lr_babel_frame_tlv_value_at(lr_babel_frame_t frame,
                                      uintptr_t index,
                                      uint8_t *out,
                                      uintptr_t cap);
void lr_babel_frame_free(lr_babel_frame_t frame);

/* TLV constructors (RFC 8966 §4.4). */
lr_babel_tlv_t lr_babel_tlv_new(uint8_t kind,
                                const uint8_t *value,
                                uintptr_t value_len);
lr_babel_tlv_t lr_babel_tlv_pad1(void);
lr_babel_tlv_t lr_babel_tlv_pad_n(uintptr_t n);
uint8_t lr_babel_tlv_kind(lr_babel_tlv_t t);
int32_t lr_babel_tlv_value(lr_babel_tlv_t t, lr_bytes_t *out);
void lr_babel_tlv_free(lr_babel_tlv_t t);
uint8_t lr_babel_tlv_type_to_u8(uint8_t value);
uint8_t lr_babel_tlv_type_from_u8(uint8_t wire);
const char *lr_babel_tlv_type_name(uint8_t value);

/* RouteKey + BabelRoute + BabelRouteTable (RFC 8966 §3.2 / §3.5). */
lr_babel_route_key_t lr_babel_route_key_new(uint8_t dest_is_ipv6,
                                            const uint8_t *dest_addr,
                                            uint8_t dest_prefix_len,
                                            uint8_t source_present,
                                            uint8_t source_is_ipv6,
                                            const uint8_t *source_addr,
                                            uint8_t source_prefix_len,
                                            const uint8_t *router_id);
void lr_babel_route_key_free(lr_babel_route_key_t k);
uint8_t lr_babel_route_key_destination_is_ipv6(lr_babel_route_key_t k);
int32_t lr_babel_route_key_destination_addr(lr_babel_route_key_t k, uint8_t *out);
uint8_t lr_babel_route_key_destination_prefix_len(lr_babel_route_key_t k);
uint8_t lr_babel_route_key_source_present(lr_babel_route_key_t k);
uint8_t lr_babel_route_key_source_is_ipv6(lr_babel_route_key_t k);
int32_t lr_babel_route_key_source_addr(lr_babel_route_key_t k, uint8_t *out);
uint8_t lr_babel_route_key_source_prefix_len(lr_babel_route_key_t k);
int32_t lr_babel_route_key_router_id(lr_babel_route_key_t k, uint8_t *out);

lr_babel_route_t lr_babel_route_new(lr_babel_route_key_t key,
                                    uint16_t seqno,
                                    uint32_t metric,
                                    uint8_t next_hop_is_ipv6,
                                    const uint8_t *next_hop,
                                    uint8_t feasible,
                                    uint8_t installed);
void lr_babel_route_free(lr_babel_route_t r);
uint16_t lr_babel_route_seqno(lr_babel_route_t r);
uint32_t lr_babel_route_metric(lr_babel_route_t r);
uint8_t lr_babel_route_next_hop_is_ipv6(lr_babel_route_t r);
int32_t lr_babel_route_next_hop(lr_babel_route_t r, uint8_t *out);
uint8_t lr_babel_route_feasible(lr_babel_route_t r);
uint8_t lr_babel_route_installed(lr_babel_route_t r);
lr_babel_route_key_t lr_babel_route_borrow_key(lr_babel_route_t r);

lr_babel_route_table_t lr_babel_route_table_new(void);
void lr_babel_route_table_free(lr_babel_route_table_t r);
uintptr_t lr_babel_route_table_len(lr_babel_route_table_t r);
uint8_t lr_babel_route_table_is_empty(lr_babel_route_table_t r);
int32_t lr_babel_route_table_insert(lr_babel_route_table_t table, lr_babel_route_t route);
int32_t lr_babel_route_table_insert_timed(lr_babel_route_table_t table,
                                          lr_babel_route_t route,
                                          uint16_t interval_cs,
                                          uint64_t now_ms);
int32_t lr_babel_route_table_withdraw(lr_babel_route_table_t table, lr_babel_route_key_t key);
uintptr_t lr_babel_route_table_expire(lr_babel_route_table_t table, uint64_t now_ms);
uint8_t lr_babel_route_table_contains(lr_babel_route_table_t table, lr_babel_route_key_t key);
uintptr_t lr_babel_route_table_best_routes_count(lr_babel_route_table_t table);
lr_babel_route_t lr_babel_route_table_get(lr_babel_route_table_t table, lr_babel_route_key_t key);
int32_t lr_babel_route_table_iter(lr_babel_route_table_t table,
                                  lr_babel_route_iter_cb cb,
                                  void *user);
int32_t lr_babel_route_table_best_routes_iter(lr_babel_route_table_t table,
                                              lr_babel_route_iter_cb cb,
                                              void *user);

/* BabelNeighbor (RFC 8966 §3.4) — Hello / IHU feeding, RTT tracking. */
lr_babel_neighbor_t lr_babel_neighbor_new(const uint8_t *addr_v4,
                                          const uint8_t *addr_v6,
                                          uint64_t now_ms);
void lr_babel_neighbor_free(lr_babel_neighbor_t r);
int32_t lr_babel_neighbor_hello(lr_babel_neighbor_t r,
                                uint16_t seqno,
                                uint16_t interval_cs,
                                uint64_t now_ms);
int32_t lr_babel_neighbor_ihu(lr_babel_neighbor_t r,
                              uint16_t rxcost,
                              uint16_t interval_cs,
                              uint64_t now_ms);
uint32_t lr_babel_neighbor_rtt_us(lr_babel_neighbor_t r, uint64_t now_ms);
uint8_t lr_babel_neighbor_rtt_valid(lr_babel_neighbor_t r, uint64_t now_ms);

/* Auth helpers (RFC 8967) — MAC key, pseudo-header, replay protection. */
lr_babel_mac_key_t lr_babel_mac_key_new(int32_t algorithm,
                                const uint8_t *secret,
                                uintptr_t secret_len);
lr_babel_mac_key_t lr_babel_mac_key_hmac_sha256(const uint8_t *secret, uintptr_t secret_len);
lr_babel_mac_key_t lr_babel_mac_key_blake2s128(const uint8_t *secret, uintptr_t secret_len);
int32_t lr_babel_mac_key_algorithm(lr_babel_mac_key_t k);
uintptr_t lr_babel_mac_key_digest_len(lr_babel_mac_key_t k);
uintptr_t lr_babel_mac_key_secret_len(lr_babel_mac_key_t k);
int32_t lr_babel_mac_key_secret_copy(lr_babel_mac_key_t k, uint8_t *out, uintptr_t cap);
void lr_babel_mac_key_free(lr_babel_mac_key_t k);

lr_babel_pseudo_header_t lr_babel_pseudo_header_new_v4(const uint8_t *src_v4,
                                                       uint16_t src_port,
                                                       const uint8_t *dst_v4,
                                                       uint16_t dst_port);
lr_babel_pseudo_header_t lr_babel_pseudo_header_new_v6(const uint8_t *src_v6,
                                                       uint16_t src_port,
                                                       const uint8_t *dst_v6,
                                                       uint16_t dst_port);
int32_t lr_babel_pseudo_header_encode(lr_babel_pseudo_header_t p, lr_bytes_t *out);
void lr_babel_pseudo_header_free(lr_babel_pseudo_header_t p);

lr_babel_packet_counter_t lr_babel_packet_counter_new(const uint8_t *index,
                                                      uintptr_t index_len,
                                                      uint32_t initial);
uint32_t lr_babel_packet_counter_peek_counter(lr_babel_packet_counter_t c);
uintptr_t lr_babel_packet_counter_peek_index_len(lr_babel_packet_counter_t c);
int32_t lr_babel_packet_counter_peek_index_copy(lr_babel_packet_counter_t c,
                                                uint8_t *out,
                                                uintptr_t cap);
void lr_babel_packet_counter_free(lr_babel_packet_counter_t c);

lr_babel_replay_protection_t lr_babel_replay_protection_new(void);
int32_t lr_babel_replay_protection_accept(lr_babel_replay_protection_t r,
                                          const uint8_t *index,
                                          uintptr_t index_len,
                                          uint32_t counter);
void lr_babel_replay_protection_free(lr_babel_replay_protection_t r);

/* Babel message constructors (RFC 8966 §4.4) — Hello / IHU / AckReq /
 * Ack / NextHop / RouterId / RouteRequest / SeqnoRequest. */
lr_babel_hello_t lr_babel_hello_new(uint16_t seqno, uint16_t interval_cs);
int32_t lr_babel_hello_set_unicast(lr_babel_hello_t h, uint8_t on);
uint16_t lr_babel_hello_seqno(lr_babel_hello_t h);
uint16_t lr_babel_hello_interval_cs(lr_babel_hello_t h);
uint16_t lr_babel_hello_flags(lr_babel_hello_t h);
int32_t lr_babel_hello_timestamp(lr_babel_hello_t h, uint32_t *out);
int32_t lr_babel_hello_encode(lr_babel_hello_t h, lr_bytes_t *out);
void lr_babel_hello_free(lr_babel_hello_t h);

lr_babel_ihu_t lr_babel_ihu_new(uint16_t rxcost, uint16_t interval_cs);
uint8_t lr_babel_ihu_ae(lr_babel_ihu_t h);
uint16_t lr_babel_ihu_rxcost(lr_babel_ihu_t h);
uint16_t lr_babel_ihu_interval_cs(lr_babel_ihu_t h);
int32_t lr_babel_ihu_address(lr_babel_ihu_t h, uint8_t *octets_out, uint8_t *present_out);
int32_t lr_babel_ihu_encode(lr_babel_ihu_t h, lr_bytes_t *out);
void lr_babel_ihu_free(lr_babel_ihu_t h);

lr_babel_ack_req_t lr_babel_ack_req_new(uint16_t nonce, uint16_t interval_cs);
uint16_t lr_babel_ack_req_nonce(lr_babel_ack_req_t a);
uint16_t lr_babel_ack_req_interval_cs(lr_babel_ack_req_t a);
void lr_babel_ack_req_free(lr_babel_ack_req_t a);

lr_babel_ack_t lr_babel_ack_new(uint16_t opaque);
uint16_t lr_babel_ack_opaque(lr_babel_ack_t a);
int32_t lr_babel_ack_encode(lr_babel_ack_t a, lr_bytes_t *out);
void lr_babel_ack_free(lr_babel_ack_t a);

lr_babel_next_hop_t lr_babel_next_hop_new_v4(const uint8_t *addr);
lr_babel_next_hop_t lr_babel_next_hop_new_v6(const uint8_t *addr);
uint8_t lr_babel_next_hop_ae(lr_babel_next_hop_t n);
uintptr_t lr_babel_next_hop_address(lr_babel_next_hop_t n, uint8_t *out, uintptr_t out_len);
int32_t lr_babel_next_hop_encode(lr_babel_next_hop_t n, lr_bytes_t *out);
void lr_babel_next_hop_free(lr_babel_next_hop_t n);

lr_babel_router_id_t lr_babel_router_id_new(const uint8_t *router_id);
int32_t lr_babel_router_id_bytes(lr_babel_router_id_t r, uint8_t *out);
void lr_babel_router_id_free(lr_babel_router_id_t r);

lr_babel_route_request_t lr_babel_route_request_new_wildcard(void);
void lr_babel_route_request_free(lr_babel_route_request_t r);

lr_babel_seqno_request_t lr_babel_seqno_request_new(const uint8_t *prefix_v4,
                                                   const uint8_t *prefix_v6,
                                                   uint8_t prefix_len,
                                                   uint16_t seqno,
                                                   const uint8_t *router_id,
                                                   uint8_t hop_count);
void lr_babel_seqno_request_free(lr_babel_seqno_request_t r);

/* Misc Babel helpers (RFC 8966 §A.2.4 / §3.1 / §3.2.2). */
uint16_t lr_babel_rtt_penalty(uint32_t rtt_us,
                              uint32_t rtt_min_us,
                              uint32_t rtt_max_us,
                              uint16_t max_penalty);
uint32_t lr_babel_route_metric_sum(const uint32_t *link_metrics, uintptr_t count);
uint8_t lr_babel_feasible(uint16_t route_seqno,
                         uint32_t route_metric,
                         uint16_t feasible_seqno,
                         uint32_t feasible_metric);

/* RouterInstance session-state + Babel runtime (issue #92, mirrors
 * crates/lr-ffi/src/router_runtime.rs). */
const char *lr_router_session_peer_state(lr_router_t r, uint64_t session);
int32_t lr_router_session_restart_cooldown_remaining(lr_router_t r,
                                                     uint64_t session,
                                                     uint64_t *out_ms);
int32_t lr_router_take_collision_lost(lr_router_t r, uint64_t session);
int32_t lr_router_session_was_established(lr_router_t r, uint64_t session);
int64_t lr_router_rib_paths_count(lr_router_t r);
int32_t lr_router_rib_path_at(lr_router_t r,
                              uintptr_t idx,
                              lr_route_t *out_route);
int32_t lr_router_flush_rib_for_shutdown(lr_router_t r);
int32_t lr_router_babel_flush_session(lr_router_t r, uint64_t session);
int32_t lr_router_babel_gc(lr_router_t r, uint64_t now_ms);
int32_t lr_router_set_babel_own_router_id(lr_router_t r,
                                         uint64_t session,
                                         const uint8_t *id);
int32_t lr_router_set_babel_link_cost_params(lr_router_t r,
                                            uint64_t session,
                                            uint32_t rtt_min_us,
                                            uint32_t rtt_max_us,
                                            uint16_t rtt_cost);
int32_t lr_router_babel_note_peer(lr_router_t r,
                                  uint64_t session,
                                  uint8_t is_v6,
                                  const uint8_t *addr);
int32_t lr_router_babel_rtt_us(lr_router_t r,
                               uint64_t session,
                               uint64_t now_ms,
                               uint32_t *out_us);
int32_t lr_router_babel_rtt_echo(lr_router_t r,
                                 uint64_t session,
                                 uint64_t now_ms,
                                 uint32_t *out_echo_ts,
                                 uint32_t *out_recv_us);
int32_t lr_router_babel_egress_nexthops(lr_router_t r,
                                        uint64_t session,
                                        uint8_t *out_v4_present,
                                        uint8_t *out_v4,
                                        uint8_t *out_v6_present,
                                        uint8_t *out_v6);
int32_t lr_router_babel_take_route_request(lr_router_t r, uint64_t session);
int32_t lr_router_babel_take_own_seqno_request(lr_router_t r,
                                               uint64_t session,
                                               uint16_t *out_seqno);

/* ===== BGP PathAttributes (RFC 4271 §5.1) ============================
 * Mirrors crates/lr-ffi/src/bgp_path.rs (lr_bgp_path_attrs_* C ABI)
 * plus the minimal lr_bgp_large_community / lr_bgp_as_path helpers
 * required to construct / free the handles the readers return. The
 * full lr_bgp_as_path_* (21 entry points) and lr_bgp_large_community
 * encode/decode set entry points are a separate follow-up commit;
 * here we expose only the surface an embedder needs to drive the
 * PathAttributes container from Python.
 */
typedef struct OpaqueBgpPathAttrs OpaqueBgpPathAttrs;
typedef struct OpaqueBgpPathAttrs *lr_bgp_path_attrs_t;
typedef struct OpaqueBgpAsPath OpaqueBgpAsPath;
typedef struct OpaqueBgpAsPath *lr_bgp_as_path_t;
typedef struct OpaqueBgpLargeCommunity OpaqueBgpLargeCommunity;
typedef struct OpaqueBgpLargeCommunity *lr_bgp_large_community_t;

typedef struct lr_bgp_next_hop_t {
    uint8_t addr[16];
    uint8_t kind;     /* 0=IPv4, 1=IPv6, 2=V4-over-V6 (RFC 5549) */
    uint8_t present;  /* 1 when attribute is present, 0 when absent */
} lr_bgp_next_hop_t;

lr_bgp_path_attrs_t lr_bgp_path_attrs_new(void);
void lr_bgp_path_attrs_free(lr_bgp_path_attrs_t a);
uintptr_t lr_bgp_path_attrs_len(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_is_empty(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_origin(lr_bgp_path_attrs_t a, uint8_t *out_origin);
uint8_t lr_bgp_path_attrs_med(lr_bgp_path_attrs_t a, uint32_t *out_med);
uint8_t lr_bgp_path_attrs_local_pref(lr_bgp_path_attrs_t a, uint32_t *out_lp);
int32_t lr_bgp_path_attrs_set_local_pref(lr_bgp_path_attrs_t a, uint32_t value);
uint8_t lr_bgp_path_attrs_atomic_aggregate(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_aggregator(lr_bgp_path_attrs_t a,
                                     uint32_t *out_asn,
                                     uint32_t *out_speaker);
uint8_t lr_bgp_path_attrs_originator_id(lr_bgp_path_attrs_t a, uint32_t *out_originator);
uint8_t lr_bgp_path_attrs_has_cluster_list(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_has_otc(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_otc(lr_bgp_path_attrs_t a, uint32_t *out_otc);
uint8_t lr_bgp_path_attrs_has_aigp(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_aigp(lr_bgp_path_attrs_t a, uint64_t *out_aigp);
uint8_t lr_bgp_path_attrs_has_pmsi_tunnel(lr_bgp_path_attrs_t a);
uintptr_t lr_bgp_path_attrs_communities(lr_bgp_path_attrs_t a, lr_bytes_t *out);
uintptr_t lr_bgp_path_attrs_ext_communities(lr_bgp_path_attrs_t a, lr_bytes_t *out);
uintptr_t lr_bgp_path_attrs_large_communities(lr_bgp_path_attrs_t a, lr_bytes_t *out);
int32_t lr_bgp_path_attrs_insert_community(lr_bgp_path_attrs_t a, uint32_t community);
uint8_t lr_bgp_path_attrs_next_hop(lr_bgp_path_attrs_t a, lr_bgp_next_hop_t *out);
lr_bgp_as_path_t lr_bgp_path_attrs_as_path(lr_bgp_path_attrs_t a);
lr_bgp_as_path_t lr_bgp_path_attrs_as_path_wire(lr_bgp_path_attrs_t a, uint8_t asn4);
lr_bgp_as_path_t lr_bgp_path_attrs_as4_path(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_cluster_list(lr_bgp_path_attrs_t a, lr_bytes_t *out);
lr_mpls_label_stack_t lr_bgp_path_attrs_label_stack(lr_bgp_path_attrs_t a);
int32_t lr_bgp_path_attrs_set_label_stack(lr_bgp_path_attrs_t a, lr_mpls_label_stack_t stack);
uint8_t lr_bgp_path_attrs_mp_reach(lr_bgp_path_attrs_t a,
                                   uint16_t *out_family_afi,
                                   uint8_t *out_family_safi,
                                   lr_bgp_next_hop_t *out_next_hop,
                                   lr_bytes_t *out_nlri_bytes);
uint8_t lr_bgp_path_attrs_mp_unreach(lr_bgp_path_attrs_t a,
                                     uint16_t *out_family_afi,
                                     uint8_t *out_family_safi,
                                     lr_bytes_t *out_nlri_bytes);
int32_t lr_bgp_path_attrs_set_ospf_metric2(lr_bgp_path_attrs_t a, uint32_t metric);
uint8_t lr_bgp_path_attrs_ospf_metric2(lr_bgp_path_attrs_t a, uint32_t *out_metric);
uint8_t lr_bgp_path_attrs_has_ospf_metric2(lr_bgp_path_attrs_t a);
int32_t lr_bgp_path_attrs_set_ospf_router_id(lr_bgp_path_attrs_t a, uint32_t router_id);
uint8_t lr_bgp_path_attrs_ospf_router_id(lr_bgp_path_attrs_t a, uint32_t *out_router_id);
uint8_t lr_bgp_path_attrs_has_ospf_router_id(lr_bgp_path_attrs_t a);
int32_t lr_bgp_path_attrs_set_babel_seqno(lr_bgp_path_attrs_t a, uint16_t seqno);
uint8_t lr_bgp_path_attrs_babel_seqno(lr_bgp_path_attrs_t a, uint16_t *out_seqno);
uint8_t lr_bgp_path_attrs_has_babel_seqno(lr_bgp_path_attrs_t a);
int32_t lr_bgp_path_attrs_set_babel_router_id(lr_bgp_path_attrs_t a, uint64_t router_id);
uint8_t lr_bgp_path_attrs_babel_router_id(lr_bgp_path_attrs_t a, uint64_t *out_router_id);
uint8_t lr_bgp_path_attrs_has_babel_router_id(lr_bgp_path_attrs_t a);
int32_t lr_bgp_path_attrs_set_igp_metric(lr_bgp_path_attrs_t a, uint32_t metric);
uint8_t lr_bgp_path_attrs_igp_metric(lr_bgp_path_attrs_t a, uint32_t *out_metric);
uint8_t lr_bgp_path_attrs_has_igp_metric(lr_bgp_path_attrs_t a);
int32_t lr_bgp_path_attrs_set_peer_source_address(lr_bgp_path_attrs_t a,
                                                  const uint8_t *addr,
                                                  uint8_t is_ipv6);
uint8_t lr_bgp_path_attrs_peer_source_address(lr_bgp_path_attrs_t a,
                                              uint8_t *out_addr,
                                              uint8_t *out_is_ipv6);
uint8_t lr_bgp_path_attrs_has_peer_source_address(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_has_community(lr_bgp_path_attrs_t a, uint32_t community);
int32_t lr_bgp_path_attrs_insert_large_community(lr_bgp_path_attrs_t a,
                                                 lr_bgp_large_community_t c);
uint8_t lr_bgp_path_attrs_remove(lr_bgp_path_attrs_t a, uint8_t attr_type);
uint8_t lr_bgp_path_attrs_get(lr_bgp_path_attrs_t a,
                              uint8_t attr_type,
                              uint8_t *out_flags,
                              uint8_t *out_type,
                              lr_bytes_t *out_value);
int32_t lr_bgp_path_attrs_insert_raw(lr_bgp_path_attrs_t a,
                                     uint8_t flags,
                                     uint8_t attr_type,
                                     const uint8_t *value,
                                     uintptr_t value_len);
uintptr_t lr_bgp_path_attrs_count(lr_bgp_path_attrs_t a);
uint8_t lr_bgp_path_attrs_at(lr_bgp_path_attrs_t a,
                             uintptr_t index,
                             uint8_t *out_flags,
                             uint8_t *out_type,
                             lr_bytes_t *out_value);

/* Minimal lr_bgp_large_community surface: construct + read + free
 * (enough to drive insert_large_community from Python). The full
 * encode_set / decode_set entry points are a follow-up. */
lr_bgp_large_community_t lr_bgp_large_community_new(uint32_t global_admin,
                                                    uint32_t local_data1,
                                                    uint32_t local_data2);
uint32_t lr_bgp_large_community_global_admin(lr_bgp_large_community_t c);
uint32_t lr_bgp_large_community_local_data1(lr_bgp_large_community_t c);
uint32_t lr_bgp_large_community_local_data2(lr_bgp_large_community_t c);
void lr_bgp_large_community_free(lr_bgp_large_community_t c);

/* Free the lr_bgp_as_path_t handle returned by as_path/as_path_wire/
 * as4_path. The full BgpAsPath surface (decode/encode/prepend/etc)
 * is a separate follow-up. */
void lr_bgp_as_path_free(lr_bgp_as_path_t p);

typedef struct OpaqueBabelUpdate OpaqueBabelUpdate;
typedef struct OpaqueBabelUpdate *lr_babel_update_t;
typedef struct OpaqueBfdConfig OpaqueBfdConfig;
typedef struct OpaqueBfdConfig *lr_bfd_config_t;
typedef struct OpaqueBfdSessionEvent OpaqueBfdSessionEvent;
typedef struct OpaqueBfdSessionEvent *lr_bfd_session_event_t;
typedef struct OpaqueBfdSession OpaqueBfdSession;
typedef struct OpaqueBfdSession *lr_bfd_session_t;
typedef struct OpaqueBgpCapArray OpaqueBgpCapArray;
typedef struct OpaqueBgpCapArray *lr_bgp_capability_array_t;
typedef struct OpaqueBgpCapability OpaqueBgpCapability;
typedef struct OpaqueBgpCapability *lr_bgp_capability_t;
typedef struct OpaqueBgpCodec OpaqueBgpCodec;
typedef struct OpaqueBgpCodec *lr_bgp_codec_t;
typedef struct OpaqueBgpCommunity OpaqueBgpCommunity;
typedef struct OpaqueBgpCommunity *lr_bgp_community_t;
typedef struct OpaqueConfederationConfig OpaqueConfederationConfig;
typedef struct OpaqueConfederationConfig *lr_bgp_confed_config_t;
typedef struct OpaqueBgpExtCommunity OpaqueBgpExtCommunity;
typedef struct OpaqueBgpExtCommunity *lr_bgp_ext_community_t;
typedef struct OpaqueBgpLsAttr OpaqueBgpLsAttr;
typedef struct OpaqueBgpLsAttr *lr_bgp_ls_attr_t;
typedef struct OpaqueBgpLsTlvVec OpaqueBgpLsTlvVec;
typedef struct OpaqueBgpLsTlvVec *lr_bgp_ls_tlv_vec_t;
typedef struct OpaqueOtc OpaqueOtc;
typedef struct OpaqueOtc *lr_bgp_otc_t;
typedef struct OpaquePeerConfig OpaquePeerConfig;
typedef struct OpaquePeerConfig *lr_bgp_peer_config_t;
typedef struct OpaqueBgpPeer OpaqueBgpPeer;
typedef struct OpaqueBgpPeer *lr_bgp_peer_t;
typedef struct OpaquePeerTopology OpaquePeerTopology;
typedef struct OpaquePeerTopology *lr_bgp_peer_topology_t;
typedef struct OpaqueRouteReflectorConfig OpaqueRouteReflectorConfig;
typedef struct OpaqueRouteReflectorConfig *lr_bgp_rr_config_t;
typedef struct OpaqueRouteServerConfig OpaqueRouteServerConfig;
typedef struct OpaqueRouteServerConfig *lr_bgp_rs_config_t;
typedef struct OpaqueBmpCodec OpaqueBmpCodec;
typedef struct OpaqueBmpCodec *lr_bmp_codec_t;
typedef struct OpaqueBmpMessage OpaqueBmpMessage;
typedef struct OpaqueBmpMessage *lr_bmp_message_t;
typedef struct OpaqueBgpCapBytes OpaqueBgpCapBytes;
typedef struct OpaqueBgpCapBytes *lr_bytes_t_handle;
typedef struct OpaqueDampingTable OpaqueDampingTable;
typedef struct OpaqueDampingTable *lr_damping_table_t;
typedef struct OpaqueLdpDiscoveryConfig OpaqueLdpDiscoveryConfig;
typedef struct OpaqueLdpDiscoveryConfig *lr_ldp_discovery_config_t;
typedef struct OpaqueLdpDiscovery OpaqueLdpDiscovery;
typedef struct OpaqueLdpDiscovery *lr_ldp_discovery_t;
typedef struct OpaqueLdpEngineConfig OpaqueLdpEngineConfig;
typedef struct OpaqueLdpEngineConfig *lr_ldp_engine_config_t;
typedef struct OpaqueLdpEngine OpaqueLdpEngine;
typedef struct OpaqueLdpEngine *lr_ldp_engine_t;
typedef struct OpaqueLdpFec OpaqueLdpFec;
typedef struct OpaqueLdpFec *lr_ldp_fec_t;
typedef struct OpaqueLdpLabelStore OpaqueLdpLabelStore;
typedef struct OpaqueLdpLabelStore *lr_ldp_label_store_t;
typedef struct OpaqueLdpGenericLabel OpaqueLdpGenericLabel;
typedef struct OpaqueLdpGenericLabel *lr_ldp_label_t;
typedef struct OpaqueLdpPdu OpaqueLdpPdu;
typedef struct OpaqueLdpPdu *lr_ldp_pdu_t;
typedef struct OpaqueLdpSession OpaqueLdpSession;
typedef struct OpaqueLdpSession *lr_ldp_session_t;
typedef struct OpaqueLdpTransit OpaqueLdpTransit;
typedef struct OpaqueLdpTransit *lr_ldp_transit_t;
typedef struct OpaqueMrtReader OpaqueMrtReader;
typedef struct OpaqueMrtReader *lr_mrt_reader_t;
typedef struct OpaqueMrtRecord OpaqueMrtRecord;
typedef struct OpaqueMrtRecord *lr_mrt_record_t;
typedef struct OpaqueMrtRibDump OpaqueMrtRibDump;
typedef struct OpaqueMrtRibDump *lr_mrt_rib_dump_t;
typedef struct OpaqueOspfAsbrDest OpaqueOspfAsbrDest;
typedef struct OpaqueOspfAsbrDest *lr_ospf_asbr_dest_t;
typedef struct OpaqueOspfCryptoAuth OpaqueOspfCryptoAuth;
typedef struct OpaqueOspfCryptoAuth *lr_ospf_crypto_auth_t;
typedef struct OpaqueOspfDbExchange OpaqueOspfDbExchange;
typedef struct OpaqueOspfDbExchange *lr_ospf_db_exchange_t;
typedef struct OpaqueOspfExternalRoute OpaqueOspfExternalRoute;
typedef struct OpaqueOspfExternalRoute *lr_ospf_external_route_t;
typedef struct OpaqueOspfExternalRouteV3 OpaqueOspfExternalRouteV3;
typedef struct OpaqueOspfExternalRouteV3 *lr_ospf_external_route_v3_t;
typedef struct OpaqueOspfExternalRouteV3Vec OpaqueOspfExternalRouteV3Vec;
typedef struct OpaqueOspfExternalRouteV3Vec *lr_ospf_external_route_v3_vec_t;
typedef struct OpaqueOspfExternalRouteVec OpaqueOspfExternalRouteVec;
typedef struct OpaqueOspfExternalRouteVec *lr_ospf_external_route_vec_t;
typedef struct OpaqueOspfHelperEntry OpaqueOspfHelperEntry;
typedef struct OpaqueOspfHelperEntry *lr_ospf_helper_entry_t;
typedef struct OpaqueOspfIfAction OpaqueOspfIfAction;
typedef struct OpaqueOspfIfAction *lr_ospf_if_action_t;
typedef struct OpaqueOspfInterface OpaqueOspfInterface;
typedef struct OpaqueOspfInterface *lr_ospf_interface_t;
typedef struct OpaqueOspfNeighbor OpaqueOspfNeighbor;
typedef struct OpaqueOspfNeighbor *lr_ospf_neighbor_t;
typedef struct OpaqueOspfNssaDefault OpaqueOspfNssaDefault;
typedef struct OpaqueOspfNssaDefault *lr_ospf_nssa_default_t;
typedef lr_ospf_external_route_vec_t lr_ospf_nssa_route_vec_t;
typedef struct OpaqueOspfPacket OpaqueOspfPacket;
typedef struct OpaqueOspfPacket *lr_ospf_packet_t;
typedef struct OpaqueOspfRestartTracker OpaqueOspfRestartTracker;
typedef struct OpaqueOspfRestartTracker *lr_ospf_restart_tracker_t;
typedef struct OpaqueOspfRouterLsaLink OpaqueOspfRouterLsaLink;
typedef struct OpaqueOspfRouterLsaLink *lr_ospf_router_lsa_link_t;
typedef struct OpaqueOspfSimplePassword OpaqueOspfSimplePassword;
typedef struct OpaqueOspfSimplePassword *lr_ospf_simple_password_t;
typedef struct OpaqueOspfSpfResult OpaqueOspfSpfResult;
typedef struct OpaqueOspfSpfResult *lr_ospf_spf_result_t;
typedef struct OpaqueOspfSpfResultV3 OpaqueOspfSpfResultV3;
typedef struct OpaqueOspfSpfResultV3 *lr_ospf_spf_v3_result_t;
typedef struct OpaqueOspfSrDb OpaqueOspfSrDb;
typedef struct OpaqueOspfSrDb *lr_ospf_sr_db_t;
typedef struct OpaqueOspfSrv6Db OpaqueOspfSrv6Db;
typedef struct OpaqueOspfSrv6Db *lr_ospf_srv6_db_t;
typedef struct OpaqueOspfSummaryDest OpaqueOspfSummaryDest;
typedef struct OpaqueOspfSummaryDest *lr_ospf_summary_dest_t;
typedef struct OpaqueOspfV3Auth OpaqueOspfV3Auth;
typedef struct OpaqueOspfV3Auth *lr_ospf_v3_auth_t;
typedef struct OpaqueOsRouteTable OpaqueOsRouteTable;
typedef struct OpaqueOsRouteTable *lr_osroute_t;
typedef struct OpaquePolicyChain OpaquePolicyChain;
typedef struct OpaquePolicyChain *lr_policy_chain_t;
typedef struct OpaquePolicy OpaquePolicy;
typedef struct OpaquePolicy *lr_policy_t;
typedef struct OpaqueRoaTableBuilder OpaqueRoaTableBuilder;
typedef struct OpaqueRoaTableBuilder *lr_roa_table_builder_t;
typedef struct OpaqueRoaTable OpaqueRoaTable;
typedef struct OpaqueRoaTable *lr_roa_table_t;
typedef struct OpaqueRtrPdu OpaqueRtrPdu;
typedef struct OpaqueRtrPdu *lr_rtr_pdu_t;
typedef struct OpaqueSafetyNet OpaqueSafetyNet;
typedef struct OpaqueSafetyNet *lr_safety_net_t;
typedef struct OpaqueSessionConfig OpaqueSessionConfig;
typedef struct OpaqueSessionConfig *lr_session_config_t;
typedef struct OpaqueTcpAuth OpaqueTcpAuth;
typedef struct OpaqueTcpAuth *lr_tcp_auth_t;
typedef struct lr_best_path_config_t {
    uint8_t always_compare_med;
    uint8_t missing_med_as_infinity;
    uint8_t deterministic_router_id;
    uint8_t prefer_externals;
    uint8_t count_confed_in_path_len;
    uint32_t multipath;
    uint8_t multipath_relax;
    uint8_t graceful_shutdown_least_preferred;
    uint8_t compare_igp_metric;
    uint8_t prefer_next_hop_self;
} lr_best_path_config_t;
typedef struct lr_bgp_cap_add_path_family_t {
    uint16_t afi;
    uint8_t safi;
    uint8_t send;
    uint8_t recv;
} lr_bgp_cap_add_path_family_t;
typedef struct lr_bgp_cap_gr_family_t {
    uint16_t afi;
    uint8_t safi;
    uint8_t forwarding;
} lr_bgp_cap_gr_family_t;
typedef struct lr_bgp_cap_llgr_family_t {
    uint16_t afi;
    uint8_t safi;
    uint8_t forwarding;
    uint32_t stale_time_secs;
} lr_bgp_cap_llgr_family_t;
typedef struct lr_bgp_ext_next_hop_tuple_t {
    uint16_t nlri_afi;
    uint8_t nlri_safi;
    uint16_t nh_afi;
} lr_bgp_ext_next_hop_tuple_t;
typedef struct lr_bgp_ls_tlv_t {
    uint16_t tlv_type;
    uintptr_t value_offset;
    uint16_t value_len;
    uint8_t * value_ptr;
    void * _owned;
} lr_bgp_ls_tlv_t;
typedef struct lr_bgp_peer_message_stats_t {
    uint64_t open_sent;
    uint64_t open_received;
    uint64_t keepalive_sent;
    uint64_t keepalive_received;
    uint64_t notification_sent;
    uint64_t notification_received;
    uint64_t update_sent;
    uint64_t update_received;
    uint64_t route_refresh_sent;
    uint64_t route_refresh_received;
} lr_bgp_peer_message_stats_t;
typedef struct lr_bmp_peer_header_t {
    uint8_t peer_type;
    uint8_t peer_flags;
    uint64_t peer_distinguisher;
    uint8_t peer_address[16];
    uint32_t peer_as;
    uint32_t peer_bgp_id;
    uint32_t timestamp_secs;
    uint32_t timestamp_fraction;
} lr_bmp_peer_header_t;
typedef struct lr_bmp_tlv_t {
    uint16_t tlv_type;
    const uint8_t * value;
    uintptr_t value_len;
} lr_bmp_tlv_t;
typedef struct lr_damping_entry_t {
    struct lr_prefix_t prefix;
    double figure_of_merit;
    uint8_t suppressed;
    uint64_t last_decay_s;
    uint64_t last_flap_s;
    uint32_t flap_count;
} lr_damping_entry_t;
typedef struct lr_gtsm_t {
    uint8_t outbound_ttl;
    uint8_t min_ttl;
} lr_gtsm_t;
typedef struct lr_kernel_route_t {
    struct lr_prefix_t prefix;
    uint8_t next_hop[16];
    uint8_t next_hop_is_ipv6;
    uint8_t next_hop_present;
    uint8_t if_index_present;
    uint32_t if_index;
    uint32_t metric;
    int32_t protocol;
} lr_kernel_route_t;
typedef struct lr_ldp_engine_event_t {
    int32_t kind;
    uint32_t peer_lsr;
    uint16_t peer_label_space;
    int32_t discovery_kind;
    uint8_t source_is_ipv6;
    uint8_t source_addr[16];
    uint8_t transport_is_ipv6;
    uint8_t transport_addr[16];
    uint64_t conn;
    uint16_t negotiated_keepalive_time;
    uint16_t negotiated_max_pdu_len;
    int32_t session_down_reason;
    uint32_t status_code;
    uint8_t status_is_fatal;
    uint8_t graceful;
    uint8_t prefix_is_ipv6;
    uint8_t prefix_len;
    uint8_t prefix_addr[16];
    uint32_t label;
    uint32_t in_label;
    uint32_t out_label;
    uint8_t transit_next_hop_is_ipv6;
    uint8_t transit_next_hop_addr[16];
    uint32_t message_id;
    uint32_t request_message_id;
    struct lr_bytes_t prefixes;
    uint32_t prefix_count;
    struct lr_bytes_t addresses;
    uint32_t address_count;
} lr_ldp_engine_event_t;
typedef struct lr_ldp_hello_adjacency_t {
    uint32_t peer_lsr_id;
    uint16_t peer_label_space;
    uint8_t kind;
    uint8_t source_is_ipv6;
    uint8_t source[16];
    uint8_t transport_is_ipv6;
    uint8_t transport_addr[16];
    uint64_t hold_time_ms;
    uint64_t last_seen_ms;
    uint8_t config_seq_present;
    uint32_t config_seq;
    uint8_t dual_stack_present;
    uint8_t dual_stack_prefer_ipv6;
} lr_ldp_hello_adjacency_t;
typedef struct lr_ldp_id_t {
    uint8_t lsr_id[4];
    uint16_t label_space;
} lr_ldp_id_t;
typedef struct lr_ldp_prefix_t {
    uint8_t addr_v4[16];
    uint8_t addr_v6[16];
    uint8_t is_ipv6;
    uint8_t prefix_len;
} lr_ldp_prefix_t;
typedef struct lr_mrt_attr_summary_t {
    uint8_t has_next_hop_v4;
    uint8_t has_next_hop_v6;
    uint8_t next_hop_v4[4];
    uint8_t next_hop_v6[16];
    uint8_t has_local_pref;
    uint32_t local_pref;
    uint8_t has_med;
    uint32_t med;
    uintptr_t raw_len;
} lr_mrt_attr_summary_t;
typedef struct lr_mrt_peer_entry_t {
    uint32_t bgp_id;
    const uint8_t * ip_addr;
    uint8_t is_ipv6;
    uint32_t asn;
} lr_mrt_peer_entry_t;
typedef struct lr_mrt_rib_entry_t {
    uint16_t peer_index;
    uint32_t originated_time;
    uint32_t path_id;
    const uint8_t * attributes;
    uintptr_t attr_len;
} lr_mrt_rib_entry_t;
typedef struct lr_afi_safi_t lr_nlri_family_t;
typedef struct lr_ospf_e_lsa_tlv_t {
    uint16_t tlv_type;
    uint16_t length;
    uintptr_t value_offset;
} lr_ospf_e_lsa_tlv_t;
typedef struct lr_ospf_elector_t {
    uint32_t router_id;
    uint32_t ip;
    uint8_t priority;
    uint32_t stated_dr;
    uint32_t stated_bdr;
} lr_ospf_elector_t;
typedef struct lr_ospf_exchange_step_t {
    lr_ospf_packet_t * out_packets;
    uintptr_t out_packet_count;
    lr_ospf_lsa_box_t * out_lsas;
    uintptr_t out_lsa_count;
    uint8_t newly_full;
} lr_ospf_exchange_step_t;
typedef struct lr_ospf_nssa_calc_opts_t {
    uint8_t border_router;
    uint8_t summaries_suppressed;
} lr_ospf_nssa_calc_opts_t;
typedef struct lr_ospf_router_link_t {
    uint32_t link_id;
    uint32_t link_data;
    uint8_t link_type;
    uint8_t tos_count;
    uint16_t metric;
} lr_ospf_router_link_t;
typedef struct lr_ospf_spf_route_t {
    uint8_t prefix_addr[16];
    uint8_t prefix_is_ipv6;
    uint8_t prefix_len;
    uint64_t metric;
    uint32_t next_hop_count;
    uint32_t border_router;
    uint32_t advertising_router;
} lr_ospf_spf_route_t;
typedef struct lr_ospf_v3_elector_t {
    uint32_t router_id;
    uint8_t priority;
    uint32_t stated_dr;
    uint32_t stated_bdr;
} lr_ospf_v3_elector_t;
typedef struct lr_osroute_interface_v4_addr_t {
    uint8_t addr[4];
    uint8_t prefix_len;
} lr_osroute_interface_v4_addr_t;
typedef struct lr_osroute_interface_v6_addr_t {
    uint8_t addr[16];
    uint8_t prefix_len;
    uint32_t scope_id;
} lr_osroute_interface_v6_addr_t;
typedef struct lr_tcp_ao_key_t {
    uint8_t send_id;
    uint8_t recv_id;
    uintptr_t key_len;
} lr_tcp_ao_key_t;
lr_babel_update_t lr_babel_update_new(
    uint8_t prefix_len_bits,
    const uint8_t * prefix,
    uintptr_t prefix_len_bytes,
    uint16_t seqno,
    uint16_t metric
);
uint8_t lr_babel_update_ae(lr_babel_update_t u);
uint8_t lr_babel_update_flags(lr_babel_update_t u);
uint8_t lr_babel_update_prefix_len(lr_babel_update_t u);
uint8_t lr_babel_update_omitted(lr_babel_update_t u);
uint16_t lr_babel_update_interval_cs(lr_babel_update_t u);
uint16_t lr_babel_update_seqno(lr_babel_update_t u);
uint16_t lr_babel_update_metric(lr_babel_update_t u);
uintptr_t lr_babel_update_prefix(
    lr_babel_update_t u,
    uint8_t * out,
    uintptr_t out_len
);
uintptr_t lr_babel_update_prefix_len_bytes(lr_babel_update_t u);
uint8_t lr_babel_update_src_prefix_len(lr_babel_update_t u);
uintptr_t lr_babel_update_src_prefix(
    lr_babel_update_t u,
    uint8_t * out,
    uintptr_t out_len
);
int32_t lr_babel_update_set_ae(lr_babel_update_t u, uint8_t ae);
int32_t lr_babel_update_set_flags(lr_babel_update_t u, uint8_t flags);
int32_t lr_babel_update_set_omitted(lr_babel_update_t u, uint8_t omitted);
int32_t lr_babel_update_set_interval_cs(lr_babel_update_t u, uint16_t interval_cs);
int32_t lr_babel_update_encode(lr_babel_update_t u, struct lr_bytes_t * out);
void lr_babel_update_free(lr_babel_update_t u);
struct lr_best_path_config_t lr_best_path_config_default(void);
struct lr_best_path_config_t lr_best_path_config_new(
    uint8_t always_compare_med,
    uint8_t missing_med_as_infinity,
    uint8_t deterministic_router_id,
    uint8_t prefer_externals,
    uint8_t count_confed_in_path_len,
    uint32_t multipath,
    uint8_t multipath_relax,
    uint8_t graceful_shutdown_least_preferred,
    uint8_t compare_igp_metric,
    uint8_t prefer_next_hop_self
);
int32_t lr_best_path_compare(
    lr_route_t a,
    lr_route_t b,
    struct lr_best_path_config_t cfg
);
lr_route_t lr_best_path_select(
    const lr_route_t * routes,
    uintptr_t count,
    struct lr_best_path_config_t cfg
);
int32_t lr_best_path_rank(
    const lr_route_t * routes,
    uintptr_t count,
    struct lr_best_path_config_t cfg,
    struct lr_bytes_t * out
);
int32_t lr_best_path_multipath(
    const lr_route_t * routes,
    uintptr_t count,
    struct lr_best_path_config_t cfg,
    struct lr_bytes_t * out
);
int32_t lr_best_path_compare_multipath(
    lr_route_t a,
    lr_route_t b,
    struct lr_best_path_config_t cfg
);
int32_t lr_bfd_session_set_keyed_auth(lr_bfd_session_t s, lr_bfd_keyed_auth_t auth);
uint8_t lr_bfd_session_keyed_auth_present(lr_bfd_session_t s);
int32_t lr_bfd_session_update_timers(
    lr_bfd_session_t s,
    uint64_t now_ms,
    uint32_t desired_min_tx,
    uint32_t required_min_rx,
    lr_bfd_session_event_t ** out_array,
    uintptr_t * out_count
);
uint8_t lr_bfd_session_remote_detect_mult(lr_bfd_session_t s);
uint8_t lr_bfd_session_poll_active(lr_bfd_session_t s);
lr_bfd_config_t lr_bfd_config_new(
    uint8_t detect_mult,
    uint32_t desired_min_tx_interval_us,
    uint32_t required_min_rx_interval_us,
    uint32_t required_min_echo_interval_us,
    uint8_t role
);
void lr_bfd_config_free(lr_bfd_config_t c);
uint8_t lr_bfd_config_detect_mult(lr_bfd_config_t c);
uint8_t lr_bfd_config_role(lr_bfd_config_t c);
uint32_t lr_bfd_config_desired_min_tx_interval(lr_bfd_config_t c);
uint32_t lr_bfd_config_required_min_rx_interval(lr_bfd_config_t c);
uint32_t lr_bfd_config_required_min_echo_interval(lr_bfd_config_t c);
int32_t lr_bfd_config_set_detect_mult(lr_bfd_config_t c, uint8_t value);
int32_t lr_bfd_config_set_desired_min_tx_interval(lr_bfd_config_t c, uint32_t value);
int32_t lr_bfd_config_set_required_min_rx_interval(lr_bfd_config_t c, uint32_t value);
int32_t lr_bfd_config_set_required_min_echo_interval(lr_bfd_config_t c, uint32_t value);
int32_t lr_bfd_config_set_role(lr_bfd_config_t c, uint8_t role);
int32_t lr_bfd_config_set_auth_key(
    lr_bfd_config_t c,
    const uint8_t * password,
    uintptr_t password_len
);
uint8_t lr_bfd_config_has_auth_key(lr_bfd_config_t c);
uint8_t lr_bfd_session_remote_diag(lr_bfd_session_t s);
lr_bfd_session_t lr_bfd_session_new(lr_bfd_config_t cfg, uint32_t my_disc);
void lr_bfd_session_free(lr_bfd_session_t s);
uint8_t lr_bfd_session_state(lr_bfd_session_t s);
uint8_t lr_bfd_session_is_up(lr_bfd_session_t s);
uint32_t lr_bfd_session_my_discriminator(lr_bfd_session_t s);
uint32_t lr_bfd_session_remote_discriminator(lr_bfd_session_t s);
uint8_t lr_bfd_session_local_diag(lr_bfd_session_t s);
uint8_t lr_bfd_session_remote_state(lr_bfd_session_t s);
uint32_t lr_bfd_session_tx_interval_us(lr_bfd_session_t s);
uint64_t lr_bfd_session_detection_time_us(lr_bfd_session_t s);
int32_t lr_bfd_session_drain_outgoing(lr_bfd_session_t s, struct lr_bytes_t * out);
int32_t lr_bfd_session_feed_bytes(
    lr_bfd_session_t s,
    uint64_t now_ms,
    const uint8_t * data,
    uintptr_t len,
    lr_bfd_session_event_t ** out_array,
    uintptr_t * out_count
);
int32_t lr_bfd_session_tick(
    lr_bfd_session_t s,
    uint64_t now_ms,
    lr_bfd_session_event_t ** out_array,
    uintptr_t * out_count
);
int32_t lr_bfd_session_start(
    lr_bfd_session_t s,
    uint64_t now_ms,
    lr_bfd_session_event_t ** out_array,
    uintptr_t * out_count
);
int32_t lr_bfd_session_admin_down(
    lr_bfd_session_t s,
    lr_bfd_session_event_t ** out_array,
    uintptr_t * out_count
);
uint8_t lr_bfd_session_event_kind(lr_bfd_session_event_t e);
int32_t lr_bfd_session_event_state_change_fields(
    lr_bfd_session_event_t e,
    uint8_t * out_from,
    uint8_t * out_to,
    uint8_t * out_diag
);
void lr_bfd_session_event_free(lr_bfd_session_event_t e);
void lr_bfd_session_event_array_free(lr_bfd_session_event_t * array, uintptr_t count);
lr_bgp_codec_t lr_bgp_codec_new(void);
lr_bgp_codec_t lr_bgp_codec_with_asn4(uint8_t asn4);
int32_t lr_bgp_codec_set_asn4(lr_bgp_codec_t c, uint8_t asn4);
uint8_t lr_bgp_codec_asn4_active(lr_bgp_codec_t c);
int32_t lr_bgp_codec_set_add_path(
    lr_bgp_codec_t c,
    const struct lr_afi_safi_t * tx,
    uintptr_t tx_count,
    const struct lr_afi_safi_t * rx,
    uintptr_t rx_count
);
int32_t lr_bgp_codec_decode_slice(
    lr_bgp_codec_t c,
    const uint8_t * data,
    uintptr_t len,
    lr_bgp_message_t * out
);
int32_t lr_bgp_codec_encode_vec(
    lr_bgp_codec_t c,
    lr_bgp_message_t msg,
    struct lr_bytes_t * out
);
void lr_bgp_codec_free(lr_bgp_codec_t c);
int32_t lr_bgp_reconcile_as4(
    uint8_t wire_present,
    const uint8_t * wire_data,
    uintptr_t wire_len,
    uint8_t as4_present,
    const uint8_t * as4_data,
    uintptr_t as4_len,
    struct lr_bytes_t * out
);
int32_t lr_bgp_decode_tlv_stream(
    const uint8_t * data,
    uintptr_t len,
    uintptr_t * out_count,
    struct lr_bgp_ls_tlv_t ** out_array
);
int32_t lr_bgp_encode_tlv_stream(
    const struct lr_bgp_ls_tlv_t * tlvs,
    uintptr_t count,
    struct lr_bytes_t * out
);
void lr_bgp_ls_tlv_array_free(struct lr_bgp_ls_tlv_t * arr, uintptr_t count);
int32_t lr_bgp_labeled_nlri_encode_list(
    const uint8_t * data,
    uintptr_t len,
    uint8_t add_path,
    struct lr_bytes_t * out
);
lr_bgp_community_t lr_bgp_community_new(uint16_t asn, uint16_t value);
lr_bgp_community_t lr_bgp_community_from_u32(uint32_t value);
lr_bgp_community_t lr_bgp_community_new_well_known(int32_t kind);
uint32_t lr_bgp_community_as_u32(lr_bgp_community_t c);
uint16_t lr_bgp_community_asn(lr_bgp_community_t c);
uint16_t lr_bgp_community_value(lr_bgp_community_t c);
int32_t lr_bgp_community_kind(lr_bgp_community_t c);
void lr_bgp_community_free(lr_bgp_community_t c);
int32_t lr_bgp_community_encode_set(
    const uint32_t * values,
    uintptr_t count,
    struct lr_bytes_t * out
);
int32_t lr_bgp_community_decode_set(
    const uint8_t * data,
    uintptr_t len,
    struct lr_bytes_t * out_values,
    uintptr_t * out_count
);
int32_t lr_bgp_large_community_encode_set(
    const uint32_t * triples,
    uintptr_t count,
    struct lr_bytes_t * out
);
int32_t lr_bgp_large_community_decode_set(
    const uint8_t * data,
    uintptr_t len,
    struct lr_bytes_t * out_values,
    uintptr_t * out_count
);
lr_bgp_ext_community_t lr_bgp_ext_community_new(
    uint8_t kind,
    uint8_t subtype,
    uint32_t global,
    uint16_t local
);
uint8_t lr_bgp_ext_community_kind(lr_bgp_ext_community_t c);
uint8_t lr_bgp_ext_community_subtype(lr_bgp_ext_community_t c);
uint32_t lr_bgp_ext_community_global(lr_bgp_ext_community_t c);
uint16_t lr_bgp_ext_community_local(lr_bgp_ext_community_t c);
void lr_bgp_ext_community_free(lr_bgp_ext_community_t c);
int32_t lr_bgp_ext_community_encode_set(
    const uint32_t * specs,
    uintptr_t count,
    struct lr_bytes_t * out
);
int32_t lr_bgp_ext_community_decode_set(
    const uint8_t * data,
    uintptr_t len,
    struct lr_bytes_t * out_values,
    uintptr_t * out_count
);
uint8_t lr_bgp_error_code_from_u8(uint8_t v);
uint8_t lr_bgp_error_code_to_u8(uint8_t v);
const char * lr_bgp_error_code_name(uint8_t v);
uint8_t lr_bgp_open_error_subcode_from_u8(uint8_t v);
uint8_t lr_bgp_open_error_subcode_to_u8(uint8_t v);
const char * lr_bgp_open_error_subcode_name(uint8_t v);
uint8_t lr_bgp_update_error_subcode_from_u8(uint8_t v);
uint8_t lr_bgp_update_error_subcode_to_u8(uint8_t v);
const char * lr_bgp_update_error_subcode_name(uint8_t v);
uint8_t lr_bgp_header_error_subcode_from_u8(uint8_t v);
uint8_t lr_bgp_header_error_subcode_to_u8(uint8_t v);
const char * lr_bgp_header_error_subcode_name(uint8_t v);
uint8_t lr_bgp_cease_subcode_from_u8(uint8_t v);
uint8_t lr_bgp_cease_subcode_to_u8(uint8_t v);
const char * lr_bgp_cease_subcode_name(uint8_t v);
uint8_t lr_bgp_message_type_from_u8(uint8_t v);
uint8_t lr_bgp_message_type_to_u8(uint8_t v);
const char * lr_bgp_message_type_name(uint8_t v);
uint8_t lr_bgp_capability_code_from_u8(uint8_t v);
uint8_t lr_bgp_capability_code_to_u8(uint8_t v);
const char * lr_bgp_capability_code_name(uint8_t v);
uint16_t lr_bgp_ls_nlri_type_from_u16(uint16_t v);
uint16_t lr_bgp_ls_nlri_type_to_u16(uint16_t v);
const char * lr_bgp_ls_nlri_type_name(uint16_t v);
uint8_t lr_bgp_as_path_type_from_u8(uint8_t v);
uint8_t lr_bgp_as_path_type_to_u8(uint8_t v);
const char * lr_bgp_as_path_type_name(uint8_t v);
uint8_t lr_bgp_origin_kind_from_u8(uint8_t v);
uint8_t lr_bgp_origin_kind_to_u8(uint8_t v);
const char * lr_bgp_origin_kind_name(uint8_t v);
uint8_t lr_bgp_community_kind_from_u8(uint8_t v);
uint8_t lr_bgp_community_kind_to_u8(uint8_t v);
const char * lr_bgp_community_kind_name(uint8_t v);
uint8_t lr_bgp_route_refresh_subtype_from_u8(uint8_t v);
uint8_t lr_bgp_route_refresh_subtype_to_u8(uint8_t v);
const char * lr_bgp_route_refresh_subtype_name(uint8_t v);
struct lr_bgp_ls_tlv_t lr_bgp_ls_tlv_new(
    uint16_t tlv_type,
    const uint8_t * value,
    uintptr_t value_len
);
uint16_t lr_bgp_ls_tlv_type(struct lr_bgp_ls_tlv_t t);
uintptr_t lr_bgp_ls_tlv_value_len(struct lr_bgp_ls_tlv_t t);
int32_t lr_bgp_ls_tlv_value(
    struct lr_bgp_ls_tlv_t t,
    uint8_t * out,
    uintptr_t cap
);
void lr_bgp_ls_tlv_free(struct lr_bgp_ls_tlv_t t);
int32_t lr_bgp_ls_decode_tlv_stream(
    const uint8_t * data,
    uintptr_t len,
    lr_bgp_ls_tlv_vec_t * out
);
int32_t lr_bgp_ls_encode_tlv_stream(lr_bgp_ls_tlv_vec_t vec, struct lr_bytes_t * out);
uintptr_t lr_bgp_ls_tlv_vec_len(lr_bgp_ls_tlv_vec_t vec);
struct lr_bgp_ls_tlv_t lr_bgp_ls_tlv_vec_at(lr_bgp_ls_tlv_vec_t vec, uintptr_t index);
void lr_bgp_ls_tlv_vec_free(lr_bgp_ls_tlv_vec_t vec);
lr_bgp_ls_attr_t lr_bgp_ls_attr_new(void);
void lr_bgp_ls_attr_free(lr_bgp_ls_attr_t a);
uintptr_t lr_bgp_ls_attr_len(lr_bgp_ls_attr_t a);
uint8_t lr_bgp_ls_attr_is_empty(lr_bgp_ls_attr_t a);
uintptr_t lr_bgp_ls_attr_value_len(lr_bgp_ls_attr_t a);
int32_t lr_bgp_ls_attr_encode(lr_bgp_ls_attr_t a, struct lr_bytes_t * out);
int32_t lr_bgp_ls_attr_decode(
    const uint8_t * data,
    uintptr_t len,
    lr_bgp_ls_attr_t * out
);
int32_t lr_bgp_ls_attr_find(
    lr_bgp_ls_attr_t a,
    uint16_t ty,
    uintptr_t * out_index
);
lr_bgp_message_t lr_bgp_message_new_open(
    uint32_t my_as,
    uint16_t hold_time,
    uint32_t bgp_id,
    uint8_t as4
);
lr_bgp_message_t lr_bgp_message_new_update(void);
lr_bgp_message_t lr_bgp_message_new_notification(
    uint8_t error_code,
    uint8_t error_subcode,
    const uint8_t * data,
    uintptr_t data_len
);
lr_bgp_message_t lr_bgp_message_new_notification_from_code(
    uint8_t error_code,
    uint8_t error_subcode,
    const uint8_t * data,
    uintptr_t data_len
);
lr_bgp_message_t lr_bgp_message_new_keepalive(void);
lr_bgp_message_t lr_bgp_message_new_route_refresh(
    uint16_t afi,
    uint8_t safi,
    uint8_t subtype
);
lr_bgp_message_t lr_bgp_message_new_begin_of_rib(uint16_t afi, uint8_t safi);
lr_bgp_message_t lr_bgp_message_new_end_of_rib(uint16_t afi, uint8_t safi);
lr_bgp_message_t lr_bgp_message_new_open_auto_as4(
    uint32_t my_as,
    uint16_t hold_time,
    uint32_t bgp_id
);
uint8_t lr_bgp_attr_type_to_u8(uint8_t t);
int32_t lr_bgp_attr_type_from_u8(uint8_t wire, uint8_t * out_canonical);
lr_bgp_as_path_t lr_bgp_as_path_new(void);
lr_bgp_as_path_t lr_bgp_as_path_from_sequence(const uint32_t * ases, uintptr_t count);
uintptr_t lr_bgp_as_path_length(lr_bgp_as_path_t p);
uintptr_t lr_bgp_as_path_length_with_confed(lr_bgp_as_path_t p);
uintptr_t lr_bgp_as_path_as_sequence(
    lr_bgp_as_path_t p,
    uint32_t * out,
    uintptr_t cap
);
uintptr_t lr_bgp_as_path_segment_count(lr_bgp_as_path_t p);
int32_t lr_bgp_as_path_segment_at(
    lr_bgp_as_path_t p,
    uintptr_t index,
    uint8_t * out_kind,
    uintptr_t * out_count
);
uintptr_t lr_bgp_as_path_segment_ases(
    lr_bgp_as_path_t p,
    uintptr_t index,
    uint32_t * out,
    uintptr_t cap
);
int32_t lr_bgp_as_path_prepend(lr_bgp_as_path_t p, uint32_t as_);
int32_t lr_bgp_as_path_prepend_confed(lr_bgp_as_path_t p, uint32_t as_);
int32_t lr_bgp_as_path_strip_confed(lr_bgp_as_path_t p);
uint8_t lr_bgp_as_path_has_confed(lr_bgp_as_path_t p);
uint8_t lr_bgp_as_path_loop_check(lr_bgp_as_path_t p, uint32_t my_as);
lr_bgp_as_path_t lr_bgp_as_path_decode_2(const uint8_t * data, uintptr_t len);
lr_bgp_as_path_t lr_bgp_as_path_decode_4(const uint8_t * data, uintptr_t len);
int32_t lr_bgp_as_path_encode_2(lr_bgp_as_path_t p, struct lr_bytes_t * out);
int32_t lr_bgp_as_path_encode_4(lr_bgp_as_path_t p, struct lr_bytes_t * out);
lr_bgp_peer_t lr_bgp_peer_new(
    uint32_t local_as,
    uint32_t peer_as,
    uint32_t local_bgp_id,
    uint16_t hold_time,
    uint16_t keepalive,
    uint8_t asn4
);
void lr_bgp_peer_free(lr_bgp_peer_t r);
int32_t lr_bgp_peer_state(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_is_established(lr_bgp_peer_t r);
int32_t lr_bgp_peer_peer_bgp_id(lr_bgp_peer_t r, uint32_t * out);
int32_t lr_bgp_peer_peer_as(lr_bgp_peer_t r, uint32_t * out);
uint16_t lr_bgp_peer_negotiated_hold_time(lr_bgp_peer_t r);
int32_t lr_bgp_peer_feed_bytes(
    lr_bgp_peer_t r,
    const uint8_t * data,
    uintptr_t len
);
int32_t lr_bgp_peer_drain_outgoing(lr_bgp_peer_t r, struct lr_bytes_t * out);
int32_t lr_bgp_peer_step_manual_start(lr_bgp_peer_t r);
int32_t lr_bgp_peer_step_manual_stop(lr_bgp_peer_t r);
int32_t lr_bgp_peer_step_transport_open(lr_bgp_peer_t r);
int32_t lr_bgp_peer_step_transport_fatal(lr_bgp_peer_t r);
int32_t lr_bgp_peer_step_transport_close(lr_bgp_peer_t r);
int32_t lr_bgp_peer_step_timer_connect_retry(lr_bgp_peer_t r);
int32_t lr_bgp_peer_step_timer_hold_expired(lr_bgp_peer_t r);
int32_t lr_bgp_peer_step_timer_keepalive(lr_bgp_peer_t r);
int32_t lr_bgp_peer_step_timer_idle_hold(lr_bgp_peer_t r);
int32_t lr_bgp_peer_advertise(lr_bgp_peer_t r, lr_route_t route);
int32_t lr_bgp_peer_withdraw(
    lr_bgp_peer_t r,
    const struct lr_prefix_t * prefixes,
    uintptr_t count,
    uint16_t family_afi,
    uint8_t family_safi
);
int32_t lr_bgp_peer_send_end_of_rib(
    lr_bgp_peer_t r,
    uint16_t family_afi,
    uint8_t family_safi
);
int32_t lr_bgp_peer_message_stats(lr_bgp_peer_t r, struct lr_bgp_peer_message_stats_t * out);
uint16_t lr_bgp_peer_hold_time(lr_bgp_peer_t r);
uint16_t lr_bgp_peer_keepalive(lr_bgp_peer_t r);
uint32_t lr_bgp_peer_local_as(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_asn4(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_ipv4_unicast_active(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_is_rr_client(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_is_rs_client(lr_bgp_peer_t r);
int32_t lr_bgp_peer_role(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_route_refresh_negotiated(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_enhanced_route_refresh_negotiated(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_add_path_negotiated(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_add_path_tx_for(lr_bgp_peer_t r, lr_nlri_family_t family);
uint8_t lr_bgp_peer_add_path_rx_for(lr_bgp_peer_t r, lr_nlri_family_t family);
uint8_t lr_bgp_peer_extended_next_hop_for(
    lr_bgp_peer_t r,
    uint16_t nlri_afi,
    uint8_t nlri_safi,
    uint16_t nexthop_afi
);
int32_t lr_bgp_peer_negotiated_graceful_restart_time(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_llgr_negotiated(lr_bgp_peer_t r);
uint32_t lr_bgp_peer_negotiated_llgr_stale_time(lr_bgp_peer_t r, lr_nlri_family_t family);
uint8_t lr_bgp_peer_received_cease_collision(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_notification_received(lr_bgp_peer_t r);
uint8_t lr_bgp_peer_request_route_refresh(lr_bgp_peer_t r, lr_nlri_family_t family);
uint8_t lr_bgp_peer_begin_enhanced_route_refresh(lr_bgp_peer_t r, lr_nlri_family_t family);
uint8_t lr_bgp_peer_end_enhanced_route_refresh(lr_bgp_peer_t r, lr_nlri_family_t family);
int32_t lr_bgp_peer_enqueue_notification(
    lr_bgp_peer_t r,
    uint8_t code,
    uint8_t subcode
);
int32_t lr_bgp_peer_reset(lr_bgp_peer_t r);
int32_t lr_bgp_compute_originator_id(
    uint8_t existing_present,
    const uint8_t * existing_addr,
    uint32_t local_bgp_id,
    uint8_t * out_addr,
    uint8_t * out_present
);
uint8_t lr_bgp_cluster_list_has_loop(
    const uint8_t * cluster_list,
    uintptr_t count,
    uint32_t local_cluster
);
int32_t lr_bgp_prepend_cluster_id(
    const uint8_t * cluster_list,
    uintptr_t count,
    uint32_t local_cluster,
    struct lr_bytes_t * out
);
int32_t lr_bgp_otc_on_receive(
    uint8_t existing_present,
    uint32_t existing_value,
    uint8_t local_role,
    uint32_t peer_as,
    uint32_t * out_value,
    uint8_t * out_present
);
uint8_t lr_bgp_otc_can_advertise(uint32_t route_otc, uint8_t local_role);
int32_t lr_bgp_peer_advertised_tuples(
    lr_bgp_peer_t peer,
    uintptr_t * out_count,
    struct lr_bgp_ext_next_hop_tuple_t ** out_array
);
void lr_bgp_ext_next_hop_tuple_array_free(struct lr_bgp_ext_next_hop_tuple_t * arr, uintptr_t count);
uint8_t lr_bgp_ext_next_hop_supports(
    const struct lr_bgp_ext_next_hop_tuple_t * tuples,
    uintptr_t count,
    uint16_t nlri_afi,
    uint8_t nlri_safi,
    uint16_t nh_afi
);
int32_t lr_bgp_labeled_nlri_ipv4_implicit_null(
    const uint8_t * prefix_addr,
    uint8_t prefix_len,
    struct lr_bytes_t * out
);
int32_t lr_bmp_decode(
    const uint8_t * data,
    uintptr_t len,
    lr_bmp_message_t * out
);
int32_t lr_bmp_encode(lr_bmp_message_t message, struct lr_bytes_t * out);
lr_bmp_message_t lr_bmp_message_route_monitoring(
    const struct lr_bmp_peer_header_t * peer,
    const uint8_t * bgp_update,
    uintptr_t bgp_len
);
lr_bmp_message_t lr_bmp_message_termination(const struct lr_bmp_tlv_t * info, uintptr_t count);
lr_bmp_message_t lr_bmp_message_initiation(const struct lr_bmp_tlv_t * info, uintptr_t count);
lr_bmp_message_t lr_bmp_message_peer_down(
    const struct lr_bmp_peer_header_t * peer,
    uint8_t reason,
    const uint8_t * data,
    uintptr_t data_len
);
lr_bmp_message_t lr_bmp_message_peer_up(
    const struct lr_bmp_peer_header_t * peer,
    const uint8_t * local_addr,
    uintptr_t local_addr_len,
    uint16_t local_port,
    uint16_t remote_port,
    const uint8_t * sent_open,
    uintptr_t sent_open_len,
    const uint8_t * received_open,
    uintptr_t received_open_len
);
uint8_t lr_bmp_message_type(lr_bmp_message_t message);
uint8_t lr_bmp_message_peer_present(lr_bmp_message_t message);
int32_t lr_bmp_message_peer_header(lr_bmp_message_t message, struct lr_bmp_peer_header_t * out);
uint8_t lr_bmp_peer_flags_is_ipv6(uint8_t peer_flags);
uint8_t lr_bmp_peer_flags_is_post_policy(uint8_t peer_flags);
uint8_t lr_bmp_peer_flags_is_legacy_as_path(uint8_t peer_flags);
uintptr_t lr_bmp_message_payload_len(lr_bmp_message_t message);
int32_t lr_bmp_message_payload(lr_bmp_message_t message, struct lr_bytes_t * out);
void lr_bmp_message_free(lr_bmp_message_t message);
lr_bmp_codec_t lr_bmp_codec_new(void);
int32_t lr_bmp_codec_decode_slice(
    lr_bmp_codec_t c,
    const uint8_t * data,
    uintptr_t len,
    lr_bmp_message_t * out
);
int32_t lr_bmp_codec_feed(
    lr_bmp_codec_t c,
    const uint8_t * data,
    uintptr_t len
);
int32_t lr_bmp_codec_next_message(lr_bmp_codec_t c, lr_bmp_message_t * out);
int32_t lr_bmp_codec_encode_vec(
    lr_bmp_codec_t c,
    lr_bmp_message_t m,
    struct lr_bytes_t * out
);
void lr_bmp_codec_free(lr_bmp_codec_t c);
uint8_t lr_bgp_cap_code_from_wire(uint8_t wire);
lr_bgp_capability_t lr_bgp_cap_four_octet_as(uint32_t asn);
uint8_t lr_bgp_cap_code(lr_bgp_capability_t cap);
uintptr_t lr_bgp_cap_value_len(lr_bgp_capability_t cap);
uintptr_t lr_bgp_cap_value(
    lr_bgp_capability_t cap,
    uint8_t * out,
    uintptr_t cap_size
);
uint32_t lr_bgp_cap_as_four_octet(lr_bgp_capability_t cap);
lr_bgp_capability_t lr_bgp_cap_multiprotocol(uint16_t afi, uint8_t safi);
uint8_t lr_bgp_cap_as_multiprotocol(
    lr_bgp_capability_t cap,
    uint16_t * out_afi,
    uint8_t * out_safi
);
lr_bgp_capability_t lr_bgp_cap_extended_next_hop(const struct lr_bgp_ext_next_hop_tuple_t * tuples, uintptr_t count);
uintptr_t lr_bgp_cap_extended_next_hop_len(lr_bgp_capability_t cap);
uintptr_t lr_bgp_cap_extended_next_hop_tuples(
    lr_bgp_capability_t cap,
    struct lr_bgp_ext_next_hop_tuple_t * out,
    uintptr_t cap_size
);
lr_bgp_capability_t lr_bgp_cap_new(
    uint8_t code,
    const uint8_t * value,
    uintptr_t value_len
);
void lr_bgp_cap_free(lr_bgp_capability_t cap);
lr_bgp_capability_t lr_bgp_cap_route_refresh(void);
lr_bgp_capability_t lr_bgp_cap_add_path(const struct lr_bgp_cap_add_path_family_t * families, uintptr_t count);
uintptr_t lr_bgp_cap_as_add_path_len(lr_bgp_capability_t cap);
uintptr_t lr_bgp_cap_as_add_path(
    lr_bgp_capability_t cap,
    struct lr_bgp_cap_add_path_family_t * out,
    uintptr_t cap_size
);
lr_bgp_capability_t lr_bgp_cap_enhanced_rr(void);
lr_bgp_capability_t lr_bgp_cap_graceful_restart(
    uint8_t restart_flags,
    uint16_t restart_time_secs,
    const struct lr_bgp_cap_gr_family_t * families,
    uintptr_t count
);
uint8_t lr_bgp_cap_as_graceful_restart(
    lr_bgp_capability_t cap,
    uint8_t * out_flags,
    uint16_t * out_time
);
uintptr_t lr_bgp_cap_as_graceful_restart_families_len(lr_bgp_capability_t cap);
uintptr_t lr_bgp_cap_as_graceful_restart_families(
    lr_bgp_capability_t cap,
    struct lr_bgp_cap_gr_family_t * out,
    uintptr_t cap_size
);
lr_bgp_capability_t lr_bgp_cap_long_lived_gr(const struct lr_bgp_cap_llgr_family_t * families, uintptr_t count);
uintptr_t lr_bgp_cap_as_long_lived_gr_len(lr_bgp_capability_t cap);
uintptr_t lr_bgp_cap_as_long_lived_gr(
    lr_bgp_capability_t cap,
    struct lr_bgp_cap_llgr_family_t * out,
    uintptr_t cap_size
);
int32_t lr_bgp_cap_encode_set(
    const lr_bgp_capability_t * caps,
    uintptr_t count,
    lr_bytes_t_handle * out
);
int32_t lr_bgp_cap_decode_set(
    const uint8_t * data,
    uintptr_t len,
    lr_bgp_capability_array_t * out_caps,
    uintptr_t * out_count
);
void lr_bgp_cap_bytes_free(lr_bytes_t_handle b);
uintptr_t lr_bgp_cap_bytes_len(lr_bytes_t_handle b);
const uint8_t * lr_bgp_cap_bytes_ptr(lr_bytes_t_handle b);
void lr_bgp_cap_array_free(lr_bgp_capability_array_t arr, uintptr_t count);
int32_t lr_bgp_encode_ipv4_nlri(
    const struct lr_prefix_t * prefixes,
    uintptr_t count,
    struct lr_bytes_t * out
);
int32_t lr_bgp_decode_ipv4_nlri(
    const uint8_t * data,
    uintptr_t len,
    struct lr_bytes_t * out
);
lr_damping_table_t lr_damping_table_new(const struct lr_damping_config_t * cfg);
int32_t lr_damping_table_config(lr_damping_table_t t, struct lr_damping_config_t * out);
int32_t lr_damping_default_config(struct lr_damping_config_t * out);
int32_t lr_damping_config_new(
    uint32_t additive_incr,
    uint32_t suppress_threshold,
    uint32_t reuse_threshold,
    uint32_t upper_limit,
    uint64_t decay_interval_s,
    double decay_factor_active,
    double decay_factor_withdrawn,
    struct lr_damping_config_t * out
);
int32_t lr_damping_config_validate(const struct lr_damping_config_t * cfg);
void lr_damping_config_free(struct lr_damping_config_t _cfg);
int32_t lr_damping_table_on_withdraw(
    lr_damping_table_t t,
    const struct lr_prefix_t * prefix,
    uint64_t now_s
);
int32_t lr_damping_table_on_announce(
    lr_damping_table_t t,
    const struct lr_prefix_t * prefix,
    uint64_t now_s
);
int32_t lr_damping_table_is_suppressed(lr_damping_table_t t, const struct lr_prefix_t * prefix);
int64_t lr_damping_table_decay_all(
    lr_damping_table_t t,
    uint64_t now_s,
    struct lr_prefix_t * out_reactivated,
    uintptr_t cap
);
int32_t lr_damping_table_forget(lr_damping_table_t t, const struct lr_prefix_t * prefix);
uintptr_t lr_damping_table_len(lr_damping_table_t t);
int32_t lr_damping_table_at(
    lr_damping_table_t t,
    uintptr_t index,
    struct lr_damping_entry_t * out
);
void lr_damping_table_free(lr_damping_table_t t);
uint8_t lr_bfd_auth_type_from_u8(uint8_t v);
uint8_t lr_bfd_auth_type_to_u8(uint8_t v);
const char * lr_bfd_auth_type_name(uint8_t v);
uint8_t lr_bfd_diagnostic_from_u8(uint8_t v);
uint8_t lr_bfd_diagnostic_to_u8(uint8_t v);
const char * lr_bfd_diagnostic_name(uint8_t v);
uint8_t lr_bfd_state_from_u8(uint8_t v);
uint8_t lr_bfd_state_to_u8(uint8_t v);
const char * lr_bfd_state_name(uint8_t v);
uint8_t lr_bfd_keyed_auth_algorithm_from_u8(uint8_t v);
uint8_t lr_bfd_keyed_auth_algorithm_to_u8(uint8_t v);
const char * lr_bfd_keyed_auth_algorithm_name(uint8_t v);
uint8_t lr_bmp_msg_type_from_u8(uint8_t v);
uint8_t lr_bmp_msg_type_to_u8(uint8_t v);
const char * lr_bmp_msg_type_name(uint8_t v);
uint8_t lr_bmp_peer_type_from_u8(uint8_t v);
uint8_t lr_bmp_peer_type_to_u8(uint8_t v);
const char * lr_bmp_peer_type_name(uint8_t v);
uint8_t lr_bmp_peer_down_reason_from_u8(uint8_t v);
uint8_t lr_bmp_peer_down_reason_to_u8(uint8_t v);
const char * lr_bmp_peer_down_reason_name(uint8_t v);
uint8_t lr_ospf_lsa_type_v2_from_u8(uint8_t v);
uint8_t lr_ospf_lsa_type_v2_to_u8(uint8_t v);
const char * lr_ospf_lsa_type_v2_name(uint8_t v);
uint16_t lr_ospf_lsa_type_v3_from_u16(uint16_t v);
uint16_t lr_ospf_lsa_type_v3_to_u16(uint16_t v);
const char * lr_ospf_lsa_type_v3_name(uint16_t v);
uint8_t lr_ospf_router_link_type_from_u8(uint8_t v);
uint8_t lr_ospf_router_link_type_to_u8(uint8_t v);
const char * lr_ospf_router_link_type_name(uint8_t v);
uint16_t lr_ldp_message_type_from_u16(uint16_t v);
uint16_t lr_ldp_message_type_to_u16(uint16_t v);
const char * lr_ldp_message_type_name(uint16_t v);
uint16_t lr_ldp_tlv_type_from_u16(uint16_t v);
uint16_t lr_ldp_tlv_type_to_u16(uint16_t v);
const char * lr_ldp_tlv_type_name(uint16_t v);
uint8_t lr_ldp_advertisement_mode_from_u8(uint8_t v);
uint8_t lr_ldp_advertisement_mode_to_u8(uint8_t v);
const char * lr_ldp_advertisement_mode_name(uint8_t v);
const char * lr_router_ospf_network_type_name(int32_t v);
const char * lr_router_session_error_kind_name(int32_t v);
const char * lr_mpls_label_stack_error_name(int32_t v);
lr_bgp_peer_config_t lr_bgp_peer_config_new(
    uint32_t local_as,
    uint32_t peer_as,
    const uint8_t * local_bgp_id
);
void lr_bgp_peer_config_free(lr_bgp_peer_config_t c);
uint32_t lr_bgp_peer_config_local_as(lr_bgp_peer_config_t c);
uint32_t lr_bgp_peer_config_peer_as(lr_bgp_peer_config_t c);
int32_t lr_bgp_peer_config_local_bgp_id(lr_bgp_peer_config_t c, uint32_t * out);
uint16_t lr_bgp_peer_config_hold_time(lr_bgp_peer_config_t c);
uint16_t lr_bgp_peer_config_keepalive(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_asn4(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_route_refresh(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_enhanced_rr(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_graceful_restart(lr_bgp_peer_config_t c);
uint16_t lr_bgp_peer_config_graceful_restart_time(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_long_lived(lr_bgp_peer_config_t c);
uint32_t lr_bgp_peer_config_long_lived_stale_time(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_is_rr_client(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_is_rs_client(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_default_ipv4_unicast(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_add_path(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_is_ebgp(lr_bgp_peer_config_t c);
uint16_t lr_bgp_peer_config_keepalive_interval(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_ipv4_unicast_active(lr_bgp_peer_config_t c);
uint8_t lr_bgp_peer_config_peer_role(lr_bgp_peer_config_t c);
int32_t lr_bgp_peer_config_set_hold_time(lr_bgp_peer_config_t c, uint16_t hold_time);
int32_t lr_bgp_peer_config_set_keepalive(lr_bgp_peer_config_t c, uint16_t keepalive);
int32_t lr_bgp_peer_config_set_asn4(lr_bgp_peer_config_t c, uint8_t asn4);
int32_t lr_bgp_peer_config_set_rr_client(lr_bgp_peer_config_t c, uint8_t enabled);
int32_t lr_bgp_peer_config_set_graceful_restart(lr_bgp_peer_config_t c, uint8_t enabled);
lr_mpls_label_t lr_mpls_label_new_value(uint32_t value);
uint8_t lr_mpls_label_is_valid_value(uint32_t value);
lr_mpls_label_t lr_mpls_label_try_new(uint32_t value);
lr_mpls_label_stack_t lr_mpls_label_stack_from_vec(const lr_mpls_label_t * labels, uintptr_t count);
int32_t lr_mpls_label_stack_into_vec(lr_mpls_label_stack_t stack, struct lr_bytes_t * out);
int32_t lr_bfd_auth_type_from_algorithm(int32_t algorithm);
lr_ospf_helper_entry_t lr_ospf_helper_entry_new(void);
void lr_ospf_helper_entry_free(lr_ospf_helper_entry_t h);
uint8_t lr_ospf_helper_entry_is_active(lr_ospf_helper_entry_t h);
uint64_t lr_ospf_helper_entry_grace_deadline_ms(lr_ospf_helper_entry_t h);
uint32_t lr_ospf_helper_entry_last_period_secs(lr_ospf_helper_entry_t h);
uint8_t lr_ospf_restart_tracker_recovering(lr_ospf_restart_tracker_t t);
uint64_t lr_ospf_restart_tracker_grace_deadline_ms(lr_ospf_restart_tracker_t t);
lr_session_config_t lr_session_config_bgp(
    uint32_t local_as,
    uint32_t peer_as,
    uint32_t local_bgp_id
);
lr_session_config_t lr_session_config_ospfv2(uint32_t router_id, uint32_t area_id);
lr_session_config_t lr_session_config_ospfv3(uint32_t router_id, uint32_t area_id);
lr_session_config_t lr_session_config_babel(const uint8_t * addr, uintptr_t addr_len);
void lr_session_config_free(lr_session_config_t c);
lr_session_config_t lr_session_config_with_mp_families(
    lr_session_config_t c,
    const struct lr_afi_safi_t * families,
    uintptr_t count
);
lr_session_config_t lr_session_config_with_add_path(lr_session_config_t c);
lr_session_config_t lr_session_config_with_extended_next_hop(lr_session_config_t c);
lr_session_config_t lr_session_config_with_extended_next_hop_tuple(
    lr_session_config_t c,
    uint16_t nlri_afi,
    uint8_t nlri_safi,
    uint16_t nexthop_afi
);
lr_session_config_t lr_session_config_with_graceful_restart(lr_session_config_t c, uint16_t restart_time_secs);
lr_session_config_t lr_session_config_with_long_lived_gr(lr_session_config_t c, uint32_t stale_time_secs);
lr_session_config_t lr_session_config_with_llgr_max_stale_time(lr_session_config_t c, uint32_t cap_secs);
lr_session_config_t lr_session_config_with_mrai_ms(lr_session_config_t c, uint64_t mrai_ms);
lr_session_config_t lr_session_config_with_route_reflector_client(lr_session_config_t c);
lr_session_config_t lr_session_config_with_maximum_prefix(
    lr_session_config_t c,
    uint32_t limit,
    int32_t action
);
lr_session_config_t lr_session_config_with_maximum_prefix_threshold(lr_session_config_t c, uint8_t pct);
lr_session_config_t lr_session_config_with_maximum_prefix_restart_time(lr_session_config_t c, uint32_t secs);
uint8_t lr_gtsm_error_is_kernel_unsupported(int32_t err_code);
uint8_t lr_tcp_auth_error_is_kernel_unsupported(int32_t err_code);
int32_t lr_policy_peephole_optimize(
    const uint8_t * data,
    uintptr_t len,
    struct lr_bytes_t * out
);
int32_t lr_policy_lexer_tokenize(const char * src, struct lr_bytes_t * out);
lr_filter_t lr_policy_parse_filter(const char * name, const char * src);
uint8_t lr_policy_value_truthy(int32_t value_kind);
uint8_t lr_policy_binary_op_precedence(int32_t op);
uint8_t lr_policy_route_field_is_settable(int32_t kind);
int32_t lr_ip_net_into_inner(const struct lr_prefix_t * net, struct lr_prefix_t * out);
struct lr_ldp_id_t lr_ldp_id_new(const uint8_t * lsr_id, uint16_t label_space);
int32_t lr_ldp_id_to_bytes(struct lr_ldp_id_t id, uint8_t * out);
struct lr_ldp_id_t lr_ldp_id_from_bytes(const uint8_t * bytes);
int32_t lr_ldp_encode_hello_pdu(
    struct lr_ldp_id_t sender,
    uint32_t message_id,
    uint16_t hold_time,
    uint8_t target,
    struct lr_bytes_t * out
);
int32_t lr_ldp_decode(
    const uint8_t * data,
    uintptr_t len,
    lr_ldp_pdu_t * out
);
struct lr_ldp_id_t lr_ldp_pdu_sender(lr_ldp_pdu_t pdu);
uint16_t lr_ldp_pdu_version(lr_ldp_pdu_t pdu);
uintptr_t lr_ldp_pdu_message_count(lr_ldp_pdu_t pdu);
uint16_t lr_ldp_pdu_message_type_at(lr_ldp_pdu_t pdu, uintptr_t index);
uint32_t lr_ldp_pdu_message_id_at(lr_ldp_pdu_t pdu, uintptr_t index);
uint8_t lr_ldp_pdu_message_u_bit_at(lr_ldp_pdu_t pdu, uintptr_t index);
void lr_ldp_pdu_free(lr_ldp_pdu_t pdu);
lr_ldp_discovery_config_t lr_ldp_discovery_config_new(uint32_t local_lsr_id, uint16_t local_label_space);
int32_t lr_ldp_discovery_config_set_transport_v4(lr_ldp_discovery_config_t cfg, const uint8_t * addr);
int32_t lr_ldp_discovery_config_set_transport_v6(lr_ldp_discovery_config_t cfg, const uint8_t * addr);
int32_t lr_ldp_discovery_config_set_link_hello_hold(lr_ldp_discovery_config_t cfg, uint16_t hold);
int32_t lr_ldp_discovery_config_set_targeted_hello_hold(lr_ldp_discovery_config_t cfg, uint16_t hold);
int32_t lr_ldp_discovery_config_set_prefer_ipv6(lr_ldp_discovery_config_t cfg, uint8_t prefer_ipv6);
int32_t lr_ldp_discovery_config_set_accept_targeted(lr_ldp_discovery_config_t cfg, uint8_t accept);
void lr_ldp_discovery_config_free(lr_ldp_discovery_config_t cfg);
lr_ldp_discovery_t lr_ldp_discovery_new(lr_ldp_discovery_config_t cfg);
uintptr_t lr_ldp_discovery_adjacency_count(lr_ldp_discovery_t d);
int32_t lr_ldp_discovery_adjacency_at(
    lr_ldp_discovery_t d,
    uintptr_t index,
    struct lr_ldp_hello_adjacency_t * out
);
int32_t lr_ldp_discovery_adjacency_for_peer(
    lr_ldp_discovery_t d,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space,
    struct lr_ldp_hello_adjacency_t * out
);
int32_t lr_ldp_discovery_remove_adjacencies_for_peer(
    lr_ldp_discovery_t d,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space
);
uintptr_t lr_ldp_discovery_tick(lr_ldp_discovery_t d, uint64_t now_ms);
uintptr_t lr_ldp_discovery_outgoing_count(lr_ldp_discovery_t d);
void lr_ldp_discovery_free(lr_ldp_discovery_t d);
void lr_ldp_engine_config_free(lr_ldp_engine_config_t c);
int32_t lr_ldp_engine_config_set_transport_addr_v6(lr_ldp_engine_config_t c, const uint8_t * transport_addr_v6);
int32_t lr_ldp_engine_config_set_prefer_ipv6(lr_ldp_engine_config_t c, uint8_t prefer_ipv6);
int32_t lr_ldp_engine_config_set_keepalive_time(lr_ldp_engine_config_t c, uint16_t keepalive_time);
int32_t lr_ldp_engine_config_set_max_pdu_len(lr_ldp_engine_config_t c, uint16_t max_pdu_len);
int32_t lr_ldp_engine_config_set_advertisement(lr_ldp_engine_config_t c, int32_t advertisement);
int32_t lr_ldp_engine_config_set_link_hello_hold(lr_ldp_engine_config_t c, uint16_t hold);
int32_t lr_ldp_engine_config_set_targeted_hello_hold(lr_ldp_engine_config_t c, uint16_t hold);
int32_t lr_ldp_engine_config_set_accept_targeted(lr_ldp_engine_config_t c, uint8_t accept);
int32_t lr_ldp_engine_config_set_loop_detection(
    lr_ldp_engine_config_t c,
    uint8_t enabled,
    uint8_t path_vector_limit
);
int32_t lr_ldp_engine_config_set_label_range(
    lr_ldp_engine_config_t c,
    uint32_t label_min,
    uint32_t label_max
);
int32_t lr_ldp_engine_config_add_reserved_label(lr_ldp_engine_config_t c, uint32_t label);
lr_ldp_engine_t lr_ldp_engine_new(lr_ldp_engine_config_t c);
void lr_ldp_engine_free(lr_ldp_engine_t e);
int32_t lr_ldp_engine_on_connected(
    lr_ldp_engine_t e,
    uint64_t now_ms,
    uint64_t conn,
    uint32_t peer_lsr,
    uint16_t peer_label_space
);
int32_t lr_ldp_engine_on_connect_failed(
    lr_ldp_engine_t e,
    uint32_t peer_lsr,
    uint16_t peer_label_space
);
int32_t lr_ldp_engine_feed_tcp(
    lr_ldp_engine_t e,
    uint64_t now_ms,
    uint64_t conn,
    const uint8_t * data,
    uintptr_t len
);
int32_t lr_ldp_engine_on_closed(
    lr_ldp_engine_t e,
    uint64_t now_ms,
    uint64_t conn
);
int32_t lr_ldp_engine_tick(lr_ldp_engine_t e, uint64_t now_ms);
int32_t lr_ldp_engine_shutdown_peer(
    lr_ldp_engine_t e,
    uint64_t now_ms,
    uint32_t peer_lsr,
    uint16_t peer_label_space
);
int32_t lr_ldp_engine_drain_udp(lr_ldp_engine_t e, struct lr_bytes_t * out);
int32_t lr_ldp_engine_drain_tcp(
    lr_ldp_engine_t e,
    uint64_t conn,
    struct lr_bytes_t * out
);
int32_t lr_ldp_engine_drain_tcp_all(lr_ldp_engine_t e, struct lr_bytes_t * out);
uintptr_t lr_ldp_engine_transit_label_count(lr_ldp_engine_t e);
uintptr_t lr_ldp_engine_adjacency_count(lr_ldp_engine_t e);
int32_t lr_ldp_engine_adjacency_at(
    lr_ldp_engine_t e,
    uintptr_t index,
    uint32_t * out_peer_lsr,
    uint16_t * out_peer_label_space,
    int32_t * out_kind,
    uint8_t * out_source_is_ipv6,
    uint8_t * source_addr,
    uint8_t * out_transport_is_ipv6,
    uint8_t * transport_addr,
    uint32_t * out_hold_time_secs,
    uint64_t * out_last_seen_ms,
    uint8_t * out_config_seq_present,
    uint32_t * out_config_seq,
    uint8_t * out_dual_stack_present,
    uint8_t * out_dual_stack_prefer_ipv6
);
int32_t lr_ldp_engine_session_state(
    lr_ldp_engine_t e,
    uint32_t peer_lsr,
    uint16_t peer_label_space
);
uintptr_t lr_ldp_engine_take_events(
    lr_ldp_engine_t e,
    struct lr_ldp_engine_event_t * out,
    uintptr_t cap
);
lr_ldp_label_store_t lr_ldp_label_store_new(void);
void lr_ldp_label_store_free(lr_ldp_label_store_t s);
uint8_t lr_ldp_label_store_learn(
    lr_ldp_label_store_t s,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t label
);
uint8_t lr_ldp_label_store_unlearn(
    lr_ldp_label_store_t s,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t * out_label
);
uint8_t lr_ldp_label_store_label_from(
    lr_ldp_label_store_t s,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t * out_label
);
uintptr_t lr_ldp_label_store_unlearn_peer(
    lr_ldp_label_store_t s,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space
);
uintptr_t lr_ldp_label_store_unlearn_by_label(
    lr_ldp_label_store_t s,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space,
    uint32_t label,
    struct lr_ldp_prefix_t * out_prefixes,
    uintptr_t cap
);
uintptr_t lr_ldp_label_store_unlearn_all_from(
    lr_ldp_label_store_t s,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space,
    struct lr_ldp_prefix_t * out_prefixes,
    uintptr_t cap
);
uint8_t lr_ldp_label_store_advertise(
    lr_ldp_label_store_t s,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t label,
    uint32_t * out_previous
);
uint8_t lr_ldp_label_store_withdraw_advertised(
    lr_ldp_label_store_t s,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t * out_label
);
uint8_t lr_ldp_label_store_advertised_label(
    lr_ldp_label_store_t s,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t * out_label
);
lr_ldp_session_t lr_ldp_session_new(
    uint32_t local_lsr_id,
    uint16_t local_label_space,
    uint32_t peer_lsr_id,
    uint16_t peer_label_space,
    uint16_t keepalive_time,
    uint16_t max_pdu_len
);
void lr_ldp_session_free(lr_ldp_session_t r);
int32_t lr_ldp_session_state(lr_ldp_session_t r);
uint8_t lr_ldp_session_is_operational(lr_ldp_session_t r);
int32_t lr_ldp_session_start(lr_ldp_session_t r, uint64_t now_ms);
int32_t lr_ldp_session_drain_outgoing(lr_ldp_session_t r, struct lr_bytes_t * out);
int32_t lr_ldp_session_peer(lr_ldp_session_t r, struct lr_ldp_id_t * out);
int32_t lr_ldp_session_negotiated(
    lr_ldp_session_t r,
    uint16_t * out_keepalive,
    uint16_t * out_max_pdu_len
);
int32_t lr_ldp_session_tick(lr_ldp_session_t r, uint64_t now_ms);
int32_t lr_ldp_session_transport_closed(lr_ldp_session_t r);
int32_t lr_ldp_session_shutdown(lr_ldp_session_t r, uint64_t now_ms);
int32_t lr_ldp_session_feed_pdu(
    lr_ldp_session_t r,
    lr_ldp_pdu_t pdu,
    uint64_t now_ms
);
int32_t lr_ldp_session_send_label_mapping(
    lr_ldp_session_t r,
    uint32_t message_id,
    lr_ldp_fec_t fec,
    lr_ldp_label_t label
);
int32_t lr_ldp_session_send_label_withdraw(
    lr_ldp_session_t r,
    uint32_t message_id,
    lr_ldp_fec_t fec,
    lr_ldp_label_t label
);
int32_t lr_ldp_session_send_label_request(
    lr_ldp_session_t r,
    uint32_t message_id,
    lr_ldp_fec_t fec
);
int32_t lr_ldp_session_send_label_release(
    lr_ldp_session_t r,
    uint32_t message_id,
    lr_ldp_fec_t fec,
    lr_ldp_label_t label,
    uint32_t status_code
);
int32_t lr_ldp_session_send_address_message(
    lr_ldp_session_t r,
    const uint8_t * addrs,
    uintptr_t count,
    uint8_t is_ipv6
);
int32_t lr_ldp_session_enqueue_notification(
    lr_ldp_session_t r,
    uint32_t status_code,
    uint32_t msg_id,
    uint16_t msg_type
);
lr_ldp_label_t lr_ldp_label_new(uint32_t value);
uint32_t lr_ldp_label_value(lr_ldp_label_t l);
uint8_t lr_ldp_label_is_valid(lr_ldp_label_t l);
void lr_ldp_label_free(lr_ldp_label_t l);
lr_ldp_fec_t lr_ldp_fec_new_wildcard(void);
lr_ldp_fec_t lr_ldp_fec_new_prefix(
    const uint8_t * prefix_v4,
    const uint8_t * prefix_v6,
    uint8_t prefix_len
);
uint8_t lr_ldp_fec_is_wildcard(lr_ldp_fec_t f);
int32_t lr_ldp_fec_single_prefix(
    lr_ldp_fec_t f,
    uint8_t * octets_out,
    uint8_t * prefix_len_out,
    uint8_t * present_out
);
void lr_ldp_fec_free(lr_ldp_fec_t f);
uint32_t lr_ldp_status_code_new(uint32_t code);
uint8_t lr_ldp_status_code_is_fatal(uint32_t code);
uint8_t lr_ldp_status_code_is_forward(uint32_t code);
lr_ldp_transit_t lr_ldp_transit_new(
    uint32_t label_min,
    uint32_t label_max,
    const uint32_t * reserved,
    uintptr_t reserved_count
);
void lr_ldp_transit_free(lr_ldp_transit_t a);
uint8_t lr_ldp_transit_label_of(
    lr_ldp_transit_t a,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t * out_label
);
uint8_t lr_ldp_transit_is_allocated(
    lr_ldp_transit_t a,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len
);
uintptr_t lr_ldp_transit_allocated_count(lr_ldp_transit_t a);
uint8_t lr_ldp_transit_allocate(
    lr_ldp_transit_t a,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t * out_label
);
uint8_t lr_ldp_transit_release(
    lr_ldp_transit_t a,
    const uint8_t * prefix_addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t * out_label
);
uint32_t lr_babel_link_cost(uint16_t rxcost);
int32_t lr_ldp_compare_transport_addrs(
    uint8_t a_is_v6,
    const uint8_t * a,
    uint8_t b_is_v6,
    const uint8_t * b
);
int32_t lr_ldp_role_for(
    uint8_t local_is_v6,
    const uint8_t * local,
    uint8_t remote_is_v6,
    const uint8_t * remote
);
int32_t lr_ospf_sr_remote_label(
    uint32_t srgb_base,
    uint32_t srgb_range,
    uint32_t sid,
    uint8_t flags,
    uint32_t * out,
    uint8_t * out_present
);
int32_t lr_ospf_sr_encode_ri_lsa_body(
    uint32_t srgb_base,
    uint32_t srgb_range,
    struct lr_bytes_t * out
);
int32_t lr_ospf_sr_decode_ri_lsa_body(
    const uint8_t * data,
    uintptr_t len,
    uint32_t * out_srgb_base,
    uint32_t * out_srgb_range,
    uint8_t * out_present
);
uint8_t lr_ospf_sr_opaque_type_from_lsid(uint32_t link_state_id);
int32_t lr_mpls_label_stack_decode_3octet_count(
    const uint8_t * data,
    uintptr_t len,
    uintptr_t count,
    lr_mpls_label_stack_t * out
);
uint8_t lr_mpls_label_stack_all_reserved(lr_mpls_label_stack_t stack);
uint8_t lr_mpls_label_stack_contains(lr_mpls_label_stack_t stack, lr_mpls_label_t label);
int32_t lr_mpls_stack_last_err_code(void);
int32_t lr_mrt_decode(
    const uint8_t * data,
    uintptr_t len,
    lr_mrt_record_t * out
);
int32_t lr_mrt_encode_peer_index_table(
    uint32_t timestamp,
    uint32_t collector_bgp_id,
    const char * view_name,
    const struct lr_mrt_peer_entry_t * peers,
    uintptr_t peer_count,
    struct lr_bytes_t * out
);
int32_t lr_mrt_encode_rib_table(
    uint32_t timestamp,
    uint32_t sequence,
    const uint8_t * prefix_addr,
    uint8_t prefix_len,
    uint8_t is_ipv6,
    uint8_t add_path,
    const struct lr_mrt_rib_entry_t * entries,
    uintptr_t entry_count,
    struct lr_bytes_t * out
);
uint8_t lr_mrt_record_type(lr_mrt_record_t record);
uint8_t lr_mrt_record_is_rib(lr_mrt_record_t record);
int32_t lr_mrt_record_unknown_subtype(
    lr_mrt_record_t record,
    uint16_t * out_msg_type,
    uint16_t * out_subtype
);
void lr_mrt_record_free(lr_mrt_record_t record);
int32_t lr_mrt_walk_attributes(
    const struct lr_mrt_rib_entry_t * entry,
    struct lr_mrt_attr_summary_t * out_summary,
    uint8_t * as_path_buf,
    uintptr_t as_path_cap,
    uint8_t * communities_buf,
    uintptr_t communities_cap
);
lr_mrt_rib_dump_t lr_mrt_rib_dump_new(uint32_t collector_bgp_id, const char * view_name);
uint16_t lr_mrt_rib_dump_add_peer(lr_mrt_rib_dump_t dump, struct lr_mrt_peer_entry_t peer);
int32_t lr_mrt_rib_dump_add_table(
    lr_mrt_rib_dump_t dump,
    uint32_t sequence,
    const uint8_t * prefix_addr,
    uint8_t prefix_len,
    uint8_t is_ipv6,
    uint8_t add_path,
    const struct lr_mrt_rib_entry_t * entries,
    uintptr_t entry_count
);
int32_t lr_mrt_rib_dump_encode(
    lr_mrt_rib_dump_t dump,
    uint32_t timestamp,
    struct lr_bytes_t * out
);
void lr_mrt_rib_dump_free(lr_mrt_rib_dump_t dump);
lr_mrt_record_t lr_mrt_record_bgp4mp_message(
    uint32_t peer_as,
    uint32_t local_as,
    uint16_t ifindex,
    uint16_t af,
    const uint8_t * peer_addr,
    uintptr_t peer_addr_len,
    const uint8_t * local_addr,
    uintptr_t local_addr_len,
    const uint8_t * message,
    uintptr_t message_len
);
lr_mrt_record_t lr_mrt_record_bgp4mp_state_change(
    uint32_t peer_as,
    uint32_t local_as,
    uint16_t ifindex,
    uint16_t af,
    const uint8_t * peer_addr,
    uintptr_t peer_addr_len,
    const uint8_t * local_addr,
    uintptr_t local_addr_len,
    uint16_t old_state,
    uint16_t new_state
);
uint8_t lr_mrt_record_peer_index_table_summary(
    lr_mrt_record_t record,
    uint32_t * out_collector_bgp_id,
    uintptr_t * out_view_name_len,
    uintptr_t * out_peer_count
);
uintptr_t lr_mrt_record_peer_index_table_view_name(
    lr_mrt_record_t record,
    uint8_t * out,
    uintptr_t out_len
);
uint8_t lr_mrt_record_peer_index_table_peer_at(
    lr_mrt_record_t record,
    uintptr_t index,
    struct lr_mrt_peer_entry_t * out
);
uint8_t lr_mrt_record_rib_table_summary(
    lr_mrt_record_t record,
    uint32_t * out_sequence,
    struct lr_prefix_t * out_prefix,
    uint8_t * out_add_path,
    uintptr_t * out_entry_count
);
uint8_t lr_mrt_record_rib_table_entry_at(
    lr_mrt_record_t record,
    uintptr_t index,
    struct lr_mrt_rib_entry_t * out
);
int32_t lr_mrt_encode_attributes(lr_attributes_t attrs, struct lr_bytes_t * out);
lr_mrt_reader_t lr_mrt_reader_new(void);
int32_t lr_mrt_reader_decode_slice(
    lr_mrt_reader_t r,
    const uint8_t * data,
    uintptr_t len,
    lr_mrt_record_t * out
);
int32_t lr_mrt_reader_feed(
    lr_mrt_reader_t r,
    const uint8_t * data,
    uintptr_t len
);
int32_t lr_mrt_reader_next_record(lr_mrt_reader_t r, lr_mrt_record_t * out);
void lr_mrt_reader_free(lr_mrt_reader_t r);
int32_t lr_ospf_decode_v2_packet(
    const uint8_t * data,
    uintptr_t len,
    lr_ospf_packet_t * out
);
int32_t lr_ospf_decode_v3_packet(
    const uint8_t * data,
    uintptr_t len,
    lr_ospf_packet_t * out
);
int32_t lr_ospf_encode_packet(lr_ospf_packet_t packet, struct lr_bytes_t * out);
uint8_t lr_ospf_packet_version(lr_ospf_packet_t packet);
uint8_t lr_ospf_packet_type(lr_ospf_packet_t packet);
uint32_t lr_ospf_packet_router_id(lr_ospf_packet_t packet);
uint32_t lr_ospf_packet_area_id(lr_ospf_packet_t packet);
uint8_t lr_ospf_packet_body_kind(lr_ospf_packet_t packet);
void lr_ospf_packet_free(lr_ospf_packet_t packet);
uint8_t lr_ospf_finalize_v2_packet(uint8_t * bytes, uintptr_t len);
uintptr_t lr_ospf_finalize_v2_stream(uint8_t * bytes, uintptr_t len);
uint8_t lr_ospf_v2_packet_checksum_ok(const uint8_t * bytes, uintptr_t len);
uint8_t lr_ospf_finalize_v3_packet(
    uint8_t * bytes,
    uintptr_t len,
    const uint8_t * src,
    const uint8_t * dst
);
uintptr_t lr_ospf_finalize_v3_stream(
    uint8_t * bytes,
    uintptr_t len,
    const uint8_t * src,
    const uint8_t * dst
);
lr_ospf_summary_dest_t lr_ospf_summary_dest_new(
    const uint8_t * prefix_v4,
    const uint8_t * prefix_v6,
    uint8_t prefix_len,
    uint32_t metric
);
uint32_t lr_ospf_summary_dest_metric(lr_ospf_summary_dest_t d);
int32_t lr_ospf_summary_dest_prefix(
    lr_ospf_summary_dest_t d,
    uint8_t * octets_out,
    uint8_t * prefix_len_out
);
void lr_ospf_summary_dest_free(lr_ospf_summary_dest_t d);
int32_t lr_ospf_summary_lsa_id_for(
    const uint8_t * prefix_v4,
    const uint8_t * prefix_v6,
    uint8_t prefix_len,
    const uint32_t * existing,
    uintptr_t count,
    uint32_t * out
);
int32_t lr_ospf_originate_summary_lsa(
    uint32_t router_id,
    lr_ospf_summary_dest_t dest,
    const uint32_t * prev_seq,
    lr_ospf_lsa_box_t * out
);
int32_t lr_ospf_flush_summary_lsa(lr_ospf_lsa_box_t existing, lr_ospf_lsa_box_t * out);
int32_t lr_ospf_originate_v3_inter_area_prefix_lsa(
    uint32_t router_id,
    uint32_t ls_id,
    lr_ospf_summary_dest_t dest,
    const uint32_t * prev_seq,
    lr_ospf_lsa_box_t * out
);
lr_ospf_nssa_default_t lr_ospf_nssa_default_new(uint32_t metric);
void lr_ospf_nssa_default_free(lr_ospf_nssa_default_t d);
int32_t lr_ospf_originate_nssa_lsa(
    uint32_t router_id,
    lr_ospf_external_dest_t dest,
    const uint32_t * prev_seq,
    lr_ospf_lsa_box_t * out
);
int32_t lr_ospf_flush_nssa_lsa(lr_ospf_lsa_box_t existing, lr_ospf_lsa_box_t * out);
int32_t lr_ospf_originate_nssa_default_lsa(
    uint32_t router_id,
    lr_ospf_nssa_default_t default_dest,
    const uint32_t * prev_seq,
    lr_ospf_lsa_box_t * out
);
uint8_t lr_ospf_is_elected_translator(lr_ospf_lsdb_t lsdb, uint32_t router_id);
uint8_t lr_ospf_nssa_p_bit_set(lr_ospf_lsa_box_t lsa);
lr_ospf_nssa_route_vec_t lr_ospf_nssa_routes(
    lr_ospf_lsdb_t lsdb,
    lr_ospf_spf_result_t spf_result,
    struct lr_ospf_nssa_calc_opts_t opts
);
lr_ospf_external_route_v3_vec_t lr_ospf_nssa_routes_v3(
    lr_ospf_lsdb_t lsdb,
    lr_ospf_spf_v3_result_t spf_result,
    struct lr_ospf_nssa_calc_opts_t opts
);
lr_ospf_external_route_v3_vec_t lr_ospf_nssa_routes_v3_extended(
    lr_ospf_lsdb_t lsdb,
    lr_ospf_spf_v3_result_t spf_result,
    struct lr_ospf_nssa_calc_opts_t opts
);
uint16_t lr_ospf_au_type_from_u16(uint16_t wire);
uint16_t lr_ospf_au_type_to_u16(uint16_t value);
const char * lr_ospf_au_type_name(uint16_t value);
lr_ospf_simple_password_t lr_ospf_simple_password_new(const uint8_t * password, uintptr_t password_len);
uintptr_t lr_ospf_simple_password_password(lr_ospf_simple_password_t p, uint8_t * out);
void lr_ospf_simple_password_free(lr_ospf_simple_password_t p);
uint8_t lr_ospf_crypto_algorithm_to_u8(uint8_t value);
uint8_t lr_ospf_crypto_algorithm_from_u8(uint8_t value);
const char * lr_ospf_crypto_algorithm_name(uint8_t value);
uintptr_t lr_ospf_crypto_algorithm_digest_len(uint8_t value);
uintptr_t lr_ospf_crypto_algorithm_trailer_len(uint8_t value);
lr_ospf_crypto_auth_t lr_ospf_crypto_auth_new(
    uint8_t key_id,
    const uint8_t * key,
    uintptr_t key_len
);
int32_t lr_ospf_crypto_auth_with_sha1(lr_ospf_crypto_auth_t c);
uint8_t lr_ospf_crypto_auth_key_id(lr_ospf_crypto_auth_t c);
uint8_t lr_ospf_crypto_auth_algorithm(lr_ospf_crypto_auth_t c);
uint32_t lr_ospf_crypto_auth_crypto_seq(lr_ospf_crypto_auth_t c);
int32_t lr_ospf_crypto_auth_advance_seq(lr_ospf_crypto_auth_t c);
uintptr_t lr_ospf_crypto_auth_key(
    lr_ospf_crypto_auth_t c,
    uint8_t * out,
    uintptr_t out_len
);
uintptr_t lr_ospf_crypto_auth_key_len(lr_ospf_crypto_auth_t c);
void lr_ospf_crypto_auth_free(lr_ospf_crypto_auth_t c);
lr_ospf_v3_auth_t lr_ospf_v3_auth_new(
    uint16_t sa_id,
    const uint8_t * key,
    uintptr_t key_len
);
int32_t lr_ospf_v3_auth_with_sha1(lr_ospf_v3_auth_t v);
int32_t lr_ospf_v3_auth_with_source(lr_ospf_v3_auth_t v, const uint8_t * source);
uint16_t lr_ospf_v3_auth_sa_id(lr_ospf_v3_auth_t v);
uint8_t lr_ospf_v3_auth_algorithm(lr_ospf_v3_auth_t v);
uintptr_t lr_ospf_v3_auth_trailer_len(lr_ospf_v3_auth_t v);
uintptr_t lr_ospf_v3_auth_key(
    lr_ospf_v3_auth_t v,
    uint8_t * out,
    uintptr_t out_len
);
uintptr_t lr_ospf_v3_auth_key_len(lr_ospf_v3_auth_t v);
void lr_ospf_v3_auth_free(lr_ospf_v3_auth_t v);
uint32_t lr_ospf_hello_network_mask(lr_ospf_packet_t p);
uint16_t lr_ospf_hello_interval(lr_ospf_packet_t p);
uint32_t lr_ospf_hello_options(lr_ospf_packet_t p);
uint8_t lr_ospf_hello_priority(lr_ospf_packet_t p);
uint32_t lr_ospf_hello_dead_interval(lr_ospf_packet_t p);
uint32_t lr_ospf_hello_dr(lr_ospf_packet_t p);
uint32_t lr_ospf_hello_bdr(lr_ospf_packet_t p);
uintptr_t lr_ospf_hello_neighbor_count(lr_ospf_packet_t p);
uint32_t lr_ospf_hello_neighbor_at(lr_ospf_packet_t p, uintptr_t index);
uint16_t lr_ospf_db_desc_mtu(lr_ospf_packet_t p);
uint32_t lr_ospf_db_desc_options(lr_ospf_packet_t p);
uint8_t lr_ospf_db_desc_flags(lr_ospf_packet_t p);
uint32_t lr_ospf_db_desc_seq(lr_ospf_packet_t p);
uintptr_t lr_ospf_db_desc_lsa_header_count(lr_ospf_packet_t p);
int32_t lr_ospf_db_desc_lsa_header_at(
    lr_ospf_packet_t p,
    uintptr_t index,
    struct lr_ospf_lsa_hdr_t * out
);
uint32_t lr_ospf_ls_update_lsa_count(lr_ospf_packet_t p);
uintptr_t lr_ospf_ls_update_lsa_len(lr_ospf_packet_t p);
lr_ospf_db_exchange_t lr_ospf_db_exchange_new(
    uint32_t router_id,
    uint32_t area_id,
    uint16_t iface_mtu
);
lr_ospf_db_exchange_t lr_ospf_db_exchange_with_version(
    uint32_t router_id,
    uint32_t area_id,
    uint16_t iface_mtu,
    uint8_t version
);
int32_t lr_ospf_db_exchange_with_rxmt_interval(lr_ospf_db_exchange_t e, uint64_t ms);
void lr_ospf_db_exchange_free(lr_ospf_db_exchange_t e);
uint64_t lr_ospf_db_exchange_rxmt_interval_ms(lr_ospf_db_exchange_t e);
int32_t lr_ospf_db_exchange_phase(lr_ospf_db_exchange_t e);
uint8_t lr_ospf_db_exchange_is_full(lr_ospf_db_exchange_t e);
uint8_t lr_ospf_db_exchange_started(lr_ospf_db_exchange_t e);
int32_t lr_ospf_db_exchange_restart(lr_ospf_db_exchange_t e, uint32_t seq);
lr_ospf_packet_t lr_ospf_db_exchange_initial_db_desc(
    lr_ospf_db_exchange_t e,
    uint32_t seq,
    uint64_t now_ms
);
int32_t lr_ospf_db_exchange_poll(
    lr_ospf_db_exchange_t e,
    uint64_t now_ms,
    lr_ospf_packet_t ** out_packets,
    uintptr_t * out_count
);
void lr_ospf_db_exchange_packet_array_free(lr_ospf_packet_t * packets, uintptr_t count);
lr_ospf_packet_t lr_ospf_db_exchange_take_ls_request(lr_ospf_db_exchange_t e, uint64_t now_ms);
uintptr_t lr_ospf_db_exchange_pending_requests(lr_ospf_db_exchange_t e);
int32_t lr_ospf_db_exchange_on_db_desc_packet(
    lr_ospf_db_exchange_t e,
    lr_ospf_neighbor_t neighbor,
    lr_ospf_lsdb_t lsdb,
    const uint8_t * data,
    uintptr_t len,
    uint64_t now_ms,
    struct lr_ospf_exchange_step_t * out
);
int32_t lr_ospf_db_exchange_on_ls_request_packet(
    lr_ospf_db_exchange_t e,
    lr_ospf_neighbor_t neighbor,
    lr_ospf_lsdb_t lsdb,
    const uint8_t * data,
    uintptr_t len,
    uint64_t now_ms,
    struct lr_ospf_exchange_step_t * out
);
int32_t lr_ospf_db_exchange_on_ls_update_packet(
    lr_ospf_db_exchange_t e,
    lr_ospf_neighbor_t neighbor,
    const uint8_t * data,
    uintptr_t len,
    struct lr_ospf_exchange_step_t * out
);
void lr_ospf_db_exchange_step_free(struct lr_ospf_exchange_step_t * step);
int32_t lr_ospf_packet_type_from_u8(uint8_t v);
const char * lr_ospf_packet_type_name(uint8_t v);
int32_t lr_ospf_version_from_u8(uint8_t v);
const char * lr_ospf_neighbor_state_name(uint8_t state);
const char * lr_ospf_if_state_name(uint8_t state);
const char * lr_ospf_db_exchange_phase_name(uint8_t phase);
uint8_t lr_ospf_external_metric_type_e_bit(uint8_t t);
uint8_t lr_ospf_external_metric_type_from_e_bit(uint8_t e_bit);
int32_t lr_ospf_grace_tlv_type_from_u16(uint16_t v);
int32_t lr_ospf_grace_reason_from_u8(uint8_t v);
uint16_t lr_ospf_router_lsa_flags_to_word(
    uint8_t virtual_link,
    uint8_t asbr,
    uint8_t border
);
int32_t lr_ospf_router_lsa_flags_from_word(
    uint16_t word,
    uint8_t * out_v,
    uint8_t * out_e,
    uint8_t * out_b
);
int32_t lr_ospf_external_dest_prefix(
    lr_ospf_external_dest_t d,
    uint8_t * octets_out,
    uint8_t * prefix_len_out
);
lr_ospf_asbr_dest_t lr_ospf_asbr_dest_new(uint32_t asbr, uint32_t metric);
uint32_t lr_ospf_asbr_dest_asbr(lr_ospf_asbr_dest_t d);
uint32_t lr_ospf_asbr_dest_metric(lr_ospf_asbr_dest_t d);
void lr_ospf_asbr_dest_free(lr_ospf_asbr_dest_t d);
int32_t lr_ospf_originate_external_lsa(
    uint32_t router_id,
    lr_ospf_external_dest_t dest,
    const uint32_t * prev_seq,
    lr_ospf_lsa_box_t * out
);
int32_t lr_ospf_flush_external_lsa(lr_ospf_lsa_box_t existing, lr_ospf_lsa_box_t * out);
int32_t lr_ospf_originate_summary_asbr_lsa(
    uint32_t router_id,
    lr_ospf_asbr_dest_t asbr_dest,
    const uint32_t * prev_seq,
    lr_ospf_lsa_box_t * out
);
lr_ospf_external_route_vec_t lr_ospf_external_routes(lr_ospf_lsdb_t lsdb, lr_ospf_spf_result_t spf_result);
uintptr_t lr_ospf_external_route_vec_len(lr_ospf_external_route_vec_t v);
lr_ospf_external_route_t lr_ospf_external_route_vec_at(lr_ospf_external_route_vec_t v, uintptr_t index);
void lr_ospf_external_route_vec_free(lr_ospf_external_route_vec_t v);
int32_t lr_ospf_external_route_prefix(
    lr_ospf_external_route_t r,
    uint8_t * octets_out,
    uint8_t * prefix_len_out
);
uint64_t lr_ospf_external_route_metric(lr_ospf_external_route_t r);
int32_t lr_ospf_external_route_metric_type(lr_ospf_external_route_t r);
uint64_t lr_ospf_external_route_internal_cost(lr_ospf_external_route_t r);
uint32_t lr_ospf_external_route_asbr(lr_ospf_external_route_t r);
int32_t lr_ospf_external_route_border_router(
    lr_ospf_external_route_t r,
    uint8_t * present,
    uint32_t * border_router
);
uint32_t lr_ospf_external_route_forwarding_addr(lr_ospf_external_route_t r);
uint32_t lr_ospf_external_route_tag(lr_ospf_external_route_t r);
lr_ospf_external_route_v3_vec_t lr_ospf_external_routes_v3(lr_ospf_lsdb_t lsdb, lr_ospf_spf_v3_result_t spf_result);
lr_ospf_external_route_v3_vec_t lr_ospf_external_routes_v3_extended(lr_ospf_lsdb_t lsdb, lr_ospf_spf_v3_result_t spf_result);
uintptr_t lr_ospf_external_route_v3_vec_len(lr_ospf_external_route_v3_vec_t v);
lr_ospf_external_route_v3_t lr_ospf_external_route_v3_vec_at(lr_ospf_external_route_v3_vec_t v, uintptr_t index);
void lr_ospf_external_route_v3_vec_free(lr_ospf_external_route_v3_vec_t v);
int32_t lr_ospf_external_route_v3_prefix(
    lr_ospf_external_route_v3_t r,
    uint8_t * octets_out,
    uint8_t * prefix_len_out
);
uint64_t lr_ospf_external_route_v3_metric(lr_ospf_external_route_v3_t r);
int32_t lr_ospf_external_route_v3_metric_type(lr_ospf_external_route_v3_t r);
uint64_t lr_ospf_external_route_v3_internal_cost(lr_ospf_external_route_v3_t r);
uint32_t lr_ospf_external_route_v3_asbr(lr_ospf_external_route_v3_t r);
int32_t lr_ospf_external_route_v3_border_router(
    lr_ospf_external_route_v3_t r,
    uint8_t * present,
    uint32_t * border_router
);
int32_t lr_ospf_external_route_v3_next_hop(
    lr_ospf_external_route_v3_t r,
    uint8_t * octets_out,
    uint8_t * present_out
);
int32_t lr_ospf_external_route_v3_route_tag(
    lr_ospf_external_route_v3_t r,
    uint8_t * present,
    uint32_t * tag
);
lr_ospf_interface_t lr_ospf_interface_new(uint32_t area_id);
void lr_ospf_interface_free(lr_ospf_interface_t i);
uint8_t lr_ospf_interface_state(lr_ospf_interface_t i);
uint8_t lr_ospf_interface_priority(lr_ospf_interface_t i);
uint16_t lr_ospf_interface_hello_interval(lr_ospf_interface_t i);
uint32_t lr_ospf_interface_dead_interval(lr_ospf_interface_t i);
uint32_t lr_ospf_interface_dr(lr_ospf_interface_t i);
uint32_t lr_ospf_interface_bdr(lr_ospf_interface_t i);
uint32_t lr_ospf_interface_area_id(lr_ospf_interface_t i);
uint32_t lr_ospf_interface_router_id(lr_ospf_interface_t i);
uint32_t lr_ospf_interface_ip(lr_ospf_interface_t i);
int32_t lr_ospf_interface_set_priority(lr_ospf_interface_t i, uint8_t priority);
int32_t lr_ospf_interface_set_hello_interval(lr_ospf_interface_t i, uint16_t hello_interval);
int32_t lr_ospf_interface_set_dead_interval(lr_ospf_interface_t i, uint32_t dead_interval);
int32_t lr_ospf_interface_set_router_id(lr_ospf_interface_t i, uint32_t router_id);
int32_t lr_ospf_interface_set_ip(lr_ospf_interface_t i, uint32_t ip);
int32_t lr_ospf_interface_step_interface_up(
    lr_ospf_interface_t i,
    lr_ospf_if_action_t ** out_array,
    uintptr_t * out_count
);
int32_t lr_ospf_interface_step_interface_down(
    lr_ospf_interface_t i,
    lr_ospf_if_action_t ** out_array,
    uintptr_t * out_count
);
int32_t lr_ospf_interface_step_wait_timer(
    lr_ospf_interface_t i,
    lr_ospf_if_action_t ** out_array,
    uintptr_t * out_count
);
int32_t lr_ospf_interface_step_backup_seen(
    lr_ospf_interface_t i,
    lr_ospf_if_action_t ** out_array,
    uintptr_t * out_count
);
int32_t lr_ospf_interface_step_neighbor_change(
    lr_ospf_interface_t i,
    const struct lr_ospf_elector_t * electors,
    uintptr_t count,
    lr_ospf_if_action_t ** out_array,
    uintptr_t * out_count
);
uint8_t lr_ospf_interface_action_kind(lr_ospf_if_action_t a);
int32_t lr_ospf_interface_action_peer_state_name(
    lr_ospf_if_action_t a,
    uint8_t * out,
    uintptr_t cap
);
void lr_ospf_interface_action_free(lr_ospf_if_action_t a);
void lr_ospf_interface_action_array_free(lr_ospf_if_action_t * array, uintptr_t count);
int32_t lr_ospf_elect(
    const struct lr_ospf_elector_t * electors,
    uintptr_t count,
    uint32_t self_router_id,
    uint32_t self_ip,
    uint8_t self_priority,
    uint32_t self_stated_dr,
    uint32_t self_stated_bdr,
    uint32_t * out_dr,
    uint32_t * out_bdr
);
int32_t lr_ospf_elect_v3(
    const struct lr_ospf_v3_elector_t * electors,
    uintptr_t count,
    uint32_t self_router_id,
    uint8_t self_priority,
    uint32_t self_stated_dr,
    uint32_t self_stated_bdr,
    uint32_t * out_dr,
    uint32_t * out_bdr
);
uint32_t lr_ospf_clamp_grace_period(uint32_t secs);
uint32_t lr_ospf_mask_to_prefix_len(uint32_t mask);
uint32_t lr_ospf_prefix_len_to_mask(uint8_t len);
uint16_t lr_ospf_grace_lsa_type(void);
uint32_t lr_ospf_opaque_lsa_id(uint8_t opaque_type, uint32_t opaque_id);
int32_t lr_ospf_unpack_opaque_lsa_id(
    uint32_t link_state_id,
    uint8_t * out_type,
    uint32_t * out_id
);
uint8_t lr_ospf_with_grace_restart_capable(uint8_t options);
uint8_t lr_ospf_is_grace_restart_capable(uint8_t options);
int32_t lr_ospf_interface_address_tlv(
    uint8_t is_v6,
    const uint8_t * addr,
    uint8_t * out_v4_present,
    uint8_t * out_v4,
    uint8_t * out_v6_present,
    uint8_t * out_v6
);
int32_t lr_ospf_encode_summary_lsa_body(
    uint32_t network_mask,
    uint32_t metric,
    struct lr_bytes_t * out
);
int32_t lr_ospf_decode_summary_lsa_body(
    const uint8_t * data,
    uintptr_t len,
    uint32_t * out_mask,
    uint32_t * out_metric
);
int32_t lr_ospf_encode_as_external_body(
    uint32_t network_mask,
    uint32_t metric,
    uint8_t external_type2,
    const uint8_t * forwarding_addr_v4,
    uint32_t external_route_tag,
    struct lr_bytes_t * out
);
int32_t lr_ospf_decode_as_external_body(
    const uint8_t * data,
    uintptr_t len,
    uint32_t * out_mask,
    uint32_t * out_metric,
    uint8_t * out_external_type2,
    uint8_t * out_forwarding_addr_v4,
    uint32_t * out_external_route_tag
);
int32_t lr_ospf_decode_router_links(
    const uint8_t * data,
    uintptr_t len,
    uintptr_t * out_count,
    struct lr_ospf_router_link_t ** out_array
);
void lr_ospf_router_link_array_free(struct lr_ospf_router_link_t * arr, uintptr_t count);
int32_t lr_ospf_router_lsa_flags_byte(
    const uint8_t * data,
    uintptr_t len,
    uint8_t * out
);
int32_t lr_ospf_encode_v3_inter_area_prefix_body(
    uint8_t is_v6,
    const uint8_t * prefix_addr,
    uint8_t prefix_len,
    uint32_t metric,
    struct lr_bytes_t * out
);
int32_t lr_ospf_decode_v3_inter_area_prefix_body(
    const uint8_t * data,
    uintptr_t len,
    uint8_t * out_prefix_len,
    uint32_t * out_metric,
    uint8_t * out_prefix_addr
);
uint8_t lr_ospf_is_e_lsa_type(uint16_t ls_type);
int32_t lr_ospf_walk_e_lsa_tlvs(
    const uint8_t * data,
    uintptr_t len,
    uintptr_t * out_count,
    struct lr_ospf_e_lsa_tlv_t ** out_array
);
void lr_ospf_e_lsa_tlv_array_free(struct lr_ospf_e_lsa_tlv_t * arr, uintptr_t count);
uint8_t lr_ospf_srv6_behavior_valid_for_end_sid(uint16_t behavior);
uint8_t lr_ospf_lsa_maxage_flush(lr_ospf_lsa_box_t lsa, lr_ospf_lsa_box_t * out);
void lr_ospf_lsa_header_free(lr_ospf_lsa_hdr_box_t h);
lr_ospf_neighbor_t lr_ospf_neighbor_new(uint32_t router_id);
void lr_ospf_neighbor_free(lr_ospf_neighbor_t r);
int32_t lr_ospf_neighbor_state(lr_ospf_neighbor_t r);
int32_t lr_ospf_neighbor_step_hello_seen(
    lr_ospf_neighbor_t r,
    uint32_t dr,
    uint32_t bdr,
    uint8_t priority
);
int32_t lr_ospf_neighbor_step_adj_ok(lr_ospf_neighbor_t r, uint8_t proceed);
int32_t lr_ospf_neighbor_step_kill(lr_ospf_neighbor_t r);
lr_ospf_router_lsa_link_t lr_ospf_router_lsa_link_new(
    int32_t link_kind,
    uint32_t field1,
    uint32_t field2,
    uint8_t field3,
    uint16_t metric
);
void lr_ospf_router_lsa_link_free(lr_ospf_router_lsa_link_t l);
int32_t lr_ospf_originate_router_lsa(
    uint32_t router_id,
    uint8_t flags_byte,
    const lr_ospf_router_lsa_link_t * links,
    uintptr_t count,
    const uint32_t * prev_seq,
    lr_ospf_lsa_box_t * out
);
int32_t lr_ospf_originate_network_lsa(
    uint32_t dr_router_id,
    uint32_t dr_addr,
    uint32_t mask,
    const uint32_t * attached_routers,
    uintptr_t count,
    const uint32_t * prev_seq,
    lr_ospf_lsa_box_t * out
);
lr_ospf_spf_result_t lr_ospf_spf_run(lr_ospf_lsdb_t lsdb, uint32_t router_id);
void lr_ospf_spf_result_free(lr_ospf_spf_result_t r);
uintptr_t lr_ospf_spf_route_count(lr_ospf_spf_result_t r);
int32_t lr_ospf_spf_route_at(
    lr_ospf_spf_result_t r,
    uintptr_t index,
    struct lr_ospf_spf_route_t * out
);
uintptr_t lr_ospf_spf_summary_count(lr_ospf_lsdb_t lsdb, lr_ospf_spf_result_t r);
int32_t lr_ospf_spf_summary_at(
    lr_ospf_lsdb_t lsdb,
    lr_ospf_spf_result_t r,
    uintptr_t index,
    struct lr_ospf_spf_route_t * out
);
lr_ospf_spf_v3_result_t lr_ospf_spf_v3_run(lr_ospf_lsdb_t lsdb, uint32_t router_id);
lr_ospf_spf_v3_result_t lr_ospf_spf_v3_extended_run(lr_ospf_lsdb_t lsdb, uint32_t router_id);
void lr_ospf_spf_v3_result_free(lr_ospf_spf_v3_result_t r);
uintptr_t lr_ospf_spf_v3_route_count(lr_ospf_spf_v3_result_t r);
int32_t lr_ospf_spf_v3_route_at(
    lr_ospf_spf_v3_result_t r,
    uintptr_t index,
    struct lr_ospf_spf_route_t * out
);
uintptr_t lr_ospf_spf_v3_summary_count(lr_ospf_lsdb_t lsdb, lr_ospf_spf_v3_result_t r);
int32_t lr_ospf_spf_v3_summary_at(
    lr_ospf_lsdb_t lsdb,
    lr_ospf_spf_v3_result_t r,
    uintptr_t index,
    struct lr_ospf_spf_route_t * out
);
uintptr_t lr_ospf_spf_v3_locator_count(lr_ospf_spf_v3_result_t r);
int32_t lr_ospf_spf_v3_locator_at(
    lr_ospf_spf_v3_result_t r,
    uintptr_t index,
    struct lr_ospf_spf_route_t * out
);
lr_ospf_sr_db_t lr_ospf_sr_db_new(lr_ospf_lsdb_t lsdb);
void lr_ospf_sr_db_free(lr_ospf_sr_db_t db);
lr_ospf_srv6_db_t lr_ospf_srv6_db_new(lr_ospf_lsdb_t lsdb);
void lr_ospf_srv6_db_free(lr_ospf_srv6_db_t db);
lr_osroute_t lr_osroute_connect(void);
lr_osroute_t lr_osroute_connect_stub(void);
const char * lr_osroute_platform_name(void);
int32_t lr_osroute_add_route(
    lr_osroute_t t,
    const struct lr_prefix_t * prefix,
    const uint8_t * next_hop,
    uintptr_t next_hop_len,
    uint32_t if_index
);
int32_t lr_osroute_add_route_tagged(
    lr_osroute_t t,
    const struct lr_prefix_t * prefix,
    const uint8_t * next_hop,
    uintptr_t next_hop_len,
    uint32_t if_index,
    int32_t protocol
);
int32_t lr_osroute_add_blackhole_route(lr_osroute_t t, const struct lr_prefix_t * prefix);
int32_t lr_osroute_delete_route(lr_osroute_t t, const struct lr_prefix_t * prefix);
int64_t lr_osroute_list_routes_count(lr_osroute_t t);
int64_t lr_osroute_list_routes(
    lr_osroute_t t,
    struct lr_kernel_route_t * out,
    uintptr_t cap
);
int32_t lr_osroute_has_route(lr_osroute_t t, const struct lr_prefix_t * prefix);
void lr_osroute_destroy(lr_osroute_t t);
struct lr_gtsm_t lr_gtsm_single_hop(void);
struct lr_gtsm_t lr_gtsm_multihop(uint8_t hops);
struct lr_gtsm_t lr_gtsm_disabled(void);
uint8_t lr_gtsm_outbound_ttl(struct lr_gtsm_t g);
uint8_t lr_gtsm_min_ttl(struct lr_gtsm_t g);
uint8_t lr_gtsm_is_disabled(struct lr_gtsm_t g);
int32_t lr_gtsm_mode(struct lr_gtsm_t g);
int32_t lr_tcp_ao_key_symmetric(
    uint8_t id,
    const uint8_t * key,
    uintptr_t key_len,
    struct lr_tcp_ao_key_t * out
);
int32_t lr_tcp_ao_key_new(
    uint8_t send_id,
    uint8_t recv_id,
    const uint8_t * key,
    uintptr_t key_len,
    struct lr_tcp_ao_key_t * out
);
int32_t lr_tcp_ao_key_read(
    const struct lr_tcp_ao_key_t * key,
    uint8_t * out_send_id,
    uint8_t * out_recv_id,
    uintptr_t * out_key_len
);
int64_t lr_tcp_ao_key_copy(
    const struct lr_tcp_ao_key_t * key,
    uint8_t * out_buf,
    uintptr_t cap
);
int32_t lr_tcp_auth_kind(lr_tcp_auth_t auth);
uint8_t lr_tcp_auth_is_none(lr_tcp_auth_t auth);
lr_tcp_auth_t lr_tcp_auth_new_none(void);
lr_tcp_auth_t lr_tcp_auth_new_md5(const uint8_t * key, uintptr_t key_len);
lr_tcp_auth_t lr_tcp_auth_new_ao(
    const struct lr_tcp_ao_key_t * keys,
    uintptr_t keys_count,
    int32_t algorithm,
    uint8_t mac_len
);
void lr_tcp_auth_free(lr_tcp_auth_t auth);
uint32_t lr_osroute_prefix_mask(uint8_t prefix_len);
int32_t lr_osroute_check_source_compatibility(
    uint8_t local_is_v6,
    const uint8_t * local,
    uint8_t peer_is_v6,
    const uint8_t * peer,
    uint8_t * out_kind
);
uint32_t lr_osroute_ifindex_of(const char * interface);
uint32_t lr_osroute_ipv6_ifindex_of(const char * interface);
int32_t lr_osroute_interface_v4_addrs(
    const char * interface,
    uintptr_t * out_count,
    struct lr_osroute_interface_v4_addr_t ** out_array
);
void lr_osroute_interface_v4_addr_array_free(struct lr_osroute_interface_v4_addr_t * arr, uintptr_t count);
int32_t lr_osroute_interface_v6_addrs(
    const char * interface,
    uintptr_t * out_count,
    struct lr_osroute_interface_v6_addr_t ** out_array
);
void lr_osroute_interface_v6_addr_array_free(struct lr_osroute_interface_v6_addr_t * arr, uintptr_t count);
uint8_t lr_osroute_mpls_enabled(void);
uint8_t lr_osroute_seg6_enabled(void);
uint8_t lr_osroute_ttl_check_enforced(void);
lr_policy_chain_t lr_policy_chain_new(void);
int32_t lr_policy_chain_push(lr_policy_chain_t chain, lr_route_map_t map);
uint8_t lr_policy_chain_evaluate(
    lr_policy_chain_t chain,
    lr_route_t route,
    lr_resolver_t resolver
);
uintptr_t lr_policy_chain_len(lr_policy_chain_t chain);
void lr_policy_chain_free(lr_policy_chain_t chain);
lr_policy_t lr_policy_new(const char * name);
const char * lr_policy_name(lr_policy_t p);
lr_policy_chain_t lr_policy_chain(lr_policy_t p);
void lr_policy_free(lr_policy_t p);
lr_safety_net_t lr_safety_net_new(uint32_t local_as);
lr_safety_net_t lr_safety_net_with_local_addr(
    lr_safety_net_t r,
    const uint8_t * addr_v4,
    const uint8_t * addr_v6
);
int32_t lr_safety_net_check(
    lr_safety_net_t r,
    lr_route_t route,
    uint8_t is_ebgp
);
void lr_safety_net_free(lr_safety_net_t r);
int32_t lr_safety_net_config_enabled(lr_safety_net_t r);
int32_t lr_safety_net_config_set_enabled(lr_safety_net_t r, uint8_t enabled);
int32_t lr_safety_net_config_get_bool(lr_safety_net_t r, int32_t field);
int32_t lr_safety_net_config_set_bool(
    lr_safety_net_t r,
    int32_t field,
    uint8_t value
);
uint64_t lr_safety_net_config_get_u64(lr_safety_net_t r, int32_t field);
int32_t lr_safety_net_config_set_u64(
    lr_safety_net_t r,
    int32_t field,
    uint64_t value
);
int32_t lr_safety_net_check_violation(
    lr_safety_net_t r,
    lr_route_t route,
    uint8_t is_ebgp
);
int32_t lr_resolver_list_id(
    lr_resolver_t r,
    int32_t kind,
    const char * name
);
uintptr_t lr_resolver_route_map_count(lr_resolver_t r);
uintptr_t lr_resolver_route_map_names(
    lr_resolver_t r,
    char * out_buf,
    uintptr_t * out_offsets,
    uintptr_t * out_lens,
    uintptr_t cap
);
int32_t lr_resolver_push_route_map_entry(
    lr_resolver_t r,
    const char * name,
    lr_route_map_t map
);
int32_t lr_policy_set_bind_import(
    lr_resolver_t r,
    uint64_t session,
    const char * map_name
);
int32_t lr_policy_set_bind_export(
    lr_resolver_t r,
    uint64_t session,
    const char * map_name
);
int32_t lr_policy_set_validate(lr_resolver_t r);
int32_t lr_roa_store_add_static(lr_roa_store_t s, const struct lr_roa_entry_t * entry);
int32_t lr_roa_store_remove_static(lr_roa_store_t s, const struct lr_roa_entry_t * entry);
uintptr_t lr_roa_store_static_len(lr_roa_store_t s);
uintptr_t lr_roa_store_rtr_len(lr_roa_store_t s);
int32_t lr_roa_store_provenance_of(
    lr_roa_store_t s,
    const struct lr_roa_entry_t * entry,
    uint8_t * out
);
int32_t lr_roa_store_provenance_of_checked(
    lr_roa_store_t s,
    const struct lr_roa_entry_t * entry,
    uint8_t * out
);
lr_roa_table_builder_t lr_roa_table_builder_new(void);
void lr_roa_table_builder_free(lr_roa_table_builder_t b);
int32_t lr_roa_table_builder_add(
    lr_roa_table_builder_t b,
    const char * prefix,
    uint8_t max_length,
    uint32_t asn
);
int32_t lr_roa_table_builder_add_entry(lr_roa_table_builder_t b, struct lr_roa_entry_t entry);
lr_roa_table_t lr_roa_table_builder_build(lr_roa_table_builder_t b);
lr_roa_table_t lr_roa_table_new(void);
void lr_roa_table_free(lr_roa_table_t t);
uintptr_t lr_roa_table_len(lr_roa_table_t t);
uint8_t lr_roa_table_is_empty(lr_roa_table_t t);
uint8_t lr_roa_table_validate(
    lr_roa_table_t t,
    const uint8_t * addr,
    uint8_t is_ipv6,
    uint8_t prefix_len,
    uint32_t origin_as,
    uint8_t has_origin
);
int32_t lr_roa_table_entry_at(
    lr_roa_table_t t,
    uintptr_t index,
    uint8_t * out_addr,
    uint8_t * out_is_ipv6,
    uint8_t * out_prefix_len,
    uint8_t * out_max_length,
    uint32_t * out_asn
);
uint8_t lr_bgp_otc_role_from_u8(uint8_t v);
uint8_t lr_bgp_otc_role_to_u8(uint8_t role);
uint8_t lr_bgp_otc_role_is_upstream(uint8_t role);
uint8_t lr_bgp_otc_role_is_route_server(uint8_t role);
lr_bgp_otc_t lr_bgp_otc_new(uint32_t asn);
lr_bgp_otc_t lr_bgp_otc_decode(const uint8_t * data, uintptr_t len);
int32_t lr_bgp_otc_encode(lr_bgp_otc_t otc, uint8_t * out);
uint32_t lr_bgp_otc_value(lr_bgp_otc_t otc);
uint8_t lr_bgp_otc_is_set(lr_bgp_otc_t otc);
void lr_bgp_otc_free(lr_bgp_otc_t otc);
uint8_t lr_bgp_peer_role_from_asns(
    uint32_t local_as,
    uint32_t peer_as,
    const uint32_t * confed,
    uintptr_t confed_count
);
uint8_t lr_bgp_peer_role_is_internal(uint8_t role);
uint8_t lr_bgp_peer_role_is_external(uint8_t role);
uint8_t lr_bgp_peer_role_prepends_as_path(uint8_t role);
uint8_t lr_bgp_peer_role_rewrites_next_hop(uint8_t role);
lr_bgp_peer_topology_t lr_bgp_peer_topology_new(
    uint8_t role,
    uint8_t rr_client,
    uint8_t rs_client,
    uint8_t otc_role
);
void lr_bgp_peer_topology_free(lr_bgp_peer_topology_t t);
uint8_t lr_bgp_peer_topology_role(lr_bgp_peer_topology_t t);
uint8_t lr_bgp_peer_topology_rr_client(lr_bgp_peer_topology_t t);
uint8_t lr_bgp_peer_topology_rs_client(lr_bgp_peer_topology_t t);
uint8_t lr_bgp_peer_topology_otc_role(lr_bgp_peer_topology_t t);
uint8_t lr_bgp_peer_topology_can_advertise(
    lr_bgp_peer_topology_t to,
    lr_bgp_peer_topology_t from,
    lr_bgp_otc_t route_otc
);
uint32_t lr_bgp_cluster_id_from_u32(uint32_t v);
int32_t lr_bgp_cluster_id_to_v4_bytes(uint32_t cluster_id, uint8_t * out);
lr_bgp_rr_config_t lr_bgp_rr_config_new(uint32_t cluster_id, uint8_t enabled);
void lr_bgp_rr_config_free(lr_bgp_rr_config_t c);
uint32_t lr_bgp_rr_config_cluster_id(lr_bgp_rr_config_t c);
uint8_t lr_bgp_rr_config_enabled(lr_bgp_rr_config_t c);
lr_bgp_confed_config_t lr_bgp_confed_config_new(
    const uint32_t * members,
    uintptr_t count,
    uint32_t confederation_id
);
void lr_bgp_confed_config_free(lr_bgp_confed_config_t c);
uint8_t lr_bgp_confed_config_contains(lr_bgp_confed_config_t c, uint32_t asn);
uint32_t lr_bgp_confed_config_external_as(lr_bgp_confed_config_t c);
uintptr_t lr_bgp_confed_config_member_count(lr_bgp_confed_config_t c);
uint32_t lr_bgp_confed_config_member_at(lr_bgp_confed_config_t c, uintptr_t index);
lr_bgp_rs_config_t lr_bgp_rs_config_new(
    uint8_t client,
    const char * inbound_policy,
    const char * outbound_policy
);
void lr_bgp_rs_config_free(lr_bgp_rs_config_t c);
uint8_t lr_bgp_rs_config_client(lr_bgp_rs_config_t c);
uintptr_t lr_bgp_rs_config_strip_count(lr_bgp_rs_config_t c);
uint32_t lr_bgp_rs_config_strip_at(lr_bgp_rs_config_t c, uintptr_t index);
uintptr_t lr_bgp_rs_config_add_count(lr_bgp_rs_config_t c);
uint32_t lr_bgp_rs_config_add_at(lr_bgp_rs_config_t c, uintptr_t index);
int32_t lr_route_lrxp_store_kind(
    lr_route_t route,
    uint8_t * out,
    uint8_t * out_present
);
int32_t lr_route_lrxp_verified(lr_route_t route, uint8_t * out);
int32_t lr_route_lrxp_partial_transit(lr_route_t route, uint8_t * out);
int32_t lr_route_lrxp_hint_rank(lr_route_t route, uint8_t * out);
int32_t lr_route_lrxp_hint_damp_fom(lr_route_t route, uint16_t * out);
int32_t lr_route_lrxp_hint_igp_cost(lr_route_t route, uint32_t * out);
int32_t lr_route_lrxp_policy_role(lr_route_t route, uint8_t * out);
int32_t lr_route_lrxp_origin_as(lr_route_t route, uint32_t * out);
int32_t lr_route_lrxp_origin_max_valid_len(lr_route_t route, uint8_t * out);
int32_t lr_route_lrxp_origin_expiry(lr_route_t route, uint32_t * out);
int32_t lr_router_close_session(lr_router_t r, uint64_t session);
int32_t lr_router_shutdown_session(lr_router_t r, uint64_t session);
int32_t lr_router_remove_redistribution_pipe(
    lr_router_t r,
    int32_t source,
    int32_t target
);
int32_t lr_router_adj_rib_in_snapshot(
    lr_router_t r,
    uint64_t session,
    struct lr_bytes_t * out
);
int32_t lr_router_ospf_set_area_type(
    lr_router_t r,
    uint32_t area_id,
    int32_t kind
);
int32_t lr_router_set_ospf_sr_receive(lr_router_t r, uint8_t on);
uint8_t lr_router_ospf_sr_receive(lr_router_t r);
int32_t lr_router_set_ospf_srv6_receive(lr_router_t r, uint8_t on);
uint8_t lr_router_ospf_srv6_receive(lr_router_t r);
int32_t lr_router_set_ospf_v3_extended_lsas(lr_router_t r, uint8_t on);
uint8_t lr_router_ospf_v3_extended_lsas(lr_router_t r);
int32_t lr_rtr_pdu_encode(
    lr_rtr_pdu_t pdu,
    uint8_t version,
    struct lr_bytes_t * out
);
int32_t lr_rtr_pdu_encode_vec(
    lr_rtr_pdu_t pdu,
    uint8_t version,
    struct lr_bytes_t * out
);
int32_t lr_rtr_pdu_decode(
    const uint8_t * data,
    uintptr_t len,
    lr_rtr_pdu_t * out_pdu,
    uint8_t * out_version,
    uintptr_t * out_consumed
);
void lr_rtr_pdu_free(lr_rtr_pdu_t pdu);
int32_t lr_rtr_pdu_type(lr_rtr_pdu_t pdu, uint8_t * out);
int32_t lr_rtr_pdu_min_version(lr_rtr_pdu_t pdu, uint8_t * out);
lr_rtr_pdu_t lr_rtr_pdu_serial_notify(uint16_t session_id, uint32_t serial);
lr_rtr_pdu_t lr_rtr_pdu_serial_query(uint16_t session_id, uint32_t serial);
lr_rtr_pdu_t lr_rtr_pdu_reset_query(void);
lr_rtr_pdu_t lr_rtr_pdu_cache_response(uint16_t session_id);
lr_rtr_pdu_t lr_rtr_pdu_cache_reset(void);
lr_rtr_pdu_t lr_rtr_pdu_ipv4_prefix(
    uint8_t announce,
    const uint8_t * prefix_v4,
    uint8_t prefix_len,
    uint8_t max_length,
    uint32_t asn
);
lr_rtr_pdu_t lr_rtr_pdu_ipv6_prefix(
    uint8_t announce,
    const uint8_t * prefix_v6,
    uint8_t prefix_len,
    uint8_t max_length,
    uint32_t asn
);
lr_rtr_pdu_t lr_rtr_pdu_end_of_data(
    uint16_t session_id,
    uint32_t serial,
    uint32_t refresh_interval,
    uint32_t retry_interval,
    uint32_t expire_interval
);
lr_rtr_pdu_t lr_rtr_pdu_router_key(
    uint8_t announce,
    const uint8_t * ski,
    uint32_t asn,
    const uint8_t * spki,
    uintptr_t spki_len
);
lr_rtr_pdu_t lr_rtr_pdu_error_report(
    uint16_t error_code,
    const uint8_t * erroneous_pdu,
    uintptr_t erroneous_pdu_len,
    const char * error_text
);
lr_rtr_pdu_t lr_rtr_pdu_aspa(
    uint8_t announce,
    uint32_t customer_asn,
    const uint32_t * providers,
    uintptr_t providers_count
);
int32_t lr_rtr_pdu_session_id(lr_rtr_pdu_t pdu, uint16_t * out);
int32_t lr_rtr_pdu_serial(lr_rtr_pdu_t pdu, uint32_t * out);
int32_t lr_rtr_pdu_announce(lr_rtr_pdu_t pdu, uint8_t * out);
int32_t lr_rtr_pdu_ipv4_prefix_fields(
    lr_rtr_pdu_t pdu,
    uint8_t * out_prefix_v4,
    uint8_t * out_prefix_len,
    uint8_t * out_max_length,
    uint32_t * out_asn
);
int32_t lr_rtr_pdu_ipv6_prefix_fields(
    lr_rtr_pdu_t pdu,
    uint8_t * out_prefix_v6,
    uint8_t * out_prefix_len,
    uint8_t * out_max_length,
    uint32_t * out_asn
);
int32_t lr_rtr_pdu_end_of_data_intervals(
    lr_rtr_pdu_t pdu,
    uint8_t * out_present,
    uint32_t * out_refresh,
    uint32_t * out_retry,
    uint32_t * out_expire
);
int32_t lr_rtr_pdu_router_key_fields(
    lr_rtr_pdu_t pdu,
    uint8_t * out_ski,
    uint32_t * out_asn,
    struct lr_bytes_t * out_spki
);
int32_t lr_rtr_pdu_error_code(lr_rtr_pdu_t pdu, uint16_t * out);
int32_t lr_rtr_pdu_erroneous_pdu(lr_rtr_pdu_t pdu, struct lr_bytes_t * out);
int32_t lr_rtr_pdu_error_text(lr_rtr_pdu_t pdu, struct lr_bytes_t * out);
int32_t lr_rtr_pdu_customer_asn(lr_rtr_pdu_t pdu, uint32_t * out);
int32_t lr_rtr_pdu_providers(
    lr_rtr_pdu_t pdu,
    uint32_t * out_providers,
    uintptr_t cap,
    uintptr_t * out_count
);
int32_t lr_rtr_pdu_type_name(uint8_t ty, const char ** out_name);
int32_t lr_rtr_pdu_type_min_len(uint8_t ty, uintptr_t * out);
int32_t lr_rtr_pdu_type_from_u8(uint8_t ty, uint8_t * out);
int32_t lr_rtr_error_code_name(uint16_t code, const char ** out_name);
int32_t lr_rtr_error_code_is_fatal(uint16_t code, uint8_t * out);
int32_t lr_rtr_error_code_from_u16(uint16_t code);
int32_t lr_bgp_well_known_origin_decode(
    const uint8_t * data,
    uintptr_t len,
    uint8_t * out
);
int32_t lr_bgp_well_known_origin_encode(uint8_t kind, struct lr_bytes_t * out);
int32_t lr_bgp_well_known_next_hop_decode(
    const uint8_t * data,
    uintptr_t len,
    uint8_t * out_is_ipv6,
    uint8_t * out_addr
);
int32_t lr_bgp_well_known_next_hop_encode(
    uint8_t is_ipv6,
    const uint8_t * addr,
    struct lr_bytes_t * out
);
int32_t lr_bgp_well_known_med_decode(
    const uint8_t * data,
    uintptr_t len,
    uint32_t * out
);
int32_t lr_bgp_well_known_med_encode(uint32_t value, struct lr_bytes_t * out);
int32_t lr_bgp_well_known_local_pref_decode(
    const uint8_t * data,
    uintptr_t len,
    uint32_t * out
);
int32_t lr_bgp_well_known_local_pref_encode(uint32_t value, struct lr_bytes_t * out);
int32_t lr_bgp_well_known_aggregator_decode(
    const uint8_t * data,
    uintptr_t len,
    uint32_t * out_asn,
    uint8_t * out_speaker
);
int32_t lr_bgp_well_known_aggregator_encode_4(
    uint32_t asn,
    const uint8_t * speaker,
    struct lr_bytes_t * out
);
int32_t lr_bgp_well_known_originator_id_decode(
    const uint8_t * data,
    uintptr_t len,
    uint32_t * out_bgp_id
);
int32_t lr_bgp_well_known_originator_id_encode(uint32_t bgp_id, struct lr_bytes_t * out);
int32_t lr_bgp_well_known_cluster_list_decode(
    const uint8_t * data,
    uintptr_t len,
    uint32_t * out_clusters,
    uintptr_t cap,
    uintptr_t * out_count
);
int32_t lr_bgp_well_known_cluster_list_encode(
    const uint32_t * clusters,
    uintptr_t count,
    struct lr_bytes_t * out
);
int32_t lr_bgp_well_known_aigp_decode(
    const uint8_t * data,
    uintptr_t len,
    uint64_t * out_metric
);
int32_t lr_bgp_well_known_aigp_encode(uint64_t metric, struct lr_bytes_t * out);
int32_t lr_bgp_well_known_pmsi_tunnel_decode(
    const uint8_t * data,
    uintptr_t len,
    uint8_t * out_flags,
    uint8_t * out_tunnel_type,
    uint32_t * out_label,
    struct lr_bytes_t * out_tunnel_id
);
int32_t lr_bgp_well_known_pmsi_tunnel_encode(
    uint8_t flags,
    uint8_t tunnel_type,
    uint32_t label,
    const uint8_t * tunnel_id,
    uintptr_t tunnel_id_len,
    struct lr_bytes_t * out
);

typedef lr_ospf_external_route_vec_t lr_ospf_nssa_route_vec_t;
typedef struct lr_afi_safi_t lr_nlri_family_t;

typedef lr_ospf_external_route_vec_t lr_ospf_nssa_route_vec_t;
typedef struct lr_afi_safi_t lr_nlri_family_t;

typedef lr_ospf_external_route_vec_t lr_ospf_nssa_route_vec_t;
typedef struct lr_afi_safi_t lr_nlri_family_t;
int32_t lr_bgp_peer_advertise_with_originator(
    lr_bgp_peer_t r,
    lr_route_t route,
    uint8_t originator_bgp_id_present,
    const uint8_t * originator_bgp_id_addr
);

/* GENERATED ADDITIONS - do not edit by hand.
   Source: scripts/gen_python.py + scripts/abi.json
   Re-run: python3 scripts/gen_python.py */

typedef lr_ospf_external_route_vec_t lr_ospf_nssa_route_vec_t;
typedef struct lr_afi_safi_t lr_nlri_family_t;
uint8_t lr_ospf_v3_packet_checksum_ok(
    const uint8_t * bytes,
    uintptr_t len,
    const uint8_t * src,
    const uint8_t * dst
);
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


def last_error() -> str:
    """Return the thread-local last-error message from the C ABI."""
    cstr = get_lib().lr_last_error()
    if cstr == ffi.NULL:
        return ""
    return ffi.string(cstr).decode("utf-8", errors="replace")
