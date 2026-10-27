//! BGP role topology C ABI — Otc, OtcRole, PeerRole, PeerTopology,
//! ClusterId, RouteReflectorConfig, ConfederationConfig,
//! RouteServerConfig (RFC 9234 + RFC 4456 + RFC 5065 + RFC 7947).

#![allow(unused_unsafe)]
#![allow(dead_code)]
#![allow(unused_imports)]

use lr_bgp::role::{
    ClusterId, ConfederationConfig, Otc, OtcRole, PeerRole, PeerTopology, RouteReflectorConfig,
    RouteServerConfig,
};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;

const LR_ERR_NULL: i32 = LrError::Null as i32;
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;

// ---- OtcRole constants ----

pub const LR_OTC_ROLE_UNSET: u8 = 0;
pub const LR_OTC_ROLE_PROVIDER: u8 = 1;
pub const LR_OTC_ROLE_CUSTOMER: u8 = 2;
pub const LR_OTC_ROLE_PEER: u8 = 3;
pub const LR_OTC_ROLE_ROUTE_SERVER: u8 = 4;
pub const LR_OTC_ROLE_RS_CLIENT: u8 = 5;

#[no_mangle]
pub extern "C" fn lr_bgp_otc_role_from_u8(v: u8) -> u8 {
    guarded(
        || {
            OtcRole::from_u8(v)
                .map(|r| r.to_u8())
                .unwrap_or(LR_OTC_ROLE_UNSET)
        },
        LR_OTC_ROLE_UNSET,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_otc_role_to_u8(role: u8) -> u8 {
    guarded(
        || {
            OtcRole::from_u8(role)
                .map(|r| r.to_u8())
                .unwrap_or(LR_OTC_ROLE_UNSET)
        },
        LR_OTC_ROLE_UNSET,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_otc_role_is_upstream(role: u8) -> u8 {
    guarded(
        || {
            OtcRole::from_u8(role)
                .map(|r| r.is_upstream() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_otc_role_is_route_server(role: u8) -> u8 {
    guarded(
        || {
            OtcRole::from_u8(role)
                .map(|r| r.is_route_server() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

// ---- Otc (4-byte attribute value) ----

#[repr(C)]
pub struct OpaqueOtc {
    _private: [u8; 0],
}
pub type lr_bgp_otc_t = *mut OpaqueOtc;

fn box_otc(o: Otc) -> lr_bgp_otc_t {
    Box::into_raw(Box::new(o)) as lr_bgp_otc_t
}

unsafe fn unbox_otc(o: lr_bgp_otc_t) -> Option<Box<Otc>> {
    if o.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(o as *mut Otc) })
}

unsafe fn borrow_otc(o: lr_bgp_otc_t) -> Option<&'static Otc> {
    if o.is_null() {
        return None;
    }
    Some(unsafe { &*(o as *const Otc) })
}

#[no_mangle]
pub extern "C" fn lr_bgp_otc_new(asn: u32) -> lr_bgp_otc_t {
    guarded(|| box_otc(Otc::new(asn)), std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_otc_decode(data: *const u8, len: usize) -> lr_bgp_otc_t {
    guarded(
        || unsafe {
            if data.is_null() || len != 4 {
                return std::ptr::null_mut();
            }
            let b = unsafe { std::slice::from_raw_parts(data, 4) };
            Otc::decode(b).map(box_otc).unwrap_or(std::ptr::null_mut())
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_otc_encode(otc: lr_bgp_otc_t, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            let Some(o) = borrow_otc(otc) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = o.encode();
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 4);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_otc_value(otc: lr_bgp_otc_t) -> u32 {
    guarded(|| unsafe { borrow_otc(otc).map(|o| o.0).unwrap_or(0) }, 0)
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_otc_is_set(otc: lr_bgp_otc_t) -> u8 {
    guarded(
        || unsafe { borrow_otc(otc).map(|o| o.is_set() as u8).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_otc_free(otc: lr_bgp_otc_t) {
    guarded(
        || unsafe {
            drop(unbox_otc(otc));
        },
        (),
    )
}

// ---- PeerRole constants ----

pub const LR_PEER_ROLE_EBGP: u8 = 0;
pub const LR_PEER_ROLE_IBGP: u8 = 1;
pub const LR_PEER_ROLE_CONFED_EXTERNAL: u8 = 2;
pub const LR_PEER_ROLE_CONFED_INTERNAL: u8 = 3;

fn peer_role_from_u8(v: u8) -> Option<PeerRole> {
    Some(match v {
        LR_PEER_ROLE_EBGP => PeerRole::Ebgp,
        LR_PEER_ROLE_IBGP => PeerRole::Ibgp,
        LR_PEER_ROLE_CONFED_EXTERNAL => PeerRole::ConfederationExternal,
        LR_PEER_ROLE_CONFED_INTERNAL => PeerRole::ConfederationInternal,
        _ => return None,
    })
}

fn peer_role_to_u8(r: PeerRole) -> u8 {
    match r {
        PeerRole::Ebgp => LR_PEER_ROLE_EBGP,
        PeerRole::Ibgp => LR_PEER_ROLE_IBGP,
        PeerRole::ConfederationExternal => LR_PEER_ROLE_CONFED_EXTERNAL,
        PeerRole::ConfederationInternal => LR_PEER_ROLE_CONFED_INTERNAL,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_role_from_asns(
    local_as: u32,
    peer_as: u32,
    confed: *const u32,
    confed_count: usize,
) -> u8 {
    guarded(
        || unsafe {
            let confed_cfg = if confed.is_null() || confed_count == 0 {
                None
            } else {
                let members = unsafe { std::slice::from_raw_parts(confed, confed_count) }.to_vec();
                Some(ConfederationConfig::new(members))
            };
            let role = PeerRole::from_asns(
                lr_core::addr::Asn(local_as),
                lr_core::addr::Asn(peer_as),
                confed_cfg.as_ref(),
            );
            peer_role_to_u8(role)
        },
        LR_PEER_ROLE_EBGP,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_peer_role_is_internal(role: u8) -> u8 {
    guarded(
        || {
            peer_role_from_u8(role)
                .map(|r| r.is_internal() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_peer_role_is_external(role: u8) -> u8 {
    guarded(
        || {
            peer_role_from_u8(role)
                .map(|r| r.is_external() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_peer_role_prepends_as_path(role: u8) -> u8 {
    guarded(
        || {
            peer_role_from_u8(role)
                .map(|r| r.prepends_as_path() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub extern "C" fn lr_bgp_peer_role_rewrites_next_hop(role: u8) -> u8 {
    guarded(
        || {
            peer_role_from_u8(role)
                .map(|r| r.rewrites_next_hop() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

// ---- PeerTopology ----

#[repr(C)]
pub struct OpaquePeerTopology {
    _private: [u8; 0],
}
pub type lr_bgp_peer_topology_t = *mut OpaquePeerTopology;

fn box_topology(t: PeerTopology) -> lr_bgp_peer_topology_t {
    Box::into_raw(Box::new(t)) as lr_bgp_peer_topology_t
}

unsafe fn unbox_topology(t: lr_bgp_peer_topology_t) -> Option<Box<PeerTopology>> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(t as *mut PeerTopology) })
}

unsafe fn borrow_topology(t: lr_bgp_peer_topology_t) -> Option<&'static PeerTopology> {
    if t.is_null() {
        return None;
    }
    Some(unsafe { &*(t as *const PeerTopology) })
}

#[no_mangle]
pub extern "C" fn lr_bgp_peer_topology_new(
    role: u8,
    rr_client: u8,
    rs_client: u8,
    otc_role: u8,
) -> lr_bgp_peer_topology_t {
    guarded(
        || {
            let role = peer_role_from_u8(role).unwrap_or(PeerRole::Ebgp);
            let otc = OtcRole::from_u8(otc_role).unwrap_or(OtcRole::Unset);
            box_topology(PeerTopology {
                role,
                rr_client: rr_client != 0,
                rs_client: rs_client != 0,
                otc,
            })
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_topology_free(t: lr_bgp_peer_topology_t) {
    guarded(
        || unsafe {
            drop(unbox_topology(t));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_topology_role(t: lr_bgp_peer_topology_t) -> u8 {
    guarded(
        || unsafe {
            borrow_topology(t)
                .map(|top| peer_role_to_u8(top.role))
                .unwrap_or(LR_PEER_ROLE_EBGP)
        },
        LR_PEER_ROLE_EBGP,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_topology_rr_client(t: lr_bgp_peer_topology_t) -> u8 {
    guarded(
        || unsafe {
            borrow_topology(t)
                .map(|top| top.rr_client as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_topology_rs_client(t: lr_bgp_peer_topology_t) -> u8 {
    guarded(
        || unsafe {
            borrow_topology(t)
                .map(|top| top.rs_client as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_topology_otc_role(t: lr_bgp_peer_topology_t) -> u8 {
    guarded(
        || unsafe {
            borrow_topology(t)
                .map(|top| top.otc.to_u8())
                .unwrap_or(LR_OTC_ROLE_UNSET)
        },
        LR_OTC_ROLE_UNSET,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_peer_topology_can_advertise(
    to: lr_bgp_peer_topology_t,
    from: lr_bgp_peer_topology_t,
    route_otc: lr_bgp_otc_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(to_t) = borrow_topology(to) else {
                return 0;
            };
            let from_t_owned: Option<PeerTopology> = borrow_topology(from).cloned();
            let route_otc_v: Option<Otc> = borrow_otc(route_otc).copied();
            let from_t = from_t_owned.unwrap_or_default();
            to_t.can_advertise(&from_t, route_otc_v) as u8
        },
        0,
    )
}

// ---- ClusterId ----

#[no_mangle]
pub extern "C" fn lr_bgp_cluster_id_from_u32(v: u32) -> u32 {
    guarded(|| ClusterId::from_u32(v).0, 0)
}

#[no_mangle]
pub extern "C" fn lr_bgp_cluster_id_to_v4_bytes(cluster_id: u32, out: *mut u8) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = ClusterId(cluster_id).to_v4_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 4);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

// ---- RouteReflectorConfig ----

#[repr(C)]
pub struct OpaqueRouteReflectorConfig {
    _private: [u8; 0],
}
pub type lr_bgp_rr_config_t = *mut OpaqueRouteReflectorConfig;

fn box_rr(c: RouteReflectorConfig) -> lr_bgp_rr_config_t {
    Box::into_raw(Box::new(c)) as lr_bgp_rr_config_t
}

unsafe fn unbox_rr(c: lr_bgp_rr_config_t) -> Option<Box<RouteReflectorConfig>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut RouteReflectorConfig) })
}

unsafe fn borrow_rr(c: lr_bgp_rr_config_t) -> Option<&'static RouteReflectorConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const RouteReflectorConfig) })
}

#[no_mangle]
pub extern "C" fn lr_bgp_rr_config_new(cluster_id: u32, enabled: u8) -> lr_bgp_rr_config_t {
    guarded(
        || {
            box_rr(RouteReflectorConfig {
                cluster_id: ClusterId(cluster_id),
                enabled: enabled != 0,
            })
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rr_config_free(c: lr_bgp_rr_config_t) {
    guarded(
        || unsafe {
            drop(unbox_rr(c));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rr_config_cluster_id(c: lr_bgp_rr_config_t) -> u32 {
    guarded(
        || unsafe { borrow_rr(c).map(|c| c.cluster_id.0).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rr_config_enabled(c: lr_bgp_rr_config_t) -> u8 {
    guarded(
        || unsafe { borrow_rr(c).map(|c| c.enabled as u8).unwrap_or(0) },
        0,
    )
}

// ---- ConfederationConfig ----

#[repr(C)]
pub struct OpaqueConfederationConfig {
    _private: [u8; 0],
}
pub type lr_bgp_confed_config_t = *mut OpaqueConfederationConfig;

fn box_confed(c: ConfederationConfig) -> lr_bgp_confed_config_t {
    Box::into_raw(Box::new(c)) as lr_bgp_confed_config_t
}

unsafe fn unbox_confed(c: lr_bgp_confed_config_t) -> Option<Box<ConfederationConfig>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut ConfederationConfig) })
}

unsafe fn borrow_confed(c: lr_bgp_confed_config_t) -> Option<&'static ConfederationConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const ConfederationConfig) })
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_confed_config_new(
    members: *const u32,
    count: usize,
    confederation_id: u32,
) -> lr_bgp_confed_config_t {
    guarded(
        || unsafe {
            if members.is_null() && count != 0 {
                return std::ptr::null_mut();
            }
            let member_vec: Vec<u32> = if count == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(members, count) }.to_vec()
            };
            let cfg = if confederation_id == 0 {
                ConfederationConfig::new(member_vec)
            } else {
                ConfederationConfig::with_id(member_vec, confederation_id)
            };
            box_confed(cfg)
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_confed_config_free(c: lr_bgp_confed_config_t) {
    guarded(
        || unsafe {
            drop(unbox_confed(c));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_confed_config_contains(c: lr_bgp_confed_config_t, asn: u32) -> u8 {
    guarded(
        || unsafe { borrow_confed(c).map(|c| c.contains(asn) as u8).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_confed_config_external_as(c: lr_bgp_confed_config_t) -> u32 {
    guarded(
        || unsafe { borrow_confed(c).and_then(|c| c.external_as()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_confed_config_member_count(c: lr_bgp_confed_config_t) -> usize {
    guarded(
        || unsafe { borrow_confed(c).map(|c| c.members.len()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_confed_config_member_at(
    c: lr_bgp_confed_config_t,
    index: usize,
) -> u32 {
    guarded(
        || unsafe {
            borrow_confed(c)
                .and_then(|c| c.members.get(index).copied())
                .unwrap_or(0)
        },
        0,
    )
}

// ---- RouteServerConfig ----

#[repr(C)]
pub struct OpaqueRouteServerConfig {
    _private: [u8; 0],
}
pub type lr_bgp_rs_config_t = *mut OpaqueRouteServerConfig;

fn box_rs(c: RouteServerConfig) -> lr_bgp_rs_config_t {
    Box::into_raw(Box::new(c)) as lr_bgp_rs_config_t
}

unsafe fn unbox_rs(c: lr_bgp_rs_config_t) -> Option<Box<RouteServerConfig>> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(c as *mut RouteServerConfig) })
}

unsafe fn borrow_rs(c: lr_bgp_rs_config_t) -> Option<&'static RouteServerConfig> {
    if c.is_null() {
        return None;
    }
    Some(unsafe { &*(c as *const RouteServerConfig) })
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rs_config_new(
    client: u8,
    inbound_policy: *const std::os::raw::c_char,
    outbound_policy: *const std::os::raw::c_char,
) -> lr_bgp_rs_config_t {
    guarded(
        || unsafe {
            let inbound = cstr_to_optional_string(inbound_policy);
            let outbound = cstr_to_optional_string(outbound_policy);
            box_rs(RouteServerConfig {
                client: client != 0,
                inbound_policy: inbound,
                outbound_policy: outbound,
                strip_communities: Vec::new(),
                add_communities: Vec::new(),
            })
        },
        std::ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rs_config_free(c: lr_bgp_rs_config_t) {
    guarded(
        || unsafe {
            drop(unbox_rs(c));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rs_config_client(c: lr_bgp_rs_config_t) -> u8 {
    guarded(
        || unsafe { borrow_rs(c).map(|c| c.client as u8).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rs_config_strip_count(c: lr_bgp_rs_config_t) -> usize {
    guarded(
        || unsafe { borrow_rs(c).map(|c| c.strip_communities.len()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rs_config_strip_at(c: lr_bgp_rs_config_t, index: usize) -> u32 {
    guarded(
        || unsafe {
            borrow_rs(c)
                .and_then(|c| c.strip_communities.get(index).copied())
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rs_config_add_count(c: lr_bgp_rs_config_t) -> usize {
    guarded(
        || unsafe { borrow_rs(c).map(|c| c.add_communities.len()).unwrap_or(0) },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_bgp_rs_config_add_at(c: lr_bgp_rs_config_t, index: usize) -> u32 {
    guarded(
        || unsafe {
            borrow_rs(c)
                .and_then(|c| c.add_communities.get(index).copied())
                .unwrap_or(0)
        },
        0,
    )
}

// ---- shared helpers ----

unsafe fn cstr_to_optional_string(s: *const std::os::raw::c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(s) };
    match cstr.to_str() {
        Ok(s) => Some(s.to_string()),
        Err(e) => {
            set_last_error(format!("invalid UTF-8 in C string: {e}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_otc_role_round_trip() {
        for r in [
            LR_OTC_ROLE_UNSET,
            LR_OTC_ROLE_PROVIDER,
            LR_OTC_ROLE_CUSTOMER,
            LR_OTC_ROLE_PEER,
            LR_OTC_ROLE_ROUTE_SERVER,
            LR_OTC_ROLE_RS_CLIENT,
        ] {
            assert_eq!(lr_bgp_otc_role_to_u8(r), r);
            assert_eq!(lr_bgp_otc_role_from_u8(r), r);
        }
    }

    #[test]
    fn ffi_otc_role_is_upstream() {
        assert_eq!(lr_bgp_otc_role_is_upstream(LR_OTC_ROLE_PROVIDER), 1);
        assert_eq!(lr_bgp_otc_role_is_upstream(LR_OTC_ROLE_PEER), 1);
        assert_eq!(lr_bgp_otc_role_is_upstream(LR_OTC_ROLE_CUSTOMER), 0);
    }

    #[test]
    fn ffi_otc_new_and_value() {
        let o = lr_bgp_otc_new(64512);
        assert_eq!(unsafe { lr_bgp_otc_value(o) }, 64512);
        assert_eq!(unsafe { lr_bgp_otc_is_set(o) }, 1);
        unsafe { lr_bgp_otc_free(o) };
    }

    #[test]
    fn ffi_otc_encode_roundtrip() {
        let o = lr_bgp_otc_new(0x0a000001);
        let mut buf = [0u8; 4];
        assert_eq!(unsafe { lr_bgp_otc_encode(o, buf.as_mut_ptr()) }, 0);
        assert_eq!(buf, [0x0a, 0x00, 0x00, 0x01]);
        let o2 = unsafe { lr_bgp_otc_decode(buf.as_ptr(), 4) };
        assert!(!o2.is_null());
        assert_eq!(unsafe { lr_bgp_otc_value(o2) }, 0x0a000001);
        unsafe {
            lr_bgp_otc_free(o);
            lr_bgp_otc_free(o2);
        };
    }

    #[test]
    fn ffi_peer_role_from_asns() {
        assert_eq!(
            unsafe { lr_bgp_peer_role_from_asns(64512, 64512, std::ptr::null(), 0) },
            LR_PEER_ROLE_IBGP
        );
        assert_eq!(
            unsafe { lr_bgp_peer_role_from_asns(64512, 64513, std::ptr::null(), 0) },
            LR_PEER_ROLE_EBGP
        );
        let members = [64512u32, 64513, 64514];
        let role =
            unsafe { lr_bgp_peer_role_from_asns(64512, 64513, members.as_ptr(), members.len()) };
        assert_eq!(role, LR_PEER_ROLE_CONFED_EXTERNAL);
    }

    #[test]
    fn ffi_peer_role_predicates() {
        assert_eq!(lr_bgp_peer_role_is_internal(LR_PEER_ROLE_IBGP), 1);
        assert_eq!(lr_bgp_peer_role_is_external(LR_PEER_ROLE_EBGP), 1);
        assert_eq!(lr_bgp_peer_role_prepends_as_path(LR_PEER_ROLE_EBGP), 1);
        assert_eq!(lr_bgp_peer_role_rewrites_next_hop(LR_PEER_ROLE_EBGP), 1);
        assert_eq!(lr_bgp_peer_role_prepends_as_path(LR_PEER_ROLE_IBGP), 0);
    }

    #[test]
    fn ffi_peer_topology_new_and_readers() {
        let t = lr_bgp_peer_topology_new(LR_PEER_ROLE_IBGP, 1, 0, LR_OTC_ROLE_UNSET);
        assert!(!t.is_null());
        assert_eq!(unsafe { lr_bgp_peer_topology_role(t) }, LR_PEER_ROLE_IBGP);
        assert_eq!(unsafe { lr_bgp_peer_topology_rr_client(t) }, 1);
        assert_eq!(unsafe { lr_bgp_peer_topology_rs_client(t) }, 0);
        assert_eq!(
            unsafe { lr_bgp_peer_topology_otc_role(t) },
            LR_OTC_ROLE_UNSET
        );
        unsafe { lr_bgp_peer_topology_free(t) };
    }

    #[test]
    fn ffi_cluster_id_roundtrip() {
        let cid = lr_bgp_cluster_id_from_u32(0x0a000001);
        let mut out = [0u8; 4];
        assert_eq!(lr_bgp_cluster_id_to_v4_bytes(cid, out.as_mut_ptr()), 0);
        assert_eq!(out, [0x0a, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn ffi_rr_config_new_and_readers() {
        let c = lr_bgp_rr_config_new(0x0a000001, 1);
        assert_eq!(unsafe { lr_bgp_rr_config_cluster_id(c) }, 0x0a000001);
        assert_eq!(unsafe { lr_bgp_rr_config_enabled(c) }, 1);
        unsafe { lr_bgp_rr_config_free(c) };
    }

    #[test]
    fn ffi_confed_config_new_and_external_as() {
        let members = [64512u32, 64513, 64514];
        let c = unsafe { lr_bgp_confed_config_new(members.as_ptr(), members.len(), 0) };
        assert_eq!(unsafe { lr_bgp_confed_config_member_count(c) }, 3);
        assert_eq!(unsafe { lr_bgp_confed_config_contains(c, 64513) }, 1);
        assert_eq!(unsafe { lr_bgp_confed_config_external_as(c) }, 64512);
        unsafe { lr_bgp_confed_config_free(c) };
    }

    #[test]
    fn ffi_confed_config_with_explicit_id() {
        let members = [64512u32, 64513];
        let c = unsafe { lr_bgp_confed_config_new(members.as_ptr(), members.len(), 200) };
        assert_eq!(unsafe { lr_bgp_confed_config_external_as(c) }, 200);
        unsafe { lr_bgp_confed_config_free(c) };
    }

    #[test]
    fn ffi_rs_config_new_basic() {
        let c = unsafe { lr_bgp_rs_config_new(1, std::ptr::null(), std::ptr::null()) };
        assert_eq!(unsafe { lr_bgp_rs_config_client(c) }, 1);
        unsafe { lr_bgp_rs_config_free(c) };
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_bgp_otc_free(std::ptr::null_mut());
            lr_bgp_peer_topology_free(std::ptr::null_mut());
            lr_bgp_rr_config_free(std::ptr::null_mut());
            lr_bgp_confed_config_free(std::ptr::null_mut());
            lr_bgp_rs_config_free(std::ptr::null_mut());
        }
    }
}
