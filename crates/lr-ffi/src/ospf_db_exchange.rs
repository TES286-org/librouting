#![allow(unused_unsafe)]

use lr_ospf::exchange::{DbExchange, ExchangeStep, Phase};
use lr_ospf::packet::{OspfBody, OspfPacket, OspfVersion};
use lr_ospf::{codec::OspfCodec, lsdb::Lsdb};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::ospf::lr_ospf_packet_t;
use crate::ospf_lsdb::{borrow_lsdb, lr_ospf_lsa_box_t, lr_ospf_lsdb_t};
use crate::ospf_neighbor::{borrow_neighbor_mut, lr_ospf_neighbor_t};

const LR_ERR_NULL: i32 = LrError::Null as i32;

/// Opaque `DbExchange` handle.
#[repr(C)]
pub struct OpaqueOspfDbExchange {
    _private: [u8; 0],
}
pub type lr_ospf_db_exchange_t = *mut OpaqueOspfDbExchange;

fn box_exchange(e: DbExchange) -> lr_ospf_db_exchange_t {
    Box::into_raw(Box::new(e)) as lr_ospf_db_exchange_t
}
unsafe fn borrow_exchange(e: lr_ospf_db_exchange_t) -> Option<&'static DbExchange> {
    if e.is_null() {
        return None;
    }
    Some(unsafe { &*(e as *const DbExchange) })
}
unsafe fn borrow_exchange_mut(e: lr_ospf_db_exchange_t) -> Option<&'static mut DbExchange> {
    if e.is_null() {
        return None;
    }
    Some(unsafe { &mut *(e as *mut DbExchange) })
}
unsafe fn unbox_exchange(e: lr_ospf_db_exchange_t) -> Option<Box<DbExchange>> {
    if e.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(e as *mut DbExchange) })
}

// ---- Phase constants (mirror the Phase enum) ----

pub const LR_OSPF_PHASE_EX_START: i32 = 1;
pub const LR_OSPF_PHASE_EXCHANGE: i32 = 2;
pub const LR_OSPF_PHASE_LOADING: i32 = 3;
pub const LR_OSPF_PHASE_FULL: i32 = 4;

fn phase_to_i32(p: Phase) -> i32 {
    match p {
        Phase::ExStart => LR_OSPF_PHASE_EX_START,
        Phase::Exchange => LR_OSPF_PHASE_EXCHANGE,
        Phase::Loading => LR_OSPF_PHASE_LOADING,
        Phase::Full => LR_OSPF_PHASE_FULL,
    }
}

// ---- DbExchange surface ----

/// Construct a `DbExchange` for v2 (RFC 2328 §10.3). The driver
/// starts in ExStart with no pending DBD. Use
/// [`lr_ospf_db_exchange_with_version`] for a v3 driver.
#[no_mangle]
pub extern "C" fn lr_ospf_db_exchange_new(
    router_id: u32,
    area_id: u32,
    iface_mtu: u16,
) -> lr_ospf_db_exchange_t {
    guarded(
        || {
            box_exchange(DbExchange::with_version(
                router_id,
                area_id,
                iface_mtu,
                OspfVersion::V2,
            ))
        },
        std::ptr::null_mut(),
    )
}

/// Construct a `DbExchange` for `version` (1 = v2, anything else =
/// v3 / RFC 5340).
#[no_mangle]
pub extern "C" fn lr_ospf_db_exchange_with_version(
    router_id: u32,
    area_id: u32,
    iface_mtu: u16,
    version: u8,
) -> lr_ospf_db_exchange_t {
    guarded(
        || {
            let v = if version == 1 {
                OspfVersion::V2
            } else {
                OspfVersion::V3
            };
            box_exchange(DbExchange::with_version(router_id, area_id, iface_mtu, v))
        },
        std::ptr::null_mut(),
    )
}

/// Override the per-neighbor retransmit interval (RFC 2328 Appendix B
/// `RxmtInterval`; BIRD `rxmtint` / FRR `retransmit-interval`). The
/// default is 5000 ms; values of 0 are clamped to 1 ms so the poll
/// loop never busy-spins.
///
/// # Safety
/// `e` must be a valid DbExchange handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_with_rxmt_interval(
    e: lr_ospf_db_exchange_t,
    ms: u64,
) -> i32 {
    guarded(
        || unsafe {
            if e.is_null() {
                return LR_ERR_NULL;
            }
            // `with_rxmt_interval` consumes `self` (builder pattern).
            // Read the value out of the slot, apply the builder, write
            // the new value back. We use ptr::read + ptr::write so the
            // slot is left in a valid state (the builder's output).
            let old = unsafe { std::ptr::read(e as *const DbExchange) };
            let new = old.with_rxmt_interval(ms);
            unsafe { std::ptr::write(e as *mut DbExchange, new) };
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `DbExchange`. Safe to call with NULL.
///
/// # Safety
/// `e` must have been produced by a `lr_ospf_db_exchange_*`
/// constructor and not already freed.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_free(e: lr_ospf_db_exchange_t) {
    guarded(
        || unsafe {
            drop(unbox_exchange(e));
        },
        (),
    )
}

/// The current retransmit interval in milliseconds. Returns 0 on a
/// NULL handle.
///
/// # Safety
/// `e` must be a valid DbExchange handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_rxmt_interval_ms(e: lr_ospf_db_exchange_t) -> u64 {
    guarded(
        || unsafe {
            borrow_exchange(e)
                .map(|x| x.rxmt_interval_ms())
                .unwrap_or(0)
        },
        0,
    )
}

/// The current phase. Returns one of the `LR_OSPF_PHASE_*`
/// constants, or 0 on a NULL handle.
///
/// # Safety
/// See [`lr_ospf_db_exchange_rxmt_interval_ms`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_phase(e: lr_ospf_db_exchange_t) -> i32 {
    guarded(
        || unsafe {
            borrow_exchange(e)
                .map(|x| phase_to_i32(x.phase()))
                .unwrap_or(0)
        },
        0,
    )
}

/// True when the adjacency reached Full. Returns 1 on Full, 0
/// otherwise (or NULL handle).
///
/// # Safety
/// See [`lr_ospf_db_exchange_rxmt_interval_ms`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_is_full(e: lr_ospf_db_exchange_t) -> u8 {
    guarded(
        || unsafe { borrow_exchange(e).map(|x| x.is_full() as u8).unwrap_or(0) },
        0,
    )
}

/// True once the initial DBD was sent for this round (restarted by
/// a sequence mismatch). Returns 0 on a NULL handle.
///
/// # Safety
/// See [`lr_ospf_db_exchange_rxmt_interval_ms`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_started(e: lr_ospf_db_exchange_t) -> u8 {
    guarded(
        || unsafe { borrow_exchange(e).map(|x| x.started() as u8).unwrap_or(0) },
        0,
    )
}

/// Reset for a fresh negotiation round (ExStart re-entry — §10.9
/// sequence-mismatch handling).
///
/// # Safety
/// `e` must be a valid DbExchange handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_restart(e: lr_ospf_db_exchange_t, seq: u32) -> i32 {
    guarded(
        || unsafe {
            let Some(ex) = borrow_exchange_mut(e) else {
                return LR_ERR_NULL;
            };
            ex.restart(seq);
            0
        },
        LR_ERR_PANIC,
    )
}

/// Build the initial DBD packet (§10.3 — I|M|MS set, empty, sequence
/// chosen by the caller). Idempotent per negotiation round.
/// Returns a new `lr_ospf_packet_t` handle; the caller frees it with
/// `lr_ospf_packet_free`.
///
/// # Safety
/// `e` must be a valid DbExchange handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_initial_db_desc(
    e: lr_ospf_db_exchange_t,
    seq: u32,
    now_ms: u64,
) -> lr_ospf_packet_t {
    guarded(
        || unsafe {
            let Some(ex) = borrow_exchange_mut(e) else {
                return std::ptr::null_mut();
            };
            let pkt = ex.initial_db_desc(seq, now_ms);
            // Box the packet — lr_ospf_packet_free will drop it.
            Box::into_raw(Box::new(pkt)) as lr_ospf_packet_t
        },
        std::ptr::null_mut(),
    )
}

/// Periodic retransmission (§10.8 RxmtInterval): returns a freshly
/// allocated array of `lr_ospf_packet_t` handles (one per pending
/// retransmit — DBD and/or LS-Request). The array length is written
/// to `*out_count`; the array itself is written to `*out_packets`
/// (caller frees each entry with `lr_ospf_packet_free`, then frees
/// the array with `lr_ospf_db_exchange_packet_array_free`).
///
/// Returns 0 on success, `LR_ERR_NULL` on a NULL handle / NULL
/// out-pointers.
///
/// # Safety
/// `e` must be a valid DbExchange handle. `out_packets` and
/// `out_count` must point to writable memory.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_poll(
    e: lr_ospf_db_exchange_t,
    now_ms: u64,
    out_packets: *mut *mut lr_ospf_packet_t,
    out_count: *mut usize,
) -> i32 {
    guarded(
        || unsafe {
            let Some(ex) = borrow_exchange_mut(e) else {
                return LR_ERR_NULL;
            };
            if out_packets.is_null() || out_count.is_null() {
                return LR_ERR_NULL;
            }
            let packets = ex.poll(now_ms);
            let n = packets.len();
            if n == 0 {
                unsafe {
                    *out_packets = std::ptr::null_mut();
                    *out_count = 0;
                }
                return 0;
            }
            // Allocate a C array of packet handles.
            // lr_ospf_packet_t is itself *mut OpaqueOspfPacket, so an
            // array of handles is *mut lr_ospf_packet_t = *mut *mut OpaqueOspfPacket.
            let layout = std::alloc::Layout::array::<lr_ospf_packet_t>(n).expect("layout");
            let arr = unsafe { std::alloc::alloc_zeroed(layout) as *mut lr_ospf_packet_t };
            if arr.is_null() {
                set_alloc_failure();
                return LrError::Other as i32;
            }
            for (i, pkt) in packets.into_iter().enumerate() {
                let handle = Box::into_raw(Box::new(pkt)) as lr_ospf_packet_t;
                unsafe {
                    *arr.add(i) = handle;
                }
            }
            unsafe {
                *out_packets = arr;
                *out_count = n;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop an array of `lr_ospf_packet_t` handles returned by
/// `lr_ospf_db_exchange_poll`. Frees each entry via
/// `lr_ospf_packet_free`, then frees the array allocation.
///
/// # Safety
/// `packets` must have been produced by `lr_ospf_db_exchange_poll`
/// and `count` must match the count returned by that call.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_packet_array_free(
    packets: *mut lr_ospf_packet_t,
    count: usize,
) {
    guarded(
        || unsafe {
            if packets.is_null() || count == 0 {
                return;
            }
            for i in 0..count {
                let handle = unsafe { *packets.add(i) };
                if !handle.is_null() {
                    // lr_ospf_packet_free is the public dtor.
                    crate::ospf::lr_ospf_packet_free(handle);
                }
            }
            let layout = std::alloc::Layout::array::<lr_ospf_packet_t>(count).expect("layout");
            unsafe { std::alloc::dealloc(packets as *mut u8, layout) };
        },
        (),
    )
}

/// Build the LS-Request packet for the current queue (Loading).
/// Returns a new `lr_ospf_packet_t` handle when there are pending
/// requests, NULL when the queue is empty (or NULL exchange).
///
/// # Safety
/// `e` must be a valid DbExchange handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_take_ls_request(
    e: lr_ospf_db_exchange_t,
    now_ms: u64,
) -> lr_ospf_packet_t {
    guarded(
        || unsafe {
            let Some(ex) = borrow_exchange_mut(e) else {
                return std::ptr::null_mut();
            };
            match ex.take_ls_request(now_ms) {
                Some(pkt) => Box::into_raw(Box::new(pkt)) as lr_ospf_packet_t,
                None => std::ptr::null_mut(),
            }
        },
        std::ptr::null_mut(),
    )
}

/// Number of LSAs still queued in Loading (the LS-Request queue
/// length). Returns 0 on a NULL handle.
///
/// # Safety
/// See [`lr_ospf_db_exchange_rxmt_interval_ms`].
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_pending_requests(e: lr_ospf_db_exchange_t) -> usize {
    guarded(
        || unsafe {
            borrow_exchange(e)
                .map(|x| x.pending_requests())
                .unwrap_or(0)
        },
        0,
    )
}

// ---- Receive path: on_db_desc / on_ls_request / on_ls_update ----

#[repr(C)]
pub struct lr_ospf_exchange_step_t {
    pub out_packets: *mut lr_ospf_packet_t,
    pub out_packet_count: usize,
    pub out_lsas: *mut lr_ospf_lsa_box_t,
    pub out_lsa_count: usize,
    pub newly_full: u8,
}

impl Default for lr_ospf_exchange_step_t {
    fn default() -> Self {
        Self {
            out_packets: std::ptr::null_mut(),
            out_packet_count: 0,
            out_lsas: std::ptr::null_mut(),
            out_lsa_count: 0,
            newly_full: 0,
        }
    }
}

fn box_packet(p: OspfPacket) -> lr_ospf_packet_t {
    Box::into_raw(Box::new(p)) as lr_ospf_packet_t
}

fn pack_step(step: ExchangeStep) -> Result<lr_ospf_exchange_step_t, ()> {
    let mut out = lr_ospf_exchange_step_t {
        newly_full: step.newly_full as u8,
        ..lr_ospf_exchange_step_t::default()
    };
    if !step.outbound.is_empty() {
        let n = step.outbound.len();
        let layout = std::alloc::Layout::array::<lr_ospf_packet_t>(n).map_err(|_| ())?;
        let arr = unsafe { std::alloc::alloc_zeroed(layout) as *mut lr_ospf_packet_t };
        if arr.is_null() {
            return Err(());
        }
        for (i, pkt) in step.outbound.into_iter().enumerate() {
            unsafe { *arr.add(i) = box_packet(pkt) };
        }
        out.out_packets = arr;
        out.out_packet_count = n;
    }
    if !step.lsas.is_empty() {
        let n = step.lsas.len();
        let layout = std::alloc::Layout::array::<lr_ospf_lsa_box_t>(n).map_err(|_| {
            if !out.out_packets.is_null() {
                unsafe {
                    lr_ospf_db_exchange_packet_array_free(out.out_packets, out.out_packet_count);
                }
            }
        })?;
        let arr = unsafe { std::alloc::alloc_zeroed(layout) as *mut lr_ospf_lsa_box_t };
        if arr.is_null() {
            if !out.out_packets.is_null() {
                unsafe {
                    lr_ospf_db_exchange_packet_array_free(out.out_packets, out.out_packet_count);
                }
            }
            return Err(());
        }
        for (i, lsa) in step.lsas.into_iter().enumerate() {
            let h = Box::into_raw(Box::new(lsa)) as lr_ospf_lsa_box_t;
            unsafe { *arr.add(i) = h };
        }
        out.out_lsas = arr;
        out.out_lsa_count = n;
    }
    Ok(out)
}

unsafe fn decode_packet_v2(data: *const u8, len: usize) -> Result<Option<OspfPacket>, ()> {
    if data.is_null() && len != 0 {
        set_last_error("decode: null data".into());
        return Err(());
    }
    let slice = if len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    let mut codec = OspfCodec::v2();
    match codec.decode_slice(slice) {
        Ok(Some(p)) => Ok(Some(p)),
        Ok(None) => Ok(None),
        Err(e) => {
            set_last_error(format!("OSPFv2 decode: {e:?}"));
            Err(())
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_on_db_desc_packet(
    e: lr_ospf_db_exchange_t,
    neighbor: lr_ospf_neighbor_t,
    lsdb: lr_ospf_lsdb_t,
    data: *const u8,
    len: usize,
    now_ms: u64,
    out: *mut lr_ospf_exchange_step_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(ex) = borrow_exchange_mut(e) else {
                return LR_ERR_NULL;
            };
            let Some(neighbor_ref) = borrow_neighbor_mut(neighbor) else {
                return LR_ERR_NULL;
            };
            let empty_lsdb = Lsdb::new();
            let lsdb_ref: &Lsdb = unsafe { borrow_lsdb(lsdb) }.unwrap_or(&empty_lsdb);
            let pkt = match unsafe { decode_packet_v2(data, len) } {
                Ok(Some(p)) => p,
                Ok(None) => {
                    set_last_error("on_db_desc: truncated".into());
                    return LrError::Codec as i32;
                }
                Err(()) => return LrError::Codec as i32,
            };
            let body = match pkt.body {
                OspfBody::DbDesc(d) => d,
                ref other => {
                    set_last_error(format!(
                        "expected DbDesc, got {:?}",
                        std::mem::discriminant(other)
                    ));
                    return LrError::Other as i32;
                }
            };
            let step = ex.on_db_desc(&body, pkt.header.router_id, lsdb_ref, neighbor_ref, now_ms);
            match pack_step(step) {
                Ok(packed) => {
                    unsafe { *out = packed };
                    0
                }
                Err(()) => {
                    crate::error::set_last_error("alloc failed".into());
                    LrError::Other as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_on_ls_request_packet(
    e: lr_ospf_db_exchange_t,
    neighbor: lr_ospf_neighbor_t,
    lsdb: lr_ospf_lsdb_t,
    data: *const u8,
    len: usize,
    now_ms: u64,
    out: *mut lr_ospf_exchange_step_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(ex) = borrow_exchange_mut(e) else {
                return LR_ERR_NULL;
            };
            let Some(neighbor_ref) = borrow_neighbor_mut(neighbor) else {
                return LR_ERR_NULL;
            };
            let empty_lsdb = Lsdb::new();
            let lsdb_ref: &Lsdb = unsafe { borrow_lsdb(lsdb) }.unwrap_or(&empty_lsdb);
            let pkt = match unsafe { decode_packet_v2(data, len) } {
                Ok(Some(p)) => p,
                Ok(None) => {
                    set_last_error("on_ls_request: truncated".into());
                    return LrError::Codec as i32;
                }
                Err(()) => return LrError::Codec as i32,
            };
            let body = match pkt.body {
                OspfBody::LsRequest(r) => r,
                ref other => {
                    set_last_error(format!(
                        "expected LsRequest, got {:?}",
                        std::mem::discriminant(other)
                    ));
                    return LrError::Other as i32;
                }
            };
            let step = ex.on_ls_request(&body, lsdb_ref, neighbor_ref, now_ms);
            match pack_step(step) {
                Ok(packed) => {
                    unsafe { *out = packed };
                    0
                }
                Err(()) => {
                    crate::error::set_last_error("alloc failed".into());
                    LrError::Other as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_on_ls_update_packet(
    e: lr_ospf_db_exchange_t,
    neighbor: lr_ospf_neighbor_t,
    data: *const u8,
    len: usize,
    out: *mut lr_ospf_exchange_step_t,
) -> i32 {
    guarded(
        || unsafe {
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let Some(ex) = borrow_exchange_mut(e) else {
                return LR_ERR_NULL;
            };
            let Some(neighbor_ref) = borrow_neighbor_mut(neighbor) else {
                return LR_ERR_NULL;
            };
            let pkt = match unsafe { decode_packet_v2(data, len) } {
                Ok(Some(p)) => p,
                Ok(None) => {
                    set_last_error("on_ls_update: truncated".into());
                    return LrError::Codec as i32;
                }
                Err(()) => return LrError::Codec as i32,
            };
            let lsas = match pkt.body {
                OspfBody::LsUpdate(u) => u.lsas,
                ref other => {
                    set_last_error(format!(
                        "expected LsUpdate, got {:?}",
                        std::mem::discriminant(other)
                    ));
                    return LrError::Other as i32;
                }
            };
            let step = ex.on_ls_update(&lsas, neighbor_ref);
            match pack_step(step) {
                Ok(packed) => {
                    unsafe { *out = packed };
                    0
                }
                Err(()) => {
                    crate::error::set_last_error("alloc failed".into());
                    LrError::Other as i32
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_ospf_db_exchange_step_free(step: *mut lr_ospf_exchange_step_t) {
    guarded(
        || unsafe {
            if step.is_null() {
                return;
            }
            let s = unsafe { &mut *step };
            if !s.out_packets.is_null() && s.out_packet_count > 0 {
                unsafe {
                    lr_ospf_db_exchange_packet_array_free(s.out_packets, s.out_packet_count);
                }
                s.out_packets = std::ptr::null_mut();
                s.out_packet_count = 0;
            }
            if !s.out_lsas.is_null() && s.out_lsa_count > 0 {
                unsafe {
                    crate::ospf_lsdb::lr_ospf_lsa_array_free(s.out_lsas, s.out_lsa_count);
                }
                s.out_lsas = std::ptr::null_mut();
                s.out_lsa_count = 0;
            }
            s.newly_full = 0;
        },
        (),
    )
}

// ---- helpers ----

fn set_alloc_failure() {
    crate::error::set_last_error("packet array allocation failed".into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_db_exchange_new_and_phase() {
        let e = lr_ospf_db_exchange_new(0x01020304, 0, 1500);
        assert!(!e.is_null());
        assert_eq!(
            unsafe { lr_ospf_db_exchange_phase(e) },
            LR_OSPF_PHASE_EX_START
        );
        assert_eq!(unsafe { lr_ospf_db_exchange_is_full(e) }, 0);
        assert_eq!(unsafe { lr_ospf_db_exchange_started(e) }, 0);
        assert_eq!(unsafe { lr_ospf_db_exchange_pending_requests(e) }, 0);
        unsafe { lr_ospf_db_exchange_free(e) };
    }

    #[test]
    fn ffi_db_exchange_initial_db_desc() {
        let e = lr_ospf_db_exchange_new(0x01020304, 0, 1500);
        let pkt = unsafe { lr_ospf_db_exchange_initial_db_desc(e, 0x12345678, 0) };
        assert!(!pkt.is_null());
        assert_eq!(unsafe { lr_ospf_db_exchange_started(e) }, 1);
        // The packet type is DatabaseDescription (2).
        assert_eq!(unsafe { crate::ospf::lr_ospf_packet_type(pkt) }, 2);
        unsafe {
            crate::ospf::lr_ospf_packet_free(pkt);
            lr_ospf_db_exchange_free(e);
        };
    }

    #[test]
    fn ffi_db_exchange_with_rxmt_interval() {
        let e = lr_ospf_db_exchange_new(0x01020304, 0, 1500);
        let rc = unsafe { lr_ospf_db_exchange_with_rxmt_interval(e, 10_000) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_ospf_db_exchange_rxmt_interval_ms(e) }, 10_000);
        unsafe { lr_ospf_db_exchange_free(e) };
    }

    #[test]
    fn ffi_db_exchange_restart() {
        let e = lr_ospf_db_exchange_new(0x01020304, 0, 1500);
        let _ = unsafe { lr_ospf_db_exchange_initial_db_desc(e, 0x12345678, 0) };
        assert_eq!(unsafe { lr_ospf_db_exchange_started(e) }, 1);
        let rc = unsafe { lr_ospf_db_exchange_restart(e, 0x87654321) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_ospf_db_exchange_started(e) }, 0);
        unsafe { lr_ospf_db_exchange_free(e) };
    }

    #[test]
    fn ffi_db_exchange_poll_no_op_on_fresh() {
        // A fresh exchange has no pending DBD and no LS-Request queue.
        let e = lr_ospf_db_exchange_new(0x01020304, 0, 1500);
        let mut packets: *mut lr_ospf_packet_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc = unsafe { lr_ospf_db_exchange_poll(e, 0, &raw mut packets, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 0);
        // No array to free when count is 0.
        unsafe { lr_ospf_db_exchange_free(e) };
    }

    #[test]
    fn ffi_db_exchange_poll_retransmits_pending_db_desc() {
        let e = lr_ospf_db_exchange_new(0x01020304, 0, 1500);
        // Send the initial DBD at t=0.
        let pkt = unsafe { lr_ospf_db_exchange_initial_db_desc(e, 0x12345678, 0) };
        unsafe { crate::ospf::lr_ospf_packet_free(pkt) };

        // Poll at t=rxmt_interval — should retransmit the pending DBD.
        let rxmt = unsafe { lr_ospf_db_exchange_rxmt_interval_ms(e) };
        let mut packets: *mut lr_ospf_packet_t = std::ptr::null_mut();
        let mut count: usize = 0;
        let rc = unsafe { lr_ospf_db_exchange_poll(e, rxmt, &raw mut packets, &raw mut count) };
        assert_eq!(rc, 0);
        assert_eq!(count, 1, "should retransmit the pending DBD");
        // Free the retransmitted packet array.
        unsafe { lr_ospf_db_exchange_packet_array_free(packets, count) };
        unsafe { lr_ospf_db_exchange_free(e) };
    }

    #[test]
    fn ffi_db_exchange_take_ls_request_returns_null_when_empty() {
        let e = lr_ospf_db_exchange_new(0x01020304, 0, 1500);
        let pkt = unsafe { lr_ospf_db_exchange_take_ls_request(e, 0) };
        assert!(pkt.is_null());
        unsafe { lr_ospf_db_exchange_free(e) };
    }

    #[test]
    fn ffi_db_exchange_handles_null_safely() {
        assert_eq!(
            unsafe { lr_ospf_db_exchange_phase(std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { lr_ospf_db_exchange_rxmt_interval_ms(std::ptr::null_mut()) },
            0
        );
        assert_eq!(
            unsafe { lr_ospf_db_exchange_pending_requests(std::ptr::null_mut()) },
            0
        );
        unsafe {
            lr_ospf_db_exchange_free(std::ptr::null_mut());
            lr_ospf_db_exchange_packet_array_free(std::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn ffi_db_exchange_with_version_v3() {
        let e = unsafe { lr_ospf_db_exchange_with_version(0x01020304, 0, 1500, 2) };
        assert!(!e.is_null());
        // v3 packets have version byte 3 in the OSPF header; the
        // exchange driver tracks the same version internally.
        unsafe { lr_ospf_db_exchange_free(e) };
    }
}
