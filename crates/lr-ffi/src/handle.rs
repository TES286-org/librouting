//! Opaque handle types exposed to C.

use lr_router::DefaultRouter;
use std::sync::Mutex;

/// Opaque router handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueRouter {
    _private: [u8; 0],
}

pub type lr_router_t = *mut OpaqueRouter;

/// Rust-allocated byte slice that the embedder owns and must free.
#[repr(C)]
pub struct lr_bytes_t {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl lr_bytes_t {
    pub fn from_vec(v: Vec<u8>) -> Self {
        let mut v = v;
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        std::mem::forget(v);
        Self { ptr, len, cap }
    }

    /// Reclaim the bytes from a foreign-owned buffer and drop it.
    ///
    /// # Safety
    /// The pointer must have been produced by [`Self::from_vec`].
    pub unsafe fn reclaim_into_vec(&mut self) -> Vec<u8> {
        if self.ptr.is_null() {
            return Vec::new();
        }
        let v = unsafe { Vec::from_raw_parts(self.ptr, self.len, self.cap) };
        self.ptr = std::ptr::null_mut();
        self.len = 0;
        self.cap = 0;
        v
    }
}

/// Helper to construct an opaque router from a DefaultRouter (behind a Mutex).
pub fn box_router(r: DefaultRouter) -> lr_router_t {
    let boxed: Box<Mutex<DefaultRouter>> = Box::new(Mutex::new(r));
    Box::into_raw(boxed) as lr_router_t
}

/// Helper to drop an opaque router back into its boxed Mutex<DefaultRouter>.
///
/// # Destroy contract
///
/// `lr_router_destroy` must not run concurrently with any other `lr_*` call
/// on the same router handle, and must not be called from a thread that
/// currently holds the router lock (e.g. from inside a hook, sink or
/// callback running under [`lock_router`]). Destroying while another thread
/// is inside a call is a use-after-free; destroying the same handle twice is
/// a double-free. Nothing is drained or flushed here: the boxed mutex (and
/// with it all session state, RIBs and queued output) is dropped as-is, so
/// callers that need a graceful teardown must drain/tick first and must
/// ensure no other thread can still call into the router before destroying.
///
/// # Safety
/// The pointer must have been produced by [`box_router`] and not already
/// destroyed.
pub unsafe fn unbox_router(r: lr_router_t) {
    if r.is_null() {
        return;
    }
    unsafe {
        let boxed: Box<Mutex<DefaultRouter>> = Box::from_raw(r as *mut Mutex<DefaultRouter>);
        drop(boxed);
    }
}

/// Lock the router for use.
///
/// # Non-reentrant — deadlock hazard (read carefully)
///
/// Every FFI entry point holds this lock for the entire call, including
/// while running import/export hooks and the BMP sink. The underlying
/// `std::sync::Mutex` is **not reentrant**: a hook, sink or callback that
/// calls *any* `lr_*` function for the same router on the same thread will
/// deadlock on the second acquisition. Never call back into the FFI from
/// code that runs under this lock — collect the work you need and call back
/// only after the entry point returns.
///
/// A panic while the lock is held poisons the mutex; after that every
/// `lock_router` returns `None` and every entry point fails. The
/// `catch_unwind` barrier in `lib.rs` prevents most panics from escaping,
/// but a panic that originates outside Rust (C unwind, abort) is not
/// recoverable and leaves the router unusable — treat the handle as
/// poisoned after any such event.
///
/// # Safety
/// `r` must have been produced by [`box_router`] and must not be destroyed
/// (via [`unbox_router`]) while another thread is inside a call that holds
/// this lock — see the destroy contract above.
pub unsafe fn lock_router(r: lr_router_t) -> Option<std::sync::MutexGuard<'static, DefaultRouter>> {
    if r.is_null() {
        return None;
    }
    unsafe {
        let m: &Mutex<DefaultRouter> = &*(r as *const Mutex<DefaultRouter>);
        m.lock().ok()
    }
}

// ---- ROA store handle (`lr_roa_store_t`, ROADMAP-v3 D2.3) ----

/// Opaque ROA store handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueRoaStore {
    _private: [u8; 0],
}

pub type lr_roa_store_t = *mut OpaqueRoaStore;

/// Helper to construct an opaque store from a `RoaStore`. No Mutex
/// wrapper — `RoaStore` is already `Send + Sync` (its readers are
/// read-locked `Arc` clones), so wrapping it in a `Mutex` would
/// serialize the FFI validation path against the advertised lock-free
/// reads. Concurrent `lr_roa_store_*` calls are safe; the only
/// exclusion is `lr_roa_store_free`, exactly like the router handle's
/// destroy contract.
pub fn box_roa_store(s: lr_bgp::RoaStore) -> lr_roa_store_t {
    Box::into_raw(Box::new(s)) as lr_roa_store_t
}

/// Helper to drop an opaque store back into its Box.
///
/// # Safety
/// `s` must have been produced by [`box_roa_store`] and must not be
/// destroyed while another thread is inside a call on the same handle.
pub unsafe fn unbox_roa_store(s: lr_roa_store_t) -> Box<lr_bgp::RoaStore> {
    unsafe { Box::from_raw(s as *mut lr_bgp::RoaStore) }
}
