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
/// # Safety
/// The pointer must have been produced by [`box_router`].
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
/// # Safety
/// `r` must have been produced by [`box_router`].
pub unsafe fn lock_router(r: lr_router_t) -> Option<std::sync::MutexGuard<'static, DefaultRouter>> {
    if r.is_null() {
        return None;
    }
    unsafe {
        let m: &Mutex<DefaultRouter> = &*(r as *const Mutex<DefaultRouter>);
        m.lock().ok()
    }
}
