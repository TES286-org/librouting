//! Error code surface + thread-local last-error string.

use std::cell::RefCell;

/// Error code returned by FFI functions. 0 = success, negative = error.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LrError {
    Ok = 0,
    Null = -1,
    InvalidHandle = -2,
    BadUtf8 = -3,
    Panic = -4,
    AbiMismatch = -5,
    Other = -6,
}

pub type lr_error_t = i32;

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

pub fn set_last_error(s: String) {
    LAST_ERROR.with(|c| *c.borrow_mut() = s);
}

/// Get the last error message. Returned string is NUL-terminated UTF-8.
///
/// # Safety
/// The returned pointer is valid until the next FFI call on this thread.
#[no_mangle]
pub extern "C" fn lr_last_error() -> *const std::os::raw::c_char {
    thread_local! {
        static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    BUF.with(|b| {
        let mut b = b.borrow_mut();
        b.clear();
        LAST_ERROR.with(|e| {
            b.extend_from_slice(e.borrow().as_bytes());
        });
        b.push(0);
        b.as_ptr() as *const std::os::raw::c_char
    })
}

/// ABI version packed as u32. Compare to `lr_core::ABI_VERSION`.
#[no_mangle]
pub extern "C" fn lr_abi_version() -> u32 {
    lr_core::ABI_VERSION
}
