//! MPLS label and label-stack codec FFI (RFC 3032 §2.1, RFC 8277 §2.2/§2.3).
//!
//! Stateless. Mirrors the public Rust API of `lr_mpls::{Label, LabelStack}`
//! so an embedder can build, inspect and round-trip MPLS label stacks
//! without going through the Rust compiler.
//!
//! # Surface
//!
//! - `lr_mpls_label_new` / `lr_mpls_label_with_tc` / `lr_mpls_label_with_ttl`
//!   — construct a `Label` (returned as `lr_mpls_label_t`, an opaque handle
//!   to a boxed `Label`).
//! - `lr_mpls_label_value` / `lr_mpls_label_tc` / `lr_mpls_label_ttl` —
//!   readers.
//! - `lr_mpls_label_encode_3octet` / `lr_mpls_label_encode_4octet` —
//!   single-entry encoders (3-octet NLRI form vs 4-octet wire form).
//! - `lr_mpls_label_free` — drop the boxed `Label`.
//!
//! - `lr_mpls_label_stack_new` — empty stack (builder starting point).
//! - `lr_mpls_label_stack_from_values` / `lr_mpls_label_stack_from_4octet` /
//!   `lr_mpls_label_stack_from_3octet` — bulk constructors.
//! - `lr_mpls_label_stack_push` / `lr_mpls_label_stack_push_bottom` /
//!   `lr_mpls_label_stack_pop` — top/bottom mutation.
//! - `lr_mpls_label_stack_len` / `lr_mpls_label_stack_is_empty` /
//!   `lr_mpls_label_stack_at` — readers.
//! - `lr_mpls_label_stack_encode_3octet` / `lr_mpls_label_stack_encode_4octet`
//!   / `lr_mpls_label_stack_decode_3octet` /
//!   `lr_mpls_label_stack_decode_4octet` — wire-form round-trip.
//! - `lr_mpls_label_stack_free` — drop the boxed `LabelStack`.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier
//! ([`crate::guarded`]): a panic returns `LR_ERR_PANIC` and sets the
//! thread-local last-error string.

// The closure body passed to `guarded` is wrapped in a single `unsafe`
// block to mirror the `pub unsafe extern "C" fn` shape — the inner
// `unsafe { ... }` blocks would otherwise trip `unused_unsafe` under
// the crate's `-D warnings` clippy gate.
#![allow(unused_unsafe)]

use lr_mpls::{Label, LabelStack, LabelStackError};

use crate::error::{set_last_error, LrError, LR_ERR_PANIC};
use crate::guarded;
use crate::handle::lr_bytes_t;

/// `LR_ERR_NULL` (-1) — null pointer or null handle.
const LR_ERR_NULL: i32 = LrError::Null as i32;
/// `LR_ERR_INVALID_HANDLE` (-2) — wrong message variant or invalid index.
const LR_ERR_INVALID_HANDLE: i32 = LrError::InvalidHandle as i32;
/// `LR_ERR_OTHER` (-6) — index out of range or other documented failure.
const LR_ERR_OTHER: i32 = LrError::Other as i32;

/// Opaque `Label` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueMplsLabel {
    _private: [u8; 0],
}

pub type lr_mpls_label_t = *mut OpaqueMplsLabel;

/// Opaque `LabelStack` handle. C side never touches internals.
#[repr(C)]
pub struct OpaqueMplsLabelStack {
    _private: [u8; 0],
}

pub type lr_mpls_label_stack_t = *mut OpaqueMplsLabelStack;

/// Box a `Label` into an opaque handle.
fn box_label(l: Label) -> lr_mpls_label_t {
    Box::into_raw(Box::new(l)) as lr_mpls_label_t
}

/// Reclaim a `Label` handle back into its boxed `Label`.
///
/// # Safety
/// `l` must have been produced by [`box_label`] and not already freed.
unsafe fn unbox_label(l: lr_mpls_label_t) -> Option<Box<Label>> {
    if l.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(l as *mut Label) })
}

/// Borrow a `Label` handle as `&Label` for read-only access.
///
/// # Safety
/// `l` must have been produced by [`box_label`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_label(l: lr_mpls_label_t) -> Option<&'static Label> {
    if l.is_null() {
        return None;
    }
    Some(unsafe { &*(l as *const Label) })
}

/// Box a `LabelStack` into an opaque handle.
pub(crate) fn box_stack(s: LabelStack) -> lr_mpls_label_stack_t {
    Box::into_raw(Box::new(s)) as lr_mpls_label_stack_t
}

/// Reclaim a `LabelStack` handle.
///
/// # Safety
/// `s` must have been produced by [`box_stack`] and not already freed.
unsafe fn unbox_stack(s: lr_mpls_label_stack_t) -> Option<Box<LabelStack>> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(s as *mut LabelStack) })
}

/// Borrow a `LabelStack` handle as `&LabelStack` for read-only access.
///
/// # Safety
/// `s` must have been produced by [`box_stack`] and not be freed while
/// the returned reference is live.
unsafe fn borrow_stack(s: lr_mpls_label_stack_t) -> Option<&'static LabelStack> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &*(s as *const LabelStack) })
}

/// Reclaim a `LabelStack` handle as a `&mut LabelStack` for in-place
/// mutation. The borrow is unbounded — the caller must not race the
/// mutation with another `lr_mpls_label_stack_*` call on the same
/// handle.
///
/// # Safety
/// `s` must have been produced by [`box_stack`] and not be freed while
/// the returned reference is live. The handle type is `*mut`, so the
/// borrow checker cannot help enforce the no-race contract — the
/// embedder must.
unsafe fn borrow_stack_mut(s: lr_mpls_label_stack_t) -> Option<&'static mut LabelStack> {
    if s.is_null() {
        return None;
    }
    Some(unsafe { &mut *(s as *mut LabelStack) })
}

/// Translate a [`LabelStackError`] to a negative `lr_*` return code.
fn err_code(e: &LabelStackError) -> i32 {
    match e {
        // Input shape problems → Other (-6): documented as "index out of
        // range or other documented failure". Keeps Codec (-5) reserved
        // for SRv6 SRH encode/decode only (see error.rs).
        LabelStackError::TooShort
        | LabelStackError::UnevenLength
        | LabelStackError::MidStackBottom
        | LabelStackError::ValueOutOfRange(_) => LR_ERR_OTHER,
    }
}

// ---- Label surface ----

/// Construct a `Label` with default TC=0 and TTL=64 (RFC 3032 §2.1).
/// Infallible — the value is masked to 20 bits on encode. Returns
/// `NULL` only on a panic.
///
/// `value > Label::MAX_VALUE` is allowed here (matches the Rust
/// `Label::new` semantics); use [`lr_mpls_label_new_checked`] to
/// validate the 20-bit range.
#[no_mangle]
pub extern "C" fn lr_mpls_label_new(value: u32) -> lr_mpls_label_t {
    guarded(|| box_label(Label::new(value)), std::ptr::null_mut())
}

/// Checked constructor — returns `NULL` and sets the last-error string
/// when `value` exceeds the 20-bit label range (RFC 3032 §2.1). On
/// success the boxed `Label` carries `tc=0, ttl=64`.
#[no_mangle]
pub extern "C" fn lr_mpls_label_new_checked(value: u32) -> lr_mpls_label_t {
    guarded(
        || match Label::try_new(value) {
            Ok(l) => box_label(l),
            Err(e) => {
                set_last_error(e.to_string());
                std::ptr::null_mut()
            }
        },
        std::ptr::null_mut(),
    )
}

/// Set the Traffic Class (3 bits, RFC 5462). The lower 3 bits of `tc`
/// are taken; the rest are masked. Returns a NEW handle (the input
/// handle is consumed and freed); returns `NULL` if `label` is NULL.
///
/// The builder-style `with_tc` returns a NEW `Label` in Rust; the FFI
/// surface mirrors that by transferring ownership: the input handle is
/// invalid after the call. Use the returned handle for subsequent
/// reads.
///
/// # Safety
/// `label` must have been produced by [`lr_mpls_label_new`] (or one of
/// the other `lr_mpls_label_*` constructors) and must not be used
/// after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_with_tc(label: lr_mpls_label_t, tc: u8) -> lr_mpls_label_t {
    guarded(
        || unsafe { label_with_field(label, |l| l.with_tc(tc)) }.unwrap_or(std::ptr::null_mut()),
        std::ptr::null_mut(),
    )
}

/// Set the TTL. Returns a NEW handle; the input is consumed.
///
/// # Safety
/// See [`lr_mpls_label_with_tc`].
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_with_ttl(
    label: lr_mpls_label_t,
    ttl: u8,
) -> lr_mpls_label_t {
    guarded(
        || unsafe { label_with_field(label, |l| l.with_ttl(ttl)) }.unwrap_or(std::ptr::null_mut()),
        std::ptr::null_mut(),
    )
}

/// Shared body for `with_tc` / `with_ttl`: take ownership of the boxed
/// `Label`, apply the field-mapping closure, and box the result back.
/// Returns `None` when `label` is NULL (the caller surfaces that as
/// NULL on the C side).
///
/// # Safety
/// `label` must have been produced by [`box_label`] and not already
/// freed.
unsafe fn label_with_field<F: FnOnce(Label) -> Label>(
    label: lr_mpls_label_t,
    f: F,
) -> Option<lr_mpls_label_t> {
    let boxed = unsafe { unbox_label(label) }?;
    Some(box_label(f(*boxed)))
}

/// Read the 20-bit label value. Returns 0 on a NULL handle.
///
/// # Safety
/// `label` must have been produced by a `lr_mpls_label_*` constructor
/// and not freed.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_value(label: lr_mpls_label_t) -> u32 {
    guarded(
        || unsafe { borrow_label(label).map(|l| l.value).unwrap_or(0) },
        0,
    )
}

/// Read the 3-bit Traffic Class. Returns 0 on a NULL handle.
///
/// # Safety
/// See [`lr_mpls_label_value`].
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_tc(label: lr_mpls_label_t) -> u8 {
    guarded(
        || unsafe { borrow_label(label).map(|l| l.tc).unwrap_or(0) },
        0,
    )
}

/// Read the 8-bit TTL. Returns 0 on a NULL handle.
///
/// # Safety
/// See [`lr_mpls_label_value`].
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_ttl(label: lr_mpls_label_t) -> u8 {
    guarded(
        || unsafe { borrow_label(label).map(|l| l.ttl).unwrap_or(0) },
        0,
    )
}

/// True when the label value is in the reserved range 0–15 (RFC 3032
/// §2.1). Returns 0 (false) on a NULL handle.
///
/// # Safety
/// See [`lr_mpls_label_value`].
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_is_reserved(label: lr_mpls_label_t) -> u8 {
    guarded(
        || unsafe {
            borrow_label(label)
                .map(|l| l.is_reserved() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

/// Encode as a single 3-octet NLRI entry (RFC 8277 §2.2/§2.3:
/// `Label(20) | Rsrv(3) | S(1)`, no TTL and no TC field). `bottom`
/// sets the S bit. Writes 3 bytes to `*out`. Returns 0 on success,
/// negative on error.
///
/// # Safety
/// `label` must be a valid handle. `out` must point to writable memory
/// of at least 3 bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_encode_3octet(
    label: lr_mpls_label_t,
    bottom: u8,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(l) = borrow_label(label) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = l.encode_3octet(bottom != 0);
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 3);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode as a single 4-octet wire entry (RFC 3032 §2.1: label + TC
/// + S + TTL). `bottom` sets the S bit. Writes 4 bytes to `*out`.
///
/// # Safety
/// See [`lr_mpls_label_encode_3octet`]; `out` needs at least 4 bytes.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_encode_4octet(
    label: lr_mpls_label_t,
    bottom: u8,
    out: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(l) = borrow_label(label) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = l.encode_4octet(bottom != 0);
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 4);
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `Label`. Safe to call with NULL.
///
/// # Safety
/// `label` must have been produced by a `lr_mpls_label_*` constructor
/// and must not be used after this call. Double-free is undefined
/// behaviour.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_free(label: lr_mpls_label_t) {
    guarded(
        || unsafe {
            drop(unbox_label(label));
        },
        (),
    )
}

// ---- LabelStack surface ----

/// Construct an empty `LabelStack` (RFC 3032 §2.1). Useful as a
/// builder starting point; not a valid wire value (an MPLS frame
/// must carry at least one label).
#[no_mangle]
pub extern "C" fn lr_mpls_label_stack_new() -> lr_mpls_label_stack_t {
    guarded(|| box_stack(LabelStack::new()), std::ptr::null_mut())
}

/// Build a stack from a flat array of label values (TC=0, TTL=64).
/// Returns `NULL` on a null pointer or panic.
///
/// # Safety
/// `values` must point to `count` readable `uint32_t` values.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_from_values(
    values: *const u32,
    count: usize,
) -> lr_mpls_label_stack_t {
    guarded(
        || unsafe {
            if values.is_null() && count != 0 {
                return std::ptr::null_mut();
            }
            let slice = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(values, count) }
            };
            box_stack(LabelStack::from_values(slice.iter().copied()))
        },
        std::ptr::null_mut(),
    )
}

/// Build a stack from a flat array of fully-specified labels
/// (`value`, `tc`, `ttl` triples). Returns `NULL` on a null pointer
/// or panic.
///
/// # Safety
/// `labels` must point to `count` readable `lr_mpls_label_spec_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_from_labels(
    labels: *const lr_mpls_label_spec_t,
    count: usize,
) -> lr_mpls_label_stack_t {
    guarded(
        || unsafe {
            if labels.is_null() && count != 0 {
                return std::ptr::null_mut();
            }
            let slice: &[lr_mpls_label_spec_t] = if count == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(labels, count) }
            };
            let mapped: Vec<Label> = slice
                .iter()
                .map(|s| Label::new(s.value).with_tc(s.tc).with_ttl(s.ttl))
                .collect();
            box_stack(LabelStack::from_labels(mapped))
        },
        std::ptr::null_mut(),
    )
}

/// Decode the 4-octet-per-entry wire form (RFC 3032 §2.1). On
/// success writes a freshly-allocated `lr_mpls_label_stack_t` to
/// `*out`. Returns 0 on success, negative on error.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out` must point to a
/// writable `lr_mpls_label_stack_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_decode_4octet(
    data: *const u8,
    len: usize,
    out: *mut lr_mpls_label_stack_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match LabelStack::decode_4octet(slice) {
                Ok(s) => {
                    unsafe { *out = box_stack(s) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    err_code(&e)
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Decode the 3-octet-per-entry NLRI form (RFC 8277 §2.2/§2.3).
///
/// # Safety
/// See [`lr_mpls_label_stack_decode_4octet`].
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_decode_3octet(
    data: *const u8,
    len: usize,
    out: *mut lr_mpls_label_stack_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match LabelStack::decode_3octet(slice) {
                Ok(s) => {
                    unsafe { *out = box_stack(s) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    err_code(&e)
                }
            }
        },
        LR_ERR_PANIC,
    )
}

/// Encode the stack as the 4-octet-per-entry wire form (RFC 3032
/// §2.1). The S bit is set on the last entry.
///
/// # Safety
/// `stack` must be a valid handle. `out` must point to a writable
/// `lr_bytes_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_encode_4octet(
    stack: lr_mpls_label_stack_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_stack(stack) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = s.encode_4octet();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Encode the stack as the 3-octet-per-entry NLRI form (RFC 8277
/// §2.2/§2.3).
///
/// # Safety
/// See [`lr_mpls_label_stack_encode_4octet`].
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_encode_3octet(
    stack: lr_mpls_label_stack_t,
    out: *mut lr_bytes_t,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_stack(stack) else {
                return LR_ERR_NULL;
            };
            if out.is_null() {
                return LR_ERR_NULL;
            }
            let bytes = s.encode_3octet();
            unsafe { *out = lr_bytes_t::from_vec(bytes) }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Number of labels in the stack. Returns 0 on a NULL handle.
///
/// # Safety
/// `stack` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_len(stack: lr_mpls_label_stack_t) -> usize {
    guarded(
        || unsafe { borrow_stack(stack).map(|s| s.len()).unwrap_or(0) },
        0,
    )
}

/// True when the stack holds no labels. Returns 1 (true) on a NULL
/// handle (the safe default for "no labels to encode").
///
/// # Safety
/// See [`lr_mpls_label_stack_len`].
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_is_empty(stack: lr_mpls_label_stack_t) -> u8 {
    guarded(
        || unsafe { borrow_stack(stack).map(|s| s.is_empty() as u8).unwrap_or(1) },
        1,
    )
}

/// Read one label by index. Returns 0 on success and writes a copy
/// of the label's `(value, tc, ttl)` to `*out_value`, `*out_tc`,
/// `*out_ttl`. Returns `LR_ERR_NULL` (-1) on a NULL stack,
/// `LR_ERR_INVALID_HANDLE` (-2) when the index is out of range.
///
/// # Safety
/// `stack` must be a valid handle. The three out-pointers must point
/// to writable `uint32_t` / `uint8_t` / `uint8_t`.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_at(
    stack: lr_mpls_label_stack_t,
    index: usize,
    out_value: *mut u32,
    out_tc: *mut u8,
    out_ttl: *mut u8,
) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_stack(stack) else {
                return LR_ERR_NULL;
            };
            if out_value.is_null() || out_tc.is_null() || out_ttl.is_null() {
                return LR_ERR_NULL;
            }
            let Some(l) = s.labels().get(index) else {
                set_last_error(format!(
                    "label index {index} out of range (len={})",
                    s.len()
                ));
                return LR_ERR_INVALID_HANDLE;
            };
            unsafe {
                *out_value = l.value;
                *out_tc = l.tc;
                *out_ttl = l.ttl;
            }
            0
        },
        LR_ERR_PANIC,
    )
}

/// Push a label onto the top of the stack (the label examined first
/// when a labelled packet arrives). Consumes the `label` handle.
///
/// # Safety
/// `stack` must be a valid handle. `label` must be a valid handle and
/// is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_push(
    stack: lr_mpls_label_stack_t,
    label: lr_mpls_label_t,
) -> i32 {
    guarded(
        || unsafe { stack_push(stack, label, LabelStack::push) },
        LR_ERR_PANIC,
    )
}

/// Push a label onto the bottom of the stack (last to be examined).
/// Consumes the `label` handle.
///
/// # Safety
/// See [`lr_mpls_label_stack_push`].
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_push_bottom(
    stack: lr_mpls_label_stack_t,
    label: lr_mpls_label_t,
) -> i32 {
    guarded(
        || unsafe { stack_push(stack, label, LabelStack::push_bottom) },
        LR_ERR_PANIC,
    )
}

/// Shared body for `push` / `push_bottom`: take ownership of the
/// boxed `Label`, borrow the stack mutably, and apply the
/// stack-mutating closure.
///
/// # Safety
/// `stack` must have been produced by [`box_stack`] and `label` by
/// [`box_label`]; neither must be used concurrently while this call
/// runs.
unsafe fn stack_push<F: FnOnce(&mut LabelStack, Label)>(
    stack: lr_mpls_label_stack_t,
    label: lr_mpls_label_t,
    f: F,
) -> i32 {
    let Some(s) = (unsafe { borrow_stack_mut(stack) }) else {
        return LR_ERR_NULL;
    };
    let Some(boxed) = (unsafe { unbox_label(label) }) else {
        return LR_ERR_NULL;
    };
    f(s, *boxed);
    0
}

/// Pop the top label. Returns 1 when a label was popped (the popped
/// label is dropped), 0 when the stack was already empty. Returns
/// `LR_ERR_NULL` (-1) on a NULL stack handle.
///
/// # Safety
/// `stack` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_pop(stack: lr_mpls_label_stack_t) -> i32 {
    guarded(
        || unsafe {
            let Some(s) = borrow_stack_mut(stack) else {
                return LR_ERR_NULL;
            };
            if s.pop().is_some() {
                1
            } else {
                0
            }
        },
        LR_ERR_PANIC,
    )
}

/// Drop a boxed `LabelStack`. Safe to call with NULL.
///
/// # Safety
/// `stack` must have been produced by a `lr_mpls_label_stack_*`
/// constructor and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_free(stack: lr_mpls_label_stack_t) {
    guarded(
        || unsafe {
            drop(unbox_stack(stack));
        },
        (),
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_decode_3octet_count(
    data: *const u8,
    len: usize,
    count: usize,
    out: *mut lr_mpls_label_stack_t,
) -> i32 {
    guarded(
        || unsafe {
            if data.is_null() || out.is_null() {
                return LR_ERR_NULL;
            }
            let slice = unsafe { std::slice::from_raw_parts(data, len) };
            match LabelStack::decode_3octet_count(slice, count) {
                Ok(s) => {
                    unsafe { *out = box_stack(s) }
                    0
                }
                Err(e) => {
                    set_last_error(e.to_string());
                    err_code(&e)
                }
            }
        },
        LR_ERR_PANIC,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_all_reserved(stack: lr_mpls_label_stack_t) -> u8 {
    guarded(
        || unsafe {
            borrow_stack(stack)
                .map(|s| s.all_reserved() as u8)
                .unwrap_or(0)
        },
        0,
    )
}

#[no_mangle]
pub unsafe extern "C" fn lr_mpls_label_stack_contains(
    stack: lr_mpls_label_stack_t,
    label: lr_mpls_label_t,
) -> u8 {
    guarded(
        || unsafe {
            let Some(s) = borrow_stack(stack) else {
                return 0;
            };
            let Some(l) = borrow_label(label) else {
                return 0;
            };
            s.contains(l) as u8
        },
        0,
    )
}

/// One fully-specified label `(value, tc, ttl)`. Used by
/// [`lr_mpls_label_stack_from_labels`] to build a stack from a flat
/// array of label specs without round-tripping through individual
/// `lr_mpls_label_t` handles.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct lr_mpls_label_spec_t {
    /// 20-bit label value. Values 0–15 are reserved (RFC 3032 §2.1).
    pub value: u32,
    /// 3-bit Traffic Class (RFC 5462, formerly EXP). High bits are
    /// masked on encode.
    pub tc: u8,
    /// 8-bit Time-to-Live.
    pub ttl: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reclaim a `lr_bytes_t` into a Rust `Vec<u8>` for assertions.
    /// Takes ownership — the caller must not use the handle afterwards.
    unsafe fn bytes_to_vec(b: &mut lr_bytes_t) -> Vec<u8> {
        if b.ptr.is_null() {
            return Vec::new();
        }
        let v = unsafe { Vec::from_raw_parts(b.ptr, b.len, b.cap) };
        b.ptr = std::ptr::null_mut();
        b.len = 0;
        b.cap = 0;
        v
    }

    #[test]
    fn ffi_label_new_and_readers() {
        let l = lr_mpls_label_new(100);
        assert!(!l.is_null());
        assert_eq!(unsafe { lr_mpls_label_value(l) }, 100);
        assert_eq!(unsafe { lr_mpls_label_tc(l) }, 0);
        assert_eq!(unsafe { lr_mpls_label_ttl(l) }, 64);
        assert_eq!(unsafe { lr_mpls_label_is_reserved(l) }, 0);
        unsafe { lr_mpls_label_free(l) };
    }

    #[test]
    fn ffi_label_reserved() {
        let l = lr_mpls_label_new(0);
        assert_eq!(unsafe { lr_mpls_label_is_reserved(l) }, 1);
        unsafe { lr_mpls_label_free(l) };
    }

    #[test]
    fn ffi_label_new_checked_rejects_oversize() {
        let l = lr_mpls_label_new_checked(Label::MAX_VALUE + 1);
        assert!(l.is_null(), "oversize value must return NULL");
        // The last-error string should mention "exceeds the 20-bit range".
        let err = unsafe { std::ffi::CStr::from_ptr(crate::error::lr_last_error()) }
            .to_string_lossy()
            .into_owned();
        assert!(err.contains("20-bit range"), "got: {err}");
    }

    #[test]
    fn ffi_label_with_tc_and_ttl() {
        let l = lr_mpls_label_new(Label::MAX_VALUE);
        let l = unsafe { lr_mpls_label_with_tc(l, 7) };
        let l = unsafe { lr_mpls_label_with_ttl(l, 255) };
        assert_eq!(unsafe { lr_mpls_label_tc(l) }, 7);
        assert_eq!(unsafe { lr_mpls_label_ttl(l) }, 255);
        unsafe { lr_mpls_label_free(l) };
    }

    #[test]
    fn ffi_label_with_tc_masks_high_bits() {
        // tc is masked to 3 bits — high bits are dropped.
        let l = lr_mpls_label_new(16);
        let l = unsafe { lr_mpls_label_with_tc(l, 0xff) };
        assert_eq!(unsafe { lr_mpls_label_tc(l) }, 0x07);
        unsafe { lr_mpls_label_free(l) };
    }

    #[test]
    fn ffi_label_with_tc_on_null_returns_null() {
        let l = unsafe { lr_mpls_label_with_tc(std::ptr::null_mut(), 7) };
        assert!(l.is_null());
    }

    #[test]
    fn ffi_label_encode_3octet_and_4octet() {
        let l = lr_mpls_label_new(100).with_rust_tc_and_ttl(0, 64);
        let mut out3 = [0u8; 3];
        let rc = unsafe { lr_mpls_label_encode_3octet(l, 1, out3.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // Label 100 = 0x00064; bottom bit on.
        assert_eq!(out3, [0x00, 0x06, 0x41]);

        let mut out4 = [0u8; 4];
        let rc = unsafe { lr_mpls_label_encode_4octet(l, 1, out4.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(out4, [0x00, 0x06, 0x41, 0x40]);
        unsafe { lr_mpls_label_free(l) };
    }

    #[test]
    fn ffi_label_encode_returns_null_error_on_null_handle() {
        let mut out = [0u8; 4];
        let rc = unsafe { lr_mpls_label_encode_4octet(std::ptr::null_mut(), 1, out.as_mut_ptr()) };
        assert_eq!(rc, LR_ERR_NULL);
    }

    #[test]
    fn ffi_label_encode_returns_null_error_on_null_out() {
        let l = lr_mpls_label_new(16);
        let rc = unsafe { lr_mpls_label_encode_4octet(l, 1, std::ptr::null_mut()) };
        assert_eq!(rc, LR_ERR_NULL);
        unsafe { lr_mpls_label_free(l) };
    }

    #[test]
    fn ffi_stack_from_values_roundtrip_4octet() {
        let values = [16u32, 240, 1048575];
        let s = unsafe { lr_mpls_label_stack_from_values(values.as_ptr(), values.len()) };
        assert!(!s.is_null());
        assert_eq!(unsafe { lr_mpls_label_stack_len(s) }, 3);
        assert_eq!(unsafe { lr_mpls_label_stack_is_empty(s) }, 0);

        // Read back the middle entry.
        let mut v = 0u32;
        let mut tc = 0u8;
        let mut ttl = 0u8;
        let rc = unsafe { lr_mpls_label_stack_at(s, 1, &raw mut v, &raw mut tc, &raw mut ttl) };
        assert_eq!(rc, 0);
        assert_eq!(v, 240);

        // Encode as 4-octet wire form (12 bytes) and decode it back.
        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_mpls_label_stack_encode_4octet(s, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        assert_eq!(bytes.len(), 12);

        let mut decoded: lr_mpls_label_stack_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_mpls_label_stack_decode_4octet(bytes.as_ptr(), bytes.len(), &raw mut decoded)
        };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_mpls_label_stack_len(decoded) }, 3);

        // The last entry's bottom-of-stack bit was set on encode.
        let mut last_v = 0u32;
        let mut tc = 0u8;
        let mut ttl = 0u8;
        let rc = unsafe {
            lr_mpls_label_stack_at(decoded, 2, &raw mut last_v, &raw mut tc, &raw mut ttl)
        };
        assert_eq!(rc, 0);
        assert_eq!(last_v, 1048575);

        unsafe {
            lr_mpls_label_stack_free(s);
            lr_mpls_label_stack_free(decoded);
        }
    }

    #[test]
    fn ffi_stack_from_labels_roundtrip_3octet() {
        let labels = [
            lr_mpls_label_spec_t {
                value: 16,
                tc: 0,
                ttl: 0,
            },
            lr_mpls_label_spec_t {
                value: 240,
                tc: 0,
                ttl: 0,
            },
        ];
        let s = unsafe { lr_mpls_label_stack_from_labels(labels.as_ptr(), labels.len()) };
        assert!(!s.is_null());

        let mut out = lr_bytes_t {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        };
        let rc = unsafe { lr_mpls_label_stack_encode_3octet(s, &raw mut out) };
        assert_eq!(rc, 0);
        let bytes = unsafe { bytes_to_vec(&mut out) };
        // 3-octet form: 2 entries × 3 bytes = 6 bytes.
        assert_eq!(bytes.len(), 6);

        let mut decoded: lr_mpls_label_stack_t = std::ptr::null_mut();
        let rc = unsafe {
            lr_mpls_label_stack_decode_3octet(bytes.as_ptr(), bytes.len(), &raw mut decoded)
        };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_mpls_label_stack_len(decoded) }, 2);

        unsafe {
            lr_mpls_label_stack_free(s);
            lr_mpls_label_stack_free(decoded);
        }
    }

    #[test]
    fn ffi_stack_push_pop() {
        let s = lr_mpls_label_stack_new();
        let top = lr_mpls_label_new(100);
        let rc = unsafe { lr_mpls_label_stack_push(s, top) };
        assert_eq!(rc, 0);
        let bot = lr_mpls_label_new(200);
        let rc = unsafe { lr_mpls_label_stack_push_bottom(s, bot) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { lr_mpls_label_stack_len(s) }, 2);

        // top is at index 0.
        let mut v = 0u32;
        let mut tc = 0u8;
        let mut ttl = 0u8;
        let rc = unsafe { lr_mpls_label_stack_at(s, 0, &raw mut v, &raw mut tc, &raw mut ttl) };
        assert_eq!(rc, 0);
        assert_eq!(v, 100);

        // Pop the top.
        let popped = unsafe { lr_mpls_label_stack_pop(s) };
        assert_eq!(popped, 1);
        assert_eq!(unsafe { lr_mpls_label_stack_len(s) }, 1);
        // The bottom label is now at index 0.
        let rc = unsafe { lr_mpls_label_stack_at(s, 0, &raw mut v, &raw mut tc, &raw mut ttl) };
        assert_eq!(rc, 0);
        assert_eq!(v, 200);

        // Pop again — this time the bottom label (200) is popped.
        let popped = unsafe { lr_mpls_label_stack_pop(s) };
        assert_eq!(popped, 1);
        assert_eq!(unsafe { lr_mpls_label_stack_is_empty(s) }, 1);

        // Pop on an empty stack returns 0 (no label was popped).
        let popped = unsafe { lr_mpls_label_stack_pop(s) };
        assert_eq!(popped, 0);

        unsafe { lr_mpls_label_stack_free(s) };
    }

    #[test]
    fn ffi_stack_at_returns_invalid_handle_on_oob() {
        let s = lr_mpls_label_stack_new();
        let mut v = 0u32;
        let mut tc = 0u8;
        let mut ttl = 0u8;
        let rc = unsafe { lr_mpls_label_stack_at(s, 0, &raw mut v, &raw mut tc, &raw mut ttl) };
        assert_eq!(rc, LR_ERR_INVALID_HANDLE);
        unsafe { lr_mpls_label_stack_free(s) };
    }

    #[test]
    fn ffi_stack_decode_4octet_rejects_uneven_length() {
        let bytes = [0u8, 1, 2]; // not a multiple of 4
        let mut s: lr_mpls_label_stack_t = std::ptr::null_mut();
        let rc =
            unsafe { lr_mpls_label_stack_decode_4octet(bytes.as_ptr(), bytes.len(), &raw mut s) };
        assert_eq!(rc, LR_ERR_OTHER);
        assert!(s.is_null());
    }

    #[test]
    fn ffi_stack_decode_4octet_rejects_midstack_bottom_bit() {
        // 8 bytes of zeros with S=1 on entry 0 (not the bottom).
        let mut bytes = [0u8; 8];
        bytes[2] |= 0x01;
        let mut s: lr_mpls_label_stack_t = std::ptr::null_mut();
        let rc =
            unsafe { lr_mpls_label_stack_decode_4octet(bytes.as_ptr(), bytes.len(), &raw mut s) };
        assert_eq!(rc, LR_ERR_OTHER);
        assert!(s.is_null());
    }

    #[test]
    fn ffi_free_handles_null_safely() {
        unsafe {
            lr_mpls_label_free(std::ptr::null_mut());
            lr_mpls_label_stack_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn ffi_label_value_returns_zero_on_null() {
        assert_eq!(unsafe { lr_mpls_label_value(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ffi_stack_len_returns_zero_on_null() {
        assert_eq!(unsafe { lr_mpls_label_stack_len(std::ptr::null_mut()) }, 0);
    }

    // ---- Test helpers ----

    /// Helper trait so the test can chain `with_tc`/`with_ttl` on an
    /// opaque handle without owning the intermediate values.
    trait TestLabelExt {
        fn with_rust_tc_and_ttl(self, tc: u8, ttl: u8) -> lr_mpls_label_t;
    }
    impl TestLabelExt for lr_mpls_label_t {
        fn with_rust_tc_and_ttl(self, tc: u8, ttl: u8) -> lr_mpls_label_t {
            // SAFETY: tests run single-threaded; the handle was
            // freshly produced by lr_mpls_label_new above.
            unsafe {
                let l = lr_mpls_label_with_tc(self, tc);
                lr_mpls_label_with_ttl(l, ttl)
            }
        }
    }
}
