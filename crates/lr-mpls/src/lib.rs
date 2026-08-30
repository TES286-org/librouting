//! MPLS label and label-stack codec (RFC 3032).
//!
//! This crate provides the wire-level primitives every MPLS-aware protocol
//! in librouting needs: a [`Label`] value with its Traffic-Class and TTL,
//! and a [`LabelStack`] that encodes and decodes both the on-the-wire
//! 4-octet-per-entry format (RFC 3032 §2.1, used by `AF_MPLS` netlink and
//! raw packet captures) and the 3-octet-per-entry form used inside BGP
//! labelled NLRI (RFC 8277 §2.2/§2.3 — no TTL field).
//!
//! The crate has no I/O, no clock and no platform dependency — it is
//! `no_std`-compatible and shares the `lr-core` conventions.
//!
//! ## Wire layout (RFC 3032 §2.1)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                Label                  | TC  |S|       TTL     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `Label` is the 20-bit label value; `TC` (Traffic Class, formerly EXP)
//! is 3 bits; `S` is the bottom-of-stack bit (1 on the last entry); `TTL`
//! is 8 bits. In the 3-octet NLRI form both `TTL` and `TC` are absent —
//! the entry is `Label(20) | Rsrv(3) | S(1)` (RFC 8277 §2.2/§2.3).

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::fmt;

/// A single MPLS label value with its Traffic-Class and TTL fields.
///
/// The bottom-of-stack bit is *not* stored on a `Label` — it is positional
/// (1 only on the last entry of a stack) and is therefore owned by the
/// [`LabelStack`] container. This matches RFC 3032 §2.1, where the `S` bit
/// is part of the encoding rather than a property of the label itself, and
/// keeps label values comparable by their 20-bit value alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Label {
    /// 20-bit label value. Values 0–15 are reserved (RFC 3032 §2.1).
    pub value: u32,
    /// 3-bit Traffic Class (RFC 5462, formerly EXP).
    pub tc: u8,
    /// 8-bit Time-To-Live.
    pub ttl: u8,
}

impl Label {
    /// Maximum legal label value (20-bit range, RFC 3032 §2.1).
    pub const MAX_VALUE: u32 = (1 << 20) - 1;

    /// IPv4 Explicit NULL (label 0, RFC 3032 §2.1).
    pub const IPV4_EXPLICIT_NULL: Self = Self::new_value(0);
    /// Router Alert Label (label 1, RFC 3032 §2.1).
    pub const ROUTER_ALERT: Self = Self::new_value(1);
    /// IPv6 Explicit NULL (label 2, RFC 3032 §2.1).
    pub const IPV6_EXPLICIT_NULL: Self = Self::new_value(2);
    /// Implicit NULL (label 3, RFC 3032 §2.1). Never appears on the wire —
    /// only in label-distribution signaling (LDP, RSVP-TE, BGP-LU).
    pub const IMPLICIT_NULL: Self = Self::new_value(3);
    /// Entropy LSE Indicator (label 7, RFC 6790).
    pub const ELI: Self = Self::new_value(7);
    /// Generic Associated Channel Label (label 13, RFC 5586).
    pub const GAL: Self = Self::new_value(13);
    /// OAM Alert Label (label 14, RFC 3429).
    pub const OAM_ALERT: Self = Self::new_value(14);
    /// Extension Label (label 15, RFC 7274).
    pub const EXTENSION: Self = Self::new_value(15);

    /// First label value outside the reserved range (RFC 3032 §2.1).
    pub const FIRST_NORMAL: u32 = 16;

    /// Construct a label with default TC=0 and TTL=64.
    ///
    /// Infallible and `const`, so it can be used in constant contexts.
    /// It does *not* validate `value`: an out-of-range value is masked to
    /// 20 bits on encode. Use [`Self::try_new`] when the range must be
    /// enforced (RFC 3032 §2.1 labels are 20 bits).
    pub const fn new(value: u32) -> Self {
        Self {
            value,
            tc: 0,
            ttl: 64,
        }
    }

    /// Construct a label with just the value (TC=0, TTL=0). Used for the
    /// BGP-LU 3-octet NLRI form, where TTL is absent.
    ///
    /// Like [`Self::new`], infallible and unchecked — use [`Self::try_new`]
    /// to validate the 20-bit range.
    pub const fn new_value(value: u32) -> Self {
        Self {
            value,
            tc: 0,
            ttl: 0,
        }
    }

    /// Construct a label, validating that `value` fits in the 20-bit label
    /// range (RFC 3032 §2.1).
    ///
    /// This is the checked counterpart of the const constructors
    /// [`Self::new`] / [`Self::new_value`], which silently mask out-of-range
    /// values on encode. Returns `Err(LabelStackError::ValueOutOfRange)` for
    /// values above [`Self::MAX_VALUE`] so callers that must not truncate
    /// can validate up front.
    pub fn try_new(value: u32) -> Result<Self, LabelStackError> {
        if value > Self::MAX_VALUE {
            return Err(LabelStackError::ValueOutOfRange(value));
        }
        Ok(Self::new(value))
    }

    /// Set the Traffic Class (3 bits, RFC 5462). Returns `self` for chaining.
    #[must_use]
    pub const fn with_tc(mut self, tc: u8) -> Self {
        self.tc = tc & 0x07;
        self
    }

    /// Set the TTL. Returns `self` for chaining.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// True when the label is in the reserved range (0–15).
    pub const fn is_reserved(self) -> bool {
        self.value < Self::FIRST_NORMAL
    }

    /// Validate that the value fits in 20 bits.
    pub const fn is_valid_value(value: u32) -> bool {
        value <= Self::MAX_VALUE
    }

    /// Encode as a single 3-octet NLRI entry (RFC 8277 §2.2/§2.3:
    /// `Label(20) | Rsrv(3) | S(1)` — no TTL and no TC field). The
    /// `bottom` flag sets the S bit (bottom-of-stack). The 3 reserved bits
    /// (bits 10-8) are always written as zero, as RFC 8277 §2.2 requires on
    /// transmission.
    pub const fn encode_3octet(self, bottom: bool) -> [u8; 3] {
        let byte2 = ((self.value & 0x0f) << 4) | (bottom as u32);
        [
            ((self.value >> 12) & 0xff) as u8,
            ((self.value >> 4) & 0xff) as u8,
            byte2 as u8,
        ]
    }

    /// Encode as a single 4-octet wire entry (RFC 3032 §2.1: label + TC + S
    /// + TTL). The `bottom` flag sets the S bit.
    pub const fn encode_4octet(self, bottom: bool) -> [u8; 4] {
        let byte2 = ((self.value & 0x0f) << 4) | ((self.tc as u32 & 0x07) << 1) | (bottom as u32);
        [
            ((self.value >> 12) & 0xff) as u8,
            ((self.value >> 4) & 0xff) as u8,
            byte2 as u8,
            self.ttl,
        ]
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "Label({}, tc={}, ttl={})", self.value, self.tc, self.ttl)
        } else {
            write!(f, "{}", self.value)
        }
    }
}

/// Decode error for label-stack wire forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelStackError {
    /// The input was shorter than the minimum one-entry stack.
    TooShort,
    /// The input length is not a multiple of the entry width (3 or 4 octets).
    UnevenLength,
    /// A bottom-of-stack (S) bit was set on a non-bottom entry. RFC 3032
    /// §2.1 requires S=1 only on the bottom entry of the stack.
    MidStackBottom,
    /// A label value exceeded the 20-bit range. Unreachable from a valid 3-
    /// or 4-octet encoding (the value is masked on decode), but returned by
    /// [`Label::try_new`] for out-of-range construction.
    ValueOutOfRange(u32),
}

#[cfg(feature = "std")]
impl fmt::Display for LabelStackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("label stack input is empty"),
            Self::UnevenLength => f.write_str("label stack input is not a multiple of entry width"),
            Self::MidStackBottom => {
                f.write_str("bottom-of-stack bit set on a non-bottom entry")
            }
            Self::ValueOutOfRange(v) => write!(f, "label value {} exceeds the 20-bit range", v),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LabelStackError {}

/// An ordered MPLS label stack (RFC 3032 §2.1).
///
/// The first element of the Vec is the *top* of the stack — the label that
/// is examined first when a labelled packet arrives. The bottom-of-stack
/// bit is set automatically on the last entry when encoding and is stripped
/// when decoding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct LabelStack {
    labels: Vec<Label>,
}

impl LabelStack {
    /// An empty stack. Useful as a builder starting point; not a valid wire
    /// value (an MPLS frame must carry at least one label).
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a stack from a slice of label values (TC=0, TTL=64).
    pub fn from_values(values: impl IntoIterator<Item = u32>) -> Self {
        Self {
            labels: values.into_iter().map(Label::new).collect(),
        }
    }

    /// Build a stack from a slice of fully-specified labels.
    pub fn from_labels(labels: impl IntoIterator<Item = Label>) -> Self {
        Self {
            labels: labels.into_iter().collect(),
        }
    }

    /// Wrap an existing Vec of labels.
    pub fn from_vec(labels: Vec<Label>) -> Self {
        Self { labels }
    }

    /// Number of labels in the stack.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// True when there are no labels.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Borrow the labels.
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }

    /// Take the underlying Vec.
    pub fn into_vec(self) -> Vec<Label> {
        self.labels
    }

    /// Push a label onto the top of the stack.
    pub fn push(&mut self, label: Label) {
        self.labels.insert(0, label);
    }

    /// Push a label onto the bottom of the stack (last to be examined).
    pub fn push_bottom(&mut self, label: Label) {
        self.labels.push(label);
    }

    /// Pop the top label, if any.
    pub fn pop(&mut self) -> Option<Label> {
        if self.labels.is_empty() {
            None
        } else {
            Some(self.labels.remove(0))
        }
    }

    /// True when every label in the stack is in the reserved range 0–15.
    /// Reserved labels carry special semantics (explicit-null, router-alert,
    /// implicit-null, etc.) and a stack made up entirely of them typically
    /// signals a control-plane-only value.
    pub fn all_reserved(&self) -> bool {
        !self.labels.is_empty() && self.labels.iter().all(|l| l.is_reserved())
    }

    /// Encode as the on-the-wire 4-octet-per-entry form (RFC 3032 §2.1).
    /// The S bit is set on the last entry. Returns an empty Vec for an empty
    /// stack — callers must validate before sending.
    pub fn encode_4octet(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.labels.len() * 4);
        let last = self.labels.len().saturating_sub(1);
        for (i, l) in self.labels.iter().enumerate() {
            out.extend_from_slice(&l.encode_4octet(i == last));
        }
        out
    }

    /// Encode as the 3-octet-per-entry NLRI form (RFC 8277 §2.2/§2.3:
    /// `Label(20) | Rsrv(3) | S(1)` — no TTL and no TC field). The S bit is
    /// set on the last entry; the reserved bits are written as zero.
    pub fn encode_3octet(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.labels.len() * 3);
        let last = self.labels.len().saturating_sub(1);
        for (i, l) in self.labels.iter().enumerate() {
            out.extend_from_slice(&l.encode_3octet(i == last));
        }
        out
    }

    /// Decode the 4-octet-per-entry wire form (RFC 3032 §2.1). The S bit
    /// must mark the bottom entry only: an entry claiming bottom-of-stack
    /// mid-stack is rejected with [`LabelStackError::MidStackBottom`]
    /// rather than silently truncating the stack.
    pub fn decode_4octet(bytes: &[u8]) -> Result<Self, LabelStackError> {
        if bytes.is_empty() {
            return Err(LabelStackError::TooShort);
        }
        if !bytes.len().is_multiple_of(4) {
            return Err(LabelStackError::UnevenLength);
        }
        let mut labels = Vec::with_capacity(bytes.len() / 4);
        for (i, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
            let word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let value = (word >> 12) & Label::MAX_VALUE;
            let tc = ((word >> 9) & 0x07) as u8;
            let bottom = (word >> 8) & 0x01 != 0;
            let ttl = (word & 0xff) as u8;
            if value > Label::MAX_VALUE {
                return Err(LabelStackError::ValueOutOfRange(value));
            }
            labels.push(Label { value, tc, ttl });
            if bottom {
                // RFC 3032 §2.1: S=1 marks the bottom of the stack and may
                // only appear on the last entry. A mid-stack S bit means a
                // malformed stack — error instead of dropping the rest.
                if i + 1 < bytes.len() / 4 {
                    return Err(LabelStackError::MidStackBottom);
                }
                break;
            }
        }
        Ok(Self { labels })
    }

    /// Decode the 3-octet-per-entry NLRI form (RFC 8277 §2.2/§2.3). TTL is
    /// not carried in this form and defaults to 0. The reserved bits
    /// (bits 10-8) are ignored on reception per RFC 8277 §2.2 — they are
    /// *not* a Traffic Class field — so decoded labels always carry
    /// `tc == 0`. The S bit terminates the stack: any trailing bytes after
    /// a bottom-of-stack entry are considered part of the surrounding NLRI
    /// prefix, not the stack.
    pub fn decode_3octet(bytes: &[u8]) -> Result<Self, LabelStackError> {
        if bytes.is_empty() {
            return Err(LabelStackError::TooShort);
        }
        if !bytes.len().is_multiple_of(3) {
            return Err(LabelStackError::UnevenLength);
        }
        let mut labels = Vec::with_capacity(bytes.len() / 3);
        for chunk in bytes.as_chunks::<3>().0 {
            // RFC 8277 §2.2: each 3-octet entry is Label(20) | Rsrv(3) |
            // S(1). The value reassembles as `chunk[0] << 12 | chunk[1] <<
            // 4 | chunk[2] >> 4`; the three bits between the label and the
            // S bit are reserved and MUST be ignored on reception (there is
            // no TC field here), so they are read and discarded.
            let value =
                ((chunk[0] as u32) << 12) | ((chunk[1] as u32) << 4) | ((chunk[2] as u32) >> 4);
            let _rsrv = (chunk[2] >> 1) & 0x07; // ignored per RFC 8277 §2.2
            let bottom = (chunk[2] & 0x01) != 0;
            if value > Label::MAX_VALUE {
                return Err(LabelStackError::ValueOutOfRange(value));
            }
            labels.push(Label::new_value(value));
            if bottom {
                break;
            }
        }
        Ok(Self { labels })
    }

    /// Decode the 3-octet NLRI form from a known-length slice inside a BGP
    /// NLRI: returns the parsed stack and the number of bytes consumed.
    /// The caller supplies the *total* number of label octets (always a
    /// multiple of 3 in valid NLRI).
    pub fn decode_3octet_count(bytes: &[u8], count: usize) -> Result<Self, LabelStackError> {
        if count == 0 || !count.is_multiple_of(3) || count > bytes.len() {
            return Err(LabelStackError::UnevenLength);
        }
        Self::decode_3octet(&bytes[..count])
    }
}

impl fmt::Display for LabelStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, l) in self.labels.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", l.value)?;
        }
        f.write_str("]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_constants_match_rfc_3032() {
        assert_eq!(Label::IPV4_EXPLICIT_NULL.value, 0);
        assert_eq!(Label::ROUTER_ALERT.value, 1);
        assert_eq!(Label::IPV6_EXPLICIT_NULL.value, 2);
        assert_eq!(Label::IMPLICIT_NULL.value, 3);
        assert_eq!(Label::ELI.value, 7);
        assert_eq!(Label::GAL.value, 13);
        assert_eq!(Label::OAM_ALERT.value, 14);
        assert_eq!(Label::EXTENSION.value, 15);
        assert!(Label::IPV4_EXPLICIT_NULL.is_reserved());
        assert!(!Label::new(16).is_reserved());
    }

    #[test]
    fn label_4octet_roundtrip_single() {
        // Label 100, TC=0, TTL=64, bottom-of-stack.
        let l = Label::new(100).with_ttl(64);
        let enc = l.encode_4octet(true);
        // value 100 = 0x00064 → top 20 bits of a 32-bit word
        // expected: 0x00 0x06 0x41 0x40
        // (00 06 4_ | _1 0_ | _64) where 4_1 = (00 4 << 4) | (0 << 1) | 1
        assert_eq!(enc, [0x00, 0x06, 0x41, 0x40]);
        let dec = LabelStack::decode_4octet(&enc).unwrap();
        assert_eq!(dec.len(), 1);
        assert_eq!(dec.labels()[0].value, 100);
        assert_eq!(dec.labels()[0].ttl, 64);
    }

    #[test]
    fn label_4octet_roundtrip_max_value() {
        let l = Label::new(Label::MAX_VALUE).with_tc(7).with_ttl(255);
        let enc = l.encode_4octet(true);
        // 0xFFFFF << 12 | 7 << 9 | 1 << 8 | 0xFF = 0xFFFFFFFF
        assert_eq!(enc, [0xff, 0xff, 0xff, 0xff]);
        let dec = LabelStack::decode_4octet(&enc).unwrap();
        assert_eq!(dec.labels()[0].value, Label::MAX_VALUE);
        assert_eq!(dec.labels()[0].tc, 7);
        assert_eq!(dec.labels()[0].ttl, 255);
    }

    #[test]
    fn label_stack_4octet_roundtrip_multi() {
        let s = LabelStack::from_labels([
            Label::new(100).with_ttl(63),
            Label::new(200).with_ttl(63),
            Label::new(300).with_ttl(63),
        ]);
        let enc = s.encode_4octet();
        assert_eq!(enc.len(), 12);
        // Only the last entry has S bit set.
        assert_eq!(enc[2] & 0x01, 0); // entry 0: not bottom
        assert_eq!(enc[6] & 0x01, 0); // entry 1: not bottom
        assert_eq!(enc[10] & 0x01, 1); // entry 2: bottom
        let dec = LabelStack::decode_4octet(&enc).unwrap();
        assert_eq!(dec, s);
    }

    #[test]
    fn label_stack_3octet_roundtrip() {
        // 3-octet NLRI form does not carry TTL — decode produces TTL=0.
        let s = LabelStack::from_labels([
            Label::new_value(16),
            Label::new_value(240),
            Label::new_value(1048575),
        ]);
        let enc = s.encode_3octet();
        assert_eq!(enc.len(), 9);
        // Bottom-of-stack bit on the last entry only.
        assert_eq!(enc[2] & 0x01, 0);
        assert_eq!(enc[5] & 0x01, 0);
        assert_eq!(enc[8] & 0x01, 1);
        let dec = LabelStack::decode_3octet(&enc).unwrap();
        assert_eq!(dec, s);
    }

    #[test]
    fn label_stack_3octet_truncates_at_bottom_bit() {
        // 6 bytes of label data but the first entry already claims bottom.
        let mut bytes = vec![0u8; 6];
        bytes[2] |= 0x01; // S bit on entry 0
        let dec = LabelStack::decode_3octet(&bytes).unwrap();
        assert_eq!(dec.len(), 1, "decoding stops at the bottom-of-stack bit");
    }

    #[test]
    fn label_stack_4octet_rejects_midstack_bottom_bit() {
        // RFC 3032 §2.1: S=1 is only legal on the bottom entry. A mid-stack
        // S bit marks a malformed stack and must error rather than silently
        // truncate the remaining entries.
        let mut bytes = vec![0u8; 8];
        bytes[2] |= 0x01; // S bit on entry 0 — not the bottom entry
        assert_eq!(
            LabelStack::decode_4octet(&bytes).unwrap_err(),
            LabelStackError::MidStackBottom
        );
    }

    #[test]
    fn label_3octet_has_no_tc_field() {
        // RFC 8277 §2.2: the NLRI label entry is Label(20) | Rsrv(3) | S(1)
        // — there is no TC field. The reserved bits MUST be zero on the
        // wire and MUST be ignored on reception.
        let l = Label::new_value(16).with_tc(7);
        let enc = l.encode_3octet(true);
        assert_eq!(
            (enc[2] >> 1) & 0x07,
            0,
            "reserved bits must be zero on the wire even when tc != 0"
        );
        // value 16 → bytes 0x00 0x01 0x01 (label, zero Rsrv, S set).
        assert_eq!(enc, [0x00, 0x01, 0x01]);
        // A non-conforming sender may leave the reserved bits set; the
        // decoder must ignore them and yield tc == 0.
        let mut bytes = enc;
        bytes[2] |= 0b0000_1110; // set all three reserved bits
        let dec = LabelStack::decode_3octet(&bytes).unwrap();
        assert_eq!(dec.len(), 1);
        assert_eq!(dec.labels()[0].value, 16);
        assert_eq!(dec.labels()[0].tc, 0);
    }

    #[test]
    fn label_try_new_validates_range() {
        assert_eq!(
            Label::try_new(Label::MAX_VALUE).unwrap().value,
            Label::MAX_VALUE
        );
        assert_eq!(
            Label::try_new(Label::MAX_VALUE + 1).unwrap_err(),
            LabelStackError::ValueOutOfRange(Label::MAX_VALUE + 1)
        );
        // The unchecked const constructors keep working (they mask on
        // encode), but the decoded value is truncated to 20 bits.
        assert_eq!(Label::new_value(0x1_0000_0).value, 0x1_0000_0);
        let enc = Label::new_value(0x1_0000_0).encode_3octet(true);
        assert_eq!(LabelStack::decode_3octet(&enc).unwrap().labels()[0].value, 0);
    }

    #[test]
    fn label_stack_decode_rejects_short_and_uneven() {
        assert_eq!(
            LabelStack::decode_4octet(&[]).unwrap_err(),
            LabelStackError::TooShort
        );
        assert_eq!(
            LabelStack::decode_4octet(&[1, 2, 3]).unwrap_err(),
            LabelStackError::UnevenLength
        );
        assert_eq!(
            LabelStack::decode_3octet(&[1, 2, 3, 4]).unwrap_err(),
            LabelStackError::UnevenLength
        );
    }

    #[test]
    fn label_stack_decode_count_helper() {
        // 3-octet NLRI form does not carry TTL — decode produces TTL=0.
        let s = LabelStack::from_labels([Label::new_value(16), Label::new_value(17)]);
        let enc = s.encode_3octet();
        // Pass a longer buffer simulating trailing prefix bytes; the helper
        // must consume only `count` bytes.
        let mut buf = enc.clone();
        buf.extend_from_slice(&[0x18, 0xc0, 0x00]); // fake trailing prefix
        let dec = LabelStack::decode_3octet_count(&buf, 6).unwrap();
        assert_eq!(dec, s);
    }

    #[test]
    fn label_stack_push_pop_semantics() {
        let mut s = LabelStack::new();
        s.push(Label::new(100)); // top
        s.push_bottom(Label::new(200)); // bottom
        assert_eq!(s.len(), 2);
        assert_eq!(s.labels()[0].value, 100); // top
        assert_eq!(s.labels()[1].value, 200); // bottom
        assert_eq!(s.pop().unwrap().value, 100);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn label_stack_display() {
        let s = LabelStack::from_values([16, 240, 1048575]);
        assert_eq!(format!("{}", s), "[16, 240, 1048575]");
    }

    #[test]
    fn implicit_null_round_trips() {
        // RFC 3032 §2.1: implicit-null (3) appears only in signaling, never
        // on the wire; the codec must still round-trip it for distribution
        // protocols that carry it.
        let s = LabelStack::from_values([Label::IMPLICIT_NULL.value]);
        let enc = s.encode_3octet();
        let dec = LabelStack::decode_3octet(&enc).unwrap();
        assert_eq!(dec.labels()[0].value, 3);
    }

    #[test]
    fn all_reserved_helper() {
        assert!(LabelStack::from_values([0, 1, 2]).all_reserved());
        assert!(!LabelStack::from_values([0, 16]).all_reserved());
        assert!(!LabelStack::new().all_reserved());
    }
}
