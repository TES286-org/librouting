//! SRv6 Segment Identifier — the 128-bit value that names a Segment
//! Routing instruction in the IPv6 data plane.
//!
//! A SID is, on the wire, simply an IPv6 address (RFC 8754 §3): the
//! 128-bit value is parsed as **LOC:FUNCT:ARGS** (RFC 8402 §3.2.1,
//! RFC 8754 §3.1):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Locator (BLEN*8 bits)     |    Function (LBLEN*8 bits)   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  Arguments (ABLEN*8 bits)                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - **Locator** (LOC) routes the packet to the node that owns the SID.
//!   Each node advertises a Locator block — an IPv6 prefix (RFC 8754
//!   §3.1) — and every SID under that Locator is delivered to that node
//!   by plain IPv6 forwarding.
//! - **Function** (FUNCT) identifies the behavior the receiving node
//!   executes when the SID becomes *active* (the destination address
//!   equals this SID). The behaviors are codified by RFC 8986 — see
//!   [`crate::behavior`].
//! - **Arguments** (ARGS) carry per-SID parameters and are opaque to
//!   everyone except the SID's own behavior. A behavior MAY decide the
//!   argument bits are part of the FUNCT field (e.g. `End.X` with the
//!   adjacency encoded in the low-order bits — see RFC 8986 §4.2).
//!
//! Unlike an MPLS label, a SID is structured: the locator half is the
//! IPv6 routing hint, the function half is the local instruction. The
//! crate keeps the three parts in a single [`Sid`] value but exposes
//! the structured fields via [`Sid::locator_len`] etc.

use core::fmt;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A 128-bit SRv6 Segment Identifier (RFC 8754 §3).
///
/// Stored as a plain `[u8; 16]` so the type is `Copy`, comparable by
/// value and usable in `no_std`. The LOC/FUNCT/ARGS split is *not*
/// encoded into the type — it is context-dependent on the originating
/// node's advertised locator length (RFC 8754 §3.1, `BLEN`). Helpers
/// on [`Sid`] take the configured lengths when slicing into the parts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Sid {
    /// 128-bit value, network byte order (RFC 8754 §3).
    octets: [u8; 16],
}

impl Sid {
    /// Build a SID from raw 16 bytes (network byte order).
    pub const fn from_octets(octets: [u8; 16]) -> Self {
        Self { octets }
    }

    /// All-zeros SID — the RFC 8754 §3.1 example for "no SID" is the
    /// IPv6 unspecified address. Most SRv6 control planes use it as a
    /// placeholder in TLVs that carry the SID list length only.
    pub const UNSPECIFIED: Self = Self::from_octets([0; 16]);

    /// The 16 raw bytes, network byte order.
    pub const fn octets(&self) -> [u8; 16] {
        self.octets
    }

    /// Borrow the 16 raw bytes, network byte order.
    pub fn as_bytes(&self) -> &[u8] {
        &self.octets
    }

    /// View the SID as a borrowed byte slice of length 16.
    pub fn as_slice(&self) -> &[u8; 16] {
        &self.octets
    }

    /// True when the SID equals [`Self::UNSPECIFIED`] (all-zero). RFC 8754
    /// §3.1 leaves the meaning of `::` to the control plane — callers
    /// typically treat it as "no SID".
    pub const fn is_unspecified(&self) -> bool {
        let mut i = 0;
        while i < 16 {
            if self.octets[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Slice the locator prefix out of the SID (RFC 8754 §3.1). Returns
    /// `(offset_bytes, byte_count)` so the caller can borrow the slice:
    /// `&sid.octets()[offset..offset+len]`. Returns `None` if
    /// `locator_block_bits` exceeds 128 or is not a multiple of 8 — the
    /// crate stays in whole-byte slicing to avoid bit-shift machinery.
    pub fn locator_slice(&self, locator_block_bits: u8) -> Option<(usize, usize)> {
        if locator_block_bits > 128 || !locator_block_bits.is_multiple_of(8) {
            return None;
        }
        let bytes = (locator_block_bits / 8) as usize;
        Some((0, bytes))
    }

    /// Build a SID from a locator and a function/argument tail. The
    /// locator is the leading `locator_block_bits / 8` bytes (rounded
    /// down), the tail fills the remainder of the 16 bytes. Returns
    /// `None` if `locator_block_bits` exceeds 128 or is not a multiple
    /// of 8.
    pub fn from_locator_tail(locator: &[u8], tail: &[u8], locator_block_bits: u8) -> Option<Self> {
        if locator_block_bits > 128 || !locator_block_bits.is_multiple_of(8) {
            return None;
        }
        let loc_bytes = (locator_block_bits / 8) as usize;
        if locator.len() != loc_bytes {
            return None;
        }
        if tail.len() + loc_bytes != 16 {
            return None;
        }
        let mut octets = [0u8; 16];
        octets[..loc_bytes].copy_from_slice(locator);
        octets[loc_bytes..].copy_from_slice(tail);
        Some(Self::from_octets(octets))
    }

    /// True when the SID falls inside the given locator block (RFC 8754
    /// §3.1, the leading `locator_block_bits` are equal). Returns
    /// `false` (rather than erroring) on an invalid bit length — the
    /// contract is a plain membership check.
    pub fn is_inside_locator(&self, locator: &[u8], locator_block_bits: u8) -> bool {
        if locator_block_bits > 128 || !locator_block_bits.is_multiple_of(8) {
            return false;
        }
        let loc_bytes = (locator_block_bits / 8) as usize;
        if locator.len() != loc_bytes {
            return false;
        }
        self.octets[..loc_bytes] == *locator
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({})", self)
    }
}

impl fmt::Display for Sid {
    /// Render the SID as an IPv6 address — RFC 8754 §3 says "a SID is an
    /// IPv6 address", and the canonical textual form is the IPv6 one
    /// (RFC 5952 §4). The implementation here mirrors the compressed
    /// zero-run form so two SIDs that differ only in textual form
    /// render identically.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_v6(f, &self.octets)
    }
}

impl fmt::LowerHex for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.octets.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                f.write_str(":")?;
            }
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Parse a SID from the canonical IPv6 textual form (RFC 5952 §4).
///
/// Accepts the same forms `IpAddr::from_str` does for IPv6 (with or
/// without `::` zero-run compression, with or without leading zeros in
/// each hextet). Returns `None` on any malformed input — SIDs are
/// security-sensitive, so the parser is strict.
impl core::str::FromStr for Sid {
    type Err = SidParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 16];
        parse_v6(s, &mut out)?;
        Ok(Self::from_octets(out))
    }
}

/// Errors returned when parsing a SID's textual form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidParseError {
    /// The input was empty.
    Empty,
    /// More than one `::` zero-run was present (RFC 5952 §4.2.1).
    DoubleDoubleColon,
    /// A hextet contained non-hex characters or was longer than 4 hex
    /// digits (RFC 5952 §4.2.1 forbids leading zeros, but we accept
    /// them — the wire form is what matters, not the textual form).
    BadHextet,
    /// The address did not expand to exactly 16 bytes.
    WrongLength,
}

#[cfg(feature = "std")]
impl fmt::Display for SidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty SID string"),
            Self::DoubleDoubleColon => f.write_str("more than one '::' in SID"),
            Self::BadHextet => f.write_str("bad hextet in SID"),
            Self::WrongLength => f.write_str("SID did not expand to 16 bytes"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SidParseError {}

/// Parse an IPv6 textual form into 16 bytes (RFC 5952 §4). Used by
/// `Sid::from_str` and `Locator::from_str`.
pub(crate) fn parse_v6(s: &str, out: &mut [u8; 16]) -> Result<(), SidParseError> {
    if s.is_empty() {
        return Err(SidParseError::Empty);
    }
    // Split on `::` — at most one is allowed (RFC 5952 §4.2.1).
    let mut halves = s.split("::");
    let head = halves.next().unwrap_or("");
    let tail = halves.next();
    if halves.next().is_some() {
        return Err(SidParseError::DoubleDoubleColon);
    }
    let head_hextets: Vec<&str> = if head.is_empty() {
        Vec::new()
    } else {
        head.split(':').collect()
    };
    let tail_hextets: Vec<&str> = match tail {
        None => Vec::new(),
        Some("") => Vec::new(),
        Some(t) => t.split(':').collect(),
    };
    let head_words = head_hextets.len();
    let tail_words = tail_hextets.len();
    if head_words + tail_words > 8 {
        return Err(SidParseError::WrongLength);
    }
    let zeros = 8usize.saturating_sub(head_words + tail_words);
    let need_double_colon = tail.is_some();
    if need_double_colon && head_words + tail_words == 8 {
        // `::` with no zero-run is invalid — RFC 5952 §4.2.2.
        return Err(SidParseError::WrongLength);
    }
    if !need_double_colon && head_words + tail_words != 8 {
        return Err(SidParseError::WrongLength);
    }
    let mut idx = 0usize;
    for h in &head_hextets {
        let w = parse_hextet(h)?;
        out[idx..idx + 2].copy_from_slice(&w.to_be_bytes());
        idx += 2;
    }
    for _ in 0..zeros {
        out[idx..idx + 2].copy_from_slice(&0u16.to_be_bytes());
        idx += 2;
    }
    for h in &tail_hextets {
        let w = parse_hextet(h)?;
        out[idx..idx + 2].copy_from_slice(&w.to_be_bytes());
        idx += 2;
    }
    debug_assert_eq!(idx, 16);
    Ok(())
}

fn parse_hextet(s: &str) -> Result<u16, SidParseError> {
    if s.is_empty() || s.len() > 4 {
        return Err(SidParseError::BadHextet);
    }
    let mut v: u16 = 0;
    for c in s.chars() {
        let d = c.to_digit(16).ok_or(SidParseError::BadHextet)?;
        v = v.checked_mul(16).ok_or(SidParseError::BadHextet)?;
        v = v.checked_add(d as u16).ok_or(SidParseError::BadHextet)?;
    }
    Ok(v)
}

/// Render 16 bytes as the canonical compressed IPv6 form (RFC 5952
/// §4: longest run of all-zero hextets becomes `::`, leading zeros
/// inside each hextet are dropped, lowercase hex). Writes directly
/// into a formatter so neither `std` nor `no_std` builds need an
/// allocation.
pub(crate) fn write_v6(f: &mut fmt::Formatter<'_>, b: &[u8; 16]) -> fmt::Result {
    let words: [u16; 8] = [
        u16::from_be_bytes([b[0], b[1]]),
        u16::from_be_bytes([b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]),
        u16::from_be_bytes([b[8], b[9]]),
        u16::from_be_bytes([b[10], b[11]]),
        u16::from_be_bytes([b[12], b[13]]),
        u16::from_be_bytes([b[14], b[15]]),
    ];
    // Find the longest run of zeros (RFC 5952 §4.2.2: the longest run
    // of >= 2 zero hextets becomes `::`; the first such run wins on
    // ties; a single zero hextet does not get compressed).
    let mut best_start: Option<usize> = None;
    let mut best_len = 1usize;
    let mut cur_start: Option<usize> = None;
    let mut cur_len = 0usize;
    for (i, w) in words.iter().enumerate() {
        if *w == 0 {
            if cur_start.is_none() {
                cur_start = Some(i);
                cur_len = 0;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_start = None;
            cur_len = 0;
        }
    }
    // Walk the 8 hextets. The `::` substitution replaces a run of
    // zero hextets AND the surrounding `:` separators, so:
    //
    // - When the zero-run starts at i=0, write `::` at the head.
    // - When the zero-run starts mid-address, write `::` — the first
    //   `:` is the separator that would normally sit between two
    //   hextets, the second `:` is the elision marker.
    // - After a `::`, the next non-zero hextet writes WITHOUT a
    //   leading `:` separator (the trailing `:` of `::` already
    //   serves). The `after_dc` flag tracks that.
    let mut first = true;
    let mut after_dc = false;
    let mut i = 0;
    while i < 8 {
        // RFC 5952 §4.2.2: when a run of >= 2 zero hextets starts at
        // index `i`, replace it with `::`. The first `:` is the
        // separator that would normally sit between two hextets, the
        // second `:` is the elision marker.
        if best_start == Some(i) && best_len >= 2 {
            f.write_str("::")?;
            first = false;
            after_dc = true;
            i += best_len;
            continue;
        }
        if !first && !after_dc {
            f.write_str(":")?;
        }
        write_u16_hex(f, words[i])?;
        first = false;
        after_dc = false;
        i += 1;
    }
    if first {
        // The whole address was zero hextets — render as `::`.
        f.write_str("::")?;
    }
    Ok(())
}

/// `write_u16_hex` writes the value as lowercase hex without leading
/// zeros (RFC 5952 §4.1).
fn write_u16_hex(f: &mut fmt::Formatter<'_>, w: u16) -> fmt::Result {
    core::write!(f, "{:x}", w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn sid_size_and_default() {
        assert_eq!(core::mem::size_of::<Sid>(), 16);
        assert!(Sid::UNSPECIFIED.is_unspecified());
        let s = Sid::from_octets([0xff; 16]);
        assert!(!s.is_unspecified());
    }

    #[test]
    fn sid_from_str_roundtrip_canonical() {
        // RFC 5952 §4.2.2: a run of >= 2 zero hextets MUST be
        // compressed to `::`. So `fcbb:bb00:0:0:0:0:0:1` is
        // canonically `fcbb:bb00::1`.
        let sid = Sid::from_str("fcbb:bb00:0:0:0:0:0:1").unwrap();
        assert_eq!(format!("{}", sid), "fcbb:bb00::1");
    }

    #[test]
    fn sid_from_str_compressed_form() {
        // `::` zero-run gets expanded.
        let sid = Sid::from_str("fcbb:bb00::1").unwrap();
        assert_eq!(format!("{}", sid), "fcbb:bb00::1");
        // The wire bytes are the expanded form.
        assert_eq!(
            sid.octets(),
            [0xfc, 0xbb, 0xbb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        );
    }

    #[test]
    fn sid_from_str_unspecified() {
        let sid = Sid::from_str("::").unwrap();
        assert!(sid.is_unspecified());
        assert_eq!(format!("{}", sid), "::");
    }

    #[test]
    fn sid_from_str_rejects_double_double_colon() {
        assert_eq!(
            Sid::from_str("1::2::3").unwrap_err(),
            SidParseError::DoubleDoubleColon
        );
    }

    #[test]
    fn sid_from_str_rejects_short_and_long() {
        // 7 hextets with no `::` — wrong length.
        assert_eq!(
            Sid::from_str("1:2:3:4:5:6:7").unwrap_err(),
            SidParseError::WrongLength
        );
        // 9 hextets — too long.
        assert_eq!(
            Sid::from_str("1:2:3:4:5:6:7:8:9").unwrap_err(),
            SidParseError::WrongLength
        );
    }

    #[test]
    fn sid_from_str_rejects_bad_hextet() {
        assert_eq!(
            Sid::from_str("1:2:3:4:5:6:7:8g").unwrap_err(),
            SidParseError::BadHextet
        );
        assert_eq!(
            Sid::from_str("12345:1:2:3:4:5:6:7").unwrap_err(),
            SidParseError::BadHextet
        );
    }

    #[test]
    fn sid_locator_slice_byte_granular() {
        let sid = Sid::from_str("fcbb:bb00:0:0:e1:0:0:1").unwrap();
        // 32-bit locator block (4 bytes).
        let (off, len) = sid.locator_slice(32).unwrap();
        assert_eq!((off, len), (0, 4));
        assert_eq!(&sid.octets()[off..off + len], &[0xfc, 0xbb, 0xbb, 0x00]);
    }

    #[test]
    fn sid_locator_slice_rejects_non_byte_bits() {
        let sid = Sid::UNSPECIFIED;
        assert!(sid.locator_slice(33).is_none());
        assert!(sid.locator_slice(0).is_some()); // 0 bits is a degenerate but valid locator
        assert!(sid.locator_slice(128).is_some());
        assert!(sid.locator_slice(129).is_none());
    }

    #[test]
    fn sid_is_inside_locator_membership() {
        let sid = Sid::from_str("fcbb:bb00:0:0:e1:0:0:1").unwrap();
        let loc = [0xfc, 0xbb, 0xbb, 0x00];
        assert!(sid.is_inside_locator(&loc, 32));
        let other = [0xfc, 0xbb, 0xbb, 0x01];
        assert!(!sid.is_inside_locator(&other, 32));
        // wrong bit length: must be a multiple of 8.
        assert!(!sid.is_inside_locator(&loc, 33));
    }

    #[test]
    fn sid_from_locator_tail_builds_correct_bytes() {
        let loc = [0xfc, 0xbb, 0xbb, 0x00];
        let mut tail = [0u8; 12];
        tail[0] = 0xe1;
        let sid = Sid::from_locator_tail(&loc, &tail, 32).unwrap();
        assert_eq!(sid.octets()[0..4], loc);
        assert_eq!(sid.octets()[4], 0xe1);
        assert!(sid.is_inside_locator(&loc, 32));
    }

    #[test]
    fn sid_lower_hex_format() {
        let sid = Sid::from_octets([
            0xfc, 0xbb, 0xbb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        assert_eq!(
            format!("{:x}", sid),
            "fcbb:bb00:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn sid_roundtrip_random() {
        // A roundtrip via the textual form: parse, format, parse again
        // should give the same SID (RFC 5952 canonical form).
        let cases = [
            "fcbb:bb00:0:0:0:0:0:1",
            "2001:db8::1",
            "2001:db8:0:0:1:0:0:1",
            "::1",
            "1::",
            "1:2:3:4:5:6:7:8",
        ];
        for c in cases {
            let s1 = Sid::from_str(c).unwrap();
            let canonical = format!("{}", s1);
            let s2 = Sid::from_str(&canonical).unwrap();
            assert_eq!(s1, s2, "roundtrip mismatch on {}", c);
        }
    }
}
