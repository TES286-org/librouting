//! SRv6 Locator — an IPv6 prefix owned by a node and advertised so
//! that packets destined for any SID under the locator are routed to
//! that node (RFC 8754 §3.1).
//!
//! A Locator is conceptually a structured prefix: the high-order bits
//! are the **block** (BLOC, the operator-assigned aggregation), the
//! next bits are the **node** identifier, and the remainder is the
//! function/argument space. The split is convention-only — on the
//! wire, a Locator is just an IPv6 prefix that the node owns.
//!
//! The crate models the Locator as a 16-byte address plus a prefix
//! length (RFC 8754 §3.1 "Locator" = the IPv6 prefix the IGP
//! advertises). The structured `block_len` / `node_len` split is
//! stored alongside so behaviors and the daemon can render the
//! human-readable `LOC:FUNCT:ARGS` form without recomputation.

use core::fmt;
use core::str::FromStr;

use crate::sid::{parse_v6, Sid, SidParseError};

/// Maximum locator block length in bits (RFC 8754 §3.1).
pub const MAX_BLOCK_BITS: u8 = 128;

/// A locator block: an IPv6 prefix plus its bit length (RFC 8754
/// §3.1). The address carries 16 bytes of network-byte-order data;
/// host bits beyond `block_bits` are zero on construction and on
/// `from_str` parsing (RFC 8754 §3.1 — a Locator is a *prefix*, not
/// an address).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Locator {
    /// 16-byte network-order address. Host bits are always zero.
    addr: [u8; 16],
    /// Number of leading bits that form the locator prefix.
    /// Must be in `0..=128`; other values are rejected at the API
    /// boundary.
    block_bits: u8,
}

impl Locator {
    /// Construct a Locator from a 16-byte address and a bit length.
    /// The address is masked so host bits are zero (RFC 8754 §3.1).
    /// Returns `None` if `block_bits > 128`.
    pub fn new(addr: [u8; 16], block_bits: u8) -> Option<Self> {
        if block_bits > MAX_BLOCK_BITS {
            return None;
        }
        let mut addr = addr;
        mask_in_place(&mut addr, block_bits);
        Some(Self { addr, block_bits })
    }

    /// Construct from a [`Sid`]: the SID's high `block_bits` bits
    /// become the locator, the rest are dropped. Returns `None` if
    /// `block_bits > 128`.
    pub fn from_sid(sid: Sid, block_bits: u8) -> Option<Self> {
        Self::new(sid.octets(), block_bits)
    }

    /// The raw 16-byte address (host bits zeroed).
    pub const fn addr(&self) -> [u8; 16] {
        self.addr
    }

    /// Borrow the raw 16-byte address.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.addr
    }

    /// The locator prefix length in bits (RFC 8754 §3.1).
    pub const fn block_bits(&self) -> u8 {
        self.block_bits
    }

    /// The locator's byte length (rounded up). `block_bits=32` gives
    /// `block_bytes=4`, `block_bits=33` gives `block_bytes=5`.
    pub const fn block_bytes(&self) -> usize {
        (self.block_bits as usize).div_ceil(8)
    }

    /// Build a [`Sid`] under this locator by appending the 16-byte
    /// `tail` (function + arguments). The leading `block_bytes` of
    /// `tail` are zeroed-out and replaced with the locator — i.e.
    /// the caller passes a 16-byte buffer whose first `block_bytes`
    /// are don't-care, the rest are FUNCT:ARGS. This mirrors the way
    /// RFC 8754 §3.1 describes a SID: "The Locator is the IPv6 prefix
    /// advertised by the IGP".
    pub fn sid_with_tail(&self, tail: [u8; 16]) -> Sid {
        let mut octets = tail;
        let n = self.block_bytes();
        // Mask off the partial tail byte if `block_bits` is not a
        // multiple of 8 (the locator's last byte already has host
        // bits zero, so copying them onto `tail` is correct).
        octets[..n].copy_from_slice(&self.addr[..n]);
        Sid::from_octets(octets)
    }

    /// True when `sid` falls inside this locator.
    pub fn contains_sid(&self, sid: Sid) -> bool {
        sid.is_inside_locator(&self.addr[..self.block_bytes()], self.block_bits)
    }

    /// Allocate a SID at a given function index inside this locator.
    /// The index is placed in the first 4 bytes after the locator,
    /// big-endian — this matches the "function = index" convention
    /// RFC 8986 §4.1 uses for End (the function is a 16-bit opcode,
    /// but the field is wider when arguments are absent).
    pub fn sid_with_index(&self, function_index: u32) -> Option<Sid> {
        let mut tail = [0u8; 16];
        let n = self.block_bytes();
        if n > 12 {
            // Need at least 4 bytes of function space.
            return None;
        }
        tail[n..n + 4].copy_from_slice(&function_index.to_be_bytes());
        Some(self.sid_with_tail(tail))
    }
}

impl fmt::Debug for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Locator({}/{})", self, self.block_bits)
    }
}

impl fmt::Display for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::sid::write_v6(f, &self.addr)
    }
}

impl FromStr for Locator {
    type Err = LocatorParseError;
    /// Parse `"fcbb:bb00:0:0:0:0:0:0/48"` (RFC 8754 §3.1 + RFC 5952
    /// §4 + a `/prefix` suffix). Returns `Err` if the prefix length
    /// is missing or out of range.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, bits_str) = s
            .split_once('/')
            .ok_or(LocatorParseError::MissingPrefixLen)?;
        let mut addr = [0u8; 16];
        parse_v6(addr_str, &mut addr).map_err(LocatorParseError::BadAddr)?;
        let block_bits: u16 = bits_str
            .parse()
            .map_err(|_| LocatorParseError::BadPrefixLen)?;
        if block_bits > MAX_BLOCK_BITS as u16 {
            return Err(LocatorParseError::BadPrefixLen);
        }
        Self::new(addr, block_bits as u8).ok_or(LocatorParseError::BadPrefixLen)
    }
}

/// Errors returned when parsing a [`Locator`] textual form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocatorParseError {
    /// The `/prefixlen` suffix was missing.
    MissingPrefixLen,
    /// The IPv6 address portion was malformed (RFC 5952 §4).
    BadAddr(SidParseError),
    /// The prefix length was missing or out of range.
    BadPrefixLen,
}

#[cfg(feature = "std")]
impl fmt::Display for LocatorParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefixLen => f.write_str("locator string is missing /prefixlen"),
            Self::BadAddr(e) => write!(f, "bad locator address: {}", e),
            Self::BadPrefixLen => f.write_str("locator prefix length is missing or out of range"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LocatorParseError {}

/// Zero out the host bits of `addr` past `bits` (RFC 8754 §3.1 — a
/// Locator is a *prefix*, not an address). In-place for `no_std`.
fn mask_in_place(addr: &mut [u8; 16], bits: u8) {
    let full_bytes = (bits as usize) / 8;
    let leftover = (bits as usize) % 8;
    if full_bytes < 16 {
        // Clear the trailing bits of the partial byte first.
        if leftover != 0 {
            let mask = 0xffu8 << (8 - leftover);
            addr[full_bytes] &= mask;
        }
        // Then zero the rest.
        for b in &mut addr[full_bytes + (leftover != 0) as usize..] {
            *b = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_zeroes_host_bits() {
        let addr = [
            0xfc, 0xbb, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ];
        let loc = Locator::new(addr, 32).unwrap();
        assert_eq!(
            loc.addr(),
            [0xfc, 0xbb, 0xbb, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn locator_zeroes_partial_byte() {
        // 36-bit locator: 32 full bytes + 4 bits of the 5th byte.
        let addr = [
            0xfc, 0xbb, 0xbb, 0xff, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let loc = Locator::new(addr, 36).unwrap();
        // The 5th byte should be 0xf0 (the 4 high bits preserved, the
        // low 4 bits cleared).
        assert_eq!(loc.addr()[4], 0xf0);
        // Now feed an address with low bits set in the partial byte —
        // they must be cleared.
        let mut dirty = addr;
        dirty[4] = 0xff;
        let loc = Locator::new(dirty, 36).unwrap();
        assert_eq!(loc.addr()[4], 0xf0);
    }

    #[test]
    fn locator_rejects_oversize_bits() {
        let addr = [0; 16];
        assert!(Locator::new(addr, 129).is_none());
        assert!(Locator::new(addr, 128).is_some());
    }

    #[test]
    fn locator_from_str_roundtrip() {
        let s = "fcbb:bb00:0:0:0:0:0:0/48";
        let loc = Locator::from_str(s).unwrap();
        assert_eq!(loc.block_bits(), 48);
        assert_eq!(format!("{}", loc), "fcbb:bb00::");
        assert_eq!(format!("{:?}", loc), "Locator(fcbb:bb00::/48)");
    }

    #[test]
    fn locator_from_str_rejects_missing_prefix() {
        assert_eq!(
            Locator::from_str("fcbb:bb00::").unwrap_err(),
            LocatorParseError::MissingPrefixLen
        );
    }

    #[test]
    fn locator_from_str_rejects_bad_prefix_len() {
        assert_eq!(
            Locator::from_str("fcbb:bb00::/129").unwrap_err(),
            LocatorParseError::BadPrefixLen
        );
        assert_eq!(
            Locator::from_str("fcbb:bb00::/abc").unwrap_err(),
            LocatorParseError::BadPrefixLen
        );
    }

    #[test]
    fn locator_sid_with_tail_zeros_first_bytes() {
        let loc = Locator::from_str("fcbb:bb00:0:0:0:0:0:0/32").unwrap();
        let mut tail = [0u8; 16];
        tail[4] = 0xe1;
        tail[5] = 0x00;
        let sid = loc.sid_with_tail(tail);
        // Locator is the first 4 bytes.
        assert_eq!(&sid.octets()[0..4], &[0xfc, 0xbb, 0xbb, 0x00]);
        assert_eq!(sid.octets()[4], 0xe1);
        assert!(loc.contains_sid(sid));
    }

    #[test]
    fn locator_sid_with_index_places_function_be() {
        let loc = Locator::from_str("fcbb:bb00:0:0:0:0:0:0/32").unwrap();
        let sid = loc.sid_with_index(0x0000_e100).unwrap();
        assert_eq!(&sid.octets()[4..8], &[0x00, 0x00, 0xe1, 0x00]);
        assert!(loc.contains_sid(sid));
    }

    #[test]
    fn locator_sid_with_index_rejects_short_block() {
        // A /128 locator leaves no function space.
        let loc = Locator::from_str("fcbb:bb00:0:0:0:0:0:0/128").unwrap();
        assert!(loc.sid_with_index(1).is_none());
    }

    #[test]
    fn locator_contains_sid_false_for_other_blocks() {
        let loc = Locator::from_str("fcbb:bb00:0:0:0:0:0:0/32").unwrap();
        let other = Sid::from_str("fcbb:bb01:0:0:0:0:0:1").unwrap();
        assert!(!loc.contains_sid(other));
    }

    #[test]
    fn locator_from_sid_extracts_high_bits() {
        let sid = Sid::from_str("fcbb:bb00:0:0:e1:0:0:1").unwrap();
        let loc = Locator::from_sid(sid, 32).unwrap();
        assert_eq!(loc.block_bits(), 32);
        assert_eq!(&loc.addr()[0..4], &[0xfc, 0xbb, 0xbb, 0x00]);
    }

    #[test]
    fn locator_block_bytes_rounding() {
        let loc = Locator::from_str("fcbb:bb00::/32").unwrap();
        assert_eq!(loc.block_bytes(), 4);
        let loc = Locator::from_str("fcbb:bb00::/33").unwrap();
        assert_eq!(loc.block_bytes(), 5);
        let loc = Locator::from_str("fcbb:bb00::/128").unwrap();
        assert_eq!(loc.block_bytes(), 16);
        let loc = Locator::from_str("::/0").unwrap();
        assert_eq!(loc.block_bytes(), 0);
    }
}
