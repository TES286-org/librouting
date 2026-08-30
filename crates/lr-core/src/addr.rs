//! Addressing primitives shared across BGP, OSPF and Babel.
//!
//! - [`Prefix`] — IPv4/IPv6 network prefix (address + prefix length)
//! - [`IpNet`] — network with explicit host bits zeroed
//! - [`IpAddr`] — IPv4 or IPv6 address
//! - [`Asn`] — Autonomous System Number (2-byte or 4-byte unified)
//! - [`RouterId`] — 32-bit router identifier
//! - Communities live in [`super::attr`]

use core::fmt;
use core::str::FromStr;

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

/// IPv4 or IPv6 address. Stored compactly.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddr {
    pub const UNSPECIFIED: Self = Self::V4([0; 4]);

    #[inline]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    #[inline]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::V6(_))
    }

    #[inline]
    pub fn is_unspecified(&self) -> bool {
        match self {
            Self::V4(b) => b == &[0; 4],
            Self::V6(b) => b == &[0; 16],
        }
    }

    pub fn from_v4_bytes(b: [u8; 4]) -> Self {
        Self::V4(b)
    }

    pub fn from_v6_bytes(b: [u8; 16]) -> Self {
        Self::V6(b)
    }

    /// Bytes of the address in network byte order.
    pub fn octets(&self) -> &[u8] {
        match self {
            Self::V4(b) => b,
            Self::V6(b) => b,
        }
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b.len() {
            4 => {
                let mut a = [0u8; 4];
                a.copy_from_slice(b);
                Some(Self::V4(a))
            }
            16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Some(Self::V6(a))
            }
            _ => None,
        }
    }

    pub fn is_ipv4_mapped_ipv6(&self) -> bool {
        if let Self::V6(b) = self {
            b[0..10] == [0; 10] && b[10..12] == [0xff, 0xff]
        } else {
            false
        }
    }

    /// Map an IPv4 address to an IPv4-mapped IPv6 address.
    pub fn to_ipv4_mapped(&self) -> Self {
        match self {
            Self::V4(b) => {
                let mut v = [0u8; 16];
                v[10..12].copy_from_slice(&[0xff, 0xff]);
                v[12..16].copy_from_slice(b);
                Self::V6(v)
            }
            other => *other,
        }
    }
}

impl fmt::Debug for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(b) => write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            Self::V6(b) => {
                let s = to_ipv6_string(b);
                f.write_str(&s)
            }
        }
    }
}

impl FromStr for IpAddr {
    type Err = ParseAddrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(v4) = parse_ipv4(s) {
            return Ok(Self::V4(v4));
        }
        if let Some(v6) = parse_ipv6(s) {
            return Ok(Self::V6(v6));
        }
        Err(ParseAddrError)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseAddrError;

impl fmt::Display for ParseAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IP address")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseAddrError {}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        // parse_ipv4_octet rejects empty, oversized, and non-digit octets
        // (including a leading '+' that Rust's integer parse accepts).
        out[i] = parse_ipv4_octet(p)?;
    }
    Some(out)
}

fn parse_ipv4_octet(p: &str) -> Option<u8> {
    if p.is_empty() || p.len() > 3 {
        return None;
    }
    let mut v = 0u16;
    for c in p.chars() {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c as u16 - b'0' as u16);
        if v > 255 {
            return None;
        }
    }
    Some(v as u8)
}

fn parse_ipv4_strict(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = parse_ipv4_octet(p)?;
    }
    Some(out)
}

/// Parse an IPv6 address in any standard textual form (RFC 4291 §2.2),
/// including the `::` shorthand. Mixed `::ffff:1.2.3.4` form is accepted
/// only with the dotted quad in the final position (RFC 4291 §2.2.3).
fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    // Split on "::" (at most one occurrence).
    let (left, right) = if let Some(idx) = s.find("::") {
        (&s[..idx], &s[idx + 2..])
    } else {
        (s, "")
    };
    let left_groups: Vec<&str> = if left.is_empty() {
        Vec::new()
    } else {
        left.split(':').collect()
    };
    let right_groups: Vec<&str> = if right.is_empty() {
        Vec::new()
    } else {
        right.split(':').collect()
    };

    // Reject malformed input (e.g. ":::" → pieces with empty strings).
    if left_groups.iter().any(|g| g.is_empty()) && !left.is_empty() {
        return None;
    }
    if right_groups.iter().any(|g| g.is_empty()) && !right.is_empty() {
        return None;
    }

    // A dotted quad, if present, must be the *last* group of its side and
    // counts as two hextets.
    let last = right_groups.last().or_else(|| left_groups.last());
    let has_quad = last.map(|g| g.contains('.')).unwrap_or(false);
    let (quad_bytes, quad_units) = if has_quad {
        (parse_ipv4_strict(last.unwrap())?, 2)
    } else {
        ([0u8; 4], 0)
    };

    let has_double_colon = s.contains("::");
    // The quad (when present) is one element of the split groups but counts
    // as two hextets; adjust so `total` is in hextet units.
    let quad_element = usize::from(has_quad);
    let total = left_groups.len() + right_groups.len() - quad_element + quad_units;

    if !has_double_colon {
        // Need exactly 8 hextets (or 6 hextets + quad).
        if total != 8 {
            return None;
        }
        let mut out = [0u8; 16];
        let mut pos = 0;
        let hextet_count = left_groups.len() - if has_quad { 1 } else { 0 };
        for g in left_groups.iter().take(hextet_count) {
            let v = u16::from_str_radix(g, 16).ok()?;
            out[pos] = (v >> 8) as u8;
            out[pos + 1] = v as u8;
            pos += 2;
        }
        if has_quad {
            out[pos..pos + 4].copy_from_slice(&quad_bytes);
        }
        return Some(out);
    }

    // With "::": total must be < 8.
    if total >= 8 {
        return None;
    }
    let zeros = 8 - total;
    let mut out = [0u8; 16];
    let mut pos = 0;
    for g in &left_groups {
        let v = parse_group(g, false)?;
        let bytes = parse_group_to_bytes(v)?;
        out[pos..pos + 2].copy_from_slice(&bytes);
        pos += 2;
    }
    pos += zeros * 2; // skip zero-filled middle
    for (i, g) in right_groups.iter().enumerate() {
        let is_last = i + 1 == right_groups.len();
        if g.contains('.') {
            // The quad must be the last group and it was already consumed
            // into quad_bytes above.
            if !is_last || pos + 4 > 16 {
                return None;
            }
            out[pos..pos + 4].copy_from_slice(&quad_bytes);
            break;
        }
        let v = parse_group(g, false)?;
        let bytes = parse_group_to_bytes(v)?;
        out[pos..pos + 2].copy_from_slice(&bytes);
        pos += 2;
    }
    Some(out)
}

fn parse_group(g: &str, _strict: bool) -> Option<u16> {
    if g.is_empty() || g.len() > 4 {
        return None;
    }
    u16::from_str_radix(g, 16).ok()
}

fn parse_group_to_bytes(v: u16) -> Option<[u8; 2]> {
    Some([(v >> 8) as u8, v as u8])
}

fn to_ipv6_string(b: &[u8; 16]) -> String {
    // RFC 4291 §2.2.3: IPv4-mapped addresses render with a dotted quad.
    if b[0..10] == [0; 10] && b[10..12] == [0xff, 0xff] {
        let mut head = String::new();
        // The 5 zero groups compress to "::"; then "ffff" + the quad.
        head.push_str("::ffff:");
        use core::fmt::Write;
        let _ = write!(head, "{}.{}.{}.{}", b[12], b[13], b[14], b[15]);
        return head;
    }

    // Compress the longest run of zero groups into "::" (RFC 5952 §4.2.3).
    let groups: [u16; 8] = [
        u16::from_be_bytes([b[0], b[1]]),
        u16::from_be_bytes([b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]),
        u16::from_be_bytes([b[8], b[9]]),
        u16::from_be_bytes([b[10], b[11]]),
        u16::from_be_bytes([b[12], b[13]]),
        u16::from_be_bytes([b[14], b[15]]),
    ];

    // Find longest run of zero groups of length >= 2.
    let mut best_start = None;
    let mut best_len = 0usize;
    let mut cur_start = None;
    let mut cur_len = 0usize;
    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if cur_start.is_none() {
                cur_start = Some(i);
                cur_len = 1;
            } else {
                cur_len += 1;
            }
        } else {
            if cur_len >= 2 && cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
            cur_start = None;
            cur_len = 0;
        }
    }
    if cur_len >= 2 && cur_len > best_len {
        best_start = cur_start;
        best_len = cur_len;
    }

    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if best_start == Some(i) {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if i > 0 && !out.ends_with(':') {
            out.push(':');
        }
        use core::fmt::Write;
        let _ = write!(out, "{:x}", groups[i]);
        i += 1;
    }
    out
}

/// A network prefix: address + prefix length. The host bits may or may not be
/// zeroed — callers normalize via [`Prefix::network`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl Prefix {
    pub const fn new_v4(addr: [u8; 4], prefix_len: u8) -> Self {
        Self {
            addr: IpAddr::V4(addr),
            prefix_len,
        }
    }

    pub const fn new_v6(addr: [u8; 16], prefix_len: u8) -> Self {
        Self {
            addr: IpAddr::V6(addr),
            prefix_len,
        }
    }

    pub fn v4(addr: [u8; 4], prefix_len: u8) -> Self {
        Self::new_v4(addr, prefix_len)
    }

    pub fn v6(addr: [u8; 16], prefix_len: u8) -> Self {
        Self::new_v6(addr, prefix_len)
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// Network address (host bits zeroed).
    pub fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(b) => {
                let pl = self.prefix_len.min(32) as u32;
                let mask: u32 = if pl == 0 { 0 } else { !0u32 << (32 - pl) };
                let net_u = u32::from_be_bytes(b) & mask;
                IpAddr::V4(net_u.to_be_bytes())
            }
            IpAddr::V6(b) => {
                let mut n = b;
                let pl = self.prefix_len.min(128) as usize;
                let full_bytes = pl / 8;
                let rem_bits = pl % 8;
                for (i, byte) in n.iter_mut().enumerate().skip(full_bytes) {
                    let _ = i;
                    *byte = 0;
                }
                if rem_bits > 0 && full_bytes < 16 {
                    let mask = 0xffu8 << (8 - rem_bits);
                    n[full_bytes] &= mask;
                }
                IpAddr::V6(n)
            }
        }
    }

    /// True if `other` is contained in this prefix.
    pub fn contains(&self, other: &IpAddr) -> bool {
        match (self.addr, other) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let pl = self.prefix_len.min(32) as u32;
                if pl == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - pl);
                let net_u = u32::from_be_bytes(net) & mask;
                let addr_u = u32::from_be_bytes(*addr) & mask;
                net_u == addr_u
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let pl = self.prefix_len.min(128) as usize;
                let full = pl / 8;
                let rem = pl % 8;
                if net[..full] != addr[..full] {
                    return false;
                }
                if rem > 0 && full < 16 {
                    let mask = 0xffu8 << (8 - rem);
                    if (net[full] & mask) != (addr[full] & mask) {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }

    pub fn contains_prefix(&self, other: &Self) -> bool {
        if self.addr.is_ipv4() != other.addr.is_ipv4() {
            return false;
        }
        if self.prefix_len > other.prefix_len {
            return false;
        }
        self.contains(&other.addr)
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for Prefix {
    type Err = ParseAddrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, p) = s.split_once('/').ok_or(ParseAddrError)?;
        let addr = IpAddr::from_str(a)?;
        let pl: u8 = p.parse().map_err(|_| ParseAddrError)?;
        if pl
            > match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            }
        {
            return Err(ParseAddrError);
        }
        Ok(Self {
            addr,
            prefix_len: pl,
        })
    }
}

/// Network with host bits zeroed. Useful for canonical comparison.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet(pub Prefix);

impl IpNet {
    pub fn new(p: Prefix) -> Self {
        Self(Prefix {
            addr: p.network(),
            prefix_len: p.prefix_len,
        })
    }

    pub fn into_inner(self) -> Prefix {
        self.0
    }

    pub fn prefix(&self) -> Prefix {
        self.0
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Autonomous System Number. Internally always 4-byte; encoded as 2-byte on
/// the wire when `<= 0xffff` (RFC 4893 two-octet AS space).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Asn(pub u32);

impl Asn {
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn as_u16(self) -> Option<u16> {
        if self.0 <= 0xffff {
            Some(self.0 as u16)
        } else {
            None
        }
    }

    pub fn is_as23456(self) -> bool {
        // AS_TRANS placeholder (RFC 4893)
        self.0 == 23456
    }

    pub fn is_private(self) -> bool {
        // Per RFC 6996: private ASNs are 64512..65534 and 4_200_000_000..4_294_967_294.
        matches!(self.0, 64512..=65534 | 4_200_000_000..=4_294_967_294)
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

impl fmt::Debug for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Asn {
    type Err = ParseAddrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("AS")
            .or_else(|| s.strip_prefix("as"))
            .unwrap_or(s);
        let v: u32 = rest.parse().map_err(|_| ParseAddrError)?;
        if v == 0 || v == 0xffff_ffff {
            // 0 is reserved; AS 4294967295 is reserved.
            return Err(ParseAddrError);
        }
        Ok(Self(v))
    }
}

/// 32-bit router identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouterId(pub u32);

impl RouterId {
    pub const fn from_u32(v: u32) -> Self {
        Self(v)
    }

    pub const fn from_v4(b: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(b))
    }

    pub fn to_v4_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for RouterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.to_v4_bytes();
        write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }
}

impl fmt::Debug for RouterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for RouterId {
    type Err = ParseAddrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = parse_ipv4_strict(s).ok_or(ParseAddrError)?;
        Ok(Self::from_v4(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_prefix() {
        let p: Prefix = "10.0.0.0/8".parse().unwrap();
        assert!(p.is_ipv4());
        assert_eq!(p.prefix_len, 8);
    }

    #[test]
    fn ipv6_textual_roundtrip() {
        // Canonical form per RFC 5952: zero runs compressed to "::".
        let cases = [
            ("2001:db8::1", "2001:db8::1"),
            ("::1", "::1"),
            ("::", "::"),
            ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
            ("fe80::1", "fe80::1"),
            ("2001:db8:0:0::1", "2001:db8::1"),
        ];
        for (input, expected) in cases {
            let a: IpAddr = input.parse().unwrap();
            assert_eq!(a.to_string(), expected, "roundtrip failed for {}", input);
        }
    }

    #[test]
    fn prefix_contains() {
        let p: Prefix = "10.0.0.0/8".parse().unwrap();
        assert!(p.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!p.contains(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn prefix_contains_ipv6() {
        let p: Prefix = "2001:db8::/32".parse().unwrap();
        assert!(p.contains(&"2001:db8:1:2:3:4:5:6".parse().unwrap()));
        assert!(!p.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn network_zeroes_host_bits() {
        let p: Prefix = "192.168.1.5/24".parse().unwrap();
        let n = p.network();
        assert_eq!(n.to_string(), "192.168.1.0");
    }

    #[test]
    fn asn_private() {
        assert!(Asn(64513).is_private());
        assert!(!Asn(100).is_private());
    }

    #[test]
    fn router_id_parse() {
        let r: RouterId = "1.2.3.4".parse().unwrap();
        assert_eq!(r.to_string(), "1.2.3.4");
        assert_eq!(r.as_u32(), 0x01020304);
    }

    /// RFC 4291 §2.2.3 mixed IPv4-mapped IPv6 form must parse, and
    /// malformed inputs (quad not last, trailing junk) must be rejected.
    #[test]
    fn ipv6_mixed_form() {
        let a: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        eprintln!("parsed: {:02x?} -> {}", a.octets(), a.to_string());
        assert!(a.is_ipv4_mapped_ipv6());
        assert_eq!(a.to_string(), "::ffff:1.2.3.4");

        let b: IpAddr = "0:0:0:0:0:ffff:192.168.1.1".parse().unwrap();
        assert_eq!(b.to_string(), "::ffff:192.168.1.1");

        // Quad must be the last group.
        assert!("::1.2.3.4:5".parse::<IpAddr>().is_err());
        assert!("1.2.3.4::5".parse::<IpAddr>().is_err());
        // Junk after the quad.
        assert!("::ffff:1.2.3.4junk".parse::<IpAddr>().is_err());
        // Too many hextets.
        assert!("1:2:3:4:5:6:7:8:9".parse::<IpAddr>().is_err());
    }

    /// A leading '+' must not be accepted as an IPv4 octet.
    #[test]
    fn ipv4_rejects_plus_prefix() {
        assert!("+1.2.3.4".parse::<IpAddr>().is_err());
        assert!("1.2.3.4".parse::<IpAddr>().is_ok());
    }
}
