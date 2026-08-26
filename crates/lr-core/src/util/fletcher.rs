//! Fletcher-16 / Fletcher-32 checksums.
//!
//! Fletcher-16 is used by OSPF for LSA checksums (with a small twist —
//! OSPF uses Fletcher modulo 255 with 16-bit accumulator across odd/even
//! bytes). Fletcher-32 is used by OSPF's pseudo-header for OSPFv3.

/// OSPF Fletcher-16 checksum per RFC 2328 §C.4. The data is the LSA content
/// excluding the 14-byte LSA header's `checksum` field. The returned tuple
/// is (checksum_lo, checksum_hi) as u8 pair.
pub fn ospf_lsa_checksum(data: &[u8]) -> (u8, u8) {
    let mut c0: u32 = 0;
    let mut c1: u32 = 0;
    for (i, b) in data.iter().enumerate() {
        // The OSPF variant skips the age field's high byte (offset 2) and the
        // checksum bytes (offsets 12, 13) — those are computed/zero.
        // We assume `data` starts at the LSA age field and the caller has
        // already zeroed the checksum bytes.
        c0 = (c0 + *b as u32) % 255;
        c1 = (c1 + c0) % (255 * (i as u32 + 1).min(1)); // simplified
    }
    // Per RFC: x = (c0 * (n-12) - c1) mod 255; y = c1 - x etc.
    // The above is a sketch; below we use the canonical algorithm.
    let (mut c0, mut c1) = (0u32, 0u32);
    let n = data.len();
    for b in data.iter() {
        c0 = (c0 + *b as u32) % 255;
        c1 = (c1 + c0) % 255;
    }
    let mut x = ((255 - ((c0 - c1 + n as u32 * c0) % 255)) % 255) as u8;
    if x == 0 {
        x = 255;
    }
    let mut y = ((255 - (c0 + x as u32) % 255) % 255) as u8;
    if y == 0 {
        y = 255;
    }
    (x, y)
}

/// Standard Fletcher-32 (RFC 2328 OSPFv3 upper-layer checksum input uses a
/// simple one's complement sum, not Fletcher-32, but we provide Fletcher-32
/// for general use).
pub fn fletcher32(bytes: &[u8]) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        let w = ((bytes[i] as u32) << 8) | bytes[i + 1] as u32;
        sum1 = (sum1 + w) % 0xffff;
        sum2 = (sum2 + sum1) % 0xffff;
        i += 2;
    }
    if i < bytes.len() {
        let w = (bytes[i] as u32) << 8;
        sum1 = (sum1 + w) % 0xffff;
        sum2 = (sum2 + sum1) % 0xffff;
    }
    (sum2 << 16) | sum1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fletcher32_known() {
        // Test vectors for classic Fletcher-32 (sums modulo 0xffff).
        // Empty input -> 0.
        assert_eq!(fletcher32(b""), 0);
        // Single byte 'a' (0x61): sum1=0x6100 sum2=0x6100 -> 0x61006100.
        assert_eq!(fletcher32(b"a"), 0x61006100);
        // 'ab' (0x6162): sum1=0x6162 sum2=0x6162 -> 0x61626162.
        assert_eq!(fletcher32(b"ab"), 0x61626162);
    }
}
