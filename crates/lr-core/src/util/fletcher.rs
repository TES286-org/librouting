//! Fletcher checksums used by OSPF.
//!
//! OSPF protects every LSA with the "Fletcher checksum" defined in
//! RFC 2328 §C.4 (inherited from RFC 905 Annex B): a Fletcher-16 over the
//! LSA content, with the two `ls_age` bytes excluded and the checksum
//! field itself zeroed during computation. Inserting the computed pair
//! into the checksum field makes both running sums congruent to zero,
//! which is exactly the property [`ospf_lsa_checksum_ok`] verifies.
//!
//! Fletcher-32 is provided for general use (e.g. checksum-protected
//! payloads elsewhere in the protocol stack).

/// Byte offset of the LSA checksum field within a serialized LSA
/// (RFC 2328 §A.4.1 header layout).
pub const LSA_CHECKSUM_OFFSET: usize = 16;

/// Compute the RFC 2328 §C.4 LSA checksum.
///
/// `lsa` must be the complete serialized LSA — the 20-byte header
/// followed by the body. Bytes 0–1 (`ls_age`) are excluded from the sum
/// and the checksum field at bytes 16–17 is treated as zero, exactly as
/// the RFC prescribes. The returned `u16` is in wire order:
/// `((x as u8) << 8) | (y as u8)`.
///
/// Returns `0` when `lsa` is shorter than a full LSA header, which
/// callers should treat as "no checksum" rather than a valid value.
pub fn ospf_lsa_checksum(lsa: &[u8]) -> u16 {
    if lsa.len() < LSA_CHECKSUM_OFFSET + 2 {
        return 0;
    }
    // The pair occupies its wire position while zeroed, so it still
    // advances the Fletcher state machine (RFC 905 Annex B convention).
    let (c0, c1, n) = fletcher_sums(lsa, false);
    let (x, y) = fletcher_checksum_pair(c0, c1, n);
    ((x as u8 as u16) << 8) | (y as u8 as u16)
}

/// Verify an LSA's embedded checksum: both running Fletcher sums over the
/// LSA content (age excluded, checksum bytes included) must be congruent
/// to zero modulo 255 (RFC 2328 §C.4).
pub fn ospf_lsa_checksum_ok(lsa: &[u8]) -> bool {
    if lsa.len() < LSA_CHECKSUM_OFFSET + 2 {
        return false;
    }
    let (c0, c1, _) = fletcher_sums(lsa, true);
    c0 == 0 && c1 == 0
}

/// Running sums `(c0, c1)` over `lsa[2..]` modulo 255, plus the summed
/// position count. When `include_checksum` is false the two checksum
/// bytes are substituted with zero (they are zero at computation time
/// but still advance the state machine); when true the stored bytes are
/// summed as-is (verification).
fn fletcher_sums(lsa: &[u8], include_checksum: bool) -> (u32, u32, usize) {
    let mut c0: u32 = 0;
    let mut c1: u32 = 0;
    let mut n: usize = 0;
    for (i, &raw) in lsa.iter().enumerate().skip(2) {
        let b = if !include_checksum && (LSA_CHECKSUM_OFFSET..LSA_CHECKSUM_OFFSET + 2).contains(&i)
        {
            0
        } else {
            raw
        };
        c0 = (c0 + u32::from(b)) % 255;
        c1 = (c1 + c0) % 255;
        n += 1;
    }
    (c0, c1, n)
}

/// Derive the Fletcher checksum byte pair that zeroes both sums when
/// inserted at `LSA_CHECKSUM_OFFSET` (RFC 905 Annex B positioning).
///
/// With `n` summed bytes and the pair inserted so that `x` sits `n - 15`
/// positions before the end (per the OSPF layout, where the pair occupies
/// data offsets 14 and 15), the zero-sum conditions solve to:
///
/// ```text
/// x = (n - 15) * c0 - c1   (mod 255)
/// y = -c0 - x              (mod 255)
/// ```
///
/// Both bytes are mapped into `1..=255` (never zero) per convention.
fn fletcher_checksum_pair(c0: u32, c1: u32, n: usize) -> (i32, i32) {
    let c0 = c0 as i32;
    let c1 = c1 as i32;
    let mut x = ((n as i32 - 15) * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }
    (x, y)
}

/// Standard Fletcher-32 (sums modulo 0xffff over 16-bit big-endian
/// words).
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

    /// Serialize a minimal LSA (header + body) with a zeroed checksum.
    fn lsa_bytes(options: u8, ls_type: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(20 + body.len());
        v.extend_from_slice(&0u16.to_be_bytes()); // ls_age
        v.push(options);
        v.push(ls_type);
        v.extend_from_slice(&0x0a000001u32.to_be_bytes()); // link_state_id
        v.extend_from_slice(&0x01020304u32.to_be_bytes()); // advertising_router
        v.extend_from_slice(&0x80000001u32.to_be_bytes()); // seq
        v.extend_from_slice(&0u16.to_be_bytes()); // checksum (zeroed)
        v.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes()); // length
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn checksum_insertion_zeroes_sums() {
        // The defining property: after embedding the computed checksum,
        // both Fletcher sums over the content must be zero (mod 255).
        let body = [0xffu8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x0a, 0x00];
        let mut lsa = lsa_bytes(0x02, 3, &body);
        let sum = ospf_lsa_checksum(&lsa);
        assert_ne!(sum, 0, "checksum must not be all-zero");
        lsa[16..18].copy_from_slice(&sum.to_be_bytes());
        assert!(ospf_lsa_checksum_ok(&lsa));
    }

    #[test]
    fn checksum_sums_to_zero_various_shapes() {
        // Exercise several lengths and body patterns — the zero-sum
        // property must hold regardless of content parity.
        for len in [0usize, 1, 4, 8, 11] {
            let body: Vec<u8> = (0..len).map(|i| (i * 37 + 5) as u8).collect();
            for ls_type in [1u8, 3, 5] {
                let mut lsa = lsa_bytes(0x02, ls_type, &body);
                let sum = ospf_lsa_checksum(&lsa);
                lsa[16..18].copy_from_slice(&sum.to_be_bytes());
                assert!(
                    ospf_lsa_checksum_ok(&lsa),
                    "zero-sum property failed for len={len} type={ls_type}"
                );
            }
        }
    }

    #[test]
    fn checksum_detects_corruption() {
        let mut lsa = lsa_bytes(0x02, 3, &[0, 0, 0, 0x0a]);
        let sum = ospf_lsa_checksum(&lsa);
        lsa[16..18].copy_from_slice(&sum.to_be_bytes());
        assert!(ospf_lsa_checksum_ok(&lsa));
        // Flip one body bit — verification must fail.
        lsa[20] ^= 0x01;
        assert!(!ospf_lsa_checksum_ok(&lsa));
    }

    #[test]
    fn checksum_bytes_never_zero() {
        // Convention: neither half of the checksum may be zero.
        for len in [0usize, 2, 5, 12, 30] {
            let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let lsa = lsa_bytes(0x00, 3, &body);
            let sum = ospf_lsa_checksum(&lsa);
            assert_ne!(sum >> 8, 0, "x half zero at len={len}");
            assert_ne!(sum & 0xff, 0, "y half zero at len={len}");
        }
    }

    #[test]
    fn truncated_lsa_yields_zero() {
        assert_eq!(ospf_lsa_checksum(&[0u8; 10]), 0);
        assert!(!ospf_lsa_checksum_ok(&[0u8; 10]));
    }

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
