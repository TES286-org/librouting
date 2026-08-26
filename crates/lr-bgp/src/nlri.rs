//! BGP NLRI helpers. Most NLRI work lives in `path::mp_nlri` for MP-BGP; this
//! module has the legacy IPv4 NLRI codec used outside of MP_REACH_NLRI.

use lr_core::addr::Prefix;

/// Encode a slice of IPv4 NLRI prefixes per RFC 4271 §4.3 (variable-length
/// prefix-length + minimal address bytes).
pub fn encode_ipv4_nlri(prefixes: &[Prefix]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in prefixes {
        debug_assert!(p.is_ipv4(), "ipv4 NLRI must contain IPv4 prefixes");
        out.push(p.prefix_len);
        let n = (p.prefix_len as usize).div_ceil(8);
        if let lr_core::addr::IpAddr::V4(b) = &p.addr {
            out.extend_from_slice(&b[..n]);
        }
    }
    out
}

/// Decode a slice of IPv4 NLRI prefixes.
pub fn decode_ipv4_nlri(bytes: &[u8]) -> Option<Vec<Prefix>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let pl = bytes[i];
        i += 1;
        let n = (pl as usize).div_ceil(8);
        if i + n > bytes.len() {
            return None;
        }
        let mut a = [0u8; 4];
        a[..n].copy_from_slice(&bytes[i..i + n]);
        i += n;
        out.push(Prefix::new_v4(a, pl));
    }
    Some(out)
}
