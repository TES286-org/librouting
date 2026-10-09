//! RFC 8277 BGP labelled-unicast NLRI codec.
//!
//! RFC 8277 §3 defines the encoding of MPLS-labelled prefixes in BGP. The
//! NLRI for a labelled-unicast family (AFI=1/SAFI=4 for IPv4, AFI=2/SAFI=4
//! for IPv6) carries the label stack immediately before the IP prefix:
//!
//! ```text
//! +---------------------------+
//! |    Length (1 octet)       |
//! +---------------------------+
//! |   Label 1 (3 octets)      |
//! +---------------------------+
//! |   Label 2 (3 octets)      |
//! +---------------------------+
//! |          ...              |
//! +---------------------------+
//! |   Label n (3 octets, S=1) |
//! +---------------------------+
//! |   Prefix (variable)       |
//! +---------------------------+
//! ```
//!
//! - Each label is the 3-octet form of RFC 3032 §2.1 (no TTL). The
//!   bottom-of-stack bit (S) is set on the last label.
//! - `Length` is the total bit count: `3*n*8 + ip_prefix_bits`. The total
//!   number of trailing bytes after the length octet is `ceil(Length / 8)`.
//! - The number of labels `n` is not encoded explicitly — it is recovered
//!   by walking the label stack until the S bit is set.
//!
//! When the family also negotiates RFC 7911 Add-Path, every NLRI entry is
//! prefixed by a 4-octet path identifier (RFC 7911 §4.3), encoded before
//! the length octet — the same convention as the plain NLRI form.

use lr_core::addr::{IpAddr, Prefix};
use lr_core::nlri::NlriFamily;
use lr_mpls::{Label, LabelStack};

/// One RFC 8277 labelled NLRI entry: an optional Add-Path identifier, an
/// MPLS label stack, and the IP prefix it advertises.
///
/// The label stack is *non-empty* on the wire (RFC 8277 §3.2 forbids a
/// zero-length label field). The [`IMPLICIT_NULL`](Label::IMPLICIT_NULL)
/// label (value 3) is the canonical "forward the packet unlabelled" marker
/// carried in the stack on transit routes whose egress peering pops.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LabeledNlri {
    /// RFC 7911 path identifier; 0 when Add-Path is not negotiated.
    pub path_id: u32,
    /// MPLS label stack — top of stack at index 0. The bottom-of-stack
    /// bit is set on encode and stripped on decode by [`LabelStack`].
    pub label_stack: LabelStack,
    /// The IP prefix the labels reach.
    pub prefix: Prefix,
}

impl LabeledNlri {
    /// Construct a labelled NLRI with no Add-Path identifier.
    pub fn new(label_stack: LabelStack, prefix: Prefix) -> Self {
        Self {
            path_id: 0,
            label_stack,
            prefix,
        }
    }

    /// Construct a labelled NLRI with an explicit RFC 7911 path identifier.
    pub fn with_path_id(path_id: u32, label_stack: LabelStack, prefix: Prefix) -> Self {
        Self {
            path_id,
            label_stack,
            prefix,
        }
    }

    /// Encode a single entry as the on-the-wire NLRI bytes (path-id prefix
    /// included only when `add_path` is true). Returns `None` when the
    /// label stack is empty — RFC 8277 §3.2 forbids a zero-length label
    /// field on the wire.
    pub fn encode(&self, add_path: bool) -> Option<Vec<u8>> {
        if self.label_stack.is_empty() {
            return None;
        }
        let label_bytes = self.label_stack.encode_3octet();
        let ip_octets = match &self.prefix.addr {
            IpAddr::V4(b) => b.to_vec(),
            IpAddr::V6(b) => b.to_vec(),
        };
        let ip_len_bits = self.prefix.prefix_len as usize;
        let ip_octet_count = ip_len_bits.div_ceil(8);
        let mut ip_bytes = ip_octets;
        ip_bytes.truncate(ip_octet_count);
        // Mask the last octet's host bits (defensive — callers should pass
        // already-normalised prefixes; mirrors mp_nlri.rs).
        if !ip_len_bits.is_multiple_of(8) {
            if let Some(last) = ip_bytes.last_mut() {
                let mask = 0xffu8 << (8 - ip_len_bits % 8);
                *last &= mask;
            }
        }
        // Length octet = label-stack bits + prefix bits.
        let total_bits = (label_bytes.len() * 8) + ip_len_bits;
        if total_bits > u8::MAX as usize {
            return None;
        }
        let mut out =
            Vec::with_capacity(4 * add_path as usize + 1 + label_bytes.len() + ip_bytes.len());
        if add_path {
            out.extend_from_slice(&self.path_id.to_be_bytes());
        }
        out.push(total_bits as u8);
        out.extend_from_slice(&label_bytes);
        out.extend_from_slice(&ip_bytes);
        Some(out)
    }

    /// Decode one entry from the front of `bytes`, returning the parsed
    /// entry and the number of bytes consumed. Returns `None` on any
    /// framing error.
    ///
    /// `family` selects the IP prefix width (AFI=1 → 4-octet, AFI=2 →
    /// 16-octet). `add_path` toggles the RFC 7911 path-id prefix.
    pub fn decode(family: NlriFamily, bytes: &[u8], add_path: bool) -> Option<(Self, usize)> {
        let mut i = 0;
        let path_id = if add_path {
            if bytes.len() < 4 {
                return None;
            }
            let id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            i += 4;
            id
        } else {
            0
        };
        if i >= bytes.len() {
            return None;
        }
        let total_bits = bytes[i] as usize;
        i += 1;
        let total_octets = total_bits.div_ceil(8);
        if i + total_octets > bytes.len() {
            return None;
        }
        // Walk labels one at a time, stopping at the bottom-of-stack bit.
        // The S bit — not total_bits — terminates the label field; total_bits
        // only validates the resulting IP prefix length.
        let mut labels: Vec<Label> = Vec::new();
        let label_start = i;
        loop {
            if i + 3 > bytes.len() {
                return None;
            }
            // Bounds-check: the label region cannot exceed total_octets.
            if i - label_start >= total_octets {
                // Ran out of label budget without an S bit — malformed.
                return None;
            }
            let off = i;
            let value = ((bytes[off] as u32) << 12)
                | ((bytes[off + 1] as u32) << 4)
                | ((bytes[off + 2] as u32) >> 4);
            let tc = (bytes[off + 2] >> 1) & 0x07;
            let bottom = (bytes[off + 2] & 0x01) != 0;
            labels.push(Label::new_value(value).with_tc(tc));
            i += 3;
            if bottom {
                break;
            }
        }
        let label_octets = i - label_start;
        if label_octets == 0 {
            return None;
        }
        let stack = LabelStack::from_vec(labels);
        // Validate: label-octet count must be a multiple of 3 (already
        // guaranteed by the loop) and total_bits must equal
        // label_octets*8 + ip_bits, with ip_bits within the family's range.
        if total_bits < label_octets * 8 {
            return None;
        }
        let ip_bits = total_bits - label_octets * 8;
        if ip_bits > 32 && family.is_ipv4() {
            return None;
        }
        if ip_bits > 128 && family.is_ipv6() {
            return None;
        }
        let ip_octet_count = ip_bits.div_ceil(8);
        if i + ip_octet_count > bytes.len() {
            return None;
        }
        let prefix = match family.afi {
            1 => {
                let mut a = [0u8; 4];
                if ip_octet_count > 4 {
                    return None;
                }
                a[..ip_octet_count].copy_from_slice(&bytes[i..i + ip_octet_count]);
                Prefix::new_v4(a, ip_bits as u8)
            }
            2 => {
                let mut a = [0u8; 16];
                if ip_octet_count > 16 {
                    return None;
                }
                a[..ip_octet_count].copy_from_slice(&bytes[i..i + ip_octet_count]);
                Prefix::new_v6(a, ip_bits as u8)
            }
            _ => return None,
        };
        let consumed = i + ip_octet_count;
        Some((
            Self {
                path_id,
                label_stack: stack,
                prefix,
            },
            consumed,
        ))
    }
}

/// Encode a slice of labelled NLRI entries into the NLRI portion of an
/// MP_REACH_NLRI / MP_UNREACH_NLRI attribute value.
pub fn encode_list(entries: &[LabeledNlri], add_path: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        if let Some(b) = e.encode(add_path) {
            out.extend_from_slice(&b);
        }
    }
    out
}

/// Decode a slice of labelled NLRI entries from the NLRI portion of an
/// MP_REACH_NLRI / MP_UNREACH_NLRI attribute value.
pub fn decode_list(family: NlriFamily, bytes: &[u8], add_path: bool) -> Option<Vec<LabeledNlri>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let (entry, consumed) = LabeledNlri::decode(family, &bytes[i..], add_path)?;
        if consumed == 0 {
            return None;
        }
        i += consumed;
        out.push(entry);
    }
    Some(out)
}

/// Convenience: a one-label IPv4 NLRI with the implicit-null label.
/// Uses `new_value` (TTL=0) since the 3-octet NLRI form does not carry TTL.
pub fn ipv4_implicit_null(prefix: Prefix) -> LabeledNlri {
    LabeledNlri::new(
        LabelStack::from_labels([Label::new_value(Label::IMPLICIT_NULL.value)]),
        prefix,
    )
}

// ===== MP_REACH_NLRI / MP_UNREACH_NLRI helpers =====
//
// `MpReach`/`MpUnreach` carry plain NLRI; for labelled families we encode
// the NLRI portion via `encode_list` and assemble the full attribute value
// with the helpers below. The wire layout is identical to plain MP-BGP:
//
//   MP_REACH:  AFI(2) | SAFI(1) | nh-len(1) | next-hop(nh-len) | reserved(1) | NLRI...
//   MP_UNREACH: AFI(2) | SAFI(1) | NLRI...
//
// Only the NLRI bytes differ — they are RFC 8277 labelled NLRI entries.

use crate::path::MpNextHop;

/// Build the MP_REACH_NLRI attribute value for a labelled family.
pub fn encode_mp_reach(
    family: NlriFamily,
    next_hop: &MpNextHop,
    entries: &[LabeledNlri],
    add_path: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&family.afi.to_be_bytes());
    out.push(family.safi);
    let nh = next_hop.encode();
    out.push(nh.len() as u8);
    out.extend_from_slice(&nh);
    out.push(0); // reserved
    out.extend_from_slice(&encode_list(entries, add_path));
    out
}

/// Build the MP_UNREACH_NLRI attribute value for a labelled family.
pub fn encode_mp_unreach(family: NlriFamily, entries: &[LabeledNlri], add_path: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&family.afi.to_be_bytes());
    out.push(family.safi);
    out.extend_from_slice(&encode_list(entries, add_path));
    out
}

/// Parse the MP_REACH_NLRI attribute value for a labelled family. Returns
/// `(family, next_hop, entries)` or `None` on a framing error.
pub fn decode_mp_reach(
    b: &[u8],
    add_path: bool,
) -> Option<(NlriFamily, MpNextHop, Vec<LabeledNlri>)> {
    if b.len() < 3 + 1 {
        return None;
    }
    let afi = u16::from_be_bytes([b[0], b[1]]);
    let safi = b[2];
    let family = NlriFamily { afi, safi };
    if !family.is_labeled_unicast() {
        return None;
    }
    let nh_len = b[3] as usize;
    if b.len() < 4 + nh_len {
        return None;
    }
    let next_hop = decode_next_hop(&b[4..4 + nh_len], family)?;
    let mut i = 4 + nh_len;
    if i >= b.len() {
        return Some((family, next_hop, Vec::new()));
    }
    i += 1; // reserved
    let entries = decode_list(family, &b[i..], add_path)?;
    Some((family, next_hop, entries))
}

/// Parse the MP_UNREACH_NLRI attribute value for a labelled family.
pub fn decode_mp_unreach(b: &[u8], add_path: bool) -> Option<(NlriFamily, Vec<LabeledNlri>)> {
    if b.len() < 3 {
        return None;
    }
    let afi = u16::from_be_bytes([b[0], b[1]]);
    let safi = b[2];
    let family = NlriFamily { afi, safi };
    if !family.is_labeled_unicast() {
        return None;
    }
    let entries = decode_list(family, &b[3..], add_path)?;
    Some((family, entries))
}

/// Same next-hop decoding rules as plain MP-BGP, restricted to the
/// labelled-unicast families (IPv4 → 4 or 16 bytes; IPv6 → 16 or 32).
fn decode_next_hop(b: &[u8], family: NlriFamily) -> Option<MpNextHop> {
    match (family.afi, b.len()) {
        (1, 4) => {
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            Some(MpNextHop::V4(a))
        }
        (1, 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(MpNextHop::V4OverV6(a))
        }
        (2, 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(MpNextHop::V6Global(a))
        }
        (2, 32) => {
            let mut g = [0u8; 16];
            let mut l = [0u8; 16];
            g.copy_from_slice(&b[..16]);
            l.copy_from_slice(&b[16..]);
            Some(MpNextHop::V6GlobalLinkLocal(g, l))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "labeled_nlri_tests.rs"]
mod tests;
