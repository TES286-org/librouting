//! Typed interpretation of RIB-entry path attributes (feature `bgp`).
//!
//! The codec keeps attributes as raw `flags | type | len | value` TLVs
//! (the format layer stays `lr-bgp`-free); this module walks the TLV
//! sequence and decodes the display-relevant attributes through the
//! `lr-bgp` decoders — one source of truth for AS paths, next hops and
//! communities.

use lr_bgp::path::{AttrType, MpNextHop, PathAttrFlags, PathAttribute, PathAttributes};
use lr_core::addr::IpAddr;

use crate::RibEntry;

/// The display-relevant projection of one RIB entry's attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttrSummary {
    /// NEXT_HOP (type 3) or, failing that, the MP_REACH_NLRI next hop.
    pub next_hop: Option<IpAddr>,
    /// AS path in display form (`"65001 65002"`); empty when absent.
    pub as_path: String,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    /// Communities in `asn:value` form.
    pub communities: Vec<String>,
    /// Total size of the raw attribute set.
    pub raw_len: usize,
}

/// Walk `entry.attributes` and decode the interesting parts.
///
/// The AS path is resolved at 4-byte width by default (modern dumps);
/// when the entry carries both AS_PATH and AS4_PATH — the RFC 4893
/// transition encoding where AS_PATH holds `AS_TRANS` placeholders —
/// the 4-byte path wins. A 2-byte-only path is decoded as such when no
/// 4-byte form decodes.
pub fn walk_attributes(entry: &RibEntry) -> AttrSummary {
    let attrs = decode_tlv_set(&entry.attributes);
    let mut summary = AttrSummary {
        raw_len: entry.attributes.len(),
        ..Default::default()
    };
    let next_hop = attrs.next_hop().map(|n| n.to_ip());
    summary.next_hop = match next_hop {
        Some(ip) => Some(ip),
        None => mp_reach_next_hop(&attrs),
    };
    // Prefer the AS4_PATH when present (RFC 4893 §4.2.2 transition
    // encoding); otherwise decode AS_PATH at 4-byte width, falling back
    // to 2-byte.
    summary.as_path = attrs
        .as4_path()
        .or_else(|| attrs.as_path())
        .or_else(|| attrs.as_path_wire(false))
        .map(|p| p.to_string())
        .unwrap_or_default();
    summary.local_pref = attrs.local_pref().map(|lp| lp.0);
    summary.med = attrs.med().map(|m| m.0);
    summary.communities = attrs.communities().iter().map(|c| c.to_string()).collect();
    summary
}

/// Decode a raw `flags | type | len | value` sequence. Malformed
/// trailing bytes are dropped (a dump tool must not die on one bad
/// entry — BIRD/FRR agree).
fn decode_tlv_set(bytes: &[u8]) -> PathAttributes {
    let mut out = PathAttributes::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let flags = PathAttrFlags(bytes[i]);
        let ty = AttrType::from_u8(bytes[i + 1]);
        let len_size = if flags.extended_length() { 2 } else { 1 };
        let len_start = i + 2;
        let Some(len) = read_len(&bytes[len_start..], flags.extended_length()) else {
            break;
        };
        let value_start = len_start + len_size;
        if value_start + len > bytes.len() {
            break;
        }
        out.insert(PathAttribute {
            flags,
            attr_type: ty,
            value: bytes[value_start..value_start + len].to_vec(),
        });
        i = value_start + len;
    }
    let _ = i;
    out
}

fn read_len(bytes: &[u8], extended: bool) -> Option<usize> {
    if extended {
        if bytes.len() < 2 {
            return None;
        }
        Some(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
    } else {
        bytes.first().map(|b| *b as usize)
    }
}

/// The MP_REACH_NLRI (type 14) next hop, when NEXT_HOP is absent.
fn mp_reach_next_hop(attrs: &PathAttributes) -> Option<IpAddr> {
    let a = attrs.get(AttrType::MpReachNlri)?;
    let reach = lr_bgp::path::MpReach::decode(&a.value)?;
    let _ = MpNextHop::V4([0; 4]); // keep the enum import honest
    Some(reach.next_hop.primary())
}
