//! OSPFv2 Segment Routing extensions — RFC 8665 (OSPF Extensions for
//! Segment Routing), riding the RFC 7684 Extended Prefix Opaque LSA and
//! the RFC 4970 Router Information LSA.
//!
//! Wire shapes live here:
//!
//! 1. **Extended Prefix Opaque LSA** (RFC 7684 §2, area-scoped:
//!    Opaque Type 7): the body is a sequence of TLVs, each
//!    **Extended Prefix TLV** (RFC 7684 §2.1, type 1) describing
//!    one prefix — Route Type, Prefix Length, AF, Flags, Address —
//!    plus sub-TLVs, and each **Extended Prefix Range TLV**
//!    (RFC 8665 §4, type 2) describing a contiguous prefix range —
//!    the SR Mapping Server advertisement (RFC 8661): the M-flagged
//!    Prefix-SID assigns SIDs on behalf of prefixes the advertising
//!    router does not own.
//! 2. **Prefix-SID sub-TLV** (RFC 8665 §5, type 2 inside the Extended
//!    Prefix / Extended Prefix Range TLV): Flags (NP/M/E/V/L),
//!    Reserved, MT-ID, Algorithm and the SID/Index/Label field — a
//!    4-octet index when V/L are clear (the only shape this crate
//!    originates), a 3-octet local label when V/L are set.
//! 3. **Router Information LSA SR TLVs** (RFC 4970 carrier + RFC 8665
//!    §3, area-scoped RI Opaque LSA with Opaque Type 4): the
//!    **SR-Algorithm TLV** (RFC 8665 §3.1, type 8) and the **SID/Label
//!    Range TLV** (RFC 8665 §3.2, type 9 — 3-octet range size,
//!    reserved, then the §2.1 SID/Label Sub-TLV with the first label).
//! 4. **Extended Link Opaque LSA** (RFC 7684 §3, area-scoped:
//!    Opaque Type 8): the body is a sequence of **Extended Link TLVs**
//!    (RFC 7684 §3.1, type 1) — Link Type, Link ID, Link Data —
//!    carrying the **Adj-SID sub-TLV** (RFC 8665 §6.1, type 2) and the
//!    **LAN Adj-SID sub-TLV** (RFC 8665 §6.2, type 3). An adjacency
//!    segment represents one hop over a specific link (RFC 8402 §2):
//!    the labels have local significance (V/L set, an absolute label
//!    from the SRLB) unless the originator advertises the global
//!    index shape.
//!
//! A remote node's label for an advertised prefix is `first_label +
//! sid_index` (RFC 8665 §5 / RFC 8402 §3.1.1; the index must fall
//! inside the originator's advertised range). For a mapping-server
//! range the same arithmetic applies per covered prefix with the
//! index shifted by the prefix's position inside the range
//! (RFC 8665 §4 / RFC 8661 §3.2).
//!
//! All TLVs are padded to four-octet alignment (RFC 7684 §2.3) with
//! the Length field excluding padding; the shapes emitted here are
//! naturally aligned except the 3-octet label encodings, whose one
//! trailing pad octet keeps the LSA length a multiple of 4 (RFC 2328
//! LSA lengths are 4-aligned — receivers reject otherwise).

use crate::abr::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::lsa::grace::{opaque_lsa_id, OPTIONS_O_BIT};
use crate::lsa::{Lsa, LsaHeader, LsaTypeV2};

/// Opaque Type for the Extended Prefix Opaque LSA (RFC 7684 §2).
pub const OPAQUE_TYPE_EXT_PREFIX: u8 = 7;
/// Opaque Type for the Router Information LSA (RFC 4970 §2.3).
pub const OPAQUE_TYPE_RI: u8 = 4;
/// Opaque Type for the Extended Link Opaque LSA (RFC 7684 §3).
pub const OPAQUE_TYPE_EXT_LINK: u8 = 8;

/// Extended Prefix TLV type (RFC 7684 §2.1).
pub const TLV_EXT_PREFIX: u16 = 1;
/// Extended Prefix Range TLV type (RFC 8665 §4): the SR Mapping
/// Server's advertisement carrier.
pub const TLV_EXT_PREFIX_RANGE: u16 = 2;
/// Extended Link TLV type (RFC 7684 §3.1).
pub const TLV_EXT_LINK: u16 = 1;
/// Prefix-SID sub-TLV type (RFC 8665 §5).
pub const SUBTLV_PREFIX_SID: u16 = 2;
/// SR-Algorithm TLV type (RFC 8665 §3.1).
pub const TLV_SR_ALGORITHM: u16 = 8;
/// SID/Label Range TLV type (RFC 8665 §3.2).
pub const TLV_SRGB: u16 = 9;
/// SID/Label Sub-TLV type (RFC 8665 §2.1), carried by the SID/Label
/// Range TLV.
pub const SUBTLV_SID_LABEL: u16 = 1;
/// Adj-SID sub-TLV type (RFC 8665 §6.1 — the Extended Link sub-TLV
/// registry; distinct numbering from the Extended Prefix one).
pub const SUBTLV_ADJ_SID: u16 = 2;
/// LAN Adj-SID sub-TLV type (RFC 8665 §6.2).
pub const SUBTLV_LAN_ADJ_SID: u16 = 3;

/// Prefix-SID sub-TLV flags (RFC 8665 §5).
pub mod sid_flags {
    /// No-PHP: the penultimate hop must not pop the label.
    pub const NP: u8 = 0x40;
    /// Mapping server: the SID was adjudicated by a mapping server.
    pub const M: u8 = 0x20;
    /// Explicit null at the penultimate hop.
    pub const E: u8 = 0x10;
    /// Value: the SID carries an absolute label (local significance).
    pub const V: u8 = 0x08;
    /// Local: the SID has local significance (implies V on the wire).
    pub const L: u8 = 0x04;
}

/// Adj-SID / LAN Adj-SID sub-TLV flags (RFC 8665 §6.1/§6.2).
pub mod adj_flags {
    /// Backup: the adjacency is eligible for protection (IP FRR or
    /// MPLS-FRR, RFC 8402 §3.5).
    pub const B: u8 = 0x80;
    /// Value: the Adj-SID carries an absolute label.
    pub const V: u8 = 0x40;
    /// Local: the value/index has local significance.
    pub const L: u8 = 0x20;
    /// Group: the Adj-SID may be assigned to other adjacencies too.
    pub const G: u8 = 0x08;
    /// Persistent: the Adj-SID survives restarts and interface flaps.
    pub const P: u8 = 0x04;
}

/// RFC 7684 §3.1 link types carried by the Extended Link TLV.
pub mod link_type {
    /// Point-to-point link (§A.1.1 link type 1).
    pub const POINT_TO_POINT: u8 = 1;
    /// Broadcast / NBMA / transit network (§A.1.1 link type 2).
    pub const TRANSIT: u8 = 2;
}

/// One prefix advertised with a Prefix-SID (RFC 8665 §5: the Extended
/// Prefix TLV + Prefix-SID sub-TLV pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrPrefixAdvert {
    /// RFC 7684 §2.1 route type: 1 = intra-area, 3 = inter-area,
    /// 5 = external, 7 = NSSA.
    pub route_type: u8,
    /// RFC 7684 §6 flags byte (A = 0x80 attach, N = 0x40 node).
    pub flags: u8,
    /// The prefix (IPv4 — the AF byte is always 0 for OSPFv2).
    pub prefix: [u8; 4],
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Prefix-SID flags (see [`sid_flags`]); the originator sets NP
    /// for a no-PHP label, E for explicit-null, M for a mapping-server
    /// SID. V/L stay clear for an SRGB-indexed global SID.
    pub sid_flags: u8,
    /// Prefix-SID value: an index into the originator's SRGB (the
    /// global shape lr originates).
    pub sid: u32,
    /// SR algorithm (0 = SPF, the only one this crate originates).
    pub algorithm: u8,
}

impl SrPrefixAdvert {
    /// Encode the Extended Prefix TLV (RFC 7684 §2.1: Route Type,
    /// Prefix Length, AF, Flags, Address) with one Prefix-SID sub-TLV
    /// (RFC 8665 §5: Flags, Reserved, MT-ID, Algorithm, 4-octet
    /// SID/Index for the global shape). The descriptor field order is
    /// load-bearing — FRR reads Prefix Length before Flags and an
    /// assert in its prefix math aborts the whole daemon on a swapped
    /// encoding (flushed out by the FRR interop lab).
    pub fn encode_ext_prefix_tlv(&self) -> Vec<u8> {
        // Value: route_type(1) prefix_len(1) af(1) flags(1)
        //        prefix(4) + sub-TLV (4 + 8).
        let mut value = Vec::with_capacity(4 + 4 + 12);
        value.push(self.route_type);
        value.push(self.prefix_len);
        value.push(0); // AF: 0 = IPv4 unicast
        value.push(self.flags);
        value.extend_from_slice(&self.prefix);
        // Prefix-SID sub-TLV (RFC 8665 §5): type(2) len(8) flags(1)
        // reserved(1) mt-id(1) algorithm(1) sid/index(4).
        value.extend_from_slice(&SUBTLV_PREFIX_SID.to_be_bytes());
        value.extend_from_slice(&8u16.to_be_bytes());
        value.push(self.sid_flags);
        value.push(0); // Reserved: zero on transmission (RFC 8665 §5)
        value.push(0); // MT-ID 0 (default topology)
        value.push(self.algorithm);
        // V/L clear: a 4-octet index into the originator's SRGB.
        value.extend_from_slice(&self.sid.to_be_bytes());
        // The sub-TLV is already 4-octet aligned; keep the guard for
        // callers that add odd-sized sub-TLVs before the wrapper.
        let sub_pad = (4 - (value.len() - 8) % 4) % 4;
        value.resize(value.len() + sub_pad, 0);
        // TLV wrapper.
        let mut out = Vec::with_capacity(4 + value.len());
        out.extend_from_slice(&TLV_EXT_PREFIX.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(&value);
        out
    }

    /// Decode one Extended Prefix TLV **value** (after the 4-byte TLV
    /// header). Returns `None` on truncation, a non-IPv4 AF, or a
    /// malformed prefix length. Sub-TLVs other than the Prefix-SID
    /// are skipped per RFC 8665 §9 (unknown sub-TLVs are ignored);
    /// a missing Prefix-SID sub-TLV is NOT an error — only the prefix
    /// descriptor is filled and `sid` stays `None`. The Prefix-SID
    /// value is a 4-octet index when its sub-TLV carries length 8 and
    /// a 3-octet local label when it carries length 7 (RFC 8665 §5);
    /// other lengths are ignored as malformed.
    pub fn decode_ext_prefix_tlv_value(
        value: &[u8],
    ) -> Option<(SrPrefixAdvertCore, Option<SrPrefixSidTlv>)> {
        if value.len() < 8 {
            return None;
        }
        let route_type = value[0];
        let prefix_len = value[1];
        let af = value[2];
        let flags = value[3];
        if af != 0 || prefix_len > 32 {
            return None;
        }
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&value[4..8]);
        let core = SrPrefixAdvertCore {
            route_type,
            flags,
            prefix,
            prefix_len,
        };
        // Sub-TLVs follow the (always 4-byte-wide) IPv4 prefix.
        let mut sid = None;
        let mut i = 8;
        while i + 4 <= value.len() {
            let st = u16::from_be_bytes([value[i], value[i + 1]]);
            let st_len = u16::from_be_bytes([value[i + 2], value[i + 3]]) as usize;
            i += 4;
            if i + st_len > value.len() {
                return None;
            }
            if st == SUBTLV_PREFIX_SID {
                // RFC 8665 §5: Flags, Reserved, MT-ID, Algorithm, then
                // the SID/Index/Label field (4 octets for an index, 3
                // for a local label).
                let parsed = match st_len {
                    8 => Some(SrPrefixSidTlv {
                        flags: value[i],
                        mt_id: value[i + 2],
                        algorithm: value[i + 3],
                        sid: u32::from_be_bytes([
                            value[i + 4],
                            value[i + 5],
                            value[i + 6],
                            value[i + 7],
                        ]),
                    }),
                    7 => Some(SrPrefixSidTlv {
                        flags: value[i],
                        mt_id: value[i + 2],
                        algorithm: value[i + 3],
                        sid: u32::from_be_bytes([0, value[i + 4], value[i + 5], value[i + 6]]),
                    }),
                    _ => None,
                };
                if parsed.is_some() {
                    sid = parsed;
                }
            }
            // Round up to the next 4-octet boundary (RFC 7684 §2.3:
            // sub-TLVs are padded).
            i += (st_len + 3) & !3;
        }
        Some((core, sid))
    }
}

/// The prefix descriptor part of an Extended Prefix TLV (RFC 7684
/// §2.1) — everything except the sub-TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrPrefixAdvertCore {
    pub route_type: u8,
    pub flags: u8,
    pub prefix: [u8; 4],
    pub prefix_len: u8,
}

/// A decoded Prefix-SID sub-TLV (RFC 8665 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrPrefixSidTlv {
    /// Flags byte — see [`sid_flags`].
    pub flags: u8,
    /// Topology ID (0 = default).
    pub mt_id: u8,
    /// Algorithm (0 = SPF).
    pub algorithm: u8,
    /// The 3-octet SID: an SRGB index when V/L are clear, an absolute
    /// label otherwise.
    pub sid: u32,
}

/// Encode the body of an **Extended Prefix Opaque LSA** carrying one
/// advertised prefix. (The LSA may carry several Extended Prefix TLVs;
/// lr originates one LSA per prefix so a SID change only re-floods the
/// LSA that changed.)
pub fn encode_ext_prefix_lsa_body(advert: &SrPrefixAdvert) -> Vec<u8> {
    advert.encode_ext_prefix_tlv()
}

/// Decode an Extended Prefix Opaque LSA body into its advertised
/// (prefix, SID) pairs. TLVs other than Extended Prefix (type 1) are
/// skipped; malformed Extended Prefix TLVs abort the decode (`None`).
/// Extended Prefix Range TLVs (the mapping-server shape) are not
/// surfaced here — use [`decode_ext_prefix_lsa_body_full`].
pub fn decode_ext_prefix_lsa_body(
    body: &[u8],
) -> Option<Vec<(SrPrefixAdvertCore, Option<SrPrefixSidTlv>)>> {
    let mut out = Vec::new();
    for tlv in decode_ext_prefix_lsa_body_full(body)? {
        if let ExtPrefixTlvAdvert::Prefix(core, sid) = tlv {
            out.push((core, sid));
        }
    }
    Some(out)
}

/// One decoded top-level TLV of an Extended Prefix Opaque LSA:
/// either an Extended Prefix TLV (RFC 7684 §2.1) or an Extended
/// Prefix Range TLV (RFC 8665 §4 — the SR Mapping Server carrier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtPrefixTlvAdvert {
    /// Extended Prefix TLV: one prefix descriptor + optional SID.
    Prefix(SrPrefixAdvertCore, Option<SrPrefixSidTlv>),
    /// Extended Prefix Range TLV: one range descriptor + optional SID
    /// (the SID assigns to the *first* prefix of the range).
    Range(SrPrefixRangeCore, Option<SrPrefixSidTlv>),
}

/// The Extended Prefix Range TLV descriptor (RFC 8665 §4) — everything
/// except the sub-TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrPrefixRangeCore {
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Number of prefixes covered by the advertisement (MUST NOT
    /// exceed the prefix's address space, §4).
    pub range_size: u16,
    /// Flags byte: IA (0x80) marks inter-area propagation (§4).
    pub flags: u8,
    /// The base prefix (IPv4 — the AF byte is always 0 for OSPFv2).
    pub prefix: [u8; 4],
}

/// Encode one **Extended Prefix Range TLV** (RFC 8665 §4, type 2 of
/// the Extended Prefix Opaque LSA): Prefix Length, AF, Range Size,
/// Flags, Reserved, Prefix, then sub-TLVs — the Prefix-SID sub-TLV
/// carries the index assigned to the *first* prefix of the range and
/// the M-flag (the advertisement comes from an SR Mapping Server,
/// RFC 8665 §7.1 / RFC 8661 §3.2).
pub fn encode_ext_prefix_range_tlv(range: &SrPrefixRangeCore, sid: &SrPrefixSidTlv) -> Vec<u8> {
    if range.prefix_len > 32 {
        return Vec::new();
    }
    // Value: prefix_len(1) af(1) range_size(2) flags(1) reserved(3)
    //        prefix(4) + sub-TLV (4 + 8).
    let mut value = Vec::with_capacity(12 + 12);
    value.push(range.prefix_len);
    value.push(0); // AF: 0 = IPv4 unicast
    value.extend_from_slice(&range.range_size.to_be_bytes());
    value.push(range.flags);
    value.extend_from_slice(&[0, 0, 0]); // Reserved: zero on transmission
    value.extend_from_slice(&range.prefix);
    // Prefix-SID sub-TLV (RFC 8665 §5), M-flag set by the caller.
    value.extend_from_slice(&SUBTLV_PREFIX_SID.to_be_bytes());
    value.extend_from_slice(&8u16.to_be_bytes());
    value.push(sid.flags);
    value.push(0); // Reserved
    value.push(sid.mt_id);
    value.push(sid.algorithm);
    value.extend_from_slice(&sid.sid.to_be_bytes());
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&TLV_EXT_PREFIX_RANGE.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    out
}

/// Decode one Extended Prefix Range TLV **value** (after the 4-byte
/// TLV header). Returns `None` on truncation, a non-IPv4 AF, or a
/// malformed prefix length; the Prefix-SID sub-TLV is optional.
pub fn decode_ext_prefix_range_tlv_value(
    value: &[u8],
) -> Option<(SrPrefixRangeCore, Option<SrPrefixSidTlv>)> {
    if value.len() < 12 {
        return None;
    }
    let prefix_len = value[0];
    let af = value[1];
    if af != 0 || prefix_len > 32 {
        return None;
    }
    let core = SrPrefixRangeCore {
        prefix_len,
        range_size: u16::from_be_bytes([value[2], value[3]]),
        flags: value[4],
        prefix: [value[8], value[9], value[10], value[11]],
    };
    // Sub-TLVs follow the (always 4-byte-wide) IPv4 prefix.
    let mut sid = None;
    let mut i = 12;
    while i + 4 <= value.len() {
        let st = u16::from_be_bytes([value[i], value[i + 1]]);
        let st_len = u16::from_be_bytes([value[i + 2], value[i + 3]]) as usize;
        i += 4;
        if i + st_len > value.len() {
            return None;
        }
        if st == SUBTLV_PREFIX_SID {
            let parsed = match st_len {
                8 => Some(SrPrefixSidTlv {
                    flags: value[i],
                    mt_id: value[i + 2],
                    algorithm: value[i + 3],
                    sid: u32::from_be_bytes([
                        value[i + 4],
                        value[i + 5],
                        value[i + 6],
                        value[i + 7],
                    ]),
                }),
                7 => Some(SrPrefixSidTlv {
                    flags: value[i],
                    mt_id: value[i + 2],
                    algorithm: value[i + 3],
                    sid: u32::from_be_bytes([0, value[i + 4], value[i + 5], value[i + 6]]),
                }),
                _ => None,
            };
            if parsed.is_some() {
                sid = parsed;
            }
        }
        i += (st_len + 3) & !3;
    }
    Some((core, sid))
}

/// Decode an Extended Prefix Opaque LSA body into every top-level TLV
/// it carries — Extended Prefix (type 1) *and* Extended Prefix Range
/// (type 2) TLVs. Malformed Extended Prefix/Range TLVs abort the
/// decode (`None`); other TLV types are skipped per RFC 8665 §9.
pub fn decode_ext_prefix_lsa_body_full(body: &[u8]) -> Option<Vec<ExtPrefixTlvAdvert>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= body.len() {
        let tlv_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let tlv_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        if i + tlv_len > body.len() {
            return None;
        }
        match tlv_type {
            TLV_EXT_PREFIX => {
                let (core, sid) =
                    SrPrefixAdvert::decode_ext_prefix_tlv_value(&body[i..i + tlv_len])?;
                out.push(ExtPrefixTlvAdvert::Prefix(core, sid));
            }
            TLV_EXT_PREFIX_RANGE => {
                let (core, sid) = decode_ext_prefix_range_tlv_value(&body[i..i + tlv_len])?;
                out.push(ExtPrefixTlvAdvert::Range(core, sid));
            }
            _ => {}
        }
        i += (tlv_len + 3) & !3;
    }
    Some(out)
}

/// Build a complete area-scoped **Extended Prefix Opaque LSA** (LS
/// type 10, Opaque Type 7) carrying one **Extended Prefix Range TLV**
/// — the SR Mapping Server advertisement (RFC 8665 §4/§7.1). The
/// Prefix-SID is emitted with the M-flag set and `sid` as the index
/// of the range's first prefix. The LSA is finalized.
pub fn originate_sr_prefix_range_lsa(
    router_id: u32,
    range: &SrPrefixRangeCore,
    sid: &SrPrefixSidTlv,
    opaque_index: u32,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let body = encode_ext_prefix_range_tlv(range, sid);
    if body.is_empty() {
        return None;
    }
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02 | OPTIONS_O_BIT,
            ls_type: LsaTypeV2::OpaqueAreaLsa as u16,
            link_state_id: opaque_lsa_id(OPAQUE_TYPE_EXT_PREFIX, opaque_index),
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body,
    };
    lsa.finalize();
    Some(lsa)
}

/// Encode the body of the **area-scoped Router Information LSA** with
/// the SR TLVs (RFC 8665 §3): SR-Algorithm (type 8, one byte per
/// algorithm — lr originates algorithm 0, SPF) followed by the
/// SID/Label Range TLV (RFC 8665 §3.2, type 9: 3-octet range size,
/// reserved octet, then the §2.1 SID/Label Sub-TLV carrying the
/// 32-bit first label of the range). `srgb_base` must be a valid
/// MPLS label value (16..=1_048_575) and the range must fit under it.
pub fn encode_ri_sr_lsa_body(srgb_base: u32, srgb_range: u32) -> Option<Vec<u8>> {
    if !(16..=1_048_575).contains(&srgb_base) {
        return None;
    }
    if srgb_range == 0 || srgb_base + srgb_range - 1 > 1_048_575 {
        return None;
    }
    // SR-Algorithm TLV (type 8): one octet per algorithm, value 0.
    let mut out = Vec::with_capacity(8 + 16);
    out.extend_from_slice(&TLV_SR_ALGORITHM.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.push(0); // algorithm 0 = SPF
    out.extend_from_slice(&[0, 0, 0]); // 4-octet alignment
                                       // SID/Label Range TLV (type 9): range size (3 octets) + reserved
                                       // (1), then the SID/Label Sub-TLV (type 1, length 4) with the
                                       // first label of the range as a 32-bit value.
    out.extend_from_slice(&TLV_SRGB.to_be_bytes());
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(&srgb_range.to_be_bytes()[1..4]);
    out.push(0); // reserved
    out.extend_from_slice(&SUBTLV_SID_LABEL.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&srgb_base.to_be_bytes());
    Some(out)
}

/// The SR block a Router Information LSA advertises: algorithm 0 plus
/// the SRGB (base, range).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiSrBlock {
    pub srgb_base: u32,
    pub srgb_range: u32,
}

/// Decode the SR TLVs of a Router Information LSA body. Returns
/// `None` on malformed TLVs; a body without both the SR-Algorithm and
/// the SID/Label Range TLV yields `Ok(None)` (the node is not an SR
/// node — per RFC 8665 §3.2 the advertised range is what makes the
/// node SR-capable).
pub fn decode_ri_sr_lsa_body(body: &[u8]) -> Option<Option<RiSrBlock>> {
    let mut algorithm = false;
    let mut srgb: Option<RiSrBlock> = None;
    let mut i = 0;
    while i + 4 <= body.len() {
        let tlv_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let tlv_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        if i + tlv_len > body.len() {
            return None;
        }
        match tlv_type {
            TLV_SR_ALGORITHM => {
                // At least algorithm 0 present?
                algorithm = body[i..i + tlv_len].contains(&0);
            }
            TLV_SRGB if tlv_len >= 4 => {
                // RFC 8665 §3.2: range size (3 octets) + reserved (1),
                // then sub-TLVs; the SID/Label Sub-TLV (§2.1, type 1)
                // carries the first label — a 4-octet value, or a
                // 3-octet value using the 20 rightmost bits.
                let range = u32::from_be_bytes([0, body[i], body[i + 1], body[i + 2]]);
                let mut j = i + 4;
                while j + 4 <= i + tlv_len {
                    let st = u16::from_be_bytes([body[j], body[j + 1]]);
                    let st_len = u16::from_be_bytes([body[j + 2], body[j + 3]]) as usize;
                    if st == SUBTLV_SID_LABEL {
                        let base = match st_len {
                            4 if j + 8 <= i + tlv_len => u32::from_be_bytes([
                                body[j + 4],
                                body[j + 5],
                                body[j + 6],
                                body[j + 7],
                            ]),
                            3 if j + 7 <= i + tlv_len => {
                                u32::from_be_bytes([0, body[j + 4], body[j + 5], body[j + 6]])
                            }
                            _ => 0,
                        };
                        if base != 0 {
                            srgb = Some(RiSrBlock {
                                srgb_base: base,
                                srgb_range: range,
                            });
                        }
                        break;
                    }
                    j += 4 + ((st_len + 3) & !3);
                }
            }
            _ => {}
        }
        i += (tlv_len + 3) & !3;
    }
    Some(if algorithm && srgb.is_some() {
        srgb
    } else {
        None
    })
}

/// The remote label for a prefix advertised with a global Prefix-SID:
/// the originator's SRGB base + the SID index (RFC 8665 §5 / RFC 8402
/// §3.1.1). `None` when the index falls outside the originator's
/// advertised range (the mapping is unusable) or the SID carries the
/// V flag (absolute/local — the global mapping does not apply).
pub fn remote_label(originator_srgb: &RiSrBlock, sid_tlv: &SrPrefixSidTlv) -> Option<u32> {
    if sid_tlv.flags & (sid_flags::V | sid_flags::L) != 0 {
        return None;
    }
    if sid_tlv.sid >= originator_srgb.srgb_range {
        return None;
    }
    Some(originator_srgb.srgb_base + sid_tlv.sid)
}

/// One link advertised inside an Extended Link Opaque LSA (RFC 7684
/// §3.1): the descriptor the Adj-SID sub-TLVs hang off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrLinkAdvert {
    /// RFC 7684 §3.1 link type — [`link_type::POINT_TO_POINT`] or
    /// [`link_type::TRANSIT`]. Unknown types are preserved verbatim
    /// (their sub-TLVs decode the same way).
    pub link_type: u8,
    /// Link ID: the neighbour's Router ID on a p2p link, the DR's
    /// interface address on a transit network (§3.1 / RFC 2328
    /// §A.4.2).
    pub link_id: [u8; 4],
    /// Link Data: this router's interface address on the link.
    pub link_data: [u8; 4],
}

/// One decoded Adj-SID / LAN Adj-SID sub-TLV (RFC 8665 §6.1 / §6.2).
/// The two shapes differ only by the LAN variant's extra neighbour
/// Router ID; `neighbor_id` is `Some` for LAN Adj-SIDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrAdjSidTlv {
    /// Flags byte — see [`adj_flags`].
    pub flags: u8,
    /// Topology ID (0 = default).
    pub mt_id: u8,
    /// Load-balancing weight (RFC 8402 §2).
    pub weight: u8,
    /// The SID: an absolute label when V/L are set, otherwise an
    /// index into the originator's SRGB.
    pub sid: u32,
    /// LAN Adj-SID only: the Router ID of the neighbour the SID
    /// steers traffic to (RFC 8665 §6.2).
    pub neighbor_id: Option<[u8; 4]>,
}

impl SrAdjSidTlv {
    /// True when this sub-TLV is the LAN shape (carries a neighbour
    /// Router ID).
    pub fn is_lan(&self) -> bool {
        self.neighbor_id.is_some()
    }

    /// Resolve the MPLS label against the originator's SRGB: V/L set
    /// means the SID *is* the label (local significance — Adj-SIDs are
    /// SRLB labels, RFC 8665 §6.1); V/L clear resolves
    /// `srgb_base + index` with the range guard of
    /// [`remote_label`]. `None` when the index falls outside the
    /// advertised range.
    pub fn remote_label(&self, originator_srgb: &RiSrBlock) -> Option<u32> {
        if self.flags & (adj_flags::V | adj_flags::L) != 0 {
            return Some(self.sid);
        }
        if self.sid >= originator_srgb.srgb_range {
            return None;
        }
        Some(originator_srgb.srgb_base + self.sid)
    }

    /// Encode the sub-TLV (RFC 8665 §6.1 for `neighbor_id == None`,
    /// §6.2 for the LAN shape): Flags, Reserved, MT-ID, Weight,
    /// [Neighbour ID,] SID/Index/Label. V/L set emits the 3-octet
    /// label shape (length 7/11 + one pad octet so the value stays
    /// 4-aligned); V/L clear emits the 4-octet index shape
    /// (length 8/12).
    fn encode(&self) -> Vec<u8> {
        let label_shape = self.flags & (adj_flags::V | adj_flags::L) != 0;
        let value_len = if label_shape { 3 } else { 4 };
        let body_len = 4 + self.neighbor_id.map_or(0, |_| 4) + value_len;
        let mut out = Vec::with_capacity(4 + body_len + 3);
        let st = if self.is_lan() {
            SUBTLV_LAN_ADJ_SID
        } else {
            SUBTLV_ADJ_SID
        };
        out.extend_from_slice(&st.to_be_bytes());
        out.extend_from_slice(&(body_len as u16).to_be_bytes());
        out.push(self.flags);
        out.push(0); // Reserved: zero on transmission (RFC 8665 §6.1)
        out.push(self.mt_id);
        out.push(self.weight);
        if let Some(rid) = self.neighbor_id {
            out.extend_from_slice(&rid);
        }
        if label_shape {
            // 3-octet label in the 20 rightmost bits + one pad octet
            // (the length field excludes padding per RFC 7684 §2.3).
            out.extend_from_slice(&self.sid.to_be_bytes()[1..4]);
            out.push(0);
        } else {
            out.extend_from_slice(&self.sid.to_be_bytes());
        }
        out
    }
}

/// Encode one **Extended Link TLV** (RFC 7684 §3.1): Link Type (1),
/// Reserved (3), Link ID (4), Link Data (4), then the adjacency SID
/// sub-TLVs. The TLV length excludes the final 4-alignment padding
/// (RFC 7684 §2.3).
pub fn encode_ext_link_tlv(advert: &SrLinkAdvert, sids: &[SrAdjSidTlv]) -> Vec<u8> {
    let mut value = Vec::with_capacity(12 + sids.iter().map(|s| s.encode().len()).sum::<usize>());
    value.push(advert.link_type);
    value.extend_from_slice(&[0, 0, 0]); // Reserved
    value.extend_from_slice(&advert.link_id);
    value.extend_from_slice(&advert.link_data);
    for sid in sids {
        value.extend_from_slice(&sid.encode());
    }
    // TLV wrapper: length is the unpadded value length; the value is
    // padded so the next TLV (and the LSA length) stays 4-aligned.
    let mut out = Vec::with_capacity(4 + value.len() + 3);
    out.extend_from_slice(&TLV_EXT_LINK.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    let pad = (4 - (value.len() % 4)) % 4;
    out.resize(out.len() + pad, 0);
    out
}

/// Decode one Extended Link TLV **value** (after the 4-byte TLV
/// header) into its descriptor plus the adjacency SID sub-TLVs.
/// Returns `None` on truncation; unknown sub-TLVs are skipped per
/// RFC 8665 §9; Adj-SID sub-TLVs with malformed lengths are ignored
/// (the descriptor still decodes — a link without a usable SID maps
/// to no segment).
pub fn decode_ext_link_tlv_value(value: &[u8]) -> Option<(SrLinkAdvert, Vec<SrAdjSidTlv>)> {
    if value.len() < 12 {
        return None;
    }
    let advert = SrLinkAdvert {
        link_type: value[0],
        link_id: [value[4], value[5], value[6], value[7]],
        link_data: [value[8], value[9], value[10], value[11]],
    };
    let mut sids = Vec::new();
    let mut i = 12;
    while i + 4 <= value.len() {
        let st = u16::from_be_bytes([value[i], value[i + 1]]);
        let st_len = u16::from_be_bytes([value[i + 2], value[i + 3]]) as usize;
        i += 4;
        if i + st_len > value.len() {
            return None;
        }
        let body = &value[i..i + st_len];
        if st == SUBTLV_ADJ_SID || st == SUBTLV_LAN_ADJ_SID {
            // RFC 8665 §6.1: Flags, Reserved, MT-ID, Weight,
            // SID/Index/Label — 4 octets for an index (length 8), 3
            // for a local label (length 7). LAN Adj-SID (§6.2) adds
            // the 4-octet Neighbour ID (lengths 12 / 11). Other
            // lengths are ignored as malformed.
            match (st, st_len) {
                (SUBTLV_ADJ_SID, 8 | 7) if body.len() >= 7 => sids.push(SrAdjSidTlv {
                    flags: body[0],
                    mt_id: body[2],
                    weight: body[3],
                    sid: read_sid_field(&body[4..]),
                    neighbor_id: None,
                }),
                (SUBTLV_LAN_ADJ_SID, 12 | 11) if body.len() >= 11 => sids.push(SrAdjSidTlv {
                    flags: body[0],
                    mt_id: body[2],
                    weight: body[3],
                    sid: read_sid_field(&body[8..]),
                    neighbor_id: Some([body[4], body[5], body[6], body[7]]),
                }),
                _ => {}
            }
        }
        i += (st_len + 3) & !3;
    }
    Some((advert, sids))
}

/// The SID/Index/Label field (RFC 8665 §2.1/§5): 4 bytes for an
/// index, the 3 rightmost of 4 bytes for a label (the field is
/// followed by the sub-TLV's 4-alignment pad).
fn read_sid_field(bytes: &[u8]) -> u32 {
    if bytes.len() >= 4 {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
    }
}

/// Encode the body of an **Extended Link Opaque LSA** (Opaque Type 8):
/// one Extended Link TLV per advertised link, each carrying its
/// adjacency SID sub-TLVs. (lr originates one LSA per interface so a
/// single adjacency change only re-floods that interface's LSA;
/// RFC 7684 §3 allows several TLVs per LSA.)
pub fn encode_ext_link_lsa_body(links: &[(SrLinkAdvert, Vec<SrAdjSidTlv>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (advert, sids) in links {
        out.extend_from_slice(&encode_ext_link_tlv(advert, sids));
    }
    out
}

/// Decode an Extended Link Opaque LSA body into its (link, Adj-SID)
/// pairs. TLVs other than Extended Link (type 1) are skipped;
/// malformed Extended Link TLVs abort the decode (`None`).
pub fn decode_ext_link_lsa_body(body: &[u8]) -> Option<Vec<(SrLinkAdvert, Vec<SrAdjSidTlv>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= body.len() {
        let tlv_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let tlv_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        if i + tlv_len > body.len() {
            return None;
        }
        if tlv_type == TLV_EXT_LINK {
            let parsed = decode_ext_link_tlv_value(&body[i..i + tlv_len])?;
            out.push(parsed);
        }
        i += (tlv_len + 3) & !3;
    }
    Some(out)
}

/// Build a complete area-scoped **Extended Link Opaque LSA** (LS type
/// 10, Opaque Type 8) for one interface's adjacencies. `opaque_index`
/// keys the LSA (the Opaque ID; a stable per-interface slot keeps
/// re-origination idempotent). The LSA is finalized (length + §C.4
/// checksum).
pub fn originate_sr_link_lsa(
    router_id: u32,
    links: &[(SrLinkAdvert, Vec<SrAdjSidTlv>)],
    opaque_index: u32,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    if links.is_empty() {
        return None;
    }
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            // E-bit + O-bit, matching the other SR originators.
            options: 0x02 | OPTIONS_O_BIT,
            ls_type: LsaTypeV2::OpaqueAreaLsa as u16,
            link_state_id: opaque_lsa_id(OPAQUE_TYPE_EXT_LINK, opaque_index),
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body: encode_ext_link_lsa_body(links),
    };
    lsa.finalize();
    Some(lsa)
}

/// Build a complete area-scoped **Extended Prefix Opaque LSA** (LS
/// type 10, Opaque Type 7) for one advertised prefix. `opaque_index`
/// disambiguates several prefix LSAs from the same router (it becomes
/// the Opaque ID; FRR keys its SRDB on (advertising router, opaque
/// ID) pairs, so a stable per-prefix index keeps re-origination
/// idempotent). The LSA is finalized (length + §C.4 checksum).
pub fn originate_sr_prefix_lsa(
    router_id: u32,
    advert: &SrPrefixAdvert,
    opaque_index: u32,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            // E-bit + O-bit, matching the Grace-LSA originator (FRR's
            // opaque LSAs set both).
            options: 0x02 | OPTIONS_O_BIT,
            ls_type: LsaTypeV2::OpaqueAreaLsa as u16,
            link_state_id: opaque_lsa_id(OPAQUE_TYPE_EXT_PREFIX, opaque_index),
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body: encode_ext_prefix_lsa_body(advert),
    };
    lsa.finalize();
    Some(lsa)
}

/// Build a complete area-scoped **Router Information LSA** (LS type
/// 10, Opaque Type 4) with the SR-Algorithm + SRGB TLVs. Opaque ID 0
/// (a router originates at most one RI SR block per area).
pub fn originate_sr_ri_lsa(
    router_id: u32,
    srgb_base: u32,
    srgb_range: u32,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02 | OPTIONS_O_BIT,
            ls_type: LsaTypeV2::OpaqueAreaLsa as u16,
            link_state_id: opaque_lsa_id(OPAQUE_TYPE_RI, 0),
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body: encode_ri_sr_lsa_body(srgb_base, srgb_range)?,
    };
    lsa.finalize();
    Some(lsa)
}

/// Extract the Opaque Type from an Opaque LSA's link_state_id (see
/// [`crate::lsa::grace::unpack_opaque_lsa_id`]).
pub fn sr_opaque_type(lsa: &Lsa) -> u8 {
    (lsa.header.link_state_id >> 24) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_advert() -> SrPrefixAdvert {
        SrPrefixAdvert {
            route_type: 1, // intra-area
            flags: 0x40,   // N-flag: prefix is a node segment
            prefix: [10, 0, 0, 0],
            prefix_len: 24,
            sid_flags: sid_flags::NP,
            sid: 100,
            algorithm: 0,
        }
    }

    #[test]
    fn ext_prefix_tlv_wire_shape_matches_rfc7684_8665() {
        let wire = sample_advert().encode_ext_prefix_tlv();
        // TLV type 1, length 20 (8 descriptor + 4 prefix + 12
        // sub-TLV) — the body is a multiple of 4 without padding.
        assert_eq!(&wire[0..2], &[0, 1]);
        assert_eq!(&wire[2..4], &20u16.to_be_bytes());
        // RFC 7684 §2.1: route_type, prefix_len, af, flags.
        assert_eq!(wire[4], 1);
        assert_eq!(wire[5], 24);
        assert_eq!(wire[6], 0);
        assert_eq!(wire[7], 0x40);
        // Prefix.
        assert_eq!(&wire[8..12], &[10, 0, 0, 0]);
        // Prefix-SID sub-TLV: type 2, len 8.
        assert_eq!(&wire[12..14], &[0, 2]);
        assert_eq!(&wire[14..16], &[0, 8]);
        // RFC 8665 §5: flags, reserved, MT-ID, algorithm, SID/Index(4).
        assert_eq!(wire[16], 0x40); // NP
        assert_eq!(wire[17], 0); // reserved
        assert_eq!(wire[18], 0); // MT-ID
        assert_eq!(wire[19], 0); // algorithm
                                 // SID 100 as a 4-octet index.
        assert_eq!(&wire[20..24], &100u32.to_be_bytes());
        assert_eq!(wire.len(), 24);
    }

    #[test]
    fn ext_prefix_lsa_roundtrip() {
        let wire = encode_ext_prefix_lsa_body(&sample_advert());
        let decoded = decode_ext_prefix_lsa_body(&wire).expect("decode");
        assert_eq!(decoded.len(), 1);
        let (core, sid) = &decoded[0];
        assert_eq!(core.route_type, 1);
        assert_eq!(core.flags, 0x40);
        assert_eq!(core.prefix, [10, 0, 0, 0]);
        assert_eq!(core.prefix_len, 24);
        let sid = sid.as_ref().expect("prefix-sid sub-TLV present");
        assert_eq!(sid.flags, sid_flags::NP);
        assert_eq!(sid.mt_id, 0);
        assert_eq!(sid.algorithm, 0);
        assert_eq!(sid.sid, 100);
    }

    #[test]
    fn ext_prefix_lsa_decode_skips_unknown_subtlvs_and_tlbs() {
        // Extended Prefix TLV with the Prefix-SID sub-TLV followed by
        // an unknown sub-TLV (type 0xBEEF): the SID still decodes, the
        // unknown one is skipped per RFC 8665 §9. Value length: 8
        // (descriptor + prefix) + 12 (SID sub-TLV) + 8 (unknown, 1
        // octet value padded to 4) = 28.
        let mut wire = Vec::new();
        wire.extend_from_slice(&TLV_EXT_PREFIX.to_be_bytes());
        wire.extend_from_slice(&28u16.to_be_bytes());
        wire.extend_from_slice(&[1, 32, 0, 0]);
        wire.extend_from_slice(&[192, 0, 2, 9]);
        wire.extend_from_slice(&SUBTLV_PREFIX_SID.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 200]);
        wire.extend_from_slice(&[0xBE, 0xEF, 0, 1, 0xAA, 0, 0, 0]);
        let decoded = decode_ext_prefix_lsa_body(&wire).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0.prefix, [192, 0, 2, 9]);
        assert_eq!(decoded[0].1.as_ref().expect("sid").sid, 200);
    }

    #[test]
    fn ext_prefix_lsa_decode_local_label_shape() {
        // RFC 8665 §5 length-7 shape: a 3-octet local label (V/L set).
        let mut wire = Vec::new();
        wire.extend_from_slice(&TLV_EXT_PREFIX.to_be_bytes());
        wire.extend_from_slice(&20u16.to_be_bytes());
        wire.extend_from_slice(&[1, 32, 0, 0]);
        wire.extend_from_slice(&[192, 0, 2, 9]);
        wire.extend_from_slice(&SUBTLV_PREFIX_SID.to_be_bytes());
        wire.extend_from_slice(&7u16.to_be_bytes());
        wire.extend_from_slice(&[sid_flags::V | sid_flags::L, 0, 0, 0]);
        wire.extend_from_slice(&[0x00, 0x01, 0x02, 0]); // label + pad
        let decoded = decode_ext_prefix_lsa_body(&wire).expect("decode");
        let sid = decoded[0].1.as_ref().expect("sid");
        assert_eq!(sid.sid, 0x000102);
    }

    #[test]
    fn ext_prefix_lsa_decode_without_prefix_sid_subtlv_yields_none_sid() {
        // RFC 7684 shape without any sub-TLV: the prefix descriptor
        // alone is valid; no SID means no label mapping.
        let mut wire = Vec::new();
        wire.extend_from_slice(&TLV_EXT_PREFIX.to_be_bytes());
        wire.extend_from_slice(&8u16.to_be_bytes());
        wire.extend_from_slice(&[1, 24, 0, 0x40, 10, 0, 0, 0]);
        let decoded = decode_ext_prefix_lsa_body(&wire).expect("decode");
        assert!(decoded[0].1.is_none());
    }

    #[test]
    fn ri_sr_lsa_wire_shape_matches_rfc8665() {
        let wire = encode_ri_sr_lsa_body(16_000, 8_000).expect("encode");
        // SR-Algorithm TLV: type 8, len 1, value 0, 3 padding.
        assert_eq!(&wire[0..2], &[0, 8]);
        assert_eq!(&wire[2..4], &[0, 1]);
        assert_eq!(wire[4], 0);
        assert_eq!(&wire[5..8], &[0, 0, 0]);
        // SID/Label Range TLV: type 9, len 12 — range size (3),
        // reserved (1), SID/Label sub-TLV (type 1, len 4, base).
        assert_eq!(&wire[8..10], &[0, 9]);
        assert_eq!(&wire[10..12], &12u16.to_be_bytes());
        assert_eq!(&wire[12..15], &8_000u32.to_be_bytes()[1..4]);
        assert_eq!(wire[15], 0); // reserved
        assert_eq!(&wire[16..18], &[0, 1]);
        assert_eq!(&wire[18..20], &4u16.to_be_bytes());
        assert_eq!(&wire[20..24], &16_000u32.to_be_bytes());
        assert_eq!(wire.len(), 24);
    }

    #[test]
    fn ri_sr_lsa_roundtrip() {
        let wire = encode_ri_sr_lsa_body(16_000, 8_000).expect("encode");
        let block = decode_ri_sr_lsa_body(&wire)
            .expect("decode")
            .expect("SR node");
        assert_eq!(
            block,
            RiSrBlock {
                srgb_base: 16_000,
                srgb_range: 8_000
            }
        );
    }

    #[test]
    fn ri_sr_lsa_without_srgb_is_not_an_sr_node() {
        // Only the algorithm TLV: no SRGB → Ok(None).
        let mut wire = Vec::new();
        wire.extend_from_slice(&TLV_SR_ALGORITHM.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.push(0);
        wire.extend_from_slice(&[0, 0, 0]);
        assert_eq!(decode_ri_sr_lsa_body(&wire), Some(None));
    }

    #[test]
    fn ri_sr_lsa_rejects_invalid_srgb() {
        // Base below the label-space floor.
        assert!(encode_ri_sr_lsa_body(15, 8_000).is_none());
        // Range overflows the 20-bit label space.
        assert!(encode_ri_sr_lsa_body(1_048_500, 8_000).is_none());
    }

    #[test]
    fn remote_label_math() {
        let srgb = RiSrBlock {
            srgb_base: 16_000,
            srgb_range: 8_000,
        };
        let sid = SrPrefixSidTlv {
            flags: 0,
            mt_id: 0,
            algorithm: 0,
            sid: 100,
        };
        assert_eq!(remote_label(&srgb, &sid), Some(16_100));
        // Index out of the SRGB range: discarded.
        let sid = SrPrefixSidTlv {
            flags: 0,
            mt_id: 0,
            algorithm: 0,
            sid: 8_001,
        };
        assert_eq!(remote_label(&srgb, &sid), None);
        // V/L flagged (absolute/local): not a global index mapping.
        let sid = SrPrefixSidTlv {
            flags: sid_flags::V | sid_flags::L,
            mt_id: 0,
            algorithm: 0,
            sid: 100,
        };
        assert_eq!(remote_label(&srgb, &sid), None);
    }

    #[test]
    fn originate_prefix_lsa_is_finalized_area_opaque_type7() {
        let lsa =
            originate_sr_prefix_lsa(0x0a00_0001, &sample_advert(), 0, None).expect("originate");
        assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueAreaLsa as u16);
        assert_eq!(
            (lsa.header.link_state_id >> 24) as u8,
            OPAQUE_TYPE_EXT_PREFIX
        );
        assert_eq!(lsa.header.options, 0x02 | OPTIONS_O_BIT);
        assert_eq!(lsa.header.advertising_router, 0x0a00_0001);
        assert!(lsa.header.length >= LsaHeader::LEN as u16);
        assert!(lsa.checksum_ok());
        // The body decodes back to the advertised prefix.
        let decoded = decode_ext_prefix_lsa_body(&lsa.body).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0.prefix, [10, 0, 0, 0]);
        assert_eq!(decoded[0].1.as_ref().expect("sid").sid, 100);
    }

    #[test]
    fn originate_ri_lsa_is_finalized_area_opaque_type4() {
        let lsa = originate_sr_ri_lsa(0x0a00_0001, 16_000, 8_000, None).expect("originate");
        assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueAreaLsa as u16);
        assert_eq!((lsa.header.link_state_id >> 24) as u8, OPAQUE_TYPE_RI);
        assert!(lsa.checksum_ok());
        let block = decode_ri_sr_lsa_body(&lsa.body)
            .expect("decode")
            .expect("SR block");
        assert_eq!(block.srgb_base, 16_000);
        assert_eq!(block.srgb_range, 8_000);
    }

    #[test]
    fn sequence_handling_matches_grace_lsa_originator() {
        // First origination starts at INITIAL_SEQUENCE_NUMBER; a
        // refresh advances by one.
        let first = originate_sr_prefix_lsa(1, &sample_advert(), 0, None).expect("first");
        let next = originate_sr_prefix_lsa(
            1,
            &sample_advert(),
            0,
            Some(first.header.ls_sequence_number),
        )
        .expect("next");
        assert_eq!(
            next.header.ls_sequence_number,
            first.header.ls_sequence_number + 1
        );
        // Sequence exhaustion returns None (§12.1.2).
        assert!(
            originate_sr_prefix_lsa(1, &sample_advert(), 0, Some(MAX_SEQUENCE_NUMBER)).is_none()
        );
        assert!(originate_sr_ri_lsa(1, 16_000, 8_000, Some(MAX_SEQUENCE_NUMBER)).is_none());
    }

    // -------------------------------------------------------------
    // RFC 8665 §6: Adj-SID / LAN Adj-SID sub-TLVs + Extended Link LSA
    // -------------------------------------------------------------

    /// A p2p link to neighbour 2.2.2.2 over 10.0.0.1 carrying one
    /// local (V/L) adjacency SID 24001 — the shape lr originates.
    fn sample_link() -> (SrLinkAdvert, Vec<SrAdjSidTlv>) {
        (
            SrLinkAdvert {
                link_type: link_type::POINT_TO_POINT,
                link_id: [2, 2, 2, 2],
                link_data: [10, 0, 0, 1],
            },
            vec![SrAdjSidTlv {
                flags: adj_flags::V | adj_flags::L | adj_flags::P,
                mt_id: 0,
                weight: 0,
                sid: 24001,
                neighbor_id: None,
            }],
        )
    }

    #[test]
    fn adj_sid_subtlv_wire_shape_matches_rfc8665_6_1() {
        let (advert, sids) = sample_link();
        let wire = encode_ext_link_tlv(&advert, &sids);
        // TLV type 1, unpadded length 24: 12 descriptor + 12 sub-TLV
        // (4 header + 8 body: flags, rsvd, mt-id, weight, 3-octet
        // label + 1 pad — the length field excludes the pad,
        // RFC 7684 §2.3).
        assert_eq!(&wire[0..2], &[0, 1]);
        assert_eq!(&wire[2..4], &24u16.to_be_bytes());
        // RFC 7684 §3.1: link_type, reserved(3), link_id, link_data.
        assert_eq!(wire[4], link_type::POINT_TO_POINT);
        assert_eq!(&wire[5..8], &[0, 0, 0]);
        assert_eq!(&wire[8..12], &[2, 2, 2, 2]);
        assert_eq!(&wire[12..16], &[10, 0, 0, 1]);
        // Adj-SID sub-TLV: type 2, length 7 (3-octet label shape).
        assert_eq!(&wire[16..18], &[0, 2]);
        assert_eq!(&wire[18..20], &7u16.to_be_bytes());
        // RFC 8665 §6.1: flags (V|L|P), reserved, MT-ID, weight,
        // SID/Index/Label (3 octets) + pad.
        assert_eq!(wire[20], adj_flags::V | adj_flags::L | adj_flags::P);
        assert_eq!(wire[21], 0); // reserved
        assert_eq!(wire[22], 0); // MT-ID
        assert_eq!(wire[23], 0); // weight
        assert_eq!(&wire[24..27], &24001u32.to_be_bytes()[1..4]);
        assert_eq!(wire[27], 0); // 4-alignment pad
                                 // The TLV is padded to a 4-octet multiple.
        assert_eq!(wire.len(), 28);
    }

    #[test]
    fn adj_sid_subtlv_index_shape_is_length_8() {
        // V/L clear: the 4-octet global index shape (RFC 8665 §6.1).
        let (advert, mut sids) = sample_link();
        sids[0].flags = adj_flags::P;
        let wire = encode_ext_link_tlv(&advert, &sids);
        assert_eq!(&wire[18..20], &8u16.to_be_bytes());
        assert_eq!(wire[20], adj_flags::P);
        assert_eq!(&wire[24..28], &24001u32.to_be_bytes());
        assert_eq!(wire.len(), 28); // no padding needed
    }

    #[test]
    fn lan_adj_sid_subtlv_wire_shape_matches_rfc8665_6_2() {
        let (advert, _) = sample_link();
        let lan = SrAdjSidTlv {
            flags: adj_flags::V | adj_flags::L | adj_flags::P,
            mt_id: 0,
            weight: 0,
            sid: 24002,
            neighbor_id: Some([3, 3, 3, 3]),
        };
        let wire = encode_ext_link_tlv(&advert, &[lan]);
        // LAN sub-TLV: type 3, length 11 (label shape + neighbour ID).
        assert_eq!(&wire[16..18], &[0, 3]);
        assert_eq!(&wire[18..20], &11u16.to_be_bytes());
        assert_eq!(&wire[24..28], &[3, 3, 3, 3]); // neighbour router id
        assert_eq!(&wire[28..31], &24002u32.to_be_bytes()[1..4]);
        assert_eq!(wire[31], 0); // pad
        assert_eq!(wire.len(), 32);
    }

    #[test]
    fn ext_link_lsa_roundtrip() {
        let (advert, sids) = sample_link();
        let wire = encode_ext_link_lsa_body(&[(advert, sids)]);
        let decoded = decode_ext_link_lsa_body(&wire).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, sample_link().0);
        assert_eq!(decoded[0].1.len(), 1);
        let sid = &decoded[0].1[0];
        assert_eq!(sid.flags, adj_flags::V | adj_flags::L | adj_flags::P);
        assert_eq!(sid.sid, 24001);
        assert_eq!(sid.neighbor_id, None);
        assert!(!sid.is_lan());
        // The LSA body is a 4-octet multiple (RFC 2328 LSA shape).
        assert_eq!(wire.len() % 4, 0);
    }

    #[test]
    fn ext_link_lsa_decode_accepts_index_and_label_lengths() {
        // FRR walks sub-TLVs with a 4-rounded body size: both the
        // index shape (length 8) and the label shape (length 7) must
        // decode, with the label read from the 20 rightmost bits.
        // Label shape: type 2, length 7.
        let mut value = Vec::new();
        value.extend_from_slice(&[link_type::POINT_TO_POINT, 0, 0, 0]);
        value.extend_from_slice(&[2, 2, 2, 2]);
        value.extend_from_slice(&[10, 0, 0, 1]);
        value.extend_from_slice(&SUBTLV_ADJ_SID.to_be_bytes());
        value.extend_from_slice(&7u16.to_be_bytes());
        value.extend_from_slice(&[adj_flags::V | adj_flags::L, 0, 0, 0]);
        value.extend_from_slice(&[0x00, 0x5D, 0xC1, 0]); // 24001 + pad
        let decoded = decode_ext_link_tlv_value(&value).expect("decode");
        assert_eq!(decoded.1.len(), 1);
        assert_eq!(decoded.1[0].sid, 24001);
        assert_eq!(decoded.1[0].flags, adj_flags::V | adj_flags::L);
        assert_eq!(decoded.1[0].neighbor_id, None);
    }

    #[test]
    fn ext_link_lsa_decode_skips_unknown_subtlvs() {
        // An Adj-SID followed by an unknown sub-TLV (type 0xBEEF):
        // the SID still decodes, the unknown one is skipped per
        // RFC 8665 §9.
        let mut value = Vec::new();
        // 12 descriptor + 12 (padded label sub-TLV) + 8 unknown.
        value.extend_from_slice(&[link_type::POINT_TO_POINT, 0, 0, 0]);
        value.extend_from_slice(&[2, 2, 2, 2]);
        value.extend_from_slice(&[10, 0, 0, 1]);
        value.extend_from_slice(&SUBTLV_ADJ_SID.to_be_bytes());
        value.extend_from_slice(&7u16.to_be_bytes());
        value.extend_from_slice(&[adj_flags::V | adj_flags::L, 0, 0, 0]);
        value.extend_from_slice(&[0x00, 0x5D, 0xC1, 0]); // 24001 + pad
        value.extend_from_slice(&[0xBE, 0xEF, 0, 1, 0xAA, 0, 0, 0]);
        let decoded = decode_ext_link_tlv_value(&value).expect("decode");
        assert_eq!(decoded.1.len(), 1);
        assert_eq!(decoded.1[0].sid, 24001);
    }

    #[test]
    fn ext_link_lsa_decode_lan_shape_roundtrip() {
        let (advert, _) = sample_link();
        let lan = SrAdjSidTlv {
            flags: adj_flags::P,
            mt_id: 0,
            weight: 5,
            sid: 24002,
            neighbor_id: Some([3, 3, 3, 3]),
        };
        let wire = encode_ext_link_lsa_body(&[(advert, vec![lan])]);
        let decoded = decode_ext_link_lsa_body(&wire).expect("decode");
        assert_eq!(decoded[0].1.len(), 1);
        let sid = &decoded[0].1[0];
        assert!(sid.is_lan());
        assert_eq!(sid.neighbor_id, Some([3, 3, 3, 3]));
        assert_eq!(sid.weight, 5);
        assert_eq!(sid.sid, 24002); // V/L clear: index preserved verbatim
    }

    #[test]
    fn ext_link_lsa_decode_malformed_length_aborts() {
        // A TLV length running past the body aborts the walk.
        let mut wire = Vec::new();
        wire.extend_from_slice(&TLV_EXT_LINK.to_be_bytes());
        wire.extend_from_slice(&100u16.to_be_bytes()); // > actual body
        wire.extend_from_slice(&[link_type::POINT_TO_POINT, 0, 0, 0]);
        assert!(decode_ext_link_lsa_body(&wire).is_none());
    }

    #[test]
    fn originate_link_lsa_is_finalized_area_opaque_type8() {
        let (advert, sids) = sample_link();
        let lsa =
            originate_sr_link_lsa(0x0a00_0001, &[(advert, sids)], 1, None).expect("originate");
        assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueAreaLsa as u16);
        assert_eq!((lsa.header.link_state_id >> 24) as u8, OPAQUE_TYPE_EXT_LINK);
        assert_eq!(lsa.header.options, 0x02 | OPTIONS_O_BIT);
        assert!(lsa.header.length.is_multiple_of(4));
        assert!(lsa.checksum_ok());
        let decoded = decode_ext_link_lsa_body(&lsa.body).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0.link_id, [2, 2, 2, 2]);
        assert_eq!(decoded[0].1[0].sid, 24001);
        // An empty link list is never originated.
        assert!(originate_sr_link_lsa(1, &[], 2, None).is_none());
        // Sequence exhaustion returns None (§12.1.2).
        assert!(originate_sr_link_lsa(1, &[sample_link()], 2, Some(MAX_SEQUENCE_NUMBER)).is_none());
    }

    #[test]
    fn adj_sid_remote_label_resolves_local_and_global_shapes() {
        let srgb = RiSrBlock {
            srgb_base: 16_000,
            srgb_range: 8_000,
        };
        // V/L set: the SID *is* the absolute label (SRLB, local).
        let local = SrAdjSidTlv {
            flags: adj_flags::V | adj_flags::L,
            mt_id: 0,
            weight: 0,
            sid: 24001,
            neighbor_id: None,
        };
        assert_eq!(local.remote_label(&srgb), Some(24001));
        // V/L clear: index into the originator's SRGB.
        let global = SrAdjSidTlv {
            flags: 0,
            mt_id: 0,
            weight: 0,
            sid: 100,
            neighbor_id: None,
        };
        assert_eq!(global.remote_label(&srgb), Some(16_100));
        // Index outside the advertised range: discarded.
        let out_of_range = SrAdjSidTlv {
            flags: 0,
            mt_id: 0,
            weight: 0,
            sid: 8_001,
            neighbor_id: None,
        };
        assert_eq!(out_of_range.remote_label(&srgb), None);
    }

    // -------------------------------------------------------------
    // RFC 8665 §4: Extended Prefix Range TLV (SR Mapping Server)
    // -------------------------------------------------------------

    /// A mapping-server range: prefixes 10.77.0.0/24 .. 10.77.0.3/24
    /// (range size 4), first index 500, M-flag set.
    fn sample_range() -> (SrPrefixRangeCore, SrPrefixSidTlv) {
        (
            SrPrefixRangeCore {
                prefix_len: 24,
                range_size: 4,
                flags: 0x00,
                prefix: [10, 77, 0, 0],
            },
            SrPrefixSidTlv {
                flags: sid_flags::M | sid_flags::NP,
                mt_id: 0,
                algorithm: 0,
                sid: 500,
            },
        )
    }

    #[test]
    fn ext_prefix_range_tlv_wire_shape_matches_rfc8665_4() {
        let (range, sid) = sample_range();
        let wire = encode_ext_prefix_range_tlv(&range, &sid);
        // TLV type 2 (the Extended Prefix LSA TLV registry), value
        // length 24: 12 descriptor + 12 sub-TLV.
        assert_eq!(&wire[0..2], &[0, 2]);
        assert_eq!(&wire[2..4], &24u16.to_be_bytes());
        // RFC 8665 §4: prefix_len, af, range_size(2), flags,
        // reserved(3), prefix.
        assert_eq!(wire[4], 24);
        assert_eq!(wire[5], 0); // AF IPv4 unicast
        assert_eq!(&wire[6..8], &4u16.to_be_bytes());
        assert_eq!(wire[8], 0); // IA clear
        assert_eq!(&wire[9..12], &[0, 0, 0]); // reserved
        assert_eq!(&wire[12..16], &[10, 77, 0, 0]);
        // Prefix-SID sub-TLV: type 2, length 8.
        assert_eq!(&wire[16..18], &[0, 2]);
        assert_eq!(&wire[18..20], &8u16.to_be_bytes());
        // M-flag + NP set, algorithm 0, index 500 (first prefix).
        assert_eq!(wire[20], sid_flags::M | sid_flags::NP);
        assert_eq!(wire[21], 0);
        assert_eq!(wire[22], 0); // MT-ID
        assert_eq!(wire[23], 0); // algorithm
        assert_eq!(&wire[24..28], &500u32.to_be_bytes());
        assert_eq!(wire.len(), 28);
    }

    #[test]
    fn ext_prefix_range_tlv_roundtrip_and_full_decode() {
        let (range, sid) = sample_range();
        let wire = encode_ext_prefix_range_tlv(&range, &sid);
        let (core, decoded_sid) = decode_ext_prefix_range_tlv_value(&wire[4..]).expect("decode");
        assert_eq!(core, range);
        assert_eq!(decoded_sid, Some(sid));
        // The full decode distinguishes the range shape from the
        // prefix shape.
        let tlvs = decode_ext_prefix_lsa_body_full(&wire).expect("decode");
        assert_eq!(tlvs.len(), 1);
        match &tlvs[0] {
            ExtPrefixTlvAdvert::Range(core, Some(sid)) => {
                assert_eq!(core.range_size, 4);
                assert_eq!(sid.flags & sid_flags::M, sid_flags::M);
                assert_eq!(sid.sid, 500);
            }
            other => panic!("expected Range advert, got {other:?}"),
        }
        // The plain prefix decode skips range TLVs (documented
        // behaviour — mapping-server entries need the full walk).
        assert!(decode_ext_prefix_lsa_body(&wire)
            .expect("decode")
            .is_empty());
    }

    #[test]
    fn originate_prefix_range_lsa_is_finalized_opaque_type7() {
        let (range, sid) = sample_range();
        let lsa =
            originate_sr_prefix_range_lsa(0x0b00_0001, &range, &sid, 21, None).expect("originate");
        assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueAreaLsa as u16);
        assert_eq!(
            (lsa.header.link_state_id >> 24) as u8,
            OPAQUE_TYPE_EXT_PREFIX
        );
        assert!(lsa.header.length.is_multiple_of(4));
        assert!(lsa.checksum_ok());
        let tlvs = decode_ext_prefix_lsa_body_full(&lsa.body).expect("decode");
        assert_eq!(tlvs.len(), 1);
        assert!(matches!(tlvs[0], ExtPrefixTlvAdvert::Range(_, Some(_))));
        // Malformed prefix length never originates.
        let bad = SrPrefixRangeCore {
            prefix_len: 40,
            ..range
        };
        assert!(originate_sr_prefix_range_lsa(1, &bad, &sid, 22, None).is_none());
        // Sequence exhaustion returns None (§12.1.2).
        assert!(
            originate_sr_prefix_range_lsa(1, &range, &sid, 23, Some(MAX_SEQUENCE_NUMBER)).is_none()
        );
    }
}
