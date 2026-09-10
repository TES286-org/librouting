//! OSPFv2 Segment Routing extensions — RFC 8665 (OSPF Extensions for
//! Segment Routing), riding the RFC 7684 Extended Prefix Opaque LSA and
//! the RFC 4970 Router Information LSA.
//!
//! Three wire shapes live here:
//!
//! 1. **Extended Prefix Opaque LSA** (RFC 7684 §2, area-scoped:
//!    LS type 10 with Opaque Type 7): the body is a sequence of TLVs,
//!    each **Extended Prefix TLV** (RFC 7684 §2.1, type 1) describing
//!    one prefix — Route Type, Prefix Length, AF, Flags, Address —
//!    plus sub-TLVs.
//! 2. **Prefix-SID sub-TLV** (RFC 8665 §5, type 2 inside the Extended
//!    Prefix TLV): Flags (NP/M/E/V/L), Reserved, MT-ID, Algorithm and
//!    the SID/Index/Label field — a 4-octet index when V/L are clear
//!    (the only shape this crate originates), a 3-octet local label
//!    when V/L are set.
//! 3. **Router Information LSA SR TLVs** (RFC 4970 carrier + RFC 8665
//!    §3, area-scoped RI Opaque LSA with Opaque Type 4): the
//!    **SR-Algorithm TLV** (RFC 8665 §3.1, type 8) and the **SID/Label
//!    Range TLV** (RFC 8665 §3.2, type 9 — 3-octet range size,
//!    reserved, then the §2.1 SID/Label Sub-TLV with the first label).
//!
//! A remote node's label for an advertised prefix is `first_label +
//! sid_index` (RFC 8665 §5 / RFC 8402 §3.1.1; the index must fall
//! inside the originator's advertised range).
//!
//! All TLVs are padded to four-octet alignment (RFC 7684 §2.3); the
//! shapes emitted here are naturally aligned.

use crate::abr::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::lsa::grace::{opaque_lsa_id, OPTIONS_O_BIT};
use crate::lsa::{Lsa, LsaHeader, LsaTypeV2};

/// Opaque Type for the Extended Prefix Opaque LSA (RFC 7684 §2).
pub const OPAQUE_TYPE_EXT_PREFIX: u8 = 7;
/// Opaque Type for the Router Information LSA (RFC 4970 §2.3).
pub const OPAQUE_TYPE_RI: u8 = 4;

/// Extended Prefix TLV type (RFC 7684 §2.1).
pub const TLV_EXT_PREFIX: u16 = 1;
/// Prefix-SID sub-TLV type (RFC 8665 §5).
pub const SUBTLV_PREFIX_SID: u16 = 2;
/// SR-Algorithm TLV type (RFC 8665 §3.1).
pub const TLV_SR_ALGORITHM: u16 = 8;
/// SID/Label Range TLV type (RFC 8665 §3.2).
pub const TLV_SRGB: u16 = 9;
/// SID/Label Sub-TLV type (RFC 8665 §2.1), carried by the SID/Label
/// Range TLV.
pub const SUBTLV_SID_LABEL: u16 = 1;

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
pub fn decode_ext_prefix_lsa_body(
    body: &[u8],
) -> Option<Vec<(SrPrefixAdvertCore, Option<SrPrefixSidTlv>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= body.len() {
        let tlv_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let tlv_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        i += 4;
        if i + tlv_len > body.len() {
            return None;
        }
        if tlv_type == TLV_EXT_PREFIX {
            let parsed = SrPrefixAdvert::decode_ext_prefix_tlv_value(&body[i..i + tlv_len])?;
            out.push(parsed);
        }
        i += (tlv_len + 3) & !3;
    }
    Some(out)
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
}
