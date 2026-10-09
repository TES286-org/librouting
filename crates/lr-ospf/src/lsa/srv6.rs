//! OSPFv3 Segment Routing over IPv6 (SRv6) extensions — RFC 9513.
//!
//! Wire shapes implemented here (all verified against the RFC diagrams
//! byte-for-byte; see the tests at the bottom of this file):
//!
//! 1. **SRv6 Capabilities TLV** (RFC 9513 §2, type 20): an optional
//!    top-level TLV of the OSPFv3 **Router Information LSA** (RFC 7770
//!    §2.2, function code 12) that MUST be advertised once by an
//!    SRv6-enabled router, area-scoped. Carries the 16-bit Flags field
//!    with the O-flag (bit 1, RFC 9259 OAM processing) and no sub-TLVs.
//!    The RI LSA also carries the **SR-Algorithm TLV** (RFC 8665 §3.1,
//!    type 8 — shared with the OSPFv2 RI carrier, see [`crate::lsa::sr`])
//!    and the **Node MSD TLV** (RFC 8476 §2, type 12) with the SRv6 MSD
//!    types from the shared "IGP MSD-Types" registry (RFC 9352 §4:
//!    41 SRH Max SL, 42 SRH Max End Pop, 44 SRH Max H.encaps, 45 SRH Max
//!    End D).
//! 2. **SRv6 Locator LSA** (RFC 9513 §7, function code 42, U-bit set):
//!    a new LSA type (distinct from the RFC 8362 Extended Prefix LSAs)
//!    whose body is a sequence of RFC 3630-format TLVs. The flooding
//!    scope follows the S1/S2 bits; area scope is REQUIRED for the
//!    capabilities-adjacent locator advertisement path and is the only
//!    scope this module originates.
//! 3. **SRv6 Locator TLV** (RFC 9513 §7.1, type 1): Route Type
//!    (1 intra-area … 6 NSSA-2 — any other value ignores the TLV),
//!    Algorithm, Locator Length (1-128), PrefixOptions (RFC 5340 §A.4.1
//!    bits extended by the §6 **AC-bit** 0x80 for anycast), Metric
//!    (0xFFFFFFFF = unreachable) and the locator prefix itself in the
//!    RFC 5340 §A.4.1 "fewest 32-bit words" encoding, followed by
//!    sub-TLVs.
//! 4. **SRv6 End SID sub-TLV** (RFC 9513 §8, type 1 of the Locator
//!    TLV): Flags (none defined), the RFC 8986 Endpoint Behavior code
//!    point and the 128-bit SID, plus optional sub-TLVs — notably the
//!    **SRv6 SID Structure sub-TLV** (§10, type 10 in the Locator LSA
//!    sub-TLV registry, type 30 in the Extended-LSA registry):
//!    LB/LN/Function/Argument lengths in bits, `Length` MUST be 4, the
//!    four lengths MUST sum to ≤ 128 and the sub-TLV MUST NOT repeat
//!    within its parent — violations ignore the parent.
//!
//! Reception rules that live here as codec-level contracts (the
//! database projection in [`crate::srv6db`] layers the cross-LSA rules
//! on top): unknown TLV/sub-TLV types are skipped (RFC 3630 convention);
//! a locator with an unsupported Route Type, a locator length above 128,
//! a SID Structure violation or a duplicate Structure sub-TLV is
//! ignored wholesale.
//!
//! Slice scope note: the End.X / LAN End.X SID sub-TLVs (RFC 9513 §9.1/
//! §9.2, types 31/32 of the "OSPFv3 Extended-LSA Sub-TLVs" registry)
//! ride the RFC 8362 E-Router-Link TLV's sub-TLV region —
//! [`Srv6EndXSidSubTlv`] / [`Srv6LanEndXSidSubTlv`] and the walkers
//! below; the locator + End SID surface is the reachability core.

use crate::abr::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::lsa::v3::V3Prefix;
use crate::lsa::{Lsa, LsaHeader};

/// OSPFv3 Router Information LSA (RFC 7770 §2.2): function code 12,
/// U-bit set, area-scoped flooding (§2.2 — "the U bit will be set";
/// RFC 9513 §2 requires area scope for the SRv6 Capabilities TLV).
/// The Link State ID is the Instance ID; instance 0 is the norm.
pub const LS_TYPE_V3_ROUTER_INFORMATION: u16 = 0xA00C;
/// SRv6 Locator LSA (RFC 9513 §7): function code 42, U-bit set,
/// area-scoped (§5 locators may use any scope; area is the scope this
/// crate originates and the §2/§7.1 preference scope for receivers).
pub const LS_TYPE_SRV6_LOCATOR: u16 = 0xA02A;

/// Router Information TLV: SRv6 Capabilities (RFC 9513 §2, "OSPF
/// Router Information (RI) TLVs" registry).
pub const RI_TLV_SRV6_CAPABILITIES: u16 = 20;
/// Router Information TLV: Node MSD (RFC 8476 §2) — the (MSD-Type,
/// MSD-Value) pairs, shared with OSPFv2.
pub const RI_TLV_NODE_MSD: u16 = 12;
/// Router Information TLV: SR-Algorithm (RFC 8665 §3.1) — the same
/// type value the OSPFv2 carrier uses ([`crate::lsa::sr::TLV_SR_ALGORITHM`];
/// re-declared here so the v3 module reads self-contained).
pub const RI_TLV_SR_ALGORITHM: u16 = 8;

/// SRv6 Capabilities TLV flag (RFC 9513 §2, IANA "OSPFv3 SRv6
/// Capabilities TLV Flags"): the router supports the SRH O-flag
/// (RFC 9259). Bit 1 of the 16-bit Flags field.
pub const SRV6_CAP_O_FLAG: u16 = 0x0002;

/// SRv6 Locator LSA top-level TLV: SRv6 Locator (RFC 9513 §7.1,
/// "OSPFv3 SRv6 Locator LSA TLVs" registry).
pub const LOCATOR_TLV_SRV6_LOCATOR: u16 = 1;
/// SRv6 Locator LSA sub-TLVs (RFC 9513 §13.9, "OSPFv3 SRv6 Locator LSA
/// Sub-TLVs" registry — the numbering applies at any nesting depth).
/// SRv6 End SID (§8).
pub const LOCATOR_SUBTLV_END_SID: u16 = 1;
/// IPv6-Forwarding-Address (RFC 8362 §4.2) — 16 octets; relevant for
/// externally propagated locators.
pub const LOCATOR_SUBTLV_IPV6_FWD_ADDR: u16 = 2;
/// Route-Tag (RFC 8362 §4.3) — 4 octets.
pub const LOCATOR_SUBTLV_ROUTE_TAG: u16 = 3;
/// Prefix Source OSPF Router-ID (RFC 9084) — parsed by a later slice
/// (matters for external locator propagation, like the forwarding
/// address it accompanies).
pub const LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ID: u16 = 4;
/// Prefix Source Router Address (RFC 9084) — later slice, see above.
pub const LOCATOR_SUBTLV_PREFIX_SRC_ROUTER_ADDR: u16 = 5;
/// SRv6 SID Structure (§10) in the Locator LSA sub-TLV registry.
pub const LOCATOR_SUBTLV_SID_STRUCTURE: u16 = 10;
/// SRv6 SID Structure (§10) in the "OSPFv3 Extended-LSA Sub-TLVs"
/// registry — the value the sub-TLV carries when it rides the End.X
/// sub-TLVs of the E-Router-Link TLV (RFC 9513 §13.7; later slice).
pub const EXT_SUBTLV_SID_STRUCTURE: u16 = 30;

/// Locator route types (RFC 9513 §7.1). Any other value ignores the
/// whole Locator TLV on receipt.
pub mod locator_route_type {
    /// Intra-area (the only route type whose reachability this crate
    /// computes today — inter-area/external locator propagation rides
    /// the v3 0x2003/0x4005 calculation, a later slice).
    pub const INTRA_AREA: u8 = 1;
    /// Inter-area.
    pub const INTER_AREA: u8 = 2;
    /// AS external type 1.
    pub const AS_EXTERNAL_1: u8 = 3;
    /// AS external type 2.
    pub const AS_EXTERNAL_2: u8 = 4;
    /// NSSA external type 1.
    pub const NSSA_1: u8 = 5;
    /// NSSA external type 2.
    pub const NSSA_2: u8 = 6;
}

/// Prefix option AC-bit (RFC 9513 §6, "OSPFv3 Prefix Options" registry
/// 0x80): the prefix/locator is anycast. Multiple routers advertising
/// the same locator with at least one AC-bit set make it anycast; the
/// AC-bit and the RFC 5340 N-bit MUST NOT both be set (a receiver that
/// sees both ignores the N-bit).
pub const PREFIX_OPT_AC: u8 = 0x80;

/// RFC 8986 §6 endpoint behaviors an OSPFv3 End SID may carry
/// (RFC 9513 §11, Table 1): End (1-4, 28-31), End.DT6 (18), End.DT4
/// (19), End.DT64 (20). Anything else — including the End.X family —
/// is invalid inside an End SID sub-TLV and the receiver ignores the
/// sub-TLV ("Unsupported or unrecognized behavior values are ignored").
pub fn behavior_valid_for_end_sid(behavior: u16) -> bool {
    matches!(behavior, 1..=4 | 18..=20 | 28..=31)
}

/// The four SRv6 MSD types RFC 9513 §4 uses (shared "IGP MSD-Types"
/// registry; RFC 9352 §4 assigned the values).
pub mod msd_type {
    /// Maximum Segments Left (§4.1).
    pub const SRH_MAX_SL: u8 = 41;
    /// Maximum End Pop — PSP/USP flavor depth (§4.2).
    pub const SRH_MAX_END_POP: u8 = 42;
    /// Maximum H.Encaps (§4.3).
    pub const SRH_MAX_H_ENCAPS: u8 = 44;
    /// Maximum End D — decapsulation depth (§4.4).
    pub const SRH_MAX_END_D: u8 = 45;
}

/// A generic Router Information LSA body walker (RFC 7770 §2.3 TLV
/// format — the RFC 3630 encoding). Returns `(type, value)` pairs with
/// the 4-octet padding stripped; `None` on a truncated or malformed
/// body. Unknown TLV types are returned untouched — the caller filters.
pub fn decode_v3_ri_tlvs(body: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    let mut tlvs = Vec::new();
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let t = u16::from_be_bytes([body[off], body[off + 1]]);
        let len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        if off + 4 + len > body.len() {
            return None;
        }
        tlvs.push((t, body[off + 4..off + 4 + len].to_vec()));
        // 4-octet alignment: the TLV occupies 4 + len rounded up.
        off += 4 + len.div_ceil(4) * 4;
    }
    Some(tlvs)
}

/// One (MSD-Type, MSD-Value) pair from the Node MSD TLV (RFC 8476 §2).
pub type NodeMsd = (u8, u8);

/// The SRv6-relevant projection of an OSPFv3 Router Information LSA
/// body (RFC 9513 §2-§4): capabilities, algorithms and node MSDs. The
/// §2 first-occurrence rule (repeat TLVs ignored) is applied by the
/// database projection; this type holds what one body advertises.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Srv6RiBlock {
    /// The SRv6 Capabilities TLV flags ([`SRV6_CAP_O_FLAG`] is the only
    /// defined bit). `None` when the body carries no capabilities TLV
    /// (a non-SRv6 RI LSA — e.g. RFC 7770 §2.1 capability-only
    /// advertisements — decodes to an empty block).
    pub capabilities: Option<u16>,
    /// SR-Algorithm TLV values (RFC 8665 §3.1), in wire order.
    pub algorithms: Vec<u8>,
    /// Node MSD TLV pairs (RFC 8476 §2), in wire order.
    pub msds: Vec<NodeMsd>,
}

/// Encode the SRv6-relevant Router Information TLVs (RFC 9513 §2-§4)
/// into an RI LSA body. `capabilities` is the 16-bit flags word
/// (0 = no O-flag). Encodes even with an empty capability bit set —
/// a v3 RI LSA advertising SRv6 always carries the capabilities TLV
/// (RFC 9513 §2 "MUST be advertised by an SRv6-enabled router").
pub fn encode_v3_srv6_ri(capabilities: u16, algorithms: &[u8], msds: &[NodeMsd]) -> Vec<u8> {
    let mut body = Vec::new();
    // SRv6 Capabilities TLV: Flags(2) | Reserved(2) — no sub-TLVs.
    let flags_be = capabilities.to_be_bytes();
    body.extend_from_slice(&RI_TLV_SRV6_CAPABILITIES.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&flags_be);
    body.extend_from_slice(&[0, 0]);
    if !algorithms.is_empty() {
        // SR-Algorithm TLV (RFC 8665 §3.1): one octet per algorithm.
        body.extend_from_slice(&RI_TLV_SR_ALGORITHM.to_be_bytes());
        body.extend_from_slice(&(algorithms.len() as u16).to_be_bytes());
        body.extend_from_slice(algorithms);
        pad4(&mut body, algorithms.len());
    }
    if !msds.is_empty() {
        // Node MSD TLV (RFC 8476 §2): (MSD-Type, MSD-Value) pairs.
        body.extend_from_slice(&RI_TLV_NODE_MSD.to_be_bytes());
        body.extend_from_slice(&(msds.len() as u16 * 2).to_be_bytes());
        for (t, v) in msds {
            body.push(*t);
            body.push(*v);
        }
    }
    body
}

/// Decode an RI LSA body into the SRv6-relevant block. `None` on a
/// malformed body (truncated TLV).
pub fn decode_v3_srv6_ri(body: &[u8]) -> Option<Srv6RiBlock> {
    let mut block = Srv6RiBlock::default();
    for (t, v) in decode_v3_ri_tlvs(body)? {
        match t {
            x if x == RI_TLV_SRV6_CAPABILITIES => {
                // Flags(2) | Reserved(2). A shorter value is malformed.
                if v.len() < 4 {
                    return None;
                }
                block
                    .capabilities
                    .get_or_insert(u16::from_be_bytes([v[0], v[1]]));
            }
            x if x == RI_TLV_SR_ALGORITHM => {
                block.algorithms = v.clone();
            }
            x if x == RI_TLV_NODE_MSD => {
                if v.len() % 2 != 0 {
                    return None;
                }
                block.msds = v.as_chunks::<2>().0.iter().map(|p| (p[0], p[1])).collect();
            }
            _ => {}
        }
    }
    Some(block)
}

/// SRv6 SID Structure sub-TLV (RFC 9513 §10): the LOC:FUNCT:ARGS bit
/// split of the SID as instantiated (RFC 8986 §3.2). Informational —
/// MUST NOT drive forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Srv6SidStructure {
    /// Locator Block length in bits.
    pub lb_len: u8,
    /// Locator Node length in bits.
    pub ln_len: u8,
    /// Function length in bits.
    pub func_len: u8,
    /// Argument length in bits.
    pub arg_len: u8,
}

impl Srv6SidStructure {
    /// The on-wire size: Type(2) + Length(2) + 4 octets.
    pub const WIRE_LEN: usize = 8;

    /// The §10 validity contract: the four lengths sum to ≤ 128 bits.
    pub fn is_valid(&self) -> bool {
        self.lb_len as u32 + self.ln_len as u32 + self.func_len as u32 + self.arg_len as u32 <= 128
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&LOCATOR_SUBTLV_SID_STRUCTURE.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.push(self.lb_len);
        out.push(self.ln_len);
        out.push(self.func_len);
        out.push(self.arg_len);
    }

    /// Encode with an explicit sub-TLV type — the §10 registry value
    /// differs by carrier (10 in the Locator LSA registry, 30 in the
    /// "OSPFv3 Extended-LSA Sub-TLVs" registry, RFC 9513 §13.7 — the
    /// End.X / LAN End.X nesting).
    pub fn encode_as(&self, out: &mut Vec<u8>, sub_tlv_type: u16) {
        out.extend_from_slice(&sub_tlv_type.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.push(self.lb_len);
        out.push(self.ln_len);
        out.push(self.func_len);
        out.push(self.arg_len);
    }

    /// Decode the 4-octet value (the caller passes the TLV value, not
    /// the header). `None` on any §10 violation — wrong length, sum
    /// above 128 — signalling "ignore the parent sub-TLV".
    pub fn decode_value(v: &[u8]) -> Option<Self> {
        if v.len() != 4 {
            return None;
        }
        let s = Self {
            lb_len: v[0],
            ln_len: v[1],
            func_len: v[2],
            arg_len: v[3],
        };
        s.is_valid().then_some(s)
    }
}

/// SRv6 End SID sub-TLV (RFC 9513 §8): one SRv6 SID instantiated on
/// the advertising router, with its RFC 8986 endpoint behavior. The
/// SID inherits its algorithm from the parent locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6EndSidSubTlv {
    /// Flags — none defined by RFC 9513 §8; MUST be 0 on transmission
    /// and ignored on receipt.
    pub flags: u8,
    /// RFC 8986 endpoint behavior code point. Only
    /// [`behavior_valid_for_end_sid`] values belong here.
    pub behavior: u16,
    /// The 128-bit SID.
    pub sid: [u8; 16],
    /// The §10 SID Structure sub-TLV when present. `None` when absent
    /// or when a §10 violation made the parent ignorable.
    pub structure: Option<Srv6SidStructure>,
}

impl Srv6EndSidSubTlv {
    /// The fixed part: Type(2) + Length(2) + Flags(1) + Reserved(1) +
    /// Behavior(2) + SID(16) = 24, plus sub-TLVs.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&LOCATOR_SUBTLV_END_SID.to_be_bytes());
        // The nested SID Structure sub-TLV occupies 4 header + 4 value
        // bytes inside the value portion; the parent Length counts all
        // of it (RFC 9513 §8: "the total length ... including its
        // nested sub-TLVs").
        let struct_len: usize = if self.structure.is_some() { 8 } else { 0 };
        let len: u16 = (20 + struct_len) as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.push(self.flags);
        out.push(0); // Reserved
        out.extend_from_slice(&self.behavior.to_be_bytes());
        out.extend_from_slice(&self.sid);
        if let Some(s) = &self.structure {
            s.encode(out);
        }
    }

    /// Decode one End SID sub-TLV at `off`. Returns the sub-TLV and the
    /// number of bytes consumed (including padding and any trailing
    /// sub-TLV bytes, which are skipped per the RFC 3630 convention).
    /// `None` when the §8 shape is truncated or the §10 contract is
    /// violated (duplicate / invalid SID Structure) — the caller must
    /// ignore the whole sub-TLV in those cases.
    pub fn decode(b: &[u8], off: usize) -> Option<(Self, usize)> {
        if off + 4 > b.len() {
            return None;
        }
        let t = u16::from_be_bytes([b[off], b[off + 1]]);
        if t != LOCATOR_SUBTLV_END_SID {
            return None;
        }
        let len = u16::from_be_bytes([b[off + 2], b[off + 3]]) as usize;
        let value_end = off + 4 + len;
        if value_end > b.len() || len < 20 {
            return None;
        }
        let flags = b[off + 4];
        // b[off+5] reserved
        let behavior = u16::from_be_bytes([b[off + 6], b[off + 7]]);
        let mut sid = [0u8; 16];
        sid.copy_from_slice(&b[off + 8..off + 24]);
        // Walk the sub-TLVs inside the remaining value bytes.
        let mut structure = None;
        let mut sub = off + 24;
        while sub + 4 <= value_end {
            let st = u16::from_be_bytes([b[sub], b[sub + 1]]);
            let slen = u16::from_be_bytes([b[sub + 2], b[sub + 3]]) as usize;
            if sub + 4 + slen > value_end {
                return None;
            }
            match st {
                x if x == LOCATOR_SUBTLV_SID_STRUCTURE => {
                    // §10: MUST NOT appear more than once in the parent.
                    if structure.is_some() {
                        return None;
                    }
                    structure = Some(Srv6SidStructure::decode_value(&b[sub + 4..sub + 4 + slen])?);
                }
                _ => {}
            }
            sub += 4 + slen.div_ceil(4) * 4;
        }
        let consumed = off + 4 + len.div_ceil(4) * 4;
        Some((
            Self {
                flags,
                behavior,
                sid,
                structure,
            },
            consumed,
        ))
    }
}

/// SRv6 End.X SID sub-TLV (RFC 9513 §9.1): one adjacency-steering SRv6
/// SID, advertised as a sub-TLV of the **Router-Link TLV** of the
/// E-Router-LSA (RFC 8362 §3.2) — "an instruction to forward to a
/// specific neighbor on a specific link". Unlike the End SID sub-TLV,
/// the behavior word leads and the algorithm/weight travel explicitly
/// (the SID may share the locator of any algorithm).
///
/// Wire shape (§9.1, figure 7):
/// `Type(2)=31 | Length(2) | Endpoint Behavior(2) | Flags(1) |
/// Reserved1(1) | Algorithm(1) | Weight(1) | Reserved2(2) | SID(16) |
/// sub-TLVs` — the optional SID Structure sub-TLV rides as type 30 of
/// the "OSPFv3 Extended-LSA Sub-TLVs" registry (§13.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6EndXSidSubTlv {
    /// B/S/P flags (§9.1): [`END_X_FLAG_B`] backup, [`END_X_FLAG_S`]
    /// set-of-adjacencies, [`END_X_FLAG_P`] persistent.
    pub flags: u8,
    /// RFC 8986 endpoint behavior code point (the End.X family — 5 for
    /// plain End.X; PSP/USP/USD flavors 6-7, 24-25, 33-34).
    pub behavior: u16,
    /// The algorithm of the locator the SID is allocated from.
    pub algorithm: u8,
    /// The load-balancing weight of the End.X SID (§9.1).
    pub weight: u8,
    /// The 128-bit SID.
    pub sid: [u8; 16],
    /// The §10 SID Structure sub-TLV (registry type 30) when present.
    pub structure: Option<Srv6SidStructure>,
}

/// End.X B-flag (§9.1): the SID refers to a path eligible for
/// protection.
pub const END_X_FLAG_B: u8 = 0x80;
/// End.X S-flag (§9.1): the SID refers to a set of adjacencies.
pub const END_X_FLAG_S: u8 = 0x40;
/// End.X P-flag (§9.1): the SID is persistently allocated.
pub const END_X_FLAG_P: u8 = 0x20;

/// "OSPFv3 Extended-LSA Sub-TLVs" registry (RFC 9513 §13.7): the
/// SRv6 End.X SID sub-TLV.
pub const EXT_SUBTLV_END_X_SID: u16 = 31;
/// "OSPFv3 Extended-LSA Sub-TLVs" registry: the SRv6 LAN End.X SID
/// sub-TLV.
pub const EXT_SUBTLV_LAN_END_X_SID: u16 = 32;

impl Srv6EndXSidSubTlv {
    /// The fixed value: Behavior(2) + Flags(1) + Reserved1(1) +
    /// Algorithm(1) + Weight(1) + Reserved2(2) + SID(16) = 24 octets.
    pub const FIXED_LEN: usize = 24;

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&EXT_SUBTLV_END_X_SID.to_be_bytes());
        let struct_len: usize = if self.structure.is_some() { 8 } else { 0 };
        let len: u16 = (Self::FIXED_LEN + struct_len) as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.behavior.to_be_bytes());
        out.push(self.flags);
        out.push(0); // Reserved1
        out.push(self.algorithm);
        out.push(self.weight);
        out.extend_from_slice(&0u16.to_be_bytes()); // Reserved2
        out.extend_from_slice(&self.sid);
        if let Some(s) = &self.structure {
            s.encode_as(out, EXT_SUBTLV_SID_STRUCTURE);
        }
    }

    /// Decode one End.X sub-TLV at `off` (inside a Router-Link TLV's
    /// sub-TLV region). Returns the sub-TLV and the bytes consumed.
    /// `None` on a truncated §9.1 shape or a §10 contract violation —
    /// the caller ignores that sub-TLV instance.
    pub fn decode(b: &[u8], off: usize) -> Option<(Self, usize)> {
        if off + 4 > b.len() {
            return None;
        }
        let t = u16::from_be_bytes([b[off], b[off + 1]]);
        if t != EXT_SUBTLV_END_X_SID {
            return None;
        }
        let len = u16::from_be_bytes([b[off + 2], b[off + 3]]) as usize;
        let value_end = off + 4 + len;
        if value_end > b.len() || len < Self::FIXED_LEN {
            return None;
        }
        Self::decode_value(&b[off + 4..value_end]).map(|s| {
            let consumed = off + 4 + len.div_ceil(4) * 4;
            (s, consumed)
        })
    }

    /// Decode from the sub-TLV value (past the header). The nested
    /// sub-TLVs may only carry the §10 SID Structure (type 30, at most
    /// once).
    pub fn decode_value(value: &[u8]) -> Option<Self> {
        if value.len() < Self::FIXED_LEN {
            return None;
        }
        let behavior = u16::from_be_bytes([value[0], value[1]]);
        let flags = value[2];
        // value[3] Reserved1
        let algorithm = value[4];
        let weight = value[5];
        // value[6..8] Reserved2
        let mut sid = [0u8; 16];
        sid.copy_from_slice(&value[8..24]);
        let mut structure = None;
        let mut sub = Self::FIXED_LEN;
        while sub + 4 <= value.len() {
            let st = u16::from_be_bytes([value[sub], value[sub + 1]]);
            let slen = u16::from_be_bytes([value[sub + 2], value[sub + 3]]) as usize;
            if sub + 4 + slen > value.len() {
                return None;
            }
            if st == EXT_SUBTLV_SID_STRUCTURE {
                // §10: MUST NOT appear more than once in the parent.
                if structure.is_some() {
                    return None;
                }
                structure = Some(Srv6SidStructure::decode_value(
                    &value[sub + 4..sub + 4 + slen],
                )?);
            }
            sub += 4 + slen.div_ceil(4) * 4;
        }
        Some(Self {
            flags,
            behavior,
            algorithm,
            weight,
            sid,
            structure,
        })
    }
}

/// SRv6 LAN End.X SID sub-TLV (RFC 9513 §9.2): the broadcast/NBMA
/// sibling — one instance per DR/DR-Other neighbor, distinguished by
/// the OSPFv3 Router-ID field, all riding the same link's Router-Link
/// TLV. Same shape as the End.X sub-TLV with the 4-octet neighbor
/// Router-ID inserted before the SID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6LanEndXSidSubTlv {
    pub flags: u8,
    pub behavior: u16,
    pub algorithm: u8,
    pub weight: u8,
    /// The OSPFv3 Router-ID of the neighbor the SID steers to (§9.2).
    pub neighbor_router_id: u32,
    pub sid: [u8; 16],
    pub structure: Option<Srv6SidStructure>,
}

impl Srv6LanEndXSidSubTlv {
    /// The fixed value: the End.X fields + the 4-octet neighbor
    /// Router-ID = 28 octets.
    pub const FIXED_LEN: usize = 28;

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&EXT_SUBTLV_LAN_END_X_SID.to_be_bytes());
        let struct_len: usize = if self.structure.is_some() { 8 } else { 0 };
        let len: u16 = (Self::FIXED_LEN + struct_len) as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.behavior.to_be_bytes());
        out.push(self.flags);
        out.push(0); // Reserved1
        out.push(self.algorithm);
        out.push(self.weight);
        out.extend_from_slice(&0u16.to_be_bytes()); // Reserved2
        out.extend_from_slice(&self.neighbor_router_id.to_be_bytes());
        out.extend_from_slice(&self.sid);
        if let Some(s) = &self.structure {
            s.encode_as(out, EXT_SUBTLV_SID_STRUCTURE);
        }
    }

    /// Decode one LAN End.X sub-TLV at `off`. Same contract as
    /// [`Srv6EndXSidSubTlv::decode`].
    pub fn decode(b: &[u8], off: usize) -> Option<(Self, usize)> {
        if off + 4 > b.len() {
            return None;
        }
        let t = u16::from_be_bytes([b[off], b[off + 1]]);
        if t != EXT_SUBTLV_LAN_END_X_SID {
            return None;
        }
        let len = u16::from_be_bytes([b[off + 2], b[off + 3]]) as usize;
        let value_end = off + 4 + len;
        if value_end > b.len() || len < Self::FIXED_LEN {
            return None;
        }
        let value = &b[off + 4..value_end];
        let behavior = u16::from_be_bytes([value[0], value[1]]);
        let flags = value[2];
        let algorithm = value[4];
        let weight = value[5];
        let neighbor_router_id = u32::from_be_bytes([value[8], value[9], value[10], value[11]]);
        let mut sid = [0u8; 16];
        sid.copy_from_slice(&value[12..28]);
        let mut structure = None;
        let mut sub = Self::FIXED_LEN;
        while sub + 4 <= value.len() {
            let st = u16::from_be_bytes([value[sub], value[sub + 1]]);
            let slen = u16::from_be_bytes([value[sub + 2], value[sub + 3]]) as usize;
            if sub + 4 + slen > value.len() {
                return None;
            }
            if st == EXT_SUBTLV_SID_STRUCTURE {
                if structure.is_some() {
                    return None;
                }
                structure = Some(Srv6SidStructure::decode_value(
                    &value[sub + 4..sub + 4 + slen],
                )?);
            }
            sub += 4 + slen.div_ceil(4) * 4;
        }
        let consumed = off + 4 + len.div_ceil(4) * 4;
        Some((
            Self {
                flags,
                behavior,
                algorithm,
                weight,
                neighbor_router_id,
                sid,
                structure,
            },
            consumed,
        ))
    }
}

/// Walk a Router-Link TLV's sub-TLV region and yield every End.X
/// (§9.1) instance, in wire order. Malformed instances are skipped
/// (the §9.1 decode contract); other sub-TLV types pass through.
pub fn walk_end_x_sub_tlvs(sub_tlvs: &[u8]) -> Vec<Srv6EndXSidSubTlv> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= sub_tlvs.len() {
        let t = u16::from_be_bytes([sub_tlvs[off], sub_tlvs[off + 1]]);
        let len = u16::from_be_bytes([sub_tlvs[off + 2], sub_tlvs[off + 3]]) as usize;
        if off + 4 + len > sub_tlvs.len() {
            break; // malformed tail — stop walking
        }
        if t == EXT_SUBTLV_END_X_SID {
            if let Some((sid, consumed)) = Srv6EndXSidSubTlv::decode(sub_tlvs, off) {
                out.push(sid);
                off = consumed;
                continue;
            }
        }
        off += 4 + len.div_ceil(4) * 4;
    }
    out
}

/// Walk a Router-Link TLV's sub-TLV region and yield every LAN End.X
/// (§9.2) instance, in wire order. Same contract as
/// [`walk_end_x_sub_tlvs`].
pub fn walk_lan_end_x_sub_tlvs(sub_tlvs: &[u8]) -> Vec<Srv6LanEndXSidSubTlv> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= sub_tlvs.len() {
        let t = u16::from_be_bytes([sub_tlvs[off], sub_tlvs[off + 1]]);
        let len = u16::from_be_bytes([sub_tlvs[off + 2], sub_tlvs[off + 3]]) as usize;
        if off + 4 + len > sub_tlvs.len() {
            break;
        }
        if t == EXT_SUBTLV_LAN_END_X_SID {
            if let Some((sid, consumed)) = Srv6LanEndXSidSubTlv::decode(sub_tlvs, off) {
                out.push(sid);
                off = consumed;
                continue;
            }
        }
        off += 4 + len.div_ceil(4) * 4;
    }
    out
}

/// SRv6 Locator TLV (RFC 9513 §7.1): one locator of the advertising
/// router, its attributes, and the End SIDs instantiated under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6LocatorTlv {
    /// [`locator_route_type`] value. Other values ignore the TLV.
    pub route_type: u8,
    /// The IGP algorithm the locator is associated with (RFC 8665 §3.1
    /// "IGP Algorithm Types" registry; 0 = SPF).
    pub algorithm: u8,
    /// Locator prefix length in bits (1-128).
    pub locator_len: u8,
    /// RFC 5340 §A.4.1 prefix options, extended by [`PREFIX_OPT_AC`]
    /// (RFC 9513 §6).
    pub options: u8,
    /// The locator metric; 0xFFFFFFFF means unreachable (§7.1).
    pub metric: u32,
    /// The locator prefix, host bits zeroed, network byte order.
    pub prefix: [u8; 16],
    /// The End SIDs under this locator (§8).
    pub end_sids: Vec<Srv6EndSidSubTlv>,
    /// IPv6-Forwarding-Address sub-TLV (§7.2, RFC 8362 §4.2) when
    /// present — the forwarding target for externally propagated
    /// locators.
    pub fwd_addr: Option<[u8; 16]>,
    /// Route-Tag sub-TLV (§7.2, RFC 8362 §4.3) when present.
    pub route_tag: Option<u32>,
}

impl Srv6LocatorTlv {
    /// Encode into `out` (appended), 4-octet padded per §7.
    ///
    /// A `locator_len` above 128 encodes the full 16 address bytes —
    /// the decoder (and the RFC) reject the TLV; the encoder never
    /// panics on out-of-range input.
    pub fn encode(&self, out: &mut Vec<u8>) {
        // Route Type | Algorithm | Locator Length | PrefixOptions.
        let mut value = vec![
            self.route_type,
            self.algorithm,
            self.locator_len,
            self.options,
        ];
        value.extend_from_slice(&self.metric.to_be_bytes());
        let n = V3Prefix::addr_bytes_len(self.locator_len.min(128));
        value.extend_from_slice(&self.prefix[..n]);
        if let Some(fa) = &self.fwd_addr {
            value.extend_from_slice(&LOCATOR_SUBTLV_IPV6_FWD_ADDR.to_be_bytes());
            value.extend_from_slice(&16u16.to_be_bytes());
            value.extend_from_slice(fa);
        }
        if let Some(tag) = &self.route_tag {
            value.extend_from_slice(&LOCATOR_SUBTLV_ROUTE_TAG.to_be_bytes());
            value.extend_from_slice(&4u16.to_be_bytes());
            value.extend_from_slice(&tag.to_be_bytes());
        }
        for sid in &self.end_sids {
            sid.encode(&mut value);
        }
        out.extend_from_slice(&LOCATOR_TLV_SRV6_LOCATOR.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(&value);
        pad4(out, value.len());
    }

    /// Decode one Locator TLV at `off`. Returns the TLV and the bytes
    /// consumed (header + padded value). `None` on any §7.1 ignore
    /// condition: unknown route type, locator length above 128, value
    /// too short for the prefix encoding, or a truncated sub-TLV.
    pub fn decode(b: &[u8], off: usize) -> Option<(Self, usize)> {
        if off + 4 > b.len() {
            return None;
        }
        let t = u16::from_be_bytes([b[off], b[off + 1]]);
        if t != LOCATOR_TLV_SRV6_LOCATOR {
            return None;
        }
        let len = u16::from_be_bytes([b[off + 2], b[off + 3]]) as usize;
        let value_end = off + 4 + len;
        if value_end > b.len() || len < 8 {
            return None;
        }
        let route_type = b[off + 4];
        if !matches!(route_type, 1..=6) {
            return None;
        }
        let algorithm = b[off + 5];
        let locator_len = b[off + 6];
        if locator_len > 128 || locator_len == 0 {
            return None;
        }
        let options = b[off + 7];
        let metric = u32::from_be_bytes([b[off + 8], b[off + 9], b[off + 10], b[off + 11]]);
        let n = V3Prefix::addr_bytes_len(locator_len);
        // The value layout after the 4-byte TLV header is the 8 fixed
        // bytes followed by n locator bytes — both must fit in `len`.
        if 8 + n > len {
            return None;
        }
        let mut prefix = [0u8; 16];
        prefix[..n].copy_from_slice(&b[off + 12..off + 12 + n]);
        // Walk sub-TLVs in the remaining value bytes.
        let mut end_sids = Vec::new();
        let mut fwd_addr = None;
        let mut route_tag = None;
        let mut sub = off + 12 + n;
        while sub + 4 <= value_end {
            let st = u16::from_be_bytes([b[sub], b[sub + 1]]);
            let slen = u16::from_be_bytes([b[sub + 2], b[sub + 3]]) as usize;
            if sub + 4 + slen > value_end {
                return None;
            }
            match st {
                x if x == LOCATOR_SUBTLV_END_SID => {
                    let (sid, used) = Srv6EndSidSubTlv::decode(b, sub)?;
                    end_sids.push(sid);
                    sub = used;
                    continue;
                }
                x if x == LOCATOR_SUBTLV_IPV6_FWD_ADDR => {
                    if slen != 16 {
                        return None;
                    }
                    let mut fa = [0u8; 16];
                    fa.copy_from_slice(&b[sub + 4..sub + 20]);
                    fwd_addr = Some(fa);
                }
                x if x == LOCATOR_SUBTLV_ROUTE_TAG => {
                    if slen != 4 {
                        return None;
                    }
                    route_tag = Some(u32::from_be_bytes([
                        b[sub + 4],
                        b[sub + 5],
                        b[sub + 6],
                        b[sub + 7],
                    ]));
                }
                _ => {}
            }
            sub += 4 + slen.div_ceil(4) * 4;
        }
        let consumed = off + 4 + len.div_ceil(4) * 4;
        Some((
            Self {
                route_type,
                algorithm,
                locator_len,
                options,
                metric,
                prefix,
                end_sids,
                fwd_addr,
                route_tag,
            },
            consumed,
        ))
    }
}

/// SRv6 Locator LSA body (RFC 9513 §7): a sequence of TLVs, of which
/// the SRv6 Locator TLVs are the ones this crate models.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Srv6LocatorLsaBody {
    pub locators: Vec<Srv6LocatorTlv>,
}

impl Srv6LocatorLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        for l in &self.locators {
            l.encode(out);
        }
    }

    /// Decode the body. `None` on a malformed TLV sequence.
    pub fn decode(body: &[u8]) -> Option<Self> {
        let mut locators = Vec::new();
        let mut off = 0usize;
        while off + 4 <= body.len() {
            let (tlv, used) = Srv6LocatorTlv::decode(body, off)?;
            locators.push(tlv);
            off += used;
        }
        Some(Self { locators })
    }
}

/// Zero-pad `out` to a 4-octet boundary after `len` appended bytes
/// (§7: "the TLV is padded to 4-octet alignment; padding is not
/// included in the Length field"; zeros).
fn pad4(out: &mut Vec<u8>, len: usize) {
    let rem = len % 4;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, 4 - rem));
    }
}

/// Build a complete area-scoped **Router Information LSA** carrying the
/// SRv6 TLVs (RFC 9513 §2-§4 on the RFC 7770 §2.2 carrier): the SRv6
/// Capabilities TLV, the SR-Algorithm TLV and the Node MSD TLV.
///
/// `prev_seq` follows the crate convention: `None` starts at the
/// initial sequence number, `Some(MAX_SEQUENCE_NUMBER)` returns `None`
/// (sequence space exhausted).
pub fn originate_v3_srv6_ri_lsa(
    router_id: u32,
    capabilities: u16,
    algorithms: &[u8],
    msds: &[NodeMsd],
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
            // OSPFv3 LSA headers carry no options byte.
            options: 0,
            ls_type: LS_TYPE_V3_ROUTER_INFORMATION,
            link_state_id: 0, // Instance ID 0 (RFC 7770 §2.2)
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body: encode_v3_srv6_ri(capabilities, algorithms, msds),
    };
    lsa.finalize();
    Some(lsa)
}

/// Build a complete area-scoped **SRv6 Locator LSA** (RFC 9513 §7)
/// advertising `locators`. The caller picks the Link State ID — the
/// RFC leaves it arbitrary and multiple Locator LSAs per router are
/// distinguished by it. The caller is responsible for satisfying the
/// §7.1 scoping note (all locators in one LSA share the LSA's flooding
/// scope; area scope is what this function emits).
pub fn originate_v3_srv6_locator_lsa(
    router_id: u32,
    link_state_id: u32,
    locators: &[Srv6LocatorTlv],
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let mut body = Vec::new();
    for l in locators {
        l.encode(&mut body);
    }
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0,
            ls_type: LS_TYPE_SRV6_LOCATOR,
            link_state_id,
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

#[cfg(test)]
#[path = "srv6_tests.rs"]
mod tests;
