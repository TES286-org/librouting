//! OSPFv3 Extended LSAs (RFC 8362) — the TLV-bodied replacements for the
//! eight fixed-format RFC 5340 LSA types.
//!
//! Wire shapes implemented here (all verified against the RFC 8362
//! figures byte-for-byte; see the tests at the bottom of this file):
//!
//! 1. **E-Router-LSA** (§4.1, function code 33, LS type 0xA021,
//!    U-bit set, area-scoped): the `0|Nt|x|V|E|B` + Options header —
//!    byte-identical to the legacy Router-LSA's (RFC 5340 §A.4.3) —
//!    followed by any number of Router-Link TLVs (§3.2), each carrying
//!    the legacy link descriptor fields plus a sub-TLV region (the
//!    extension point where the SRv6 End.X / LAN End.X SIDs of
//!    RFC 9513 §9 ride).
//! 2. **E-Network-LSA** (§4.2, 34/0xA022): a zero + Options header and
//!    exactly one Attached-Routers TLV (§3.3) — the 4-octet adjacent
//!    router IDs. A missing TLV makes the LSA malformed (§4.2); later
//!    instances are ignored.
//! 3. **E-Inter-Area-Prefix-LSA** (§4.3, 35/0xA023): no fixed header,
//!    exactly one Inter-Area-Prefix TLV (§3.4).
//! 4. **E-Inter-Area-Router-LSA** (§4.4, 36/0xA024): no fixed header,
//!    exactly one Inter-Area-Router TLV (§3.5).
//! 5. **E-AS-External-LSA** (§4.5, 37/0xC025, AS-scoped): no fixed
//!    header, exactly one External-Prefix TLV (§3.6) whose forwarding
//!    address and route tag became sub-TLVs (1/2/3) and whose
//!    Referenced LS Type/ID fields are gone. The E-Type-7-LSA (§4.6,
//!    39/0xA027, area-scoped) shares this body shape, exactly as the
//!    legacy type-7 shares the AS-external body.
//! 6. **E-Link-LSA** (§4.7, 40/0x8028, link-scoped): a Rtr Priority +
//!    Options header, one IPv6 Link-Local Address TLV (§3.8, required
//!    for the IPv6 address family — a missing TLV is malformed), an
//!    optional IPv4 Link-Local Address TLV (§3.9) and any number of
//!    Intra-Area-Prefix TLVs (§3.7).
//! 7. **E-Intra-Area-Prefix-LSA** (§4.8, 41/0xA029): a 12-byte
//!    referenced-LSA header (the Referenced LS Type MUST be 0xA021 or
//!    0xA022) followed by any number of Intra-Area-Prefix TLVs.
//!
//! Reception rules that live here as codec-level contracts (§5, §6.3):
//! malformed bodies — truncated headers, TLVs shorter than their
//! minimum length, a missing required TLV — decode to `None` so the
//! caller refuses to install, acknowledge or flood them; unknown TLV
//! and sub-TLV types are skipped; duplicate instances of
//! single-instance TLVs/sub-TLVs keep the first.
//!
//! Function code 38 is unused and will not be allocated (§2). No
//! reference implementation originates Extended LSAs as of FRR 10.3 /
//! BIRD 2.17 (verified in both sources), so interop acceptance rides
//! the U-bit: legacy speakers store and re-flood them unchanged — the
//! same transparency property the SRv6 Locator LSA already exercises
//! against FRR (`tests/interop/ospf6_frr_srv6.sh`).

use crate::lsa::v3::{next_sequence, v3_lsa, V3Prefix};
use crate::lsa::Lsa;

/// E-Router-LSA (RFC 8362 §4.1): function code 33, U-bit set,
/// area-scoped. Replaces the Router-LSA (0x2001).
pub const LS_TYPE_E_ROUTER: u16 = 0xA021;
/// E-Network-LSA (§4.2): function code 34, area-scoped.
pub const LS_TYPE_E_NETWORK: u16 = 0xA022;
/// E-Inter-Area-Prefix-LSA (§4.3): function code 35, area-scoped.
pub const LS_TYPE_E_INTER_PREFIX: u16 = 0xA023;
/// E-Inter-Area-Router-LSA (§4.4): function code 36, area-scoped.
pub const LS_TYPE_E_INTER_ROUTER: u16 = 0xA024;
/// E-AS-External-LSA (§4.5): function code 37, U-bit set with the S2
/// AS-flooding-scope bit — 0xC025.
pub const LS_TYPE_E_AS_EXTERNAL: u16 = 0xC025;
/// E-Type-7-LSA (§4.6): function code 39, area-scoped — the NSSA
/// sibling sharing the E-AS-External body.
pub const LS_TYPE_E_TYPE_7: u16 = 0xA027;
/// E-Link-LSA (§4.7): function code 40, link-scoped (no S bits) —
/// 0x8028.
pub const LS_TYPE_E_LINK: u16 = 0x8028;
/// E-Intra-Area-Prefix-LSA (§4.8): function code 41, area-scoped.
pub const LS_TYPE_E_INTRA_PREFIX: u16 = 0xA029;

/// Whether `ls_type` is one of the eight RFC 8362 Extended LSA types
/// (function code 38 is unused and never allocated, §2).
pub fn is_e_lsa_type(ls_type: u16) -> bool {
    matches!(
        ls_type,
        LS_TYPE_E_ROUTER
            | LS_TYPE_E_NETWORK
            | LS_TYPE_E_INTER_PREFIX
            | LS_TYPE_E_INTER_ROUTER
            | LS_TYPE_E_AS_EXTERNAL
            | LS_TYPE_E_TYPE_7
            | LS_TYPE_E_LINK
            | LS_TYPE_E_INTRA_PREFIX
    )
}

/// Top-level TLV: Router-Link (RFC 8362 §3.2) — only valid inside the
/// E-Router-LSA.
pub const TLV_ROUTER_LINK: u16 = 1;
/// Top-level TLV: Attached-Routers (§3.3) — only valid inside the
/// E-Network-LSA.
pub const TLV_ATTACHED_ROUTERS: u16 = 2;
/// Top-level TLV: Inter-Area-Prefix (§3.4) — only valid inside the
/// E-Inter-Area-Prefix-LSA.
pub const TLV_INTER_AREA_PREFIX: u16 = 3;
/// Top-level TLV: Inter-Area-Router (§3.5) — only valid inside the
/// E-Inter-Area-Router-LSA.
pub const TLV_INTER_AREA_ROUTER: u16 = 4;
/// Top-level TLV: External-Prefix (§3.6) — only valid inside the
/// E-AS-External-LSA and the E-Type-7-LSA.
pub const TLV_EXTERNAL_PREFIX: u16 = 5;
/// Top-level TLV: Intra-Area-Prefix (§3.7) — only valid inside the
/// E-Link-LSA and the E-Intra-Area-Prefix-LSA.
pub const TLV_INTRA_AREA_PREFIX: u16 = 6;
/// Top-level TLV: IPv6 Link-Local Address (§3.8) — only valid inside
/// the E-Link-LSA.
pub const TLV_IPV6_LINK_LOCAL: u16 = 7;
/// Top-level TLV: IPv4 Link-Local Address (§3.9) — only valid inside
/// the E-Link-LSA.
pub const TLV_IPV4_LINK_LOCAL: u16 = 8;

/// External-Prefix sub-TLV: IPv6-Forwarding-Address (RFC 8362 §3.10),
/// 16 octets, first instance wins.
pub const SUBTLV_IPV6_FWD_ADDR: u16 = 1;
/// External-Prefix sub-TLV: IPv4-Forwarding-Address (§3.11), 4 octets,
/// first instance wins.
pub const SUBTLV_IPV4_FWD_ADDR: u16 = 2;
/// External-Prefix sub-TLV: Route-Tag (§3.12), 4 octets, first
/// instance wins.
pub const SUBTLV_ROUTE_TAG: u16 = 3;

/// The External-Prefix TLV's E-bit (§3.6): type-2 (larger) external
/// metric, in the same word position the legacy AS-External-LSA uses
/// (the TLV "corresponds directly" to the §A.4.7 field layout).
pub const EXT_PREFIX_BIT_E: u32 = 0x0400_0000;
/// The 24-bit metric mask of the External-Prefix TLV's first word.
pub const EXT_PREFIX_METRIC_MASK: u32 = 0x00ff_ffff;

// ---------------------------------------------------------------------------
// TLV framing (RFC 8362 §3 — the RFC 3630 convention: Type(2) |
// Length(2) | Value, padded to 4-octet alignment; padding not counted
// in Length)
// ---------------------------------------------------------------------------

/// One decoded TLV: the type and the *borrowed* value slice (padding
/// stripped). Sub-TLV regions are re-walked with the same helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTlv<'a> {
    pub tlv_type: u16,
    pub value: &'a [u8],
}

/// Walk a TLV region (an LSA body or a parent TLV's sub-TLV region).
/// Returns `None` when a TLV header or its value is truncated — the
/// §5 malformed signal. Unknown types are returned untouched; the
/// caller filters.
pub fn walk_tlvs(body: &[u8]) -> Option<Vec<RawTlv<'_>>> {
    let mut tlvs = Vec::new();
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let tlv_type = u16::from_be_bytes([body[off], body[off + 1]]);
        let len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        if off + 4 + len > body.len() {
            return None;
        }
        tlvs.push(RawTlv {
            tlv_type,
            value: &body[off + 4..off + 4 + len],
        });
        // 4-octet alignment: the TLV occupies 4 + len rounded up. The
        // step may overshoot the region when the final TLV's padding
        // runs to the end (the value itself was fully present).
        off += 4 + len.div_ceil(4) * 4;
    }
    // A trailing fragment shorter than a TLV header is malformed;
    // `off >= len` covers both the clean end and a padding overshoot.
    (off >= body.len()).then_some(tlvs)
}

/// Append one TLV: type(2) + length(2) + value, padded to a 4-octet
/// boundary. The padding is zero and not counted in the length field.
pub fn encode_tlv(out: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    out.extend_from_slice(&tlv_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    out.extend(std::iter::repeat_n(0u8, pad));
}

// ---------------------------------------------------------------------------
// E-Router-LSA (RFC 8362 §4.1)
// ---------------------------------------------------------------------------

/// Router-Link TLV (RFC 8362 §3.2): the legacy Router-LSA link
/// descriptor (RFC 5340 §A.4.3) — link type, metric and the three
/// interface/router identifiers — plus a sub-TLV region. The SRv6
/// End.X / LAN End.X SID sub-TLVs (RFC 9513 §9) ride the sub-TLV
/// region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ERouterLinkTlv {
    /// [`crate::lsa::v3::LINK_TYPE_POINTTOPOINT`] (1),
    /// [`crate::lsa::v3::LINK_TYPE_TRANSIT`] (2) or
    /// [`crate::lsa::v3::LINK_TYPE_VIRTUAL`] (4).
    pub link_type: u8,
    /// Output cost of the link.
    pub metric: u16,
    /// The Interface ID of *our* interface on the link.
    pub interface_id: u32,
    /// The Interface ID the *neighbor* uses on the link.
    pub neighbor_interface_id: u32,
    /// The neighbor's Router ID.
    pub neighbor_router_id: u32,
    /// The raw sub-TLV region (unparsed — the End.X extension point).
    /// Empty when the link carries no sub-TLVs.
    pub sub_tlvs: Vec<u8>,
}

impl ERouterLinkTlv {
    /// The fixed part: link type(1) + 0(1) + metric(2) + three 4-octet
    /// identifiers = 16 octets; the sub-TLV region follows inside the
    /// TLV value.
    pub const FIXED_LEN: usize = 16;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut value = Vec::with_capacity(Self::FIXED_LEN + self.sub_tlvs.len());
        value.push(self.link_type);
        value.push(0);
        value.extend_from_slice(&self.metric.to_be_bytes());
        value.extend_from_slice(&self.interface_id.to_be_bytes());
        value.extend_from_slice(&self.neighbor_interface_id.to_be_bytes());
        value.extend_from_slice(&self.neighbor_router_id.to_be_bytes());
        value.extend_from_slice(&self.sub_tlvs);
        encode_tlv(out, TLV_ROUTER_LINK, &value);
    }

    /// Decode from a Router-Link TLV value. `None` when shorter than
    /// the §3.2 minimum (16 octets) — the §5 malformed signal.
    pub fn decode_value(value: &[u8]) -> Option<Self> {
        if value.len() < Self::FIXED_LEN {
            return None;
        }
        Some(Self {
            link_type: value[0],
            metric: u16::from_be_bytes([value[2], value[3]]),
            interface_id: u32::from_be_bytes([value[4], value[5], value[6], value[7]]),
            neighbor_interface_id: u32::from_be_bytes([value[8], value[9], value[10], value[11]]),
            neighbor_router_id: u32::from_be_bytes([value[12], value[13], value[14], value[15]]),
            sub_tlvs: value[Self::FIXED_LEN..].to_vec(),
        })
    }
}

/// E-Router-LSA body (RFC 8362 §4.1): the legacy Router-LSA header —
/// `bits` byte (`0|Nt|x|V|E|B`, identical to RFC 5340 §A.4.3) plus the
/// 24-bit Options — followed by Router-Link TLVs. An E-Router-LSA with
/// no links is valid (a router without area adjacencies).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ERouterLsaBody {
    /// [`crate::lsa::v3::ROUTER_BIT_*`] flags.
    pub bits: u8,
    /// 24-bit options (RFC 5340 §A.2).
    pub options: u32,
    pub links: Vec<ERouterLinkTlv>,
}

impl ERouterLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.bits);
        out.extend_from_slice(&self.options.to_be_bytes()[1..4]);
        for l in &self.links {
            l.encode_into(out);
        }
    }

    /// Decode a full E-Router-LSA body. Router-Link TLVs with a
    /// too-short value make the whole LSA malformed (§5); unknown TLV
    /// types are skipped (§6.3 rule 1).
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 4 {
            return None;
        }
        let mut out = Self {
            bits: body[0],
            options: u32::from_be_bytes([0, body[1], body[2], body[3]]),
            links: Vec::new(),
        };
        for tlv in walk_tlvs(&body[4..])? {
            if tlv.tlv_type == TLV_ROUTER_LINK {
                out.links.push(ERouterLinkTlv::decode_value(tlv.value)?);
            }
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// E-Network-LSA (RFC 8362 §4.2)
// ---------------------------------------------------------------------------

/// E-Network-LSA body (RFC 8362 §4.2): a zero + Options header and
/// exactly one Attached-Routers TLV (§3.3) — the Router IDs of every
/// fully adjacent router on the network, DR included. A missing
/// Attached-Routers TLV is malformed (§4.2); later instances are
/// ignored. The network's own prefix rides an
/// E-Intra-Area-Prefix-LSA referencing this LSA.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ENetworkLsaBody {
    /// 24-bit options (RFC 5340 §A.2).
    pub options: u32,
    pub routers: Vec<u32>,
}

impl ENetworkLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&self.options.to_be_bytes()[1..4]);
        let mut value = Vec::with_capacity(self.routers.len() * 4);
        for r in &self.routers {
            value.extend_from_slice(&r.to_be_bytes());
        }
        encode_tlv(out, TLV_ATTACHED_ROUTERS, &value);
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 4 {
            return None;
        }
        let mut out = Self {
            options: u32::from_be_bytes([0, body[1], body[2], body[3]]),
            routers: Vec::new(),
        };
        let mut seen = false;
        for tlv in walk_tlvs(&body[4..])? {
            if tlv.tlv_type == TLV_ATTACHED_ROUTERS {
                if seen {
                    // §4.2: instances subsequent to the first are ignored.
                    continue;
                }
                seen = true;
                // Each adjacent router is 4 octets; anything else is a
                // §5 encoding error.
                if tlv.value.len() % 4 != 0 {
                    return None;
                }
                out.routers = tlv
                    .value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_be_bytes(*c))
                    .collect();
            }
        }
        // §4.2: a missing Attached-Routers TLV is malformed.
        seen.then_some(out)
    }
}

// ---------------------------------------------------------------------------
// Prefix TLVs — Inter-Area-Prefix (§3.4), Intra-Area-Prefix (§3.7)
// ---------------------------------------------------------------------------

/// A prefix-carrying TLV value (RFC 8362 §3.4/§3.7): a 24-bit metric,
/// the RFC 5340 §A.4.1 prefix (`PrefixLength | PrefixOptions | 0 |
/// Address Prefix`) and a sub-TLV region. The Inter-Area-Prefix TLV
/// (type 3) and the Intra-Area-Prefix TLV (type 6) share this value
/// shape; the prefix's trailing 16-bit word is reserved (zero) — the
/// metric lives in the leading word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EPrefixTlv {
    /// 24-bit metric (§3.4; zero for intra-area prefixes today).
    pub metric: u32,
    /// The prefix (its `metric` word is the reserved zero word).
    pub prefix: V3Prefix,
    /// The raw sub-TLV region (unparsed; future extensions).
    pub sub_tlvs: Vec<u8>,
}

impl EPrefixTlv {
    /// Decode from a prefix-TLV value. `None` when truncated below the
    /// 8-octet minimum or the prefix runs past the value.
    pub fn decode_value(value: &[u8]) -> Option<Self> {
        if value.len() < 8 {
            return None;
        }
        let metric = u32::from_be_bytes([0, value[1], value[2], value[3]]);
        let (prefix, used) = V3Prefix::decode(value, 4)?;
        Some(Self {
            metric,
            prefix,
            sub_tlvs: value[4 + used..].to_vec(),
        })
    }

    /// Encode into `out` as TLV type `tlv_type` (3 = Inter-Area-Prefix,
    /// 6 = Intra-Area-Prefix).
    pub fn encode_into(&self, out: &mut Vec<u8>, tlv_type: u16) {
        let mut value = Vec::with_capacity(8 + self.sub_tlvs.len());
        value.push(0);
        value.extend_from_slice(&self.metric.to_be_bytes()[1..4]);
        self.prefix.encode(&mut value);
        value.extend_from_slice(&self.sub_tlvs);
        encode_tlv(out, tlv_type, &value);
    }
}

// ---------------------------------------------------------------------------
// E-Inter-Area-Router TLV (RFC 8362 §3.5)
// ---------------------------------------------------------------------------

/// Inter-Area-Router TLV (RFC 8362 §3.5): the legacy
/// Inter-Area-Router-LSA body (RFC 5340 §A.4.6) as a TLV — the
/// destination ASBR's mirrored options, the path metric and the
/// destination Router ID, plus a sub-TLV region.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EInterAreaRouterTlv {
    /// 24-bit options of the destination router (§A.2).
    pub options: u32,
    /// 24-bit metric of the path to the destination.
    pub metric: u32,
    /// The Router ID of the router being described.
    pub dest_router_id: u32,
}

impl EInterAreaRouterTlv {
    /// The fixed value: 0(1) + options(3) + 0(1) + metric(3) +
    /// destination(4) = 12 octets.
    pub const FIXED_LEN: usize = 12;

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut value = Vec::with_capacity(Self::FIXED_LEN);
        value.push(0);
        value.extend_from_slice(&self.options.to_be_bytes()[1..4]);
        value.push(0);
        value.extend_from_slice(&self.metric.to_be_bytes()[1..4]);
        value.extend_from_slice(&self.dest_router_id.to_be_bytes());
        encode_tlv(out, TLV_INTER_AREA_ROUTER, &value);
    }

    pub fn decode_value(value: &[u8]) -> Option<Self> {
        if value.len() < Self::FIXED_LEN {
            return None;
        }
        Some(Self {
            options: u32::from_be_bytes([0, value[1], value[2], value[3]]),
            metric: u32::from_be_bytes([0, value[5], value[6], value[7]]),
            dest_router_id: u32::from_be_bytes([value[8], value[9], value[10], value[11]]),
        })
    }
}

// ---------------------------------------------------------------------------
// External-Prefix TLV (RFC 8362 §3.6)
// ---------------------------------------------------------------------------

/// External-Prefix TLV (RFC 8362 §3.6): the legacy AS-External-LSA
/// body (RFC 5340 §A.4.7) as a TLV — the E-bit + 24-bit metric word
/// and the prefix — with the forwarding address and route tag demoted
/// to sub-TLVs (1/2/3) and the never-used Referenced LS Type/ID fields
/// dropped. Valid inside the E-AS-External-LSA and the E-Type-7-LSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EExternalPrefixTlv {
    /// `true` = type 2 (larger) external metric (E-bit).
    pub e_bit: bool,
    /// 24-bit metric of the external route.
    pub metric: u32,
    /// The advertised prefix; its `metric` word is the reserved zero.
    pub prefix: V3Prefix,
    /// The global IPv6 forwarding address (sub-TLV 1); `None`
    /// forwards to the ASBR.
    pub ipv6_fwd_addr: Option<[u8; 16]>,
    /// The IPv4 forwarding address (sub-TLV 2), for the IPv4 address
    /// family.
    pub ipv4_fwd_addr: Option<[u8; 4]>,
    /// The external route tag (sub-TLV 3).
    pub route_tag: Option<u32>,
}

impl EExternalPrefixTlv {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut value = Vec::with_capacity(20);
        let mut word = self.metric & EXT_PREFIX_METRIC_MASK;
        if self.e_bit {
            word |= EXT_PREFIX_BIT_E;
        }
        value.extend_from_slice(&word.to_be_bytes());
        self.prefix.encode(&mut value);
        if let Some(fa) = &self.ipv6_fwd_addr {
            encode_tlv(&mut value, SUBTLV_IPV6_FWD_ADDR, fa);
        }
        if let Some(fa) = &self.ipv4_fwd_addr {
            encode_tlv(&mut value, SUBTLV_IPV4_FWD_ADDR, fa);
        }
        if let Some(tag) = &self.route_tag {
            encode_tlv(&mut value, SUBTLV_ROUTE_TAG, &tag.to_be_bytes());
        }
        encode_tlv(out, TLV_EXTERNAL_PREFIX, &value);
    }

    /// Decode from an External-Prefix TLV value. Sub-TLV minimum-length
    /// violations (16/4/4 octets) make the LSA malformed (§3.10-§3.12);
    /// later instances of a repeated sub-TLV are ignored (first wins).
    pub fn decode_value(value: &[u8]) -> Option<Self> {
        if value.len() < 8 {
            return None;
        }
        let word = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        let (prefix, used) = V3Prefix::decode(value, 4)?;
        let mut out = Self {
            e_bit: word & EXT_PREFIX_BIT_E != 0,
            metric: word & EXT_PREFIX_METRIC_MASK,
            prefix,
            ipv6_fwd_addr: None,
            ipv4_fwd_addr: None,
            route_tag: None,
        };
        for sub in walk_tlvs(&value[4 + used..])? {
            match sub.tlv_type {
                SUBTLV_IPV6_FWD_ADDR => {
                    if sub.value.len() < 16 {
                        return None;
                    }
                    if out.ipv6_fwd_addr.is_none() {
                        let mut addr = [0u8; 16];
                        addr.copy_from_slice(&sub.value[..16]);
                        out.ipv6_fwd_addr = Some(addr);
                    }
                }
                SUBTLV_IPV4_FWD_ADDR => {
                    if sub.value.len() < 4 {
                        return None;
                    }
                    if out.ipv4_fwd_addr.is_none() {
                        let mut addr = [0u8; 4];
                        addr.copy_from_slice(&sub.value[..4]);
                        out.ipv4_fwd_addr = Some(addr);
                    }
                }
                SUBTLV_ROUTE_TAG => {
                    if sub.value.len() < 4 {
                        return None;
                    }
                    if out.route_tag.is_none() {
                        out.route_tag = Some(u32::from_be_bytes(sub.value[..4].try_into().ok()?));
                    }
                }
                _ => {}
            }
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Single-TLV LSA bodies: E-Inter-Area-Prefix (§4.3), E-Inter-Area-Router
// (§4.4), E-AS-External / E-Type-7 (§4.5/§4.6)
// ---------------------------------------------------------------------------

/// E-Inter-Area-Prefix-LSA body (RFC 8362 §4.3): no fixed header,
/// exactly one Inter-Area-Prefix TLV — a missing TLV is malformed and
/// later instances are ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EInterAreaPrefixLsaBody(pub EPrefixTlv);

/// E-Inter-Area-Router-LSA body (RFC 8362 §4.4): no fixed header,
/// exactly one Inter-Area-Router TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EInterAreaRouterLsaBody(pub EInterAreaRouterTlv);

/// E-AS-External-LSA body (RFC 8362 §4.5) — also the E-Type-7-LSA body
/// (§4.6): no fixed header, exactly one External-Prefix TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EAsExternalLsaBody(pub EExternalPrefixTlv);

/// Decode a single-required-TLV LSA body: the first TLV of `tlv_type`
/// wins, a missing one is malformed (§4.3/§4.4/§4.5).
fn decode_single_tlv<T>(
    body: &[u8],
    tlv_type: u16,
    decode_value: fn(&[u8]) -> Option<T>,
) -> Option<T> {
    for tlv in walk_tlvs(body)? {
        if tlv.tlv_type == tlv_type {
            return decode_value(tlv.value);
        }
    }
    None
}

impl EInterAreaPrefixLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out, TLV_INTER_AREA_PREFIX);
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        Some(Self(decode_single_tlv(
            body,
            TLV_INTER_AREA_PREFIX,
            EPrefixTlv::decode_value,
        )?))
    }
}

impl EInterAreaRouterLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        Some(Self(decode_single_tlv(
            body,
            TLV_INTER_AREA_ROUTER,
            EInterAreaRouterTlv::decode_value,
        )?))
    }
}

impl EAsExternalLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        Some(Self(decode_single_tlv(
            body,
            TLV_EXTERNAL_PREFIX,
            EExternalPrefixTlv::decode_value,
        )?))
    }
}

// ---------------------------------------------------------------------------
// E-Link-LSA (RFC 8362 §4.7)
// ---------------------------------------------------------------------------

/// E-Link-LSA body (RFC 8362 §4.7): the Rtr Priority + Options header
/// followed by an IPv6 Link-Local Address TLV (§3.8 — required for the
/// IPv6 address family; a missing TLV is malformed), an optional IPv4
/// Link-Local Address TLV (§3.9) and any number of Intra-Area-Prefix
/// TLVs (§3.7). The Link State ID of the enclosing LSA is the
/// advertising router's Interface ID on the link, as in the legacy
/// Link-LSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ELinkLsaBody {
    /// Router priority for DR election on the link.
    pub priority: u8,
    /// 24-bit options the router wants for the link.
    pub options: u32,
    /// The router's IPv6 link-local address on the link (TLV 7).
    pub link_local: [u8; 16],
    /// The router's IPv4 link-local address (TLV 8), for the IPv4
    /// address family.
    pub link_local_v4: Option<[u8; 4]>,
    /// The router's prefixes on the link (TLV 6, multiple allowed).
    pub prefixes: Vec<EPrefixTlv>,
}

impl ELinkLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.priority);
        out.extend_from_slice(&self.options.to_be_bytes()[1..4]);
        encode_tlv(out, TLV_IPV6_LINK_LOCAL, &self.link_local);
        if let Some(v4) = &self.link_local_v4 {
            encode_tlv(out, TLV_IPV4_LINK_LOCAL, v4);
        }
        for p in &self.prefixes {
            p.encode_into(out, TLV_INTRA_AREA_PREFIX);
        }
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 4 {
            return None;
        }
        let mut out = Self {
            priority: body[0],
            options: u32::from_be_bytes([0, body[1], body[2], body[3]]),
            link_local: [0u8; 16],
            link_local_v4: None,
            prefixes: Vec::new(),
        };
        let mut have_ll = false;
        for tlv in walk_tlvs(&body[4..])? {
            match tlv.tlv_type {
                TLV_IPV6_LINK_LOCAL => {
                    if tlv.value.len() < 16 {
                        return None;
                    }
                    if !have_ll {
                        out.link_local.copy_from_slice(&tlv.value[..16]);
                        have_ll = true;
                    }
                }
                TLV_IPV4_LINK_LOCAL => {
                    if tlv.value.len() < 4 {
                        return None;
                    }
                    if out.link_local_v4.is_none() {
                        out.link_local_v4 = Some(tlv.value[..4].try_into().ok()?);
                    }
                }
                TLV_INTRA_AREA_PREFIX => {
                    out.prefixes.push(EPrefixTlv::decode_value(tlv.value)?);
                }
                _ => {}
            }
        }
        // §4.7: the link-local address TLV of the running address
        // family is required — lr speaks the IPv6 family only.
        have_ll.then_some(out)
    }
}

// ---------------------------------------------------------------------------
// E-Intra-Area-Prefix-LSA (RFC 8362 §4.8)
// ---------------------------------------------------------------------------

/// E-Intra-Area-Prefix-LSA body (RFC 8362 §4.8): the 12-byte
/// referenced-LSA header — the Referenced LS Type MUST be the
/// E-Router-LSA (0xA021) or the E-Network-LSA (0xA022) — followed by
/// any number of Intra-Area-Prefix TLVs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EIntraAreaPrefixLsaBody {
    /// [`LS_TYPE_E_ROUTER`] or [`LS_TYPE_E_NETWORK`].
    pub ref_type: u16,
    pub ref_ls_id: u32,
    pub ref_adv_router: u32,
    pub prefixes: Vec<EPrefixTlv>,
}

impl EIntraAreaPrefixLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.ref_type.to_be_bytes());
        out.extend_from_slice(&self.ref_ls_id.to_be_bytes());
        out.extend_from_slice(&self.ref_adv_router.to_be_bytes());
        for p in &self.prefixes {
            p.encode_into(out, TLV_INTRA_AREA_PREFIX);
        }
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 12 {
            return None;
        }
        let mut out = Self {
            ref_type: u16::from_be_bytes([body[2], body[3]]),
            ref_ls_id: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            ref_adv_router: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
            prefixes: Vec::new(),
        };
        for tlv in walk_tlvs(&body[12..])? {
            if tlv.tlv_type == TLV_INTRA_AREA_PREFIX {
                out.prefixes.push(EPrefixTlv::decode_value(tlv.value)?);
            }
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Self-origination helpers (mirror the v3.rs originators)
// ---------------------------------------------------------------------------

/// Originate the router's own E-Router-LSA for an area (RFC 8362 §4.1).
/// Same calling convention as
/// [`crate::lsa::v3::originate_v3_router_lsa`]; the Link State ID is 0
/// and `links` carry the Router-Link TLVs (sub-TLV region included, so
/// SRv6 End.X SIDs ride along). `None` = sequence space exhausted.
pub fn originate_v3_e_router_lsa(
    router_id: u32,
    bits: u8,
    options: u32,
    links: Vec<ERouterLinkTlv>,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(4 + links.len() * 20);
    ERouterLsaBody {
        bits,
        options,
        links,
    }
    .encode(&mut body);
    Some(v3_lsa(LS_TYPE_E_ROUTER, 0, router_id, seq, body))
}

/// Originate an E-Network-LSA for a transit segment where this router
/// is the DR (RFC 8362 §4.2). `dr_interface_id` is our Interface ID on
/// the segment — the Link State ID; `attached_routers` lists every
/// fully adjacent router *including ourselves*. `None` = sequence
/// space exhausted.
pub fn originate_v3_e_network_lsa(
    dr_router_id: u32,
    dr_interface_id: u32,
    options: u32,
    attached_routers: &[u32],
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(8 + attached_routers.len() * 4);
    ENetworkLsaBody {
        options,
        routers: attached_routers.to_vec(),
    }
    .encode(&mut body);
    Some(v3_lsa(
        LS_TYPE_E_NETWORK,
        dr_interface_id,
        dr_router_id,
        seq,
        body,
    ))
}

/// Originate an E-Link-LSA for one interface (RFC 8362 §4.7).
/// `interface_id` is the Link State ID; `link_local` is our IPv6
/// link-local on the link; `prefixes` are the interface's prefixes.
/// `None` = sequence space exhausted.
pub fn originate_v3_e_link_lsa(
    router_id: u32,
    interface_id: u32,
    priority: u8,
    options: u32,
    link_local: [u8; 16],
    prefixes: Vec<EPrefixTlv>,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(24 + prefixes.len() * 8);
    ELinkLsaBody {
        priority,
        options,
        link_local,
        link_local_v4: None,
        prefixes,
    }
    .encode(&mut body);
    Some(v3_lsa(LS_TYPE_E_LINK, interface_id, router_id, seq, body))
}

/// Originate an E-Intra-Area-Prefix-LSA attaching `prefixes` to the
/// referenced E-Router- or E-Network-LSA (RFC 8362 §4.8). `ls_id` is
/// this LSA's own Link State ID (numbered 1, 2, … per §4.8.10 of
/// RFC 5340). `None` = sequence space exhausted.
pub fn originate_v3_e_intra_area_prefix_lsa(
    router_id: u32,
    ls_id: u32,
    ref_type: u16,
    ref_ls_id: u32,
    ref_adv_router: u32,
    prefixes: Vec<EPrefixTlv>,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(12 + prefixes.len() * 8);
    EIntraAreaPrefixLsaBody {
        ref_type,
        ref_ls_id,
        ref_adv_router,
        prefixes,
    }
    .encode(&mut body);
    Some(v3_lsa(LS_TYPE_E_INTRA_PREFIX, ls_id, router_id, seq, body))
}

/// Originate an E-Inter-Area-Prefix-LSA (RFC 8362 §4.3) — the ABR
/// summary route for one prefix. `None` = sequence space exhausted or
/// a non-IPv6 prefix.
pub fn originate_v3_e_inter_area_prefix_lsa(
    router_id: u32,
    ls_id: u32,
    metric: u32,
    prefix: &lr_core::addr::Prefix,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    use lr_core::addr::IpAddr;
    let IpAddr::V6(octets) = prefix.network() else {
        return None;
    };
    let seq = next_sequence(prev_seq)?;
    let tlv = EPrefixTlv {
        metric: metric.min(0x00ff_fffe),
        prefix: V3Prefix {
            prefix_len: prefix.prefix_len,
            options: 0,
            metric: 0,
            addr: octets,
        },
        sub_tlvs: Vec::new(),
    };
    let mut body = Vec::with_capacity(20);
    EInterAreaPrefixLsaBody(tlv).encode(&mut body);
    Some(v3_lsa(LS_TYPE_E_INTER_PREFIX, ls_id, router_id, seq, body))
}

/// Originate an E-Inter-Area-Router-LSA (RFC 8362 §4.4) — the ABR
/// re-advertisement of an ASBR reachable in another area. Same
/// conventions as
/// [`crate::lsa::v3::originate_v3_inter_area_router_lsa`]. `None` =
/// sequence space exhausted.
pub fn originate_v3_e_inter_area_router_lsa(
    router_id: u32,
    ls_id: u32,
    options: u32,
    dest_router_id: u32,
    metric: u32,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(16);
    EInterAreaRouterLsaBody(EInterAreaRouterTlv {
        options,
        metric: metric.min(0x00ff_fffe),
        dest_router_id,
    })
    .encode(&mut body);
    Some(v3_lsa(LS_TYPE_E_INTER_ROUTER, ls_id, router_id, seq, body))
}

/// Originate an E-AS-External-LSA (RFC 8362 §4.5, LS type 0xC025) or an
/// E-Type-7-LSA (§4.6, LS type 0xA027 — same body) for `dest`.
/// `ls_type` must be one of the two. `None` = a non-IPv6 destination,
/// a wrong LS type or an exhausted sequence space.
pub fn originate_v3_e_as_external_lsa(
    ls_type: u16,
    router_id: u32,
    ls_id: u32,
    dest: &crate::lsa::v3::V3ExternalDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    use lr_core::addr::IpAddr;
    if !matches!(ls_type, LS_TYPE_E_AS_EXTERNAL | LS_TYPE_E_TYPE_7) {
        return None;
    }
    let IpAddr::V6(octets) = dest.prefix.network() else {
        return None;
    };
    let seq = next_sequence(prev_seq)?;
    let tlv = EExternalPrefixTlv {
        e_bit: dest.type2,
        metric: dest.metric.min(0x00ff_fffe),
        prefix: V3Prefix {
            prefix_len: dest.prefix.prefix_len,
            options: 0,
            metric: 0,
            addr: octets,
        },
        ipv6_fwd_addr: dest.forwarding_addr,
        ipv4_fwd_addr: None,
        route_tag: dest.route_tag,
    };
    let mut body = Vec::with_capacity(20);
    EAsExternalLsaBody(tlv).encode(&mut body);
    Some(v3_lsa(ls_type, ls_id, router_id, seq, body))
}

#[cfg(test)]
#[path = "e_v3_tests.rs"]
mod tests;
