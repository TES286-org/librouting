//! OSPFv3 LSA bodies (RFC 5340 §A.4) and self-origination helpers.
//!
//! OSPFv3 moves the IPv6 prefixes out of the Router-LSA: the Router-LSA
//! (0x2001) describes only *connectivity* between routers and transit
//! networks, the Link-LSA (0x0008) carries each router's link-local
//! address and its prefixes on one link, and the Intra-Area-Prefix-LSA
//! (0x2009) attaches the actual prefixes to a Router- or Network-LSA.
//! The per-LSA wire shapes implemented here match RFC 5340 §A.4.3
//! (router), §A.4.4 (network), §A.4.9 (link) and §A.4.10
//! (intra-area-prefix) — verified byte-for-byte against FRR's
//! `ospf6_lsa.h` structs (`ospf6_router_lsdesc`, `ospf6_link_lsa`,
//! `ospf6_intra_prefix_lsa`, `ospf6_prefix`).

use crate::abr::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::lsa::{Lsa, LsaHeader};
use lr_core::addr::{IpAddr, Prefix};

/// Router-LSA (0x2001) — area scope.
pub const LS_TYPE_ROUTER: u16 = 0x2001;
/// Network-LSA (0x2002) — area scope.
pub const LS_TYPE_NETWORK: u16 = 0x2002;
/// Inter-Area-Prefix-LSA (0x2003) — area scope.
pub const LS_TYPE_INTER_PREFIX: u16 = 0x2003;
/// Inter-Area-Router-LSA (0x2004) — area scope.
pub const LS_TYPE_INTER_ROUTER: u16 = 0x2004;
/// AS-External-LSA (0x4005) — AS scope.
pub const LS_TYPE_AS_EXTERNAL: u16 = 0x4005;
/// Link-LSA (0x0008) — link scope.
pub const LS_TYPE_LINK: u16 = 0x0008;
/// Intra-Area-Prefix-LSA (0x2009) — area scope.
pub const LS_TYPE_INTRA_PREFIX: u16 = 0x2009;

/// Router-LSA bits (RFC 5340 §A.4.3): the router is an area border
/// router.
pub const ROUTER_BIT_B: u8 = 0x01;
/// Router-LSA bits: the router is an AS boundary router.
pub const ROUTER_BIT_E: u8 = 0x02;
/// Router-LSA bits: the router is fully capable of IPv6 (a cleared V6
/// bit excludes the router from IPv6 routing calculations, §4.8).
pub const ROUTER_BIT_V6: u8 = 0x04;

/// Router-LSA link types (RFC 5340 §A.4.3). Unlike v2 there is no stub
/// type: stub prefixes ride Intra-Area-Prefix-LSAs.
pub const LINK_TYPE_POINTTOPOINT: u8 = 1;
/// Transit network link — the neighbor side is the elected DR.
pub const LINK_TYPE_TRANSIT: u8 = 2;
/// Virtual link (treated as point-to-point, RFC 5340 §4.8.2).
pub const LINK_TYPE_VIRTUAL: u8 = 4;

/// Prefix options (RFC 5340 §A.4.1): no unicast forwarding.
pub const PREFIX_OPT_NU: u8 = 0x01;
/// Prefix options: a local address of the advertising router.
pub const PREFIX_OPT_LA: u8 = 0x02;
/// Prefix options: multicast-capable.
pub const PREFIX_OPT_MC: u8 = 0x04;
/// Prefix options: propagate (NSSA → stub advertisement, §A.4.1).
pub const PREFIX_OPT_P: u8 = 0x08;

/// One IPv6 prefix as encoded in Link-LSAs, Intra-Area-Prefix-LSAs,
/// Inter-Area-Prefix-LSAs and AS-External-LSAs (RFC 5340 §A.4.1):
/// `PrefixLength(1) | PrefixOptions(1) | 2-byte word | address` — the
/// address occupies ceil(len/32) 4-byte words, zero-padded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Prefix {
    /// Prefix length in bits (0..=128).
    pub prefix_len: u8,
    /// [`PREFIX_OPT_*`] bits.
    pub options: u8,
    /// The 2-byte trailing word: the metric for inter-area-prefix and
    /// AS-external prefixes, zero elsewhere (§A.4.1).
    pub metric: u16,
    /// The IPv6 address, network byte order, host bits zeroed.
    pub addr: [u8; 16],
}

impl V3Prefix {
    /// The on-wire size of the address bytes for `prefix_len`:
    /// ceil(len/32) × 4 (§A.4.1 "the fewest possible 32-bit words").
    pub fn addr_bytes_len(prefix_len: u8) -> usize {
        (prefix_len as usize).div_ceil(32) * 4
    }

    /// Encode into `out` (appended). The address is truncated to the
    /// wire size — host bits are the caller's responsibility.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.prefix_len);
        out.push(self.options);
        out.extend_from_slice(&self.metric.to_be_bytes());
        let n = Self::addr_bytes_len(self.prefix_len);
        out.extend_from_slice(&self.addr[..n]);
    }

    /// Decode one prefix starting at `off`. Returns the prefix and the
    /// number of bytes consumed.
    pub fn decode(b: &[u8], off: usize) -> Option<(Self, usize)> {
        if off + 4 > b.len() {
            return None;
        }
        let prefix_len = b[off];
        if prefix_len > 128 {
            return None;
        }
        let options = b[off + 1];
        let metric = u16::from_be_bytes([b[off + 2], b[off + 3]]);
        let n = Self::addr_bytes_len(prefix_len);
        if off + 4 + n > b.len() {
            return None;
        }
        let mut addr = [0u8; 16];
        addr[..n].copy_from_slice(&b[off + 4..off + 4 + n]);
        Some((
            Self {
                prefix_len,
                options,
                metric,
                addr,
            },
            4 + n,
        ))
    }
}

/// One link description in a Router-LSA (RFC 5340 §A.4.3): 16 bytes —
/// `type(1) | 0(1) | metric(2) | Interface ID(4) | Neighbor Interface
/// ID(4) | Neighbor Router ID(4)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3RouterLink {
    /// [`LINK_TYPE_POINTTOPOINT`], [`LINK_TYPE_TRANSIT`] or
    /// [`LINK_TYPE_VIRTUAL`].
    pub link_type: u8,
    /// Output cost of the link.
    pub metric: u16,
    /// The Interface ID of *our* interface on the link (the Link-LSA
    /// Link State ID of that interface).
    pub interface_id: u32,
    /// The Interface ID the *neighbor* uses on the link (from its
    /// Hello).
    pub neighbor_interface_id: u32,
    /// The neighbor's Router ID.
    pub neighbor_router_id: u32,
}

/// Router-LSA body (RFC 5340 §A.4.3): `bits(1) | options(3) | links`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V3RouterLsaBody {
    /// [`ROUTER_BIT_*`] flags.
    pub bits: u8,
    /// 24-bit options (RFC 5340 §A.2).
    pub options: u32,
    pub links: Vec<V3RouterLink>,
}

impl V3RouterLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.bits);
        out.extend_from_slice(&self.options.to_be_bytes()[1..4]);
        // No link-count field (RFC 5340 §A.4.3): descriptors run to the
        // end of the LSA, the receiver derives the count from the length.
        for l in &self.links {
            out.push(l.link_type);
            out.push(0);
            out.extend_from_slice(&l.metric.to_be_bytes());
            out.extend_from_slice(&l.interface_id.to_be_bytes());
            out.extend_from_slice(&l.neighbor_interface_id.to_be_bytes());
            out.extend_from_slice(&l.neighbor_router_id.to_be_bytes());
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        let bits = b[0];
        let options = u32::from_be_bytes([0, b[1], b[2], b[3]]);
        let mut links = Vec::with_capacity(b.len().saturating_sub(4) / 16);
        let mut off = 4;
        // Descriptors run to the end of the body; a trailing fragment
        // shorter than one descriptor is malformed.
        while off < b.len() {
            if off + 16 > b.len() {
                return None;
            }
            links.push(V3RouterLink {
                link_type: b[off],
                metric: u16::from_be_bytes([b[off + 2], b[off + 3]]),
                interface_id: u32::from_be_bytes([b[off + 4], b[off + 5], b[off + 6], b[off + 7]]),
                neighbor_interface_id: u32::from_be_bytes([
                    b[off + 8],
                    b[off + 9],
                    b[off + 10],
                    b[off + 11],
                ]),
                neighbor_router_id: u32::from_be_bytes([
                    b[off + 12],
                    b[off + 13],
                    b[off + 14],
                    b[off + 15],
                ]),
            });
            off += 16;
        }
        Some(Self {
            bits,
            options,
            links,
        })
    }
}

/// Network-LSA body (RFC 5340 §A.4.4): `0(1) | options(3) | Router IDs`.
/// The Link State ID of the LSA is the DR's Interface ID on the network;
/// there is no netmask (the network's prefix rides an Intra-Area-Prefix
/// LSA referencing this LSA).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V3NetworkLsaBody {
    /// 24-bit options (RFC 5340 §A.2).
    pub options: u32,
    /// The Router IDs of every fully adjacent router on the network,
    /// DR included (§4.4.3.2).
    pub routers: Vec<u32>,
}

impl V3NetworkLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&self.options.to_be_bytes()[1..4]);
        for r in &self.routers {
            out.extend_from_slice(&r.to_be_bytes());
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        let options = u32::from_be_bytes([0, b[1], b[2], b[3]]);
        let mut routers = Vec::new();
        let mut off = 4;
        while off + 4 <= b.len() {
            routers.push(u32::from_be_bytes([
                b[off],
                b[off + 1],
                b[off + 2],
                b[off + 3],
            ]));
            off += 4;
        }
        Some(Self { options, routers })
    }
}

/// Link-LSA body (RFC 5340 §A.4.9): `priority(1) | options(3) |
/// link-local(16) | #prefixes(4) | prefixes`. The LSA's Link State ID is
/// the Interface ID of the advertising router's interface on the link;
/// link-scoped flooding makes the (advertising router, interface ID)
/// pair the unique key the SPF uses to resolve a neighbor's link-local
/// address (§4.4.3.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V3LinkLsaBody {
    /// Router priority for DR election on the link.
    pub priority: u8,
    /// 24-bit options the router wants for the link (§4.4.3.4).
    pub options: u32,
    /// The router's link-local address on the link — the value every
    /// IPv6 next hop toward this router resolves to.
    pub link_local: [u8; 16],
    /// The router's prefixes on the link (metric word zero, §A.4.1).
    pub prefixes: Vec<V3Prefix>,
}

impl V3LinkLsaBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.priority);
        out.extend_from_slice(&self.options.to_be_bytes()[1..4]);
        out.extend_from_slice(&self.link_local);
        out.extend_from_slice(&(self.prefixes.len() as u32).to_be_bytes());
        for p in &self.prefixes {
            p.encode(out);
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 24 {
            return None;
        }
        let priority = b[0];
        let options = u32::from_be_bytes([0, b[1], b[2], b[3]]);
        let mut link_local = [0u8; 16];
        link_local.copy_from_slice(&b[4..20]);
        let n = u32::from_be_bytes([b[20], b[21], b[22], b[23]]) as usize;
        let mut prefixes = Vec::with_capacity(n.min(64));
        let mut off = 24;
        for _ in 0..n {
            let (p, used) = V3Prefix::decode(b, off)?;
            prefixes.push(p);
            off += used;
        }
        Some(Self {
            priority,
            options,
            link_local,
            prefixes,
        })
    }
}

/// Intra-Area-Prefix-LSA body (RFC 5340 §A.4.10): `#prefixes(2) |
/// ref LS type(2) | ref LS ID(4) | ref Adv Router(4) | prefixes`. The
/// referenced LSA is a Router-LSA (the router's own interface prefixes,
/// §4.4.3.5) or a Network-LSA (the network's prefix, originated by the
/// DR).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V3IntraAreaPrefixBody {
    /// The referenced LSA type: [`LS_TYPE_ROUTER`] or
    /// [`LS_TYPE_NETWORK`].
    pub ref_type: u16,
    /// The referenced LSA's Link State ID.
    pub ref_ls_id: u32,
    /// The referenced LSA's Advertising Router.
    pub ref_adv_router: u32,
    /// The prefixes (metric word zero, §A.4.1).
    pub prefixes: Vec<V3Prefix>,
}

impl V3IntraAreaPrefixBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.prefixes.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ref_type.to_be_bytes());
        out.extend_from_slice(&self.ref_ls_id.to_be_bytes());
        out.extend_from_slice(&self.ref_adv_router.to_be_bytes());
        for p in &self.prefixes {
            p.encode(out);
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 12 {
            return None;
        }
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        let ref_type = u16::from_be_bytes([b[2], b[3]]);
        let ref_ls_id = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let ref_adv_router = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        let mut prefixes = Vec::with_capacity(n.min(256));
        let mut off = 12;
        for _ in 0..n {
            let (p, used) = V3Prefix::decode(b, off)?;
            prefixes.push(p);
            off += used;
        }
        Some(Self {
            ref_type,
            ref_ls_id,
            ref_adv_router,
            prefixes,
        })
    }
}

/// Inter-Area-Router-LSA body (RFC 5340 §A.4.6): `0 | options(3) |
/// 0 | metric(3) | Destination Router ID`. The body describes one
/// destination router (an ASBR) reachable in another area; the Options
/// field mirrors the destination's own Router-LSA options (§4.4.3.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V3InterAreaRouterBody {
    /// 24-bit options of the destination router (§A.2).
    pub options: u32,
    /// 24-bit metric of the path to the destination.
    pub metric: u32,
    /// The Router ID of the router being described.
    pub dest_router_id: u32,
}

impl V3InterAreaRouterBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(0);
        out.extend_from_slice(&self.options.to_be_bytes()[1..4]);
        out.push(0);
        out.extend_from_slice(&self.metric.to_be_bytes()[1..4]);
        out.extend_from_slice(&self.dest_router_id.to_be_bytes());
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 12 {
            return None;
        }
        Some(Self {
            options: u32::from_be_bytes([0, b[1], b[2], b[3]]),
            metric: u32::from_be_bytes([0, b[5], b[6], b[7]]),
            dest_router_id: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        })
    }
}

/// AS-External-LSA flag bits (RFC 5340 §A.4.7) — the top byte of the
/// 32-bit flags+metric word. Distinct from the v2 layout, where the E
/// bit is the top bit of the word (RFC 2328 §A.4.5): FRR's
/// `ospf6_asbr.h` pins E=0x04000000 / F=0x02000000 / T=0x01000000.
pub const AS_EXT_BIT_E: u32 = 0x0400_0000;
/// AS-External-LSA flags: a forwarding address follows the prefix.
pub const AS_EXT_BIT_F: u32 = 0x0200_0000;
/// AS-External-LSA flags: an external route tag follows.
pub const AS_EXT_BIT_T: u32 = 0x0100_0000;
/// The 24-bit metric mask of the flags+metric word (FRR
/// `OSPF6_EXT_PATH_METRIC_MAX`).
pub const AS_EXT_METRIC_MASK: u32 = 0x00ff_ffff;

/// AS-External-LSA body (RFC 5340 §A.4.7): `E|F|T | metric(3) |
/// prefix` with the prefix's trailing 16-bit word carrying the
/// Referenced LS Type (not a metric), then the optional forwarding
/// address (16 bytes), external route tag (4 bytes) and referenced
/// Link State ID (4 bytes) — each present if and only if its bit is
/// set (F, T) or the referenced LS type is non-zero.
///
/// The forwarding address is a *global* IPv6 address: unspecified and
/// link-local values are illegal (§A.4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3AsExternalBody {
    /// The external metric type: `true` = type 2 (E bit set).
    pub e_bit: bool,
    /// 24-bit metric of the external route.
    pub metric: u32,
    /// The advertised prefix (§A.4.1); the prefix's trailing 16-bit
    /// word carries the Referenced LS Type — [`V3Prefix::metric`] here.
    pub prefix: V3Prefix,
    /// The global IPv6 forwarding address (F bit); `None` forwards to
    /// the ASBR.
    pub forwarding_addr: Option<[u8; 16]>,
    /// The external route tag (T bit).
    pub route_tag: Option<u32>,
    /// The referenced LSA's Link State ID, present if and only if the
    /// Referenced LS Type is non-zero (reserved — should stay 0, §4.4.3.6).
    pub referenced_ls_id: Option<u32>,
}

impl V3AsExternalBody {
    /// The advertised prefix reconstructed from the wire form (the
    /// trailing padding bytes are zero, so the result equals the
    /// originator's network-normalized prefix).
    pub fn prefix_addr_prefix(&self) -> Option<Prefix> {
        Some(Prefix::new_v6(self.prefix.addr, self.prefix.prefix_len))
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut flags = 0u32;
        if self.e_bit {
            flags |= AS_EXT_BIT_E;
        }
        if self.forwarding_addr.is_some() {
            flags |= AS_EXT_BIT_F;
        }
        if self.route_tag.is_some() {
            flags |= AS_EXT_BIT_T;
        }
        flags |= self.metric & AS_EXT_METRIC_MASK;
        out.extend_from_slice(&flags.to_be_bytes());
        self.prefix.encode(out);
        if let Some(fa) = &self.forwarding_addr {
            out.extend_from_slice(fa);
        }
        if let Some(tag) = &self.route_tag {
            out.extend_from_slice(&tag.to_be_bytes());
        }
        if self.prefix.metric != 0 {
            out.extend_from_slice(&self.referenced_ls_id.unwrap_or(0).to_be_bytes());
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        let flags = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let e_bit = flags & AS_EXT_BIT_E != 0;
        let metric = flags & AS_EXT_METRIC_MASK;
        let (prefix, used) = V3Prefix::decode(b, 4)?;
        let mut off = 4 + used;
        let forwarding_addr = if flags & AS_EXT_BIT_F != 0 {
            if off + 16 > b.len() {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&b[off..off + 16]);
            off += 16;
            Some(addr)
        } else {
            None
        };
        let route_tag = if flags & AS_EXT_BIT_T != 0 {
            if off + 4 > b.len() {
                return None;
            }
            let tag = u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
            off += 4;
            Some(tag)
        } else {
            None
        };
        // The Referenced Link State ID is present if and only if the
        // Referenced LS Type (the prefix's trailing word) is non-zero
        // (§A.4.7); the referenced-LSA mechanism is reserved and the
        // type should be 0, so a nonzero value is tolerated (decoded,
        // ignored by the calculation — §4.4.3.6) but never dropped.
        let referenced_ls_id = if prefix.metric != 0 {
            if off + 4 > b.len() {
                return None;
            }
            let id = u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
            Some(id)
        } else {
            None
        };
        Some(Self {
            e_bit,
            metric,
            prefix,
            forwarding_addr,
            route_tag,
            referenced_ls_id,
        })
    }
}

/// Advance a sequence number one step (§12.1.2). Shared by the v3
/// originators: `None` starts at `INITIAL_SEQUENCE_NUMBER`, an exhausted
/// space refuses to originate.
fn next_sequence(prev: Option<u32>) -> Option<u32> {
    match prev {
        None => Some(INITIAL_SEQUENCE_NUMBER),
        Some(MAX_SEQUENCE_NUMBER) => None,
        Some(p) => Some(p + 1),
    }
}

fn v3_lsa(ls_type: u16, link_state_id: u32, adv_router: u32, seq: u32, body: Vec<u8>) -> Lsa {
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            // v3 LSA headers carry no options byte (RFC 5340 §A.4.2).
            options: 0,
            ls_type,
            link_state_id,
            advertising_router: adv_router,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body,
    };
    lsa.finalize();
    lsa
}

/// Originate the router's own Router-LSA for an area (RFC 5340 §4.4.3.2).
///
/// `bits` carries the [`ROUTER_BIT_*`] flags (a regular IPv6 router sets
/// V6, plus B/E as applicable); `options` is the 24-bit word the body
/// advertises (usually [`crate::packet::OSPF_V3_OPTIONS_DEFAULT`]).
/// `links` are the §A.4.3 link descriptions built from the router's
/// adjacencies. The Link State ID is 0 (one Router-LSA per area).
/// `prev_seq` carries the current instance's sequence for
/// re-origination; the returned LSA is finalized. `None` = sequence
/// space exhausted (§12.1.2).
pub fn originate_v3_router_lsa(
    router_id: u32,
    bits: u8,
    options: u32,
    links: &[V3RouterLink],
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(4 + links.len() * 16);
    V3RouterLsaBody {
        bits,
        options,
        links: links.to_vec(),
    }
    .encode(&mut body);
    Some(v3_lsa(LS_TYPE_ROUTER, 0, router_id, seq, body))
}

/// Originate a Network-LSA for a transit segment where this router is
/// the DR (RFC 5340 §4.4.3.2). `dr_interface_id` is our Interface ID on
/// the segment — the Link State ID (§A.4.4); `attached_routers` lists
/// every fully adjacent router *including ourselves*. `None` = sequence
/// space exhausted.
pub fn originate_v3_network_lsa(
    dr_router_id: u32,
    dr_interface_id: u32,
    options: u32,
    attached_routers: &[u32],
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(4 + attached_routers.len() * 4);
    V3NetworkLsaBody {
        options,
        routers: attached_routers.to_vec(),
    }
    .encode(&mut body);
    Some(v3_lsa(
        LS_TYPE_NETWORK,
        dr_interface_id,
        dr_router_id,
        seq,
        body,
    ))
}

/// Originate a Link-LSA for one interface (RFC 5340 §4.4.3.4 — "a
/// router MUST originate a separate Link-LSA for each attached link").
/// `interface_id` is the Link State ID; `link_local` is our link-local
/// address on the link (the address neighbors resolve their next hops
/// to) and `prefixes` are the addresses configured on the interface.
/// `None` = sequence space exhausted.
pub fn originate_v3_link_lsa(
    router_id: u32,
    interface_id: u32,
    priority: u8,
    options: u32,
    link_local: [u8; 16],
    prefixes: Vec<V3Prefix>,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(24 + prefixes.len() * 8);
    V3LinkLsaBody {
        priority,
        options,
        link_local,
        prefixes,
    }
    .encode(&mut body);
    Some(v3_lsa(LS_TYPE_LINK, interface_id, router_id, seq, body))
}

/// Originate an Intra-Area-Prefix-LSA attaching `prefixes` to the
/// referenced Router- or Network-LSA (RFC 5340 §4.4.3.5). `ls_id` is
/// this LSA's own Link State ID — a router may originate several
/// Intra-Area-Prefix-LSAs per area, disambiguated by the Link State ID
/// (§4.4.3.5 recommends numbering them 1, 2, …). `None` = sequence
/// space exhausted.
pub fn originate_v3_intra_area_prefix_lsa(
    router_id: u32,
    ls_id: u32,
    ref_type: u16,
    ref_ls_id: u32,
    ref_adv_router: u32,
    prefixes: Vec<V3Prefix>,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(12 + prefixes.len() * 8);
    V3IntraAreaPrefixBody {
        ref_type,
        ref_ls_id,
        ref_adv_router,
        prefixes,
    }
    .encode(&mut body);
    Some(v3_lsa(LS_TYPE_INTRA_PREFIX, ls_id, router_id, seq, body))
}

/// Originate an OSPFv3 inter-area-router-LSA (type 0x2004) for an AS
/// boundary router (RFC 5340 §A.4.6). The ABR re-advertises the
/// location of an ASBR reachable in another area, exactly like the v2
/// type-4 summary-ASBR-LSA; `options` mirrors the destination router's
/// own Router-LSA options (§4.4.3.5).
///
/// `ls_id` is the 32-bit link-state ID the ABR assigns to this LSA —
/// unlike v2 it carries no addressing semantics (§4.4.3.5); the
/// destination's Router ID travels in the body. Reference
/// implementations pin it to the destination router ID, which is also
/// this crate's convention. `None` = sequence space exhausted.
pub fn originate_v3_inter_area_router_lsa(
    router_id: u32,
    ls_id: u32,
    options: u32,
    dest_router_id: u32,
    metric: u32,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = next_sequence(prev_seq)?;
    let mut body = Vec::with_capacity(12);
    V3InterAreaRouterBody {
        options,
        metric: metric.min(0x00ff_fffe),
        dest_router_id,
    }
    .encode(&mut body);
    Some(v3_lsa(LS_TYPE_INTER_ROUTER, ls_id, router_id, seq, body))
}

/// One externally redistributed destination on the OSPFv3 plane
/// (RFC 5340 §4.4.3.6) — the v3 counterpart of the v2
/// [`crate::external::ExternalDestination`].
///
/// The metric is capped just below LSInfinity (`0x00ff_ffff`). The
/// forwarding address, when present, MUST be a global IPv6 address —
/// unspecified and link-local values are illegal (§A.4.7); `None`
/// forwards traffic to the ASBR itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3ExternalDestination {
    /// The external IPv6 prefix.
    pub prefix: Prefix,
    pub metric: u32,
    /// `true` = type 2 metric (E bit set).
    pub type2: bool,
    /// The global IPv6 forwarding address (F bit); `None` = the ASBR.
    pub forwarding_addr: Option<[u8; 16]>,
    /// The external route tag (T bit); `None` omits the field.
    pub route_tag: Option<u32>,
}

impl V3ExternalDestination {
    pub fn new(prefix: Prefix, metric: u32, type2: bool) -> Self {
        Self {
            prefix,
            metric: metric.min(0x00ff_fffe),
            type2,
            forwarding_addr: None,
            route_tag: None,
        }
    }
}

/// Originate an OSPFv3 AS-external-LSA (type 0x4005) for `dest`
/// (RFC 5340 §A.4.7). `ls_id` is the 32-bit link-state ID the ASBR
/// assigns to this LSA — it carries no addressing semantics (§4.4.3.6)
/// and must be stable across re-origination for one prefix. The
/// prefix's Referenced LS Type word stays 0 (the referenced-LSA
/// mechanism is reserved, §4.4.3.6). Returns `None` for non-IPv6
/// destinations or when the sequence space is exhausted.
pub fn originate_v3_as_external_lsa(
    router_id: u32,
    ls_id: u32,
    dest: &V3ExternalDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let IpAddr::V6(octets) = dest.prefix.network() else {
        return None; // the v3 external plane advertises IPv6 prefixes
    };
    let seq = next_sequence(prev_seq)?;
    let body = {
        let mut b = Vec::with_capacity(4 + 8 + 24);
        V3AsExternalBody {
            e_bit: dest.type2,
            metric: dest.metric,
            prefix: V3Prefix {
                prefix_len: dest.prefix.prefix_len,
                options: 0,
                metric: 0, // Referenced LS Type — reserved, stays 0
                addr: octets,
            },
            forwarding_addr: dest.forwarding_addr,
            route_tag: dest.route_tag,
            referenced_ls_id: None,
        }
        .encode(&mut b);
        b
    };
    Some(v3_lsa(LS_TYPE_AS_EXTERNAL, ls_id, router_id, seq, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix64(addr_hi: u16) -> V3Prefix {
        let mut addr = [0u8; 16];
        addr[0..2].copy_from_slice(&addr_hi.to_be_bytes());
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        V3Prefix {
            prefix_len: 64,
            options: 0,
            metric: 0,
            addr,
        }
    }

    /// §A.4.3: the Router-LSA body is bits(1) + options(3) + 16-byte link
    /// descriptors running to the end of the LSA (no count field — the
    /// receiver derives it from the LSA length, FRR ospf6_lsa.h parity).
    /// Type 1 (p2p), metric 10, interface id 5, neighbor
    /// interface id 3, neighbor router id 0x0a00_0002.
    #[test]
    fn router_lsa_body_wire_shape() {
        let body = V3RouterLsaBody {
            bits: ROUTER_BIT_B | ROUTER_BIT_E | ROUTER_BIT_V6,
            options: 0x13,
            links: vec![V3RouterLink {
                link_type: LINK_TYPE_POINTTOPOINT,
                metric: 10,
                interface_id: 5,
                neighbor_interface_id: 3,
                neighbor_router_id: 0x0a00_0002,
            }],
        };
        let mut wire = Vec::new();
        body.encode(&mut wire);
        assert_eq!(wire.len(), 4 + 16);
        assert_eq!(wire[0], 0x07, "B|E|V6");
        assert_eq!(&wire[1..4], &[0, 0, 0x13], "24-bit options");
        assert_eq!(
            &wire[4..20],
            &[
                1, // p2p
                0, 0, 10, // metric
                0, 0, 0, 5, // interface id
                0, 0, 0, 3, // neighbor interface id
                0x0a, 0x00, 0x00, 0x02, // neighbor router id
            ]
        );
        let back = V3RouterLsaBody::decode(&wire).unwrap();
        assert_eq!(back, body);
        // Trailing garbage: decode must not run off the buffer.
        assert!(V3RouterLsaBody::decode(&wire[..15]).is_none());
    }

    /// §A.4.4: Network-LSA body = 0(1) + options(3) + Router IDs.
    #[test]
    fn network_lsa_body_wire_shape() {
        let body = V3NetworkLsaBody {
            options: 0x13,
            routers: vec![0x0a00_0001, 0x0a00_0002],
        };
        let mut wire = Vec::new();
        body.encode(&mut wire);
        assert_eq!(wire.len(), 12);
        assert_eq!(
            &wire,
            &[0, 0, 0, 0x13, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02]
        );
        assert_eq!(V3NetworkLsaBody::decode(&wire).unwrap(), body);
    }

    /// §A.4.9: Link-LSA body = priority(1) + options(3) + link-local(16)
    /// + #prefixes(4) + prefixes; a /64 prefix occupies 4 + 8 bytes.
    #[test]
    fn link_lsa_body_wire_shape() {
        let body = V3LinkLsaBody {
            priority: 1,
            options: 0x13,
            link_local: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            prefixes: vec![prefix64(0x2001)],
        };
        let mut wire = Vec::new();
        body.encode(&mut wire);
        assert_eq!(wire.len(), 24 + 12);
        assert_eq!(wire[0], 1, "priority");
        assert_eq!(&wire[1..4], &[0, 0, 0x13]);
        assert_eq!(&wire[4..20], &body.link_local);
        assert_eq!(&wire[20..24], &1u32.to_be_bytes(), "prefix count");
        assert_eq!(wire[24], 64, "prefix length");
        assert_eq!(wire[25], 0, "prefix options");
        assert_eq!(&wire[26..28], &[0, 0], "metric word zero");
        assert_eq!(&wire[28..36], &body.prefixes[0].addr[..8]);
        assert_eq!(V3LinkLsaBody::decode(&wire).unwrap(), body);
    }

    /// §A.4.10: Intra-Area-Prefix body = #prefixes(2) + ref type(2) +
    /// ref LS ID(4) + ref Adv Router(4) + prefixes.
    #[test]
    fn intra_area_prefix_body_wire_shape() {
        let body = V3IntraAreaPrefixBody {
            ref_type: LS_TYPE_ROUTER,
            ref_ls_id: 0,
            ref_adv_router: 0x0a00_0001,
            prefixes: vec![
                prefix64(0x2001),
                V3Prefix {
                    prefix_len: 32,
                    options: PREFIX_OPT_LA,
                    metric: 0,
                    addr: [0u8; 16],
                },
            ],
        };
        let mut wire = Vec::new();
        body.encode(&mut wire);
        // /64 → 4+8 bytes; /32 → 4+4 bytes.
        assert_eq!(wire.len(), 12 + 12 + 8);
        assert_eq!(&wire[0..2], &2u16.to_be_bytes());
        assert_eq!(&wire[2..4], &[0x20, 0x01]);
        let back = V3IntraAreaPrefixBody::decode(&wire).unwrap();
        assert_eq!(back, body);
        assert_eq!(back.prefixes[1].prefix_len, 32);
        assert_eq!(back.prefixes[1].options, PREFIX_OPT_LA);
    }

    /// A /32 prefix occupies 4+4 bytes on the wire (ceil(32/32)×4);
    /// a /127 occupies 4+16 (ceil(127/32)=4 words).
    #[test]
    fn prefix_addr_bytes_len_rounding() {
        assert_eq!(V3Prefix::addr_bytes_len(0), 0);
        assert_eq!(V3Prefix::addr_bytes_len(1), 4);
        assert_eq!(V3Prefix::addr_bytes_len(32), 4);
        assert_eq!(V3Prefix::addr_bytes_len(33), 8);
        assert_eq!(V3Prefix::addr_bytes_len(64), 8);
        assert_eq!(V3Prefix::addr_bytes_len(96), 12);
        assert_eq!(V3Prefix::addr_bytes_len(127), 16);
        assert_eq!(V3Prefix::addr_bytes_len(128), 16);
    }

    /// The originated v3 Router-LSA carries type 0x2001, LS ID 0 and a
    /// valid Fletcher checksum; re-origination advances the sequence.
    #[test]
    fn originate_v3_router_lsa_shape() {
        let links = vec![V3RouterLink {
            link_type: LINK_TYPE_POINTTOPOINT,
            metric: 10,
            interface_id: 5,
            neighbor_interface_id: 3,
            neighbor_router_id: 0x0a00_0002,
        }];
        let lsa = originate_v3_router_lsa(
            0x0a00_0001,
            ROUTER_BIT_B | ROUTER_BIT_V6,
            0x13,
            &links,
            None,
        )
        .unwrap();
        assert_eq!(lsa.header.ls_type, LS_TYPE_ROUTER);
        assert_eq!(lsa.header.link_state_id, 0);
        assert_eq!(lsa.header.advertising_router, 0x0a00_0001);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsa.header.options, 0, "v3 headers carry no options byte");
        assert!(lsa.checksum_ok(), "LSA checksum must verify");
        let decoded = V3RouterLsaBody::decode(&lsa.body).unwrap();
        assert_eq!(decoded.bits, ROUTER_BIT_B | ROUTER_BIT_V6);
        assert_eq!(decoded.options, 0x13);
        assert_eq!(decoded.links, links);
        let next = originate_v3_router_lsa(
            0x0a00_0001,
            0,
            0x13,
            &links,
            Some(lsa.header.ls_sequence_number),
        )
        .unwrap();
        assert_eq!(next.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
        // Sequence exhaustion refuses to originate (§12.1.2).
        assert!(originate_v3_router_lsa(1, 0, 0, &links, Some(MAX_SEQUENCE_NUMBER)).is_none());
    }

    /// The Link-LSA's Link State ID is the Interface ID; the body
    /// round-trips the link-local address.
    #[test]
    fn originate_v3_link_lsa_shape() {
        let ll = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let lsa = originate_v3_link_lsa(0x0a00_0001, 7, 1, 0x13, ll, vec![], None).unwrap();
        assert_eq!(lsa.header.ls_type, LS_TYPE_LINK);
        assert_eq!(lsa.header.link_state_id, 7, "LS ID = interface id");
        assert!(lsa.checksum_ok());
        let decoded = V3LinkLsaBody::decode(&lsa.body).unwrap();
        assert_eq!(decoded.link_local, ll);
        assert!(decoded.prefixes.is_empty());
    }

    /// An Intra-Area-Prefix LSA referencing a Network-LSA round-trips
    /// with its ref fields intact.
    #[test]
    fn originate_v3_intra_prefix_references_network() {
        let prefixes = vec![prefix64(0x2001)];
        let lsa = originate_v3_intra_area_prefix_lsa(
            0x0a00_0002,
            1,
            LS_TYPE_NETWORK,
            5,
            0x0a00_0002,
            prefixes.clone(),
            None,
        )
        .unwrap();
        assert_eq!(lsa.header.ls_type, LS_TYPE_INTRA_PREFIX);
        assert_eq!(lsa.header.link_state_id, 1);
        let decoded = V3IntraAreaPrefixBody::decode(&lsa.body).unwrap();
        assert_eq!(decoded.ref_type, LS_TYPE_NETWORK);
        assert_eq!(decoded.ref_ls_id, 5);
        assert_eq!(decoded.ref_adv_router, 0x0a00_0002);
        assert_eq!(decoded.prefixes, prefixes);
    }

    /// §A.4.6: the Inter-Area-Router body is 0(1) + options(3) +
    /// 0(1) + metric(3) + destination router ID — 12 bytes total.
    /// Shape from RFC 5340 §4.4.3.5's RT7 example: options
    /// V6|E|R = 0x13 (v2 §A.2 bit values), metric 14, dest 0x0a00_0007.
    #[test]
    fn inter_area_router_body_wire_shape() {
        let body = V3InterAreaRouterBody {
            options: 0x13,
            metric: 14,
            dest_router_id: 0x0a00_0007,
        };
        let mut wire = Vec::new();
        body.encode(&mut wire);
        assert_eq!(wire.len(), 12);
        assert_eq!(
            &wire,
            &[
                0, 0, 0, 0x13, // options (24-bit)
                0, 0, 0, 14, // metric (24-bit)
                0x0a, 0x00, 0x00, 0x07, // destination router ID
            ]
        );
        assert_eq!(V3InterAreaRouterBody::decode(&wire).unwrap(), body);
        assert!(V3InterAreaRouterBody::decode(&wire[..11]).is_none());
    }

    /// The originated 0x2004 LSA carries the destination in the body,
    /// the caller's LS ID and a valid checksum; the metric is capped
    /// below LSInfinity.
    #[test]
    fn originate_v3_inter_area_router_lsa_shape() {
        let lsa = originate_v3_inter_area_router_lsa(
            0x0a00_0004,
            0x0a00_0007,
            0x13,
            0x0a00_0007,
            14,
            None,
        )
        .unwrap();
        assert_eq!(lsa.header.ls_type, LS_TYPE_INTER_ROUTER);
        assert_eq!(lsa.header.link_state_id, 0x0a00_0007, "LS ID = destination");
        assert_eq!(lsa.header.advertising_router, 0x0a00_0004);
        assert_eq!(lsa.header.length, 20 + 12);
        assert!(lsa.checksum_ok());
        let decoded = V3InterAreaRouterBody::decode(&lsa.body).unwrap();
        assert_eq!(decoded.dest_router_id, 0x0a00_0007);
        assert_eq!(decoded.metric, 14);
        assert_eq!(decoded.options, 0x13);
        let next = originate_v3_inter_area_router_lsa(
            0x0a00_0004,
            0x0a00_0007,
            0x13,
            0x0a00_0007,
            14,
            Some(lsa.header.ls_sequence_number),
        )
        .unwrap();
        assert_eq!(next.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
        // LSInfinity metrics are capped at origination.
        let capped = originate_v3_inter_area_router_lsa(1, 2, 0, 3, 0xffff_ffff, None).unwrap();
        assert_eq!(
            V3InterAreaRouterBody::decode(&capped.body).unwrap().metric,
            0x00ff_fffe
        );
    }

    /// §A.4.7: the AS-External body is E|F|T + metric(3) + prefix (with
    /// the trailing word = Referenced LS Type), then the optional
    /// forwarding address / route tag / referenced LS ID. The
    /// RFC 5340 §4.4.3.6 N12 example: type 2 (E), tag, metric 2, /40
    /// prefix (8 wire bytes); LS ID 123 is arbitrary per §4.4.3.6.
    #[test]
    fn as_external_body_wire_shape() {
        let mut addr = [0u8; 16];
        addr[0..2].copy_from_slice(&0x2001u16.to_be_bytes());
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[4] = 0x0a;
        let body = V3AsExternalBody {
            e_bit: true,
            metric: 2,
            prefix: V3Prefix {
                prefix_len: 40,
                options: 0,
                metric: 0,
                addr,
            },
            forwarding_addr: None,
            route_tag: Some(7),
            referenced_ls_id: None,
        };
        let mut wire = Vec::new();
        body.encode(&mut wire);
        // 4 flags/metric + 4 prefix header + 8 prefix address + 4 tag.
        assert_eq!(wire.len(), 20);
        assert_eq!(&wire[0..4], &[0x05, 0, 0, 2], "E|T set, metric 2");
        assert_eq!(wire[4], 40, "prefix length");
        assert_eq!(wire[5], 0, "prefix options");
        assert_eq!(&wire[6..8], &[0, 0], "referenced LS type 0");
        assert_eq!(&wire[8..16], &addr[..8], "prefix address (8 words)");
        assert_eq!(&wire[16..20], &7u32.to_be_bytes(), "route tag");
        assert_eq!(V3AsExternalBody::decode(&wire).unwrap(), body);
        // Truncation never panics.
        for cut in [0usize, 3, 7, 11, 15, 19] {
            assert!(V3AsExternalBody::decode(&wire[..cut]).is_none());
        }
    }

    /// F/T bit round-trip: a forwarding address rides the body if and
    /// only if the F bit is set; the tag if and only if T is set.
    #[test]
    fn as_external_forwarding_address_round_trip() {
        let mut fa = [0u8; 16];
        fa[0] = 0x20;
        fa[1] = 0x01;
        let body = V3AsExternalBody {
            e_bit: false,
            metric: 100,
            prefix: V3Prefix {
                prefix_len: 64,
                options: 0,
                metric: 0,
                addr: [0x20; 16],
            },
            forwarding_addr: Some(fa),
            route_tag: None,
            referenced_ls_id: None,
        };
        let mut wire = Vec::new();
        body.encode(&mut wire);
        assert_eq!(wire[0], 0x02, "F set, E clear");
        assert_eq!(wire.len(), 4 + 12 + 16);
        let back = V3AsExternalBody::decode(&wire).unwrap();
        assert_eq!(back.forwarding_addr, Some(fa));
        assert_eq!(back.route_tag, None);
        assert!(!back.e_bit);
        assert_eq!(back.metric, 100);
    }

    /// The originated 0x4005 LSA pins the E/F/T layout FRR uses
    /// (E=0x04000000, distinct from the v2 top-bit form), normalizes
    /// host bits on the prefix and refuses non-IPv6 destinations.
    #[test]
    fn originate_v3_as_external_lsa_shape() {
        let dest = V3ExternalDestination::new(
            Prefix::new_v6(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, 0x99,
                ],
                48,
            ),
            150,
            true,
        );
        let lsa = originate_v3_as_external_lsa(0x0a00_0007, 123, &dest, None).unwrap();
        assert_eq!(lsa.header.ls_type, LS_TYPE_AS_EXTERNAL);
        assert_eq!(lsa.header.link_state_id, 123);
        assert_eq!(lsa.header.advertising_router, 0x0a00_0007);
        assert!(lsa.checksum_ok());
        // /48 → 8 wire bytes; the /48 host bits (0x0999 in the last two
        // bytes) are zeroed.
        assert_eq!(lsa.header.length, 20 + 4 + 4 + 8);
        let decoded = V3AsExternalBody::decode(&lsa.body).unwrap();
        assert!(decoded.e_bit);
        assert_eq!(decoded.metric, 150);
        assert_eq!(decoded.prefix.prefix_len, 48);
        assert_eq!(decoded.prefix.metric, 0, "referenced LS type 0");
        assert_eq!(&decoded.prefix.addr[..6], &[0x20, 0x01, 0x0d, 0xb8, 0, 0]);
        assert!(decoded.forwarding_addr.is_none());
        let next =
            originate_v3_as_external_lsa(0x0a00_0007, 123, &dest, Some(0x8000_0005)).unwrap();
        assert_eq!(next.header.ls_sequence_number, 0x8000_0006);
        // Non-IPv6 destinations are refused.
        let v4dest = V3ExternalDestination::new(Prefix::new_v4([10, 0, 0, 0], 8), 10, false);
        assert!(originate_v3_as_external_lsa(1, 2, &v4dest, None).is_none());
        // A global forwarding address sets the F bit and rides the body.
        let mut with_fa = dest;
        with_fa.forwarding_addr =
            Some([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let lsa = originate_v3_as_external_lsa(0x0a00_0007, 123, &with_fa, None).unwrap();
        assert_eq!(lsa.header.length, 20 + 4 + 4 + 8 + 16);
        let decoded = V3AsExternalBody::decode(&lsa.body).unwrap();
        assert_eq!(
            decoded.forwarding_addr,
            Some([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }
}
