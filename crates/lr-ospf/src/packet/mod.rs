//! OSPF versions.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OspfVersion {
    V2 = 2,
    V3 = 3,
}

impl OspfVersion {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            2 => Self::V2,
            3 => Self::V3,
            _ => return None,
        })
    }
}

/// The default OSPFv3 Options set a regular router advertises in
/// Hellos, DBDs and router/network/link LSAs: V6 | E | R
/// (RFC 5340 §A.2 — 0x01 | 0x02 | 0x10).
pub const OSPF_V3_OPTIONS_DEFAULT: u32 = 0x01 | 0x02 | 0x10;

/// OSPF packet header. v2 and v3 share the leading fields but differ in
/// length: v2 (RFC 2328 §A.3.1) is 24 bytes (AuType + 64-bit authentication
/// trailing), v3 (RFC 5340 §A.3.1) is 16 bytes — the header ends with
/// Checksum | Instance ID | 0.
///
/// For v3 the header is followed *directly* by the body: [`OspfHeader::LEN`]
/// is the v2 length; use [`OspfHeader::len_for`] wherever the version is
/// known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfHeader {
    pub version: u8,
    pub kind: u8,
    pub length: u16,
    pub router_id: u32,
    pub area_id: u32,
    /// v2: packet checksum (RFC 2328 §A.1); v3: IPv6 upper-layer checksum
    /// over the pseudo-header (RFC 5340 §A.3.1).
    pub checksum: u16,
    /// v2: AuType; v3: Instance ID (low byte — the wire's byte 15 is the
    /// reserved zero).
    pub au_type_or_instance: u16,
    /// v2: Authentication data; v3: absent from the wire (kept zero).
    pub auth_data: u64,
}

impl OspfHeader {
    /// The v2 header length (RFC 2328 §A.3.1).
    pub const LEN: usize = 24;
    /// The v3 header length (RFC 5340 §A.3.1).
    pub const LEN_V3: usize = 16;

    /// The on-wire header length for `version`.
    pub fn len_for(version: OspfVersion) -> usize {
        match version {
            OspfVersion::V2 => Self::LEN,
            OspfVersion::V3 => Self::LEN_V3,
        }
    }
}

/// OSPF packet type (RFC 2328 §A.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OspfPacketType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAck = 5,
}

impl OspfPacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Hello,
            2 => Self::DatabaseDescription,
            3 => Self::LinkStateRequest,
            4 => Self::LinkStateUpdate,
            5 => Self::LinkStateAck,
            _ => return None,
        })
    }
}

impl fmt::Display for OspfPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Hello => "Hello",
            Self::DatabaseDescription => "DBDesc",
            Self::LinkStateRequest => "LS-Request",
            Self::LinkStateUpdate => "LS-Update",
            Self::LinkStateAck => "LS-Ack",
        })
    }
}

/// Top-level OSPF packet envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfPacket {
    pub header: OspfHeader,
    pub body: OspfBody,
}

/// OSPF packet body. Each variant corresponds to one of the 5 packet types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfBody {
    Hello(HelloBody),
    DbDesc(DbDescBody),
    LsRequest(LsRequestBody),
    LsUpdate(LsUpdateBody),
    LsAck(LsAckBody),
    /// Raw bytes for unrecognized or unsupported bodies.
    Raw(Vec<u8>),
}

/// Hello packet body (RFC 2328 §A.3.2 / RFC 5340 §A.3.2.1).
///
/// The first 4 bytes of the Hello body are version-overloaded:
///   - **OSPFv2** (RFC 2328 §A.3.2) carries the network mask of the
///     interface originating the Hello.
///   - **OSPFv3** (RFC 5340 §A.3.2.1) carries the 4-byte Interface ID
///     of the originating interface — v3 has no network mask, so the
///     slot is reused. The Interface ID matches the Link State ID of
///     the interface's Link-LSA (RFC 5340 §A.4.9), letting a receiver
///     correlate the Hello with the matching Link-LSA.
///
/// The field is named `network_mask` for the v2 wire slot, and stays
/// `pub` because the public struct shape is part of the 1.0+ ABI
/// freeze — renaming the field would force a major bump. The dual
/// semantics live at the call site: a v2 caller reading `body.network_mask`
/// sees the network mask, a v3 caller reading the same field sees
/// the Interface ID. The misleading shape — `body.network_mask` reads
/// as "the network mask is 7" on a v3 Hello — is what the
/// [`HelloBody::interface_id`] / [`HelloBody::network_mask`] accessors
/// address: a v3 caller writes `body.interface_id()` and a v2 caller
/// writes `body.network_mask()`, so the intent is self-documenting at
/// every call site without the inline `// v3: Interface ID slot`
/// comments the codec and daemon previously carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloBody {
    /// v2: network mask. v3: the 4-byte Interface ID (there is no
    /// network mask in v3 Hellos). Use [`HelloBody::network_mask`] for
    /// the v2 read path and [`HelloBody::interface_id`] for the v3
    /// read path; the field stays `pub` only for struct-literal
    /// construction at sites where the version is locally obvious.
    pub network_mask: u32,
    pub hello_interval: u16,
    /// v2: 8-bit options. v3: 24-bit options (stored in the low 24 bits).
    pub options: u32,
    pub priority: u8,
    pub dead_interval: u32,
    pub dr: u32,
    pub bdr: u32,
    pub neighbors: Vec<u32>,
}

impl HelloBody {
    /// OSPFv2 network mask (RFC 2328 §A.3.2). Reading this for an
    /// OSPFv3 Hello is a misuse — v3 has no network mask; the same
    /// wire slot carries the 4-byte Interface ID
    /// ([`HelloBody::interface_id`] is the v3 accessor).
    ///
    /// Provided as a self-documenting accessor for the v2 semantics
    /// so a v2 caller writes `body.network_mask()` instead of
    /// `body.network_mask`, mirroring the v3 side. The underlying
    /// `network_mask` field stays public for struct-literal
    /// construction at sites where the version is locally obvious.
    pub const fn network_mask(&self) -> u32 {
        self.network_mask
    }

    /// OSPFv3 Interface ID (RFC 5340 §A.3.2.1) — the 4-byte wire slot
    /// that v2 uses for the network mask. v3 has no network mask; the
    /// slot identifies the interface the Hello was sent on, so the
    /// receiver can correlate it with the matching Link-LSA (per
    /// §A.4.9, the Link-LSA's Link State ID equals this Interface ID).
    ///
    /// Reading `body.network_mask` for v3 looks like "the network
    /// mask is 7" — misleading on its face. This accessor makes the
    /// v3 intent self-documenting at the call site. The two
    /// accessors read the same byte; the dual semantics live in the
    /// codec, which selects the interpretation based on
    /// [`OspfVersion`].
    pub const fn interface_id(&self) -> u32 {
        self.network_mask
    }

    /// Builder-style setter for the v2 network mask. The field stays
    /// public for struct-literal construction; this method documents
    /// the v2 intent at the call site so a reader sees
    /// `.with_network_mask(0xffffff00)` instead of
    /// `network_mask: 0xffffff00` followed by an inline comment
    /// explaining what the field is.
    #[must_use]
    pub fn with_network_mask(mut self, mask: u32) -> Self {
        self.network_mask = mask;
        self
    }

    /// Builder-style setter for the v3 Interface ID. The field stays
    /// public for struct-literal construction; this method documents
    /// the v3 intent at the call site — `.with_interface_id(7)` reads
    /// as "Interface ID 7", while `network_mask: 7` reads as "the
    /// network mask is 7", which is misleading on a v3 Hello.
    #[must_use]
    pub fn with_interface_id(mut self, interface_id: u32) -> Self {
        self.network_mask = interface_id;
        self
    }
}

/// Database Description (RFC 2328 §A.3.3 / RFC 5340 §A.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbDescBody {
    pub mtu: u16,
    /// v2: 8-bit options. v3: 24-bit options (stored in the low 24 bits).
    pub options: u32,
    pub flags: u8, // bits: I, M, MS
    pub dd_seq: u32,
    pub lsa_headers: Vec<crate::lsa::LsaHeader>,
}

/// LS-Request entry (RFC 2328 §A.3.4: (LS type, LS ID, Adv Router);
/// RFC 5340 §A.3.4: (LS type, unused, LS ID, Adv Router)). The type is
/// widened to `u16` so v3's 16-bit LS types (e.g. 0x2003) are preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsRequestEntry {
    pub ls_type: u16,
    pub ls_id: u32,
    pub adv_router: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsRequestBody {
    pub entries: Vec<LsRequestEntry>,
}

/// LS-Update (RFC 2328 §A.3.5): # of advertisements + list of LSAs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsUpdateBody {
    pub lsa_count: u32,
    pub lsas: Vec<crate::lsa::Lsa>,
}

/// LS-Ack (RFC 2328 §A.3.6): list of LSA headers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LsAckBody {
    pub lsa_headers: Vec<crate::lsa::LsaHeader>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The v2 and v3 accessors read the same wire slot; the dual
    /// semantics live at the call site, not in the field. A v2
    /// caller uses [`HelloBody::network_mask`] / `with_network_mask`;
    /// a v3 caller uses [`HelloBody::interface_id`] /
    /// `with_interface_id`. Both shapes see the same byte — the
    /// accessors are intentional mirrors so the v3 path does not
    /// have to reach into the v2-named `network_mask` field.
    #[test]
    fn hello_body_v2_and_v3_accessors_share_one_slot() {
        let v2 = HelloBody {
            network_mask: 0xffff_ff00,
            hello_interval: 10,
            options: 0x02,
            priority: 1,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            neighbors: vec![],
        };
        assert_eq!(v2.network_mask(), 0xffff_ff00);
        // The v3 accessor reads the same slot. A v3 caller would
        // never construct this body (the slot is an Interface ID
        // for v3, not a mask), but the accessors agree byte-for-byte
        // so a decoder that does not branch on version produces the
        // same byte through either accessor.
        assert_eq!(v2.interface_id(), 0xffff_ff00);

        let v3 = HelloBody {
            network_mask: 0,
            hello_interval: 10,
            options: 0x13,
            priority: 1,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            neighbors: vec![],
        }
        .with_interface_id(7);
        assert_eq!(v3.interface_id(), 7);
        // The `network_mask` field carries the v3 Interface ID
        // value because the wire slot is shared — the dual semantics
        // live at the accessor, not the field.
        assert_eq!(v3.network_mask, 7);
        assert_eq!(v3.network_mask(), 7);
    }

    /// The v2 builder mirrors the v3 builder so a v2 construction
    /// site reads as `.with_network_mask(0xffffff00)` instead of
    /// `network_mask: 0xffffff00` followed by an inline comment
    /// explaining what the field is. The two builders write the
    /// same slot; the named method documents which version's
    /// semantics the caller has in mind.
    #[test]
    fn hello_body_with_network_mask_builder_round_trips() {
        let v2 = HelloBody {
            network_mask: 0,
            hello_interval: 10,
            options: 0x02,
            priority: 1,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            neighbors: vec![],
        }
        .with_network_mask(0xffff_ff00);
        assert_eq!(v2.network_mask(), 0xffff_ff00);
        assert_eq!(v2.network_mask, 0xffff_ff00);
    }

    /// `with_interface_id` is a `#[must_use]` builder — the
    /// returned `HelloBody` carries the slot value, not the
    /// receiver. A caller that ignores the return value would
    /// silently drop the assignment; the lint surfaces the bug
    /// at the call site. The same shape applies to
    /// `with_network_mask`.
    #[test]
    fn hello_body_with_interface_id_overrides_struct_literal_value() {
        // Construct with `network_mask: 0` (the v2-shaped struct
        // literal), then call `with_interface_id(7)` to set the
        // v3 slot. The struct-literal value is overwritten by the
        // builder — the builder is the documented v3 path, so a
        // reader sees `with_interface_id(7)` and not the
        // misleading `network_mask: 0` it overrode.
        let v3 = HelloBody {
            network_mask: 0,
            hello_interval: 10,
            options: 0x13,
            priority: 1,
            dead_interval: 40,
            dr: 0,
            bdr: 0,
            neighbors: vec![],
        }
        .with_interface_id(7);
        assert_eq!(v3.interface_id(), 7);
        assert_ne!(
            v3.network_mask, 0,
            "the builder overwrote the struct-literal value"
        );
    }
}
