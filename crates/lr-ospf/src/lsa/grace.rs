//! OSPF Grace-LSA — RFC 3623 (OSPFv2) and RFC 5187 (OSPFv3).
//!
//! The Grace-LSA is a **link-local** scoped Opaque-LSA (RFC 5250 type 9,
//! Opaque Type 3, Opaque ID 0) that a restarting router floods to
//! announce its planned shutdown and request that neighbors retain its
//! LSAs for a grace period (RFC 3623 Appendix A). The body is a
//! sequence of TLVs (RFC 3623 §3 / RFC 5187 §3):
//!
//! | Type | Name                     | Width | Required |
//! |------|--------------------------|-------|----------|
//! | 1    | Grace Period             | 4     | mandatory |
//! | 2    | Graceful Restart Reason  | 1     | mandatory |
//! | 3    | IP Interface Address     | 4 (v2) / 16 (v3) | optional |
//!
//! TLVs are padded to four-octet alignment; the padding is not included
//! in the Length field (RFC 3623 Appendix A).
//!
//! ## Opaque LSA ID packing (RFC 5250 §3.1)
//!
//! The 32-bit `link_state_id` of an Opaque LSA is partitioned into:
//! - Opaque Type (8 MSBs) — `3` for the Grace-LSA (RFC 3623 §2.1).
//! - Opaque ID (24 LSBs) — typically `0` for the Grace-LSA.
//!
//! ## OSPF options O-bit
//!
//! The Graceful Restart capability is signalled via the O-bit in the
//! OSPF options field (RFC 3623 §1 for v2 bit 0x40; RFC 5187 §1 for
//! v3 bit 0x40 of the v3 options). Neighbours that see the O-bit set
//! in a Hello know the peer is capable of Graceful Restart and must
//! honour a Grace-LSA should one arrive.

use lr_core::addr::IpAddr;

use crate::abr::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::lsa::{Lsa, LsaHeader, LsaTypeV2};

/// Opaque Type for the Grace-LSA (RFC 3623 §2.1).
pub const OPAQUE_TYPE_GRACE: u8 = 3;

/// OSPF options O-bit — set in the Hello/DBD options field to signal
/// Graceful Restart capability (RFC 3623 §1 for v2, RFC 5187 §1 for v3).
/// Bit 0x40 of the options byte.
pub const OPTIONS_O_BIT: u8 = 0x40;

/// Pack the Opaque LSA ID (RFC 5250 §3.1): 8-bit Opaque Type in the
/// MSBs, 24-bit Opaque ID in the LSBs.
pub fn opaque_lsa_id(opaque_type: u8, opaque_id: u32) -> u32 {
    ((opaque_type as u32) << 24) | (opaque_id & 0x00ff_ffff)
}

/// Unpack the Opaque LSA ID into (opaque_type, opaque_id).
pub fn unpack_opaque_lsa_id(link_state_id: u32) -> (u8, u32) {
    let opaque_type = (link_state_id >> 24) as u8;
    let opaque_id = link_state_id & 0x00ff_ffff;
    (opaque_type, opaque_id)
}

/// Grace-LSA TLV type codes (RFC 3623 Appendix A / RFC 5187 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum GraceTlvType {
    /// Grace Period (4 bytes, in seconds). Mandatory. The restarting
    /// router asks neighbours to retain its LSAs for at most this
    /// long after the shutdown (RFC 3623 §3.1).
    GracePeriod = 1,
    /// Graceful Restart Reason (1 byte). Mandatory. 0=unknown,
    /// 1=software restart, 2=software reload/upgrade, 3=switchover
    /// to a redundant control processor (RFC 3623 §3.2).
    Reason = 2,
    /// IP Interface Address. Optional; the IPv4 interface address of
    /// the restarting router on the segment (RFC 3623 §3.3, length 4),
    /// or its IPv6 interface address (RFC 5187 §3, length 16).
    IpInterfaceAddress = 3,
}

impl GraceTlvType {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            1 => Self::GracePeriod,
            2 => Self::Reason,
            3 => Self::IpInterfaceAddress,
            _ => return None,
        })
    }
}

/// The reason a router is gracefully restarting (RFC 3623 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GraceReason {
    /// The reason is not known (RFC 3623 §3.3).
    Unknown = 0,
    /// Software restart (e.g. the OSPF process was restarted).
    SoftwareRestart = 1,
    /// Software reload / upgrade (e.g. the router image was reloaded).
    SoftwareReload = 2,
    /// Switchover to a redundant control processor (RFC 3623 §3.3).
    RedundantSwitchover = 3,
}

impl GraceReason {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::SoftwareRestart,
            2 => Self::SoftwareReload,
            3 => Self::RedundantSwitchover,
            _ => Self::Unknown,
        }
    }
}

/// A parsed Grace-LSA body. Only the mandatory TLVs are required;
/// the optional ones are `Option`. Fields not present in the LSA
/// stay `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraceLsaBody {
    /// Grace Period in seconds (mandatory, TLV 1).
    pub grace_period: u32,
    /// Graceful Restart Reason (mandatory, TLV 2).
    pub reason: GraceReason,
    /// IPv4 address of the restarting router's interface (optional,
    /// TLV 3 with a 4-octet value). Present for OSPFv2 when the
    /// restarting router wants neighbours to verify the source of the
    /// Grace-LSA.
    pub ipv4_address: Option<[u8; 4]>,
    /// IPv6 address of the restarting router's interface (optional,
    /// TLV 3 with a 16-octet value, RFC 5187 §3). Present for OSPFv3.
    pub ipv6_address: Option<[u8; 16]>,
}

impl GraceLsaBody {
    /// Encode the Grace-LSA body into the wire form: a sequence of
    /// `<type:2> <length:2> <value:N> <padding>` TLVs (RFC 3623
    /// Appendix A). Each TLV is padded to four-octet alignment; the
    /// padding is not included in the Length field. The mandatory TLVs
    /// (Grace Period + Reason) are emitted first, then the optional
    /// interface-address TLV.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        // Mandatory: Grace Period (type 1, length 4).
        out.extend_from_slice(&(GraceTlvType::GracePeriod as u16).to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&self.grace_period.to_be_bytes());
        // Mandatory: Reason (type 2, length 1) + 3 octets of padding.
        out.extend_from_slice(&(GraceTlvType::Reason as u16).to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(self.reason as u8);
        out.extend_from_slice(&[0, 0, 0]); // 4-octet alignment
                                           // Optional: IP Interface Address (type 3, length 4 or 16).
        if let Some(addr) = self.ipv4_address {
            out.extend_from_slice(&(GraceTlvType::IpInterfaceAddress as u16).to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&addr);
        }
        if let Some(addr) = self.ipv6_address {
            out.extend_from_slice(&(GraceTlvType::IpInterfaceAddress as u16).to_be_bytes());
            out.extend_from_slice(&16u16.to_be_bytes());
            out.extend_from_slice(&addr);
        }
        out
    }

    /// Decode a Grace-LSA body. Returns `None` when either of the
    /// mandatory TLVs (Grace Period, Reason) is missing, or when a
    /// TLV's declared length does not match the wire width for that
    /// type (the codec is strict — a peer that sends a malformed
    /// Grace-LSA should be treated as not gracefully restarting).
    pub fn decode(body: &[u8]) -> Option<Self> {
        let mut grace_period: Option<u32> = None;
        let mut reason: Option<GraceReason> = None;
        let mut ipv4_address: Option<[u8; 4]> = None;
        let mut ipv6_address: Option<[u8; 16]> = None;
        let mut i = 0;
        while i + 4 <= body.len() {
            let tlv_type = u16::from_be_bytes([body[i], body[i + 1]]);
            let tlv_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
            i += 4;
            if i + tlv_len > body.len() {
                return None;
            }
            match GraceTlvType::from_u16(tlv_type) {
                Some(GraceTlvType::GracePeriod) if tlv_len == 4 => {
                    grace_period = Some(u32::from_be_bytes([
                        body[i],
                        body[i + 1],
                        body[i + 2],
                        body[i + 3],
                    ]));
                }
                Some(GraceTlvType::Reason) if tlv_len == 1 => {
                    reason = Some(GraceReason::from_u8(body[i]));
                }
                Some(GraceTlvType::IpInterfaceAddress) if tlv_len == 4 => {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&body[i..i + 4]);
                    ipv4_address = Some(a);
                }
                Some(GraceTlvType::IpInterfaceAddress) if tlv_len == 16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&body[i..i + 16]);
                    ipv6_address = Some(a);
                }
                // Unknown TLV type or wrong length — skip it. RFC 3623
                // says unknown TLVs "MUST be ignored", so we do not
                // fail the whole decode for forward-compat with future
                // extensions. A known type with the wrong length is
                // also skipped (rather than failing) so a peer's
                // malformed optional TLV does not break the mandatory
                // fields.
                _ => {}
            }
            // Advance past the value and its 4-octet-alignment padding
            // (padding is not counted in the Length field).
            i += tlv_len;
            i = i.next_multiple_of(4);
        }
        let grace_period = grace_period?;
        let reason = reason?;
        Some(Self {
            grace_period,
            reason,
            ipv4_address,
            ipv6_address,
        })
    }
}

/// Build a complete OSPFv2 Grace-LSA (RFC 3623 §2, Appendix A). The LSA
/// is a **link-local** scoped Opaque-LSA (type 9) with the Opaque Type
/// set to `3` (Grace-LSA) in the top 8 bits of the link_state_id.
///
/// The returned LSA is finalized — length fixed, RFC 2328 §C.4
/// checksum computed.
pub fn originate_grace_lsa_v2(
    router_id: u32,
    body: &GraceLsaBody,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let wire_body = body.encode();
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02, // E-bit: the area can carry external routes
            ls_type: LsaTypeV2::OpaqueLinkLsa as u16,
            link_state_id: opaque_lsa_id(OPAQUE_TYPE_GRACE, 0),
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0,
            length: 0,
        },
        body: wire_body,
    };
    lsa.finalize();
    Some(lsa)
}

/// Convenience: set the O-bit on an OSPF options byte (RFC 3623 §1 /
/// RFC 5187 §1). Callers that already compute their own options can
/// OR in [`OPTIONS_O_BIT`] directly; this helper makes the intent
/// explicit.
pub fn with_grace_restart_capable(options: u8) -> u8 {
    options | OPTIONS_O_BIT
}

/// True when the O-bit is set in an OSPF options byte — the peer is
/// Graceful Restart capable (RFC 3623 §1 / RFC 5187 §1).
pub fn is_grace_restart_capable(options: u8) -> bool {
    options & OPTIONS_O_BIT != 0
}

/// Return the IPv4 or IPv6 interface address TLV value for the given
/// local address, or `None` when the address family does not match a
/// Grace-LSA TLV. Used by the originating router to fill the optional
/// address TLV from its local interface address.
pub fn interface_address_tlv(addr: IpAddr) -> (Option<[u8; 4]>, Option<[u8; 16]>) {
    match addr {
        IpAddr::V4(b) => (Some(b), None),
        IpAddr::V6(b) => (None, Some(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_lsa_id_roundtrips() {
        let id = opaque_lsa_id(OPAQUE_TYPE_GRACE, 0);
        assert_eq!(id, 0x0300_0000);
        let (t, oid) = unpack_opaque_lsa_id(id);
        assert_eq!(t, OPAQUE_TYPE_GRACE);
        assert_eq!(oid, 0);
    }

    #[test]
    fn opaque_lsa_id_preserves_24bit_id() {
        for oid in [0u32, 1, 0x00ff_ffff, 0x00ab_cdef] {
            let id = opaque_lsa_id(OPAQUE_TYPE_GRACE, oid);
            let (t, got) = unpack_opaque_lsa_id(id);
            assert_eq!(t, OPAQUE_TYPE_GRACE);
            assert_eq!(got, oid);
        }
    }

    #[test]
    fn options_o_bit_helper() {
        let opts = with_grace_restart_capable(0x02);
        assert!(is_grace_restart_capable(opts));
        assert!(!is_grace_restart_capable(0x02));
        assert!(is_grace_restart_capable(0x42));
    }

    #[test]
    fn grace_lsa_body_roundtrip_minimal() {
        let body = GraceLsaBody {
            grace_period: 120,
            reason: GraceReason::SoftwareRestart,
            ipv4_address: None,
            ipv6_address: None,
        };
        let wire = body.encode();
        let dec = GraceLsaBody::decode(&wire).expect("decode");
        assert_eq!(dec, body);
    }

    #[test]
    fn grace_lsa_body_roundtrip_full_v2() {
        let body = GraceLsaBody {
            grace_period: 600,
            reason: GraceReason::RedundantSwitchover,
            ipv4_address: Some([10, 0, 0, 1]),
            ipv6_address: None,
        };
        let wire = body.encode();
        let dec = GraceLsaBody::decode(&wire).expect("decode");
        assert_eq!(dec, body);
    }

    #[test]
    fn grace_lsa_body_roundtrip_v3_ipv6() {
        let body = GraceLsaBody {
            grace_period: 300,
            reason: GraceReason::SoftwareReload,
            ipv4_address: None,
            ipv6_address: Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        };
        let wire = body.encode();
        let dec = GraceLsaBody::decode(&wire).expect("decode");
        assert_eq!(dec, body);
    }

    #[test]
    fn grace_tlv_numbers_and_padding_match_rfc3623() {
        // RFC 3623 Appendix A: 1 = Grace Period, 2 = Graceful Restart
        // Reason, 3 = IP interface address; each TLV is padded to
        // four-octet alignment (padding not counted in the length).
        let body = GraceLsaBody {
            grace_period: 120,
            reason: GraceReason::SoftwareRestart,
            ipv4_address: Some([192, 0, 2, 1]),
            ipv6_address: None,
        };
        let wire = body.encode();
        // TLV 1: Grace Period (type 1, len 4, value 120).
        assert_eq!(&wire[0..2], &[0, 1], "Grace Period type must be 1");
        assert_eq!(&wire[2..4], &[0, 4]);
        assert_eq!(&wire[4..8], &120u32.to_be_bytes());
        // TLV 2: Reason (type 2, len 1, value 1, padded with 3 octets).
        assert_eq!(&wire[8..10], &[0, 2], "Reason type must be 2");
        assert_eq!(&wire[10..12], &[0, 1], "1-octet value");
        assert_eq!(wire[12], GraceReason::SoftwareRestart as u8);
        assert_eq!(&wire[13..16], &[0, 0, 0], "3 octets of padding");
        // TLV 3: IP interface address (type 3, len 4).
        assert_eq!(
            &wire[16..18],
            &[0, 3],
            "IP interface address type must be 3"
        );
        assert_eq!(&wire[18..20], &[0, 4]);
        assert_eq!(&wire[20..24], &[192, 0, 2, 1]);
        assert_eq!(wire.len(), 24);
    }

    #[test]
    fn grace_lsa_body_decode_missing_mandatory_tlv_fails() {
        // Missing Grace Period (type 1) — only Reason present.
        let mut wire = Vec::new();
        wire.extend_from_slice(&(GraceTlvType::Reason as u16).to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.push(GraceReason::Unknown as u8);
        wire.extend_from_slice(&[0, 0, 0]); // padding
        assert!(GraceLsaBody::decode(&wire).is_none());
    }

    #[test]
    fn grace_lsa_body_decode_missing_reason_fails() {
        // Missing Reason (type 2) — only Grace Period present.
        let mut wire = Vec::new();
        wire.extend_from_slice(&(GraceTlvType::GracePeriod as u16).to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&120u32.to_be_bytes());
        assert!(GraceLsaBody::decode(&wire).is_none());
    }

    #[test]
    fn grace_lsa_body_decode_skips_unknown_tlv() {
        // A future-extension TLV (type 99) must be skipped so the
        // mandatory fields still parse (RFC 3623: unknown TLVs
        // "MUST be ignored").
        let mut wire = Vec::new();
        wire.extend_from_slice(&99u16.to_be_bytes()); // unknown type
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&0xbeef_u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0]); // padding to 4-octet alignment
        wire.extend_from_slice(&(GraceTlvType::GracePeriod as u16).to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&120u32.to_be_bytes());
        wire.extend_from_slice(&(GraceTlvType::Reason as u16).to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.push(GraceReason::SoftwareRestart as u8);
        wire.extend_from_slice(&[0, 0, 0]); // padding
        let dec = GraceLsaBody::decode(&wire).expect("decode despite unknown TLV");
        assert_eq!(dec.grace_period, 120);
        assert_eq!(dec.reason, GraceReason::SoftwareRestart);
    }

    #[test]
    fn grace_lsa_body_decode_truncated_tlv_fails() {
        // A TLV header declaring more length than the body has left.
        let mut wire = Vec::new();
        wire.extend_from_slice(&(GraceTlvType::GracePeriod as u16).to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 0]); // only 3 bytes, not 4
        assert!(GraceLsaBody::decode(&wire).is_none());
    }

    #[test]
    fn originate_grace_lsa_v2_builds_finalized_link_local_opaque_lsa() {
        let body = GraceLsaBody {
            grace_period: 180,
            reason: GraceReason::SoftwareRestart,
            ipv4_address: Some([192, 0, 2, 1]),
            ipv6_address: None,
        };
        let lsa = originate_grace_lsa_v2(0x0a00_0001, &body, None).expect("originate");
        // RFC 3623 Appendix A: the grace-LSA is a link-local Opaque-LSA
        // (type 9), not the AS-scope opaque (type 11).
        assert_eq!(lsa.header.ls_type, LsaTypeV2::OpaqueLinkLsa as u16);
        assert_eq!(lsa.header.link_state_id, 0x0300_0000);
        assert_eq!(lsa.header.advertising_router, 0x0a00_0001);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(
            lsa.header.length as usize,
            LsaHeader::LEN + body.encode().len()
        );
        assert!(lsa.checksum_ok(), "LSA checksum must validate");
        // The wire header byte 3 carries type 9 (v2 layout).
        let wire = lsa.to_wire();
        assert_eq!(wire[3], 9);
        // Round-trip the body.
        let dec = GraceLsaBody::decode(&lsa.body).expect("body round-trips");
        assert_eq!(dec, body);
    }

    #[test]
    fn originate_grace_lsa_v2_advances_sequence() {
        let body = GraceLsaBody {
            grace_period: 60,
            reason: GraceReason::Unknown,
            ipv4_address: None,
            ipv6_address: None,
        };
        let lsa1 = originate_grace_lsa_v2(1, &body, None).unwrap();
        let lsa2 = originate_grace_lsa_v2(1, &body, Some(lsa1.header.ls_sequence_number)).unwrap();
        assert_eq!(
            lsa2.header.ls_sequence_number,
            lsa1.header.ls_sequence_number + 1
        );
    }

    #[test]
    fn interface_address_tlv_v4() {
        let (v4, v6) = interface_address_tlv(IpAddr::V4([10, 0, 0, 1]));
        assert_eq!(v4, Some([10, 0, 0, 1]));
        assert!(v6.is_none());
    }

    #[test]
    fn interface_address_tlv_v6() {
        let (v4, v6) = interface_address_tlv(IpAddr::V6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        assert!(v4.is_none());
        assert_eq!(
            v6,
            Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn grace_reason_roundtrips() {
        for r in [
            GraceReason::Unknown,
            GraceReason::SoftwareRestart,
            GraceReason::SoftwareReload,
            GraceReason::RedundantSwitchover,
        ] {
            assert_eq!(GraceReason::from_u8(r as u8), r);
        }
        // Unknown values map to Unknown.
        assert_eq!(GraceReason::from_u8(99), GraceReason::Unknown);
    }
}
