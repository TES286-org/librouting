//! Self-origination helpers for OSPF speakers.
//!
//! The router pipeline ([`lr_router`]) is poll-driven and deliberately
//! leaves LSA/packet origination to the embedder: it processes what
//! arrives on a session and floods what changed. A real speaker —
//! `lr-daemon` or an embedder — must additionally *produce* its own
//! artifacts:
//!
//! - **Router-LSAs** (RFC 2328 §12.4.1) describing the router's
//!   interfaces: one stub link per attached network plus one
//!   point-to-point link per adjacent neighbor.
//! - **Hello packets** (RFC 2328 §A.3.2) with a correct OSPFv2 packet
//!   checksum so peers that validate checksums (BIRD, FRR) accept them.
//!
//! Both constructors return *finalized* artifacts: the Router-LSA gets
//! its length and RFC 2328 §C.4 checksum; [`finalize_v2_packet`] patches
//! the one's-complement checksum into an encoded OSPFv2 packet (the
//! codec leaves it zeroed).

use crate::abr::{INITIAL_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER};
use crate::lsa::{Lsa, LsaHeader, LsaTypeV2, RouterLink, RouterLinkType};

/// One entry in a Router-LSA under construction: one [`Stub`] per
/// attached network plus one [`PointToPoint`] per adjacent neighbor
/// (raw links cover transit networks and virtual links).
///
/// [`Stub`]: RouterLsaLink::Stub
/// [`PointToPoint`]: RouterLsaLink::PointToPoint
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterLsaLink {
    /// Stub network (§A.4.2 type 3): `link_id` = network address,
    /// `link_data` = network mask, `metric` = interface cost.
    Stub {
        network: u32,
        mask: u32,
        metric: u16,
    },
    /// Point-to-point link to a neighboring router (type 1):
    /// `link_id` = neighbor's router-id, `link_data` = our interface
    /// address, `metric` = interface cost.
    PointToPoint {
        neighbor: u32,
        local_addr: u32,
        metric: u16,
    },
    /// Raw link with explicit fields (transit networks, virtual links).
    Raw(RouterLink),
}

impl RouterLsaLink {
    fn into_router_link(self) -> RouterLink {
        match self {
            Self::Stub {
                network,
                mask,
                metric,
            } => RouterLink {
                link_id: network,
                link_data: mask,
                link_type: RouterLinkType::StubNetwork as u8,
                tos: 0,
                metric,
            },
            Self::PointToPoint {
                neighbor,
                local_addr,
                metric,
            } => RouterLink {
                link_id: neighbor,
                link_data: local_addr,
                link_type: RouterLinkType::PointToPoint as u8,
                tos: 0,
                metric,
            },
            Self::Raw(l) => l,
        }
    }
}

/// Originate the router's own Router-LSA for an area (RFC 2328 §12.4.1).
///
/// `prev_seq` carries the sequence number of the router's current
/// instance (if any) so re-origination advances the sequence space;
/// otherwise the LSA starts at [`INITIAL_SEQUENCE_NUMBER`]. The link
/// state id of a Router-LSA is the originating router-id itself.
///
/// The returned LSA is finalized — length fixed, RFC 2328 §C.4 checksum
/// computed. Returns `None` only when the sequence space is exhausted
/// (§12.1.2: the caller must flush and re-originate).
pub fn originate_router_lsa(
    router_id: u32,
    links: &[RouterLsaLink],
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let mut body = Vec::with_capacity(4 + links.len() * 12);
    body.extend_from_slice(&0u16.to_be_bytes()); // flags (B/E/V bits)
    body.extend_from_slice(&(links.len() as u16).to_be_bytes());
    for link in links {
        let raw = link.clone().into_router_link();
        body.extend_from_slice(&raw.link_id.to_be_bytes());
        body.extend_from_slice(&raw.link_data.to_be_bytes());
        body.push(raw.link_type);
        body.push(raw.tos);
        body.extend_from_slice(&raw.metric.to_be_bytes());
    }
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02, // E-bit: the area can carry external routes
            ls_type: LsaTypeV2::RouterLsa as u8,
            link_state_id: router_id,
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

/// Patch the OSPFv2 packet checksum into an encoded packet.
///
/// The codec emits the checksum field zeroed; RFC 2328 §A.1 requires the
/// standard one's-complement checksum over the whole packet (header
/// *excluding* the 8 authentication bytes, plus body) with the checksum
/// field treated as zero. The AuType and authentication bytes are
/// excluded, exactly like OSPFv2's own definition (§A.1: "the checksum
/// ... is calculated over the whole OSPF packet, excluding the 64-bit
/// authentication field").
///
/// `bytes` must be a complete encoded packet of at least the 24-byte
/// header. The value at offset 12..14 is overwritten.
pub fn finalize_v2_packet(bytes: &mut [u8]) -> bool {
    if bytes.len() < crate::packet::OspfHeader::LEN {
        return false;
    }
    let sum = v2_packet_checksum(bytes);
    bytes[12..14].copy_from_slice(&sum.to_be_bytes());
    true
}

/// Finalize a stream of back-to-back encoded OSPFv2 packets (the shape
/// `drain_output` produces): each packet's checksum is patched in
/// place, walking the length-framed stream. Returns the number of
/// finalized packets.
pub fn finalize_v2_stream(bytes: &mut [u8]) -> usize {
    let mut off = 0usize;
    let mut count = 0usize;
    while off + crate::packet::OspfHeader::LEN <= bytes.len() {
        let len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
        if len < crate::packet::OspfHeader::LEN || off + len > bytes.len() {
            break; // malformed tail — leave the rest untouched
        }
        finalize_v2_packet(&mut bytes[off..off + len]);
        off += len;
        count += 1;
    }
    count
}

/// The OSPFv2 packet checksum of `bytes` (checksum field assumed zero /
/// ignored, authentication bytes excluded).
fn v2_packet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Header without the 8-byte authentication field (offsets 16..24).
    fold(&bytes[..16], &mut sum);
    // Body: from the 24-byte header to the end.
    fold(&bytes[crate::packet::OspfHeader::LEN..], &mut sum);
    finish(sum)
}

/// Verify the checksum of a received OSPFv2 packet.
///
/// The whole-packet sum (checksum field included, authentication bytes
/// excluded) must be `0xffff` for an intact packet — the defining
/// property of one's-complement checksums.
pub fn v2_packet_checksum_ok(bytes: &[u8]) -> bool {
    if bytes.len() < crate::packet::OspfHeader::LEN {
        return false;
    }
    let mut sum: u32 = 0;
    // Header (checksum field included) without the authentication field,
    // then the body.
    fold(&bytes[..16], &mut sum);
    fold(&bytes[crate::packet::OspfHeader::LEN..], &mut sum);
    finish(sum) == 0
}

fn fold(bytes: &[u8], sum: &mut u32) {
    let mut i = 0;
    while i + 1 < bytes.len() {
        *sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    if i < bytes.len() {
        // Odd trailing byte: pad with a zero low byte.
        *sum += u32::from(bytes[i]) << 8;
    }
}
fn finish(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::OspfCodec;
    use crate::packet::{HelloBody, OspfBody, OspfHeader, OspfPacket};

    fn hello() -> OspfPacket {
        OspfPacket {
            header: OspfHeader {
                version: 2,
                kind: 1,
                length: 0,
                router_id: 0x0a00_0001,
                area_id: 0,
                checksum: 0,
                au_type_or_instance: 0,
                auth_data: 0,
            },
            body: OspfBody::Hello(HelloBody {
                network_mask: 0xffff_ff00,
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                dr: 0,
                bdr: 0,
                neighbors: vec![0x0a00_0002, 0x0a00_0003],
            }),
        }
    }

    #[test]
    fn v2_packet_checksum_roundtrip() {
        let mut wire = OspfCodec::v2().encode_vec(&hello()).unwrap();
        assert_eq!(&wire[12..14], &[0, 0], "codec leaves checksum zeroed");
        assert!(finalize_v2_packet(&mut wire));
        let stored = u16::from_be_bytes([wire[12], wire[13]]);
        assert_ne!(stored, 0);
        assert!(v2_packet_checksum_ok(&wire), "checksum must verify");
        // Corruption anywhere the checksum covers must be detected.
        let mut bad = wire.clone();
        bad[wire.len() - 1] ^= 0x01; // last body byte
        assert!(!v2_packet_checksum_ok(&bad));
        let mut bad2 = wire.clone();
        bad2[4] ^= 0x01; // router-id byte (header, pre-auth)
        assert!(!v2_packet_checksum_ok(&bad2));
        // The authentication field is NOT covered: flipping it keeps the
        // checksum valid.
        let mut auth_only = wire.clone();
        auth_only[20] ^= 0xff; // inside the 64-bit auth field
        assert!(v2_packet_checksum_ok(&auth_only));
    }

    #[test]
    fn v2_stream_finalize_walks_frames() {
        let mut a = OspfCodec::v2().encode_vec(&hello()).unwrap();
        let mut b = OspfCodec::v2().encode_vec(&hello()).unwrap();
        b[4] ^= 0x02; // different router-id byte so the frames differ
        let mut stream = a.clone();
        stream.extend_from_slice(&b);
        let count = finalize_v2_stream(&mut stream);
        assert_eq!(count, 2);
        let mid = a.len();
        assert!(v2_packet_checksum_ok(&stream[..mid]));
        assert!(v2_packet_checksum_ok(&stream[mid..]));
        // A malformed trailing frame stops the walk without panicking.
        let mut truncated = stream.clone();
        truncated.truncate(truncated.len() - 4);
        assert_eq!(finalize_v2_stream(&mut truncated), 1);
    }

    #[test]
    fn v2_packet_checksum_short_input() {
        let mut short = vec![0u8; 10];
        assert!(!finalize_v2_packet(&mut short));
        assert!(!v2_packet_checksum_ok(&short));
    }

    #[test]
    fn router_lsa_structure_and_checksum() {
        let lsa = originate_router_lsa(
            0x0a00_0001,
            &[
                RouterLsaLink::Stub {
                    network: 0x0a0a_0a00,
                    mask: 0xffff_ff00,
                    metric: 10,
                },
                RouterLsaLink::PointToPoint {
                    neighbor: 0x0a00_0002,
                    local_addr: 0x0a0a_0a01,
                    metric: 5,
                },
            ],
            None,
        )
        .unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV2::RouterLsa as u8);
        assert_eq!(lsa.header.link_state_id, 0x0a00_0001);
        assert_eq!(lsa.header.advertising_router, 0x0a00_0001);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        // body: 2 flags + 2 count + 2 * 12 link bytes
        assert_eq!(lsa.body.len(), 4 + 24);
        assert_eq!(lsa.header.length as usize, 20 + 4 + 24);
        assert!(lsa.checksum_ok(), "LSA checksum must verify");
        // Link encoding: stub first.
        assert_eq!(&lsa.body[4..8], &0x0a0a_0a00u32.to_be_bytes());
        assert_eq!(&lsa.body[8..12], &0xffff_ff00u32.to_be_bytes());
        assert_eq!(lsa.body[12], RouterLinkType::StubNetwork as u8);
        assert_eq!(&lsa.body[14..16], &10u16.to_be_bytes());
        // Second link starts at 4 + 12 = 16; its metric sits at 26..28.
        assert_eq!(&lsa.body[26..28], &5u16.to_be_bytes());
    }

    #[test]
    fn router_lsa_sequence_advances() {
        let first = originate_router_lsa(1, &[], None).unwrap();
        let seq = first.header.ls_sequence_number;
        let second = originate_router_lsa(
            1,
            &[RouterLsaLink::Stub {
                network: 0,
                mask: 0,
                metric: 1,
            }],
            Some(seq),
        )
        .unwrap();
        assert_eq!(second.header.ls_sequence_number, seq + 1);
        assert!(second.checksum_ok());
        // Exhausted sequence space refuses to originate.
        assert!(originate_router_lsa(1, &[], Some(MAX_SEQUENCE_NUMBER)).is_none());
    }

    #[test]
    fn router_lsa_raw_link_passthrough() {
        let raw = RouterLink {
            link_id: 7,
            link_data: 8,
            link_type: RouterLinkType::VirtualLink as u8,
            tos: 0,
            metric: 99,
        };
        let lsa = originate_router_lsa(1, &[RouterLsaLink::Raw(raw)], None).unwrap();
        // metric field is the last 2 bytes of the link entry
        assert_eq!(&lsa.body[14..16], &99u16.to_be_bytes());
        assert_eq!(lsa.body[12], RouterLinkType::VirtualLink as u8);
    }
}
