//! ABR summary-LSA origination (RFC 2328 §12.4.3).
//!
//! An area border router re-advertises reachability between the areas it
//! attaches to by originating type-3 summary-LSAs:
//!
//! - into the backbone: the intra-area networks of each non-backbone area;
//! - into a non-backbone area: the routes derived from the backbone
//!   (its intra-area networks plus the inter-area routes other ABRs
//!   summarized into it).
//!
//! This one-direction-via-backbone rule is what keeps inter-area paths
//! loop-free without virtual links (§16.2).
//!
//! All helpers target OSPFv2 LSA encodings (RFC 2328 §A.4.3 bodies,
//! 32-bit link-state IDs). OSPFv3 inter-area-prefix-LSAs use a different
//! body format and are not originated here.
//!
//! # Link-state ID collisions
//!
//! The link-state ID of a summary-LSA is the summarized network address.
//! Two prefixes whose network addresses coincide with different lengths
//! (e.g. `10.0.0.0/8` and `10.0.0.0/16`) therefore collide on one LSA —
//! reference implementations remap the ID in that case. This crate does
//! not remap: the last originated LSA wins the `(type, ls-id, adv)`
//! key. Embedders requiring overlapping prefixes should summarize at a
//! single length.

use crate::lsa::{encode_summary_lsa_body, prefix_len_to_mask, Lsa, LsaHeader, LsaTypeV2};
use lr_core::addr::Prefix;

/// RFC 2328 §12.1.2: the first sequence number of a newly originated LSA.
pub const INITIAL_SEQUENCE_NUMBER: u32 = 0x8000_0001;
/// RFC 2328 §12.1.2: the largest sequence number an LSA may carry.
pub const MAX_SEQUENCE_NUMBER: u32 = 0x7fff_ffff;

/// One destination an ABR summarizes into another area: a prefix and the
/// metric to advertise. The metric is capped just below LSInfinity
/// (`0x00ff_ffff`), which is reserved to mean "unreachable".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryDestination {
    pub prefix: Prefix,
    pub metric: u32,
}

impl SummaryDestination {
    pub fn new(prefix: Prefix, metric: u32) -> Self {
        Self {
            prefix,
            metric: metric.min(0x00ff_fffe),
        }
    }
}

/// Originate a type-3 summary-LSA for `dest` (RFC 2328 §12.4.3).
///
/// `prev_seq` carries the sequence number of the router's current
/// instance for this link-state ID (if any): the new LSA continues the
/// sequence space, otherwise it starts at `INITIAL_SEQUENCE_NUMBER`.
/// The returned LSA is finalized — length fixed, RFC 2328 §C.4 checksum
/// computed.
///
/// Returns `None` for non-IPv4 destinations (v3 bodies are not
/// originated) or when the sequence space is exhausted (the caller must
/// flush the LSA and re-originate, §12.1.2).
pub fn originate_summary_lsa(
    router_id: u32,
    dest: &SummaryDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let lr_core::addr::IpAddr::V4(octets) = dest.prefix.addr else {
        return None; // v2 link-state IDs are 32-bit IPv4 networks
    };
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let mask = prefix_len_to_mask(dest.prefix.prefix_len);
    let network = u32::from_be_bytes(octets) & mask;
    let body = encode_summary_lsa_body(mask, dest.metric);
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02,
            ls_type: LsaTypeV2::SummaryIpLsa as u8,
            link_state_id: network,
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

/// Build the MaxAge instance that flushes `existing` from all databases
/// (RFC 2328 §14.1: age the LSA to MaxAge and flood). The sequence number
/// advances so peers accept the flush as newer.
///
/// Returns `None` when the sequence number cannot advance (wrapped past
/// `MAX_SEQUENCE_NUMBER`).
pub fn flush_summary_lsa(existing: &Lsa) -> Option<Lsa> {
    existing.maxage_flush()
}

// ---------------------------------------------------------------------------
// OSPFv3 inter-area-prefix-LSA origination (RFC 5340 §A.4.5 / §4.4.3.1)
// ---------------------------------------------------------------------------

/// Originate an OSPFv3 inter-area-prefix-LSA (type 0x2003) for `dest`
/// (RFC 5340 §A.4.5). The ABR re-advertises reachability to a prefix
/// from one area into another, exactly like the v2 type-3 summary-LSA.
///
/// `ls_id` is the 32-bit link-state ID the ABR assigns to this LSA.
/// Unlike v2 (where the LS-ID is the network address), v3 uses an
/// arbitrary counter because the prefix is 128 bits wide. The caller is
/// responsible for tracking LS-ID → prefix mappings.
///
/// `prev_seq` carries the sequence number of the router's current
/// instance for this link-state ID (if any). The returned LSA is
/// finalized — length fixed, RFC 2328 §C.4 checksum computed.
///
/// Returns `None` when the sequence space is exhausted.
pub fn originate_v3_inter_area_prefix_lsa(
    router_id: u32,
    ls_id: u32,
    dest: &SummaryDestination,
    prev_seq: Option<u32>,
) -> Option<Lsa> {
    let seq = match prev_seq {
        None => INITIAL_SEQUENCE_NUMBER,
        Some(MAX_SEQUENCE_NUMBER) => return None,
        Some(p) => p + 1,
    };
    let body = crate::lsa::encode_v3_inter_area_prefix_body(&dest.prefix, dest.metric);
    let mut lsa = Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x00, // v3 options — the embedder can set V/E/x bits
            ls_type: LsaTypeV3::InterAreaPrefixLsa.function_code(),
            link_state_id: ls_id,
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

use crate::lsa::LsaTypeV3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsa::decode_summary_lsa_body;
    use crate::lsdb::MAX_AGE_SECS;
    use lr_core::addr::IpAddr;

    fn net(a: u32, len: u8) -> Prefix {
        Prefix::new_v4(a.to_be_bytes(), len)
    }

    #[test]
    fn originate_first_instance() {
        let dest = SummaryDestination::new(net(0x0a0a0a00, 24), 10);
        let lsa = originate_summary_lsa(0x01020304, &dest, None).unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV2::SummaryIpLsa as u8);
        assert_eq!(lsa.header.link_state_id, 0x0a0a0a00);
        assert_eq!(lsa.header.advertising_router, 0x01020304);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsa.header.ls_age, 0);
        assert_eq!(lsa.header.length, 28); // 20 header + 8 body
        let body = decode_summary_lsa_body(&lsa.body).unwrap();
        assert_eq!(body.network_mask, 0xffff_ff00);
        assert_eq!(body.tos0_metric(), Some(10));
        assert!(
            lsa.checksum_ok(),
            "originated LSA must carry a valid checksum"
        );
    }

    #[test]
    fn originate_continues_sequence() {
        let dest = SummaryDestination::new(net(0x0a0a0a00, 24), 20);
        let lsa = originate_summary_lsa(1, &dest, Some(0x80000005)).unwrap();
        assert_eq!(lsa.header.ls_sequence_number, 0x80000006);
        assert!(lsa.checksum_ok());
    }

    #[test]
    fn originate_masks_host_bits() {
        // Host bits must be zero in the link-state ID.
        let dest = SummaryDestination::new(net(0x0a0a0aff, 24), 5);
        let lsa = originate_summary_lsa(1, &dest, None).unwrap();
        assert_eq!(lsa.header.link_state_id, 0x0a0a0a00);
    }

    #[test]
    fn originate_rejects_v6_and_max_sequence() {
        let v6 = Prefix::new_v6([0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64);
        assert!(originate_summary_lsa(1, &SummaryDestination::new(v6, 5), None).is_none());
        assert!(originate_summary_lsa(
            1,
            &SummaryDestination::new(net(1, 32), 5),
            Some(MAX_SEQUENCE_NUMBER)
        )
        .is_none());
    }

    #[test]
    fn metric_capped_below_ls_infinity() {
        let dest = SummaryDestination::new(net(1, 32), 0xffff_ffff);
        assert_eq!(dest.metric, 0x00ff_fffe);
    }

    #[test]
    fn flush_ages_to_max_and_advances_sequence() {
        let dest = SummaryDestination::new(net(0x0a0a0a00, 24), 10);
        let lsa = originate_summary_lsa(1, &dest, None).unwrap();
        let flush = flush_summary_lsa(&lsa).unwrap();
        assert_eq!(flush.header.ls_age, MAX_AGE_SECS);
        assert_eq!(flush.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER + 1);
        assert!(flush.checksum_ok());
        assert!(flush_summary_lsa(&{
            let mut m = lsa.clone();
            m.header.ls_sequence_number = MAX_SEQUENCE_NUMBER;
            m
        })
        .is_none());
    }

    #[test]
    fn v4_assert_covers_ipaddr_import() {
        // Prefix::addr is an IpAddr — keep the import honest for future
        // match arms.
        let p = Prefix::new_v4([10, 0, 0, 0], 8);
        assert!(matches!(p.addr, IpAddr::V4(_)));
    }

    // ---- OSPFv3 inter-area-prefix-LSA tests ----

    fn v6_prefix(a: [u8; 16], len: u8) -> Prefix {
        Prefix::new_v6(a, len)
    }

    #[test]
    fn v3_originate_first_instance() {
        let dest = SummaryDestination::new(
            v6_prefix(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                64,
            ),
            10,
        );
        let lsa = originate_v3_inter_area_prefix_lsa(0x01020304, 1, &dest, None).unwrap();
        assert_eq!(lsa.header.ls_type, LsaTypeV3::InterAreaPrefixLsa.function_code());
        assert_eq!(lsa.header.link_state_id, 1); // arbitrary LS-ID
        assert_eq!(lsa.header.advertising_router, 0x01020304);
        assert_eq!(lsa.header.ls_sequence_number, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsa.header.ls_age, 0);
        assert!(lsa.checksum_ok(), "v3 LSA must carry a valid checksum");

        let body = crate::lsa::decode_v3_inter_area_prefix_body(&lsa.body).unwrap();
        assert_eq!(body.metric, 10);
        assert_eq!(body.prefix_len, 64);
        // 64 bits = 8 bytes of prefix
        assert_eq!(body.prefix_bytes.len(), 8);
        assert_eq!(&body.prefix_bytes, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    }

    #[test]
    fn v3_originate_continues_sequence() {
        let dest = SummaryDestination::new(
            v6_prefix([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128),
            20,
        );
        let lsa = originate_v3_inter_area_prefix_lsa(1, 5, &dest, Some(0x80000005)).unwrap();
        assert_eq!(lsa.header.ls_sequence_number, 0x80000006);
        assert_eq!(lsa.header.link_state_id, 5);
        assert!(lsa.checksum_ok());

        // 128 bits = 16 bytes of prefix
        let body = crate::lsa::decode_v3_inter_area_prefix_body(&lsa.body).unwrap();
        assert_eq!(body.prefix_len, 128);
        assert_eq!(body.prefix_bytes.len(), 16);
    }

    #[test]
    fn v3_originate_caps_metric() {
        let dest = SummaryDestination::new(
            v6_prefix([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64),
            0xffff_ffff,
        );
        assert_eq!(dest.metric, 0x00ff_fffe);
        let lsa = originate_v3_inter_area_prefix_lsa(1, 1, &dest, None).unwrap();
        let body = crate::lsa::decode_v3_inter_area_prefix_body(&lsa.body).unwrap();
        assert_eq!(body.metric, 0x00ff_fffe);
    }

    #[test]
    fn v3_originate_rejects_max_sequence() {
        let dest = SummaryDestination::new(
            v6_prefix([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 64),
            5,
        );
        assert!(originate_v3_inter_area_prefix_lsa(1, 1, &dest, Some(MAX_SEQUENCE_NUMBER)).is_none());
    }

    #[test]
    fn v3_roundtrip_preserves_prefix() {
        let prefix = v6_prefix(
            [0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            48,
        );
        let dest = SummaryDestination::new(prefix, 42);
        let lsa = originate_v3_inter_area_prefix_lsa(0x0a0a0a0a, 7, &dest, None).unwrap();
        let body = crate::lsa::decode_v3_inter_area_prefix_body(&lsa.body).unwrap();
        let decoded = body.to_prefix().unwrap();
        assert_eq!(decoded.prefix_len, 48);
        // 48 bits = 6 bytes; the decoded prefix is zero-padded to 16
        assert_eq!(&decoded.addr, &lr_core::addr::IpAddr::V6({
            let mut b = [0u8; 16];
            b[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe]);
            b
        }));
    }
}
