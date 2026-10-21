//! Smoke test: validate the bgp_ls_attr_decode fuzz seed corpus
//! round-trips through the codec byte-for-byte. This is a unit test
//! in the lr-bgp crate so it runs in the workspace's regular
//! `cargo test --workspace` gate.

#[cfg(test)]
#[cfg(feature = "bgp_ls")]
mod seeds {
    use crate::path::bgp_ls_attr::BgpLsAttr;

    /// Each (name, bytes) pair is one seed in
    /// `fuzz/seeds/bgp_ls_attr_decode/`. The round-trip property the
    /// fuzz target asserts must hold for every seed the codec
    /// accepts — this test catches a regression on the seed corpus
    /// without needing a cargo-fuzz run.
    const SEEDS: &[(&str, &[u8])] = &[
        ("empty.bin", b""),
        ("node_flag_bits.bin", &[0x04, 0x00, 0x00, 0x01, 0x07]),
        (
            "srv6_endpoint_behavior.bin",
            &[0x04, 0xE2, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00],
        ),
        (
            "srv6_sid_structure.bin",
            &[0x04, 0xE4, 0x00, 0x04, 0x20, 0x10, 0x10, 0x00],
        ),
        // RFC 9086 §5 Egress Peer Engineering seeds. Each seed is one
        // TLV in the BGP-LS Attribute value stream. The codec accepts
        // length 7 (label form, V flag set) and length 8 (index form,
        // V flag clear); any other length or V-flag/length
        // combination falls through to Unknown — the round-trip is
        // byte-exact in all cases (Unknown preserves the raw Tlv).
        (
            "peer_node_sid_label.bin",
            &[
                0x04, 0x4D, 0x00, 0x07, 0xC0, 0x05, 0x00, 0x00, 0x00, 0x10, 0x01,
            ],
        ),
        (
            "peer_adj_sid_index.bin",
            &[
                0x04, 0x4E, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
            ],
        ),
        (
            "peer_set_sid_label.bin",
            &[
                0x04, 0x4F, 0x00, 0x07, 0xD0, 0xC8, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
            ],
        ),
        // Length 7 but V flag clear — inconsistent with RFC 9086 §5.
        // The codec falls through to Unknown; the round-trip is
        // byte-exact.
        (
            "peer_node_sid_inconsistent_v.bin",
            &[
                0x04, 0x4D, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01,
            ],
        ),
        // Length 9 — RFC 9086 §5 only permits 7 or 8. Falls through
        // to Unknown; the round-trip is byte-exact.
        (
            "peer_adj_sid_wrong_length.bin",
            &[
                0x04, 0x4E, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        ),
        // Non-zero reserved field. RFC 9086 §5 says it MUST be zero
        // on originate and ignored on receive — the codec preserves
        // the raw bytes so the round-trip is byte-exact.
        (
            "peering_sid_nonzero_reserved.bin",
            &[
                0x04, 0x4D, 0x00, 0x07, 0xC0, 0x05, 0xAB, 0xCD, 0x00, 0x10, 0x01,
            ],
        ),
    ];

    #[test]
    fn seed_corpus_round_trips() {
        for (name, bytes) in SEEDS {
            let decoded = match BgpLsAttr::decode(bytes) {
                Ok(d) => d,
                Err(e) => panic!("seed {name} failed to decode: {e:?}"),
            };
            let reencoded = decoded
                .encode()
                .unwrap_or_else(|e| panic!("seed {name} failed to encode: {e:?}"));
            assert_eq!(
                reencoded, *bytes,
                "seed {name} round-trip mismatch: reencoded != input"
            );
        }
    }
}
