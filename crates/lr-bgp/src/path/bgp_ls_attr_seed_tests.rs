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
