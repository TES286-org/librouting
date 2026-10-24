//! Smoke tests for the three crates the cross-crate integration
//! suite historically did not exercise: `lr-mrt`, `lr-damping` and
//! `lr-srv6`. None of these are on the daemon's critical path — the
//! daemon consumes them transitively through `lr-router` / `lr-cli` —
//! so the integration suite used to rely on each crate's own unit
//! tests for regression coverage. That worked, but the suite gave no
//! end-to-end guarantee that a downstream consumer could actually
//! reach the public API. These tests close that gap: each pulls the
//! crate's primary entry point through a representative round-trip or
//! state transition and asserts the public contract holds.
//!
//! Coverage is intentionally narrow — these are smoke tests, not
//! exhaustiveness tests. Each crate has its own unit-test surface for
//! the deep cases; the goal here is to catch breakage in the public
//! API shape itself (renamed methods, accidentally private items,
//! feature-gated regressions).

// ===========================================================================
// lr-mrt — RFC 6396 TABLE_DUMP_V2 codec
// ===========================================================================

mod mrt {
    use lr_core::addr::{Asn, IpAddr};
    use lr_mrt::{
        encode_peer_index_table, msg_type, tdv2_subtype, MrtReader, MrtRecord, PeerEntry,
        PeerIndexTable,
    };

    // Build a `PEER_INDEX_TABLE` record (RFC 6396 §4.3.1) with one
    // external peer, encode it through the writer, decode it back
    // through the streaming reader, and assert the round-trip
    // preserves the peer table fields. This is the entry-shape every
    // RIB_* record that follows depends on — if the writer and reader
    // disagree on its layout, the rest of the dump is unreadable.
    #[test]
    fn peer_index_table_round_trip() {
        let peer = PeerEntry {
            bgp_id: 0x01020304,
            ip: IpAddr::V4([192, 0, 2, 1]),
            asn: Asn(64512),
        };
        let bytes = encode_peer_index_table(1_700_000_000, 0x01020304, "test-view", &[peer])
            .expect("encode_peer_index_table succeeds for one peer");
        assert!(!bytes.is_empty());

        let mut reader = MrtReader::new();
        let record = reader
            .decode_slice(&bytes)
            .expect("decode_slice accepts the encoded record")
            .expect("a complete record was buffered");
        match record {
            MrtRecord::PeerIndexTable(PeerIndexTable {
                collector_bgp_id,
                view_name,
                peers,
            }) => {
                assert_eq!(collector_bgp_id, 0x01020304);
                assert_eq!(view_name, "test-view");
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].bgp_id, 0x01020304);
                assert_eq!(peers[0].asn, Asn(64512));
                assert_eq!(peers[0].ip, IpAddr::V4([192, 0, 2, 1]));
            }
            other => panic!("expected PeerIndexTable, got {other:?}"),
        }
    }

    // The reader surfaces `MrtRecord::Unknown` for subtypes it does
    // not implement rather than erroring — the contract a
    // forward-compatible tool depends on (RFC 6396 reserves subtype
    // values). A record carrying a reserved TABLE_DUMP_V2 subtype must
    // round-trip through `Unknown` so the caller can decide what to do
    // with it.
    #[test]
    fn unknown_subtype_surfaces_as_unknown() {
        // Header: timestamp(4) + type(2) + subtype(2) + length(4) = 12
        // bytes; subtype 0xFFFF is unallocated in RFC 6396 §4.3.
        let mut bytes = vec![0u8; 12];
        bytes[4..6].copy_from_slice(&msg_type::TABLE_DUMP_V2.to_be_bytes());
        bytes[6..8].copy_from_slice(&0xFFFFu16.to_be_bytes());
        // Body: 4 bytes, so length field = 4.
        bytes[8..12].copy_from_slice(&4u32.to_be_bytes());
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let mut reader = MrtReader::new();
        let record = reader
            .decode_slice(&bytes)
            .expect("decode_slice accepts the encoded record")
            .expect("a complete record was buffered");
        match record {
            MrtRecord::Unknown { msg_type, subtype } => {
                assert_eq!(msg_type, msg_type::TABLE_DUMP_V2);
                assert_eq!(subtype, 0xFFFF);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    // Subtypes the codec does implement must NOT surface as `Unknown`.
    // A regression that flipped the subtype-routing table would
    // otherwise only show up in a downstream consumer that happened to
    // pattern-match the variant.
    #[test]
    fn peer_index_subtype_does_not_classify_as_unknown() {
        let peer = PeerEntry {
            bgp_id: 0x01020304,
            ip: IpAddr::V4([192, 0, 2, 1]),
            asn: Asn(64512),
        };
        let bytes = encode_peer_index_table(1, 0x01020304, "", &[peer]).unwrap();
        let mut reader = MrtReader::new();
        let record = reader
            .decode_slice(&bytes)
            .unwrap()
            .expect("complete record");
        assert!(
            !matches!(record, MrtRecord::Unknown { .. }),
            "PEER_INDEX_TABLE subtype ({}) must classify as PeerIndexTable",
            tdv2_subtype::PEER_INDEX_TABLE
        );
    }
}

// ===========================================================================
// lr-damping — RFC 2439 route flap damping
// ===========================================================================

mod damping {
    use lr_core::addr::Prefix;
    use lr_damping::{
        DampingConfig, DampingTable, DEFAULT_ADDITIVE_INCR, DEFAULT_REUSE_THRESHOLD,
        DEFAULT_SUPPRESS_THRESHOLD,
    };

    // Two flaps of the default additive increment push the figure of
    // merit past the suppress threshold; the third flap holds it
    // suppressed. This is the simplest end-to-end exercise of the
    // public damping contract: a route that flaps enough times must be
    // suppressed, and the suppression must persist across subsequent
    // flaps (RFC 2439 §4.2 — once suppressed, FoM has to decay below
    // the reuse threshold before the route re-emerges).
    #[test]
    fn repeated_flaps_suppress_the_route() {
        let mut table = DampingTable::new(DampingConfig::default());
        let prefix = Prefix::new_v4([203, 0, 113, 0], 24);

        // First withdraw: FoM = DEFAULT_ADDITIVE_INCR = 1000. Below
        // DEFAULT_SUPPRESS_THRESHOLD (2000) — not suppressed.
        let suppressed_1 = table.on_withdraw(&prefix, 0);
        assert!(
            !suppressed_1,
            "a single flap must not suppress the route yet"
        );
        assert!(!table.is_suppressed(&prefix));

        // Second withdraw: FoM = 2000, hits the suppress threshold.
        let suppressed_2 = table.on_withdraw(&prefix, 1);
        assert!(
            suppressed_2,
            "FoM == suppress_threshold (>=) must trigger suppression"
        );
        assert!(table.is_suppressed(&prefix));

        // Third withdraw: FoM = 3000 (capped at UPPER_LIMIT = 60000).
        // Suppression persists.
        let suppressed_3 = table.on_withdraw(&prefix, 2);
        assert!(suppressed_3, "suppression persists past the trigger");
        assert!(table.is_suppressed(&prefix));
    }

    // A suppressed route re-emerges once the figure of merit decays
    // below the reuse threshold (RFC 2439 §4.3). `decay_all` advances
    // the clock; the decay factor is 0.97 per 30 s, so after enough
    // ticks the FoM drifts below `DEFAULT_REUSE_THRESHOLD`.
    #[test]
    fn suppressed_route_reuses_after_decay() {
        let mut table = DampingTable::new(DampingConfig::default());
        let prefix = Prefix::new_v4([198, 51, 100, 0], 24);

        // Drive FoM up to ~6× the suppress threshold so the decay has
        // real work to do.
        for i in 0..6 {
            table.on_withdraw(&prefix, i);
        }
        assert!(table.is_suppressed(&prefix));

        // Decay until reuse. The default `decay_factor_active` is
        // 0.97; each 30 s tick multiplies FoM by 0.97. To drop from
        // 6000 (capped) below 750 needs roughly log(750/6000) /
        // log(0.97) ≈ 73 ticks. Cap the loop so a regression in the
        // decay arithmetic surfaces rather than hanging the test.
        let mut now_s = 6u64;
        for _ in 0..200 {
            now_s += DEFAULT_REUSE_THRESHOLD as u64; // arbitrary, advances clock
            let _reused = table.decay_all(now_s);
            if !table.is_suppressed(&prefix) {
                return;
            }
        }
        panic!("route stayed suppressed after 200 decay ticks");
    }

    // A route that was never flapped is not suppressed — the table
    // returns `false` for unknown prefixes rather than panicking or
    // defaulting to suppressed.
    #[test]
    fn unknown_prefix_is_not_suppressed() {
        let table = DampingTable::new(DampingConfig::default());
        let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
        assert!(!table.is_suppressed(&prefix));
    }

    // `forget` removes the entry; the route re-emerges immediately
    // and `is_suppressed` returns false. Useful for an operator
    // clearing the flap history on a route they've just manually
    // re-installed.
    #[test]
    fn forget_clears_suppression() {
        let mut table = DampingTable::new(DampingConfig::default());
        let prefix = Prefix::new_v4([203, 0, 113, 0], 24);
        for i in 0..3 {
            table.on_withdraw(&prefix, i);
        }
        assert!(table.is_suppressed(&prefix));
        table.forget(&prefix);
        assert!(!table.is_suppressed(&prefix));
    }

    // The default thresholds are the RFC 2439 §4.7 sample parameters;
    // pinning them here catches accidental drift in the constants
    // table.
    #[test]
    fn default_thresholds_match_rfc_2439_sample_parameters() {
        assert_eq!(DEFAULT_ADDITIVE_INCR, 1000);
        assert_eq!(DEFAULT_SUPPRESS_THRESHOLD, 2000);
        assert_eq!(DEFAULT_REUSE_THRESHOLD, 750);
    }
}

// ===========================================================================
// lr-srv6 — RFC 8754 / RFC 8986 SRH + Behavior
// ===========================================================================

mod srv6 {
    use lr_srv6::{Behavior, Sid, Srh};

    // Build an SRH with two segments via the builder, encode it, then
    // decode the bytes back. The wire format must round-trip — both
    // `Srh::encode_vec` and `Srh::decode` are public API surface, so
    // an embedder feeding bytes to the kernel's `seg6_validate_srh`
    // and a peer running the same codec must agree on the layout.
    #[test]
    fn srh_round_trip_preserves_segment_list() {
        // `Sid::from_octets` is the canonical public constructor; the
        // smoke test pins it stays public.
        let seg1 = Sid::from_octets([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        let seg2 = Sid::from_octets([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ]);
        let srh = Srh::new(vec![seg1, seg2])
            .expect("two segments is in range")
            .with_next_header(6); // TCP.
        let bytes = srh.encode_vec().expect("encode succeeds for two segments");
        assert!(
            bytes.len().is_multiple_of(8),
            "SRH total length is 8-octet aligned (RFC 8200 §4.8)"
        );

        let decoded = Srh::decode(&bytes).expect("decode accepts the encoded SRH");
        // `Srh::new` defaults `segments_left` to `n - 1` (RFC 8754
        // §4.1 — the source's view). `current_destination()` returns
        // `Segment List[Segments Left]`, the address the source puts
        // on the outer IPv6 header — i.e. the last element of the
        // Rust segment vector (the source builds the list in reverse
        // order of visitation).
        assert_eq!(
            decoded.current_destination(),
            Some(seg2),
            "current_destination() is the destination (seg2, the last Rust element)"
        );
        // `first_segment()` is the segment at position 0 in the
        // Rust vector — i.e. `Segment List[0]`, the last segment
        // the packet visits. Pinning both accessors is the
        // smoke-grade guarantee that the encode/decode round-trip
        // preserves the source's view of the segment list.
        assert_eq!(
            decoded.first_segment(),
            Some(seg1),
            "first_segment() is Segment List[0] (seg1, the first Rust element)"
        );
    }

    // An SRH with too many segments is rejected. The wire ceiling is
    // 127 segments (16 bytes each = 2032 bytes; +8 fixed = 2040,
    // under the 2048-octet limit from RFC 8200 §4.8).
    #[test]
    fn srh_rejects_too_many_segments() {
        let seg = Sid::from_octets([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        let too_many = vec![seg; 128];
        Srh::new(too_many).expect_err("128 segments exceeds the wire ceiling");
    }

    // The IANA behavior registry round-trips for the variants the
    // crate models. RFC 8986 §4.1 defines `End` (behavior value 1),
    // §4.3 defines `End.X` (5), §4.6 defines `End.DX6` (16), §4.11
    // defines `End.DT4` (19). `Behavior::from_wire` returns `None`
    // for unallocated values; the modelled values must come back as
    // their enum variants so a downstream consumer pattern-matching on
    // `Behavior` does not have to interpret the raw opcode itself.
    #[test]
    fn behavior_from_wire_round_trips_for_modelled_variants() {
        // End (RFC 8986 §4.1).
        assert_eq!(Behavior::from_wire(1), Some(Behavior::End));
        // End.X (RFC 8986 §4.3).
        assert_eq!(Behavior::from_wire(5), Some(Behavior::EndX));
        // End.DX6 (§4.6).
        assert_eq!(Behavior::from_wire(16), Some(Behavior::EndDX6));
        // End.DT4 (§4.11) — the L3VPN-BE for IPv4.
        assert_eq!(Behavior::from_wire(19), Some(Behavior::EndDT4));
        // End.MAP (RFC 9433 §6.2) — landed in 1.8.0.
        assert_eq!(Behavior::from_wire(40), Some(Behavior::EndMap));
        // End.Limit (RFC 9433 §6.8).
        assert_eq!(Behavior::from_wire(41), Some(Behavior::EndLimit));
        // Unallocated value must surface as None.
        assert_eq!(Behavior::from_wire(0), None, "value 0 is unallocated");
    }
}

// Pin `Sid::from_octets` and the `IpAddr` re-export on the public API
// surface. A future rename of either surfaces as a compile error
// here rather than silently breaking every embedder that builds SIDs
// from parsed addresses.
mod sid_constructor_renamed {
    use lr_core::addr::IpAddr;
    use lr_srv6::Sid;

    #[test]
    fn sid_from_octets_is_public() {
        let sid = Sid::from_octets([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        let _ = sid;
    }

    #[test]
    fn ipaddr_re_export_exists() {
        let _ = IpAddr::V4([192, 0, 2, 1]);
    }
}
