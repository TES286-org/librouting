use super::*;

#[test]
fn roundtrip_2byte() {
    let mut p = AsPath::from_sequence([Asn(100), Asn(200)]);
    p.prepend(Asn(50));
    let enc = p.encode_2();
    let dec = AsPath::decode(&enc).unwrap();
    assert_eq!(dec, p);
    assert_eq!(dec.length(), 3);
    assert!(dec.loop_check(Asn(200)));
    assert!(!dec.loop_check(Asn(999)));
}

#[test]
fn roundtrip_4byte() {
    let p = AsPath::from_sequence([Asn(70000), Asn(80000)]);
    let enc = p.encode_4();
    let dec = AsPath::decode_4(&enc).unwrap();
    assert_eq!(dec, p);
}

#[test]
fn set_and_sequence() {
    let p = AsPath {
        segments: vec![
            AsPathSegment {
                kind: AsPathType::Sequence,
                ases: vec![Asn(1), Asn(2)],
            },
            AsPathSegment {
                kind: AsPathType::Set,
                ases: vec![Asn(3), Asn(4)],
            },
        ],
    };
    let enc = p.encode_4();
    let dec = AsPath::decode_4(&enc).unwrap();
    assert_eq!(dec, p);
    // RFC 4271 §9.1.2.2(a): an AS_SET counts as 1 regardless of size.
    assert_eq!(p.length(), 3);
}

#[test]
fn confed_segments_not_counted_by_default() {
    // RFC 5065 §5.3(3): AS_CONFED_SEQUENCE / AS_CONFED_SET SHOULD NOT
    // be counted when comparing AS_PATH length.
    let p = AsPath {
        segments: vec![
            AsPathSegment {
                kind: AsPathType::ConfedSequence,
                ases: vec![Asn(65001), Asn(65002)],
            },
            AsPathSegment {
                kind: AsPathType::Sequence,
                ases: vec![Asn(100), Asn(200)],
            },
        ],
    };
    assert_eq!(p.length(), 2);
    assert_eq!(p.length_with_confed(), 4);
}

/// RFC 6793 §4.2.3: when AS4_PATH is present and its AS count is
/// smaller than the wire AS_PATH's, the leading wire-path segments are
/// prepended so the reconstructed path has the wire-path count.
#[test]
fn reconcile_as4_prepends_leading_segments() {
    let wire = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases: vec![Asn(23456), Asn(200)],
        }],
    };
    let as4 = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases: vec![Asn(70000)],
        }],
    };
    let merged = reconcile_as4(&wire, Some(&as4));
    assert_eq!(merged.length(), 2);
    assert_eq!(merged.segments[0].ases, vec![Asn(23456)]);
    assert_eq!(merged.segments[1].ases, vec![Asn(70000)]);
}

/// RFC 6793 §4.2.3: an AS4_PATH with more ASes than the wire AS_PATH
/// is ignored — the wire path wins.
#[test]
fn reconcile_as4_ignores_larger_as4() {
    let wire = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases: vec![Asn(100)],
        }],
    };
    let as4 = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases: vec![Asn(1), Asn(2), Asn(3)],
        }],
    };
    assert_eq!(reconcile_as4(&wire, Some(&as4)), wire);
}

/// RFC 6793 §4.2.3: equal counts → AS4_PATH alone is the answer.
#[test]
fn reconcile_as4_equal_counts_uses_as4() {
    let wire = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases: vec![Asn(23456)],
        }],
    };
    let as4 = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases: vec![Asn(70000)],
        }],
    };
    assert_eq!(reconcile_as4(&wire, Some(&as4)), as4);
}

/// No AS4_PATH → the wire path passes through unchanged.
#[test]
fn reconcile_as4_without_as4_returns_wire() {
    let wire = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases: vec![Asn(100), Asn(200)],
        }],
    };
    assert_eq!(reconcile_as4(&wire, None), wire);
}

/// RFC 5065 §4.1(b): advertising to a confederation-external peer
/// (another Member-AS) prepends the local AS into an
/// AS_CONFED_SEQUENCE, extending the leftmost one when it exists.
#[test]
fn prepend_confed_extends_or_creates_segment() {
    // Fresh path: a new confed segment is inserted at the head.
    let mut p = AsPath::from_sequence([Asn(100), Asn(200)]);
    p.prepend_confed(Asn(65001));
    assert_eq!(p.segments[0].kind, AsPathType::ConfedSequence);
    assert_eq!(p.segments[0].ases, vec![Asn(65001)]);
    assert_eq!(p.segments[1].kind, AsPathType::Sequence);

    // An existing leftmost AS_CONFED_SEQUENCE is extended in place.
    let mut p = AsPath {
        segments: vec![
            AsPathSegment {
                kind: AsPathType::ConfedSequence,
                ases: vec![Asn(65010)],
            },
            AsPathSegment {
                kind: AsPathType::Sequence,
                ases: vec![Asn(100)],
            },
        ],
    };
    p.prepend_confed(Asn(65001));
    assert_eq!(p.segments[0].kind, AsPathType::ConfedSequence);
    assert_eq!(p.segments[0].ases, vec![Asn(65001), Asn(65010)]);
    assert_eq!(p.segments.len(), 2, "no new segment is inserted");
    // The confed segment stays invisible to path-length comparison.
    assert_eq!(p.length(), 1);
}

/// RFC 5065 §4.1(c)(1): AS_CONFED_SEQUENCE / AS_CONFED_SET segments
/// are removed before a route leaves the confederation. The plain
/// AS_SEQUENCE / AS_SET segments survive untouched.
#[test]
fn strip_confed_removes_only_private_segments() {
    let mut p = AsPath {
        segments: vec![
            AsPathSegment {
                kind: AsPathType::ConfedSequence,
                ases: vec![Asn(65001), Asn(65002)],
            },
            AsPathSegment {
                kind: AsPathType::Sequence,
                ases: vec![Asn(100), Asn(200)],
            },
            AsPathSegment {
                kind: AsPathType::ConfedSet,
                ases: vec![Asn(65003)],
            },
        ],
    };
    assert!(p.strip_confed());
    assert_eq!(
        p.segments,
        vec![AsPathSegment {
            kind: AsPathType::Sequence,
            ases: vec![Asn(100), Asn(200)],
        }]
    );
    // Stripping an already-clean path is a no-op reported as false.
    assert!(!p.strip_confed());
    assert!(!p.has_confed());
}

/// `has_confed` detects both confederation segment kinds so the
/// ingress validator can flag a peer that is not a confederation
/// member sending AS_CONFED_* (RFC 5065 §5).
#[test]
fn has_confed_detects_private_segments() {
    let plain = AsPath::from_sequence([Asn(100)]);
    assert!(!plain.has_confed());
    let with_confed = AsPath {
        segments: vec![AsPathSegment {
            kind: AsPathType::ConfedSet,
            ases: vec![Asn(65001)],
        }],
    };
    assert!(with_confed.has_confed());
}
