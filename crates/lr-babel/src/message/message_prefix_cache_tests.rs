use super::*;

fn update(ae: u8, plen: u8, flags: u8, omitted: u8, prefix: &[u8]) -> Update {
    Update {
        ae,
        flags,
        prefix_len: plen,
        omitted,
        interval_cs: 300,
        seqno: 7,
        metric: 202,
        prefix: prefix.to_vec(),
        src_prefix_len: 0,
        src_prefix: Vec::new(),
    }
}

/// The exact shape BIRD 3.x puts on the wire: a /64 with the Prefix
/// flag, followed by sibling /64s omitting the shared leading octets.
#[test]
fn expands_bird_style_compressed_v6_updates() {
    let mut cache = PrefixCache::default();
    // fd00:286:11e:6::/64, full 8 octets, sets the default prefix.
    let first = cache
        .expand(&update(
            2,
            64,
            Update::FLAG_PREFIX,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
        ))
        .unwrap();
    assert_eq!(first.omitted, 0);
    assert_eq!(
        first.prefix,
        vec![0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06]
    );
    // fd10:127:286:6::/64 announced as omit=1 + the last 7 octets.
    let second = cache
        .expand(&update(
            2,
            64,
            0,
            1,
            &[0x10, 0x01, 0x27, 0x02, 0x86, 0x00, 0x06],
        ))
        .unwrap();
    // Reconstructed: fd | 10 01 27 02 86 00 06.
    assert_eq!(
        second.prefix,
        vec![0xfd, 0x10, 0x01, 0x27, 0x02, 0x86, 0x00, 0x06]
    );
    // The lab-observed corruption (tail octets read as the head)
    // must not survive: 1001:2702:8600:6::/64 is wrong.
    assert_ne!(
        second.prefix,
        vec![0x10, 0x01, 0x27, 0x02, 0x86, 0x00, 0x06, 0x00]
    );
}

/// BIRD's fully-compressed /48 announcement: plen 48, omitted 6,
/// zero in-band octets. Pre-fix this TLV was dropped outright.
#[test]
fn expands_fully_compressed_v6_update() {
    let mut cache = PrefixCache::default();
    cache
        .expand(&update(
            2,
            64,
            Update::FLAG_PREFIX,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
        ))
        .unwrap();
    // fd00:286:11e::/48 with the first 6 octets omitted.
    let out = cache.expand(&update(2, 48, 0, 6, &[])).unwrap();
    assert_eq!(out.prefix, vec![0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e]);
    assert_eq!(out.prefix_len, 48);
}

/// Omission without a saved prefix is corrupt (BIRD: PARSE_ERROR).
#[test]
fn omission_without_saved_prefix_is_rejected() {
    let mut cache = PrefixCache::default();
    assert!(cache.expand(&update(2, 48, 0, 6, &[])).is_none());
}

/// Lengths that do not add up are corrupt.
#[test]
fn inconsistent_lengths_are_rejected() {
    let mut cache = PrefixCache::default();
    cache
        .expand(&update(
            2,
            64,
            Update::FLAG_PREFIX,
            0,
            &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e, 0x00, 0x06],
        ))
        .unwrap();
    // plen 64 -> 8 octets; omitted 1 + 6 octets = 7 != 8.
    assert!(cache
        .expand(&update(2, 64, 0, 1, &[0x10, 0x01, 0x27, 0x02, 0x86, 0x00]))
        .is_none());
    // omitted beyond the prefix length.
    assert!(cache.expand(&update(2, 64, 0, 9, &[])).is_none());
}

/// The compression caches are keyed per AE (BIRD keeps three
/// separate defaults); a v4 default must not leak into a v6 lookup.
#[test]
fn caches_are_keyed_per_ae() {
    let mut cache = PrefixCache::default();
    // 10.127.32.0/24 sets the AE 1 default.
    cache
        .expand(&update(1, 24, Update::FLAG_PREFIX, 0, &[10, 127, 32]))
        .unwrap();
    // An AE 2 update omitting octets has no v6 default to draw from.
    assert!(cache
        .expand(&update(2, 64, 0, 2, &[0x00, 0x06, 0x00, 0x00, 0x00, 0x00]))
        .is_none());
    // The AE 4 (IPv4-via-IPv6) cache is separate from AE 1 too.
    assert!(cache.expand(&update(4, 24, 0, 1, &[127, 32])).is_none());
}

/// Round trip: encode an expanded Update and decode it back through
/// a fresh cache (in-band full prefix, no compression).
#[test]
fn expanded_update_roundtrips() {
    let mut cache = PrefixCache::default();
    let u = update(2, 48, 0, 0, &[0xfd, 0x00, 0x02, 0x86, 0x01, 0x1e]);
    let out = cache.expand(&u).unwrap();
    let bytes = out.encode();
    let back = Update::decode(&bytes).unwrap();
    assert_eq!(back.omitted, 0);
    assert_eq!(back.prefix, u.prefix);
    assert_eq!(back.prefix_len, 48);
}
