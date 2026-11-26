use super::*;
use crate::path::{AttrType, MpNextHop, MpReach, MpUnreach, PathAttrFlags, PathAttribute};

fn mp_attr(value: Vec<u8>) -> PathAttribute {
    PathAttribute::new(
        PathAttrFlags::new().set_optional(true),
        AttrType::MpReachNlri,
        value,
    )
}

/// `Update::family()` reads the MP header rather than decoding NLRI, so
/// a labelled family is reported correctly even though the plain
/// `MpReach` decoder refuses its NLRI.
#[test]
fn family_uses_header_for_labelled_mp_reach() {
    let mut u = Update::new();
    let reach = MpReach::new(
        NlriFamily::IPV4_LABELED_UNICAST,
        MpNextHop::V4([192, 0, 2, 1]),
        vec![],
    );
    let value = reach.encode();
    u.attributes.insert(mp_attr(value));

    assert_eq!(u.family(), NlriFamily::IPV4_LABELED_UNICAST);
    assert!(u.attributes.mp_reach().is_none());
    assert_eq!(
        u.attributes.mp_reach_family(),
        Some(NlriFamily::IPV4_LABELED_UNICAST)
    );
    assert_eq!(
        u.attributes.mp_reach_header().unwrap().next_hop,
        MpNextHop::V4([192, 0, 2, 1])
    );
}

/// A withdrawal-only MP UPDATE reports the family carried in
/// MP_UNREACH_NLRI; a legacy UPDATE defaults to IPv4 unicast.
#[test]
fn family_uses_mp_unreach_and_legacy_default() {
    let mut u = Update::new();
    let unreach = MpUnreach::new(NlriFamily::IPV6_UNICAST, vec![]);
    u.attributes.insert(PathAttribute::new(
        PathAttrFlags::new().set_optional(true),
        AttrType::MpUnreachNlri,
        unreach.encode(),
    ));
    assert_eq!(u.family(), NlriFamily::IPV6_UNICAST);
    assert_eq!(
        u.attributes.mp_unreach_family(),
        Some(NlriFamily::IPV6_UNICAST)
    );

    assert_eq!(Update::new().family(), NlriFamily::IPV4_UNICAST);
}
