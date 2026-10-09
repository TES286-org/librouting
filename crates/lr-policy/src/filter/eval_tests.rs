
use super::*;
use crate::filter::compile;
use lr_core::addr::{Asn, IpAddr, Prefix};
use lr_core::attr::{AttrTag, Attribute, Attributes};
use lr_core::nlri::NlriFamily;
use lr_core::rib::{Preference, Protocol, Route, RouteKey, RouteOrigin};

/// A minimal context for tests — pulls LOCAL_PREF / MED / etc.
/// from the route's attribute bag using the same tag encoding as
/// `lr_policy::bgp` (so a filter compiled in tests sees the
/// same values the daemon would surface).
struct StubCtx;

const TAG_ORIGIN: u8 = 1;
const TAG_AS_PATH: u8 = 2;
const TAG_MED: u8 = 4;
const TAG_LOCAL_PREF: u8 = 5;
const TAG_COMMUNITIES: u8 = 8;
const TAG_EXT_COMMUNITIES: u8 = 16;
const TAG_LARGE_COMMUNITIES: u8 = 32;

fn attr(route: &Route, tag: u8) -> Option<Vec<u8>> {
    route
        .attributes
        .get(AttrTag::raw(tag))
        .map(|a| a.value.clone())
}

impl FilterContext for StubCtx {
    fn bgp_local_pref(&self, route: &Route) -> Option<u32> {
        // GitHub #19 P3: use the in-place `get_u32_be` fast path
        // (matches production `lr_policy::bgp::local_pref`).
        route.attributes.get_u32_be(AttrTag::raw(TAG_LOCAL_PREF))
    }
    fn bgp_med(&self, route: &Route) -> Option<u32> {
        route.attributes.get_u32_be(AttrTag::raw(TAG_MED))
    }
    fn bgp_origin(&self, route: &Route) -> Option<u8> {
        route.attributes.get_u8(AttrTag::raw(TAG_ORIGIN))
    }
    fn bgp_next_hop(&self, _route: &Route) -> Option<IpAddr> {
        None
    }
    fn bgp_as_path(&self, route: &Route) -> Vec<Asn> {
        let Some(b) = attr(route, TAG_AS_PATH) else {
            return Vec::new();
        };
        if b.is_empty() {
            return Vec::new();
        }
        // segment: type (1B) + length (1B) + N*4 bytes
        let mut out = Vec::new();
        let mut i = 0;
        while i + 2 <= b.len() {
            let _seg_type = b[i];
            let count = b[i + 1] as usize;
            i += 2;
            for _ in 0..count {
                if i + 4 > b.len() {
                    break;
                }
                let asn = u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
                out.push(Asn(asn));
                i += 4;
            }
        }
        out
    }
    fn bgp_communities(&self, route: &Route) -> Vec<(Asn, u16)> {
        let Some(b) = attr(route, TAG_COMMUNITIES) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // RFC 1997 §4: communities are 4 bytes — the high two
        // bytes are the ASN, the low two are the value.
        // `as_chunks::<4>()` is the clippy-preferred form and
        // is stable since Rust 1.52 (well within the project's
        // MSRV of 1.88).
        for chunk in b.as_chunks::<4>().0 {
            let asn = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            let val = u16::from_be_bytes([chunk[2], chunk[3]]);
            out.push((Asn(asn), val));
        }
        out
    }
    fn roa_state(&self, _route: &Route) -> RoaStateLit {
        RoaStateLit::NotFound
    }
    fn set_bgp_local_pref(&self, route: &mut Route, value: u32) {
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_LOCAL_PREF),
            flags: 0x40,
            value: value.to_be_bytes().to_vec(),
        });
    }
    fn set_bgp_med(&self, route: &mut Route, value: u32) {
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_MED),
            flags: 0x80,
            value: value.to_be_bytes().to_vec(),
        });
    }
    fn set_bgp_next_hop(&self, _route: &mut Route, _value: IpAddr) {}
    fn bgp_as_path_prepend(&self, route: &mut Route, asn: Asn) {
        let mut path = self.bgp_as_path(route);
        path.insert(0, asn);
        let mut v = vec![2u8, path.len() as u8];
        for a in &path {
            v.extend_from_slice(&a.0.to_be_bytes());
        }
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_AS_PATH),
            flags: 0x40,
            value: v,
        });
    }
    fn bgp_communities_add(&self, route: &mut Route, asn: Asn, val: u16) {
        let mut set = self.bgp_communities(route);
        let new = (asn, val);
        if set.contains(&new) {
            return;
        }
        set.push(new);
        Self::put_communities(route, &set);
    }
    fn set_bgp_communities(&self, route: &mut Route, set: Vec<(Asn, u16)>) {
        Self::put_communities(route, &set);
    }
    fn bgp_large_communities(&self, route: &Route) -> Vec<(u32, u32, u32)> {
        attr(route, TAG_LARGE_COMMUNITIES)
            .map(|b| {
                lr_bgp::path::communities::LargeCommunity::decode_set(&b)
                    .into_iter()
                    .map(|c| (c.global_admin, c.local_data1, c.local_data2))
                    .collect()
            })
            .unwrap_or_default()
    }
    fn bgp_ext_communities(&self, route: &Route) -> Vec<(u8, u8, u32, u16)> {
        attr(route, TAG_EXT_COMMUNITIES)
            .map(|b| {
                lr_bgp::path::communities::ExtendedCommunity::decode_set(&b)
                    .into_iter()
                    .map(|c| (c.kind, c.subtype, c.global, c.local))
                    .collect()
            })
            .unwrap_or_default()
    }
    fn set_bgp_large_communities(&self, route: &mut Route, set: Vec<(u32, u32, u32)>) {
        let cs: Vec<lr_bgp::path::communities::LargeCommunity> = set
            .into_iter()
            .map(|(g, d1, d2)| lr_bgp::path::communities::LargeCommunity::new(g, d1, d2))
            .collect();
        if cs.is_empty() {
            route.attributes.remove(AttrTag::raw(TAG_LARGE_COMMUNITIES));
            return;
        }
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_LARGE_COMMUNITIES),
            flags: 0xC0,
            value: lr_bgp::path::communities::LargeCommunity::encode_set(&cs),
        });
    }
    fn set_bgp_ext_communities(&self, route: &mut Route, set: Vec<(u8, u8, u32, u16)>) {
        let cs: Vec<lr_bgp::path::communities::ExtendedCommunity> = set
            .into_iter()
            .map(|(k, s, g, l)| lr_bgp::path::communities::ExtendedCommunity::new(k, s, g, l))
            .collect();
        if cs.is_empty() {
            route.attributes.remove(AttrTag::raw(TAG_EXT_COMMUNITIES));
            return;
        }
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_EXT_COMMUNITIES),
            flags: 0xC0,
            value: lr_bgp::path::communities::ExtendedCommunity::encode_set(&cs),
        });
    }
    fn set_bgp_as_path(&self, route: &mut Route, seq: Vec<Asn>) {
        if seq.is_empty() {
            route.attributes.remove(AttrTag::raw(TAG_AS_PATH));
            return;
        }
        let mut v = Vec::with_capacity(2 + seq.len() * 4);
        v.push(2u8); // AS_SEQUENCE
        v.push(seq.len() as u8);
        for a in &seq {
            v.extend_from_slice(&a.0.to_be_bytes());
        }
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_AS_PATH),
            flags: 0x40,
            value: v,
        });
    }
}

impl StubCtx {
    fn put_communities(route: &mut Route, set: &[(Asn, u16)]) {
        if set.is_empty() {
            route.attributes.remove(AttrTag::raw(TAG_COMMUNITIES));
            return;
        }
        let mut v = Vec::with_capacity(set.len() * 4);
        for (a, val) in set {
            v.extend_from_slice(&(a.0 as u16).to_be_bytes());
            v.extend_from_slice(&val.to_be_bytes());
        }
        route.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_COMMUNITIES),
            flags: 0xC0,
            value: v,
        });
    }
}

fn route_with(prefix: &str, local_pref: u32, med: u32) -> Route {
    let prefix: Prefix = prefix.parse().unwrap();
    let mut attrs = Attributes::new();
    attrs.insert(Attribute {
        tag: AttrTag::raw(TAG_LOCAL_PREF),
        flags: 0x40,
        value: local_pref.to_be_bytes().to_vec(),
    });
    attrs.insert(Attribute {
        tag: AttrTag::raw(TAG_MED),
        flags: 0x80,
        value: med.to_be_bytes().to_vec(),
    });
    Route {
        key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin { proto: 1, peer: 0 },
        protocol: Protocol::Bgp,
        preference: Preference::new(20, 100),
        next_hop: None,
        attributes: attrs,
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

fn run(filter_src: &str, route: &mut Route) -> EvalResult {
    let f = compile("test", filter_src).unwrap_or_else(|e| panic!("{e}"));
    evaluate(&f, route, &StubCtx)
}

#[test]
fn accept_unconditionally() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(run("accept;", &mut r), EvalResult::Accept);
}

#[test]
fn reject_unconditionally() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(run("reject;", &mut r), EvalResult::Reject(None));
}

#[test]
fn reject_with_reason() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("reject with \"too short\";", &mut r),
        EvalResult::Reject(Some("too short".to_string()))
    );
}

#[test]
fn if_local_pref_high_accepts() {
    let mut r = route_with("203.0.113.0/24", 200, 0);
    let src = "if bgp.local_pref > 100 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn if_local_pref_low_rejects() {
    let mut r = route_with("203.0.113.0/24", 50, 0);
    let src = "if bgp.local_pref > 100 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Reject(None));
}

#[test]
fn if_else_branches() {
    let mut r = route_with("203.0.113.0/24", 50, 0);
    let src = "if bgp.local_pref > 100 then accept; else reject;";
    assert_eq!(run(src, &mut r), EvalResult::Reject(None));
}

#[test]
fn let_and_arithmetic() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "let x = 50; let y = x * 2; if bgp.local_pref == y then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn assignment_to_bgp_local_pref() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "bgp.local_pref = 250; accept;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
    assert_eq!(StubCtx.bgp_local_pref(&r), Some(250));
}

#[test]
fn prefix_membership_match() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "if net ~ 203.0.113.0/24 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn prefix_membership_no_match() {
    let mut r = route_with("198.51.100.0/24", 100, 0);
    let src = "if net ~ 203.0.113.0/24 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Reject(None));
}

#[test]
fn prefix_set_membership() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "if net ~ [ 10.0.0.0/8, 203.0.113.0/24 ] then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn prefix_set_with_range_matches_more_specific() {
    let mut r = route_with("10.1.2.0/24", 100, 0);
    let src = "if net ~ [ 10.0.0.0/8{16,24} ] then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn prefix_set_with_range_rejects_too_specific() {
    let mut r = route_with("10.1.2.0/25", 100, 0);
    let src = "if net ~ [ 10.0.0.0/8{16,24} ] then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Reject(None));
}

#[test]
fn boolean_short_circuit_and() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "if net ~ 203.0.113.0/24 && bgp.local_pref >= 100 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn boolean_short_circuit_or() {
    let mut r = route_with("203.0.113.0/24", 50, 0);
    let src = "if bgp.local_pref > 100 || net ~ 203.0.113.0/24 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn case_statement_routes_to_default() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "case proto { \"ospfv2\" => accept; default => reject; }";
    assert_eq!(run(src, &mut r), EvalResult::Reject(None));
}

#[test]
fn not_match_negates_prefix_match() {
    // `!~` is the negation of `~`: a route inside the excluded
    // prefix is rejected, a route outside is accepted.
    let mut inside = route_with("203.0.113.0/24", 100, 0);
    let mut outside = route_with("198.51.100.0/24", 100, 0);
    let src = "if net !~ 203.0.113.0/24 then accept; reject;";
    assert_eq!(run(src, &mut inside), EvalResult::Reject(None));
    assert_eq!(run(src, &mut outside), EvalResult::Accept);
}

#[test]
fn not_match_against_set() {
    let mut in_set = route_with("203.0.113.0/24", 100, 0);
    let mut out_set = route_with("192.0.2.0/24", 100, 0);
    let src = "if net !~ [ 203.0.113.0/24, 198.51.100.0/24 ] then accept; reject;";
    assert_eq!(run(src, &mut in_set), EvalResult::Reject(None));
    assert_eq!(run(src, &mut out_set), EvalResult::Accept);
}

#[test]
fn method_prepend_adds_to_as_path() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "bgp.as_path.prepend(65001); accept;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
    let path = StubCtx.bgp_as_path(&r);
    assert_eq!(path, vec![Asn(65001)]);
}

#[test]
fn communities_append() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "bgp.communities += [ 64512:100 ]; accept;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
    let cs = StubCtx.bgp_communities(&r);
    assert!(cs.contains(&(Asn(64512), 100)), "{cs:?}");
}

#[test]
fn function_len_on_as_path() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "bgp.as_path.prepend(65001); bgp.as_path.prepend(65002); \
                   if len(bgp.as_path) == 2 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn undefined_variable_is_an_error_fallthrough() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if undefined_var > 0 then accept; reject;", &mut r),
        EvalResult::Fallthrough
    );
}

#[test]
fn fallthrough_when_no_terminal() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(run("let x = 5;", &mut r), EvalResult::Fallthrough);
}

#[test]
fn arithmetic_precedence() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "let x = 1 + 2 * 3; if x == 7 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn division_by_zero_is_fallthrough() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "let x = 1 / 0; accept;";
    assert_eq!(run(src, &mut r), EvalResult::Fallthrough);
}

#[test]
fn nested_blocks_have_separate_scope() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "let x = 1; { let x = 2; } if x == 1 then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn roa_state_string_equality() {
    // Verify `roa.state == "invalid"` form works — the StubCtx
    // returns NotFound for every route, so the equality test
    // checks that branch.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "if roa.state == \"not-found\" then accept; reject;";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

#[test]
fn roa_state_string_inequality_rejects() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let src = "if roa.state == \"invalid\" then accept; reject;";
    // StubCtx returns NotFound, so the equality fails and we
    // fall through to `reject;`.
    assert_eq!(run(src, &mut r), EvalResult::Reject(None));
}

/// Build a route with an explicit protocol kind, for `proto` field
/// tests. The default `route_with` helper hard-codes
/// `Protocol::Bgp`, which is fine for everything except the
/// `proto` string surface.
fn route_with_proto(prefix: &str, protocol: Protocol) -> Route {
    let prefix: Prefix = prefix.parse().unwrap();
    let mut attrs = Attributes::new();
    attrs.insert(Attribute {
        tag: AttrTag::raw(TAG_LOCAL_PREF),
        flags: 0x40,
        value: 100u32.to_be_bytes().to_vec(),
    });
    attrs.insert(Attribute {
        tag: AttrTag::raw(TAG_MED),
        flags: 0x80,
        value: 0u32.to_be_bytes().to_vec(),
    });
    Route {
        key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin { proto: 1, peer: 0 },
        protocol,
        preference: Preference::new(protocol.default_admin_distance(), 100),
        next_hop: None,
        attributes: attrs,
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

#[test]
fn proto_field_returns_bird_style_lowercase_name() {
    // Regression for the Filter DSL `proto` string form: the
    // previous implementation returned Rust Debug strings
    // (`"Bgp"`, `"Ospfv2"`, …). BIRD and the lr docs use the
    // lowercase form, so `proto == "bgp"` must hold for a BGP
    // route. Mirrors the docstring on `RouteFieldKind::Proto`.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if proto == \"bgp\" then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn proto_field_does_not_match_rust_debug_form() {
    // The buggy Debug form (`"Bgp"`) must no longer match.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if proto == \"Bgp\" then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn proto_field_matches_each_protocol_bird_name() {
    for (proto, name) in [
        (Protocol::Bgp, "bgp"),
        (Protocol::Ospfv2, "ospf"),
        (Protocol::Ospfv3, "ospf3"),
        (Protocol::Babel, "babel"),
        (Protocol::Static, "static"),
        (Protocol::Connected, "direct"),
        (Protocol::Other(99), "unknown"),
    ] {
        let mut r = route_with_proto("203.0.113.0/24", proto);
        let src = format!("if proto == \"{name}\" then accept; reject;");
        assert_eq!(
            run(&src, &mut r),
            EvalResult::Accept,
            "proto {proto:?} did not match bird-name {name:?}",
        );
    }
}

#[test]
fn proto_field_case_statement_routes_bird_names() {
    // Replaces the legacy `case proto { "ospfv2" => accept; … }`
    // form: BIRD-style names are lowercase without the `v2`
    // suffix for OSPFv2.
    let mut r = route_with_proto("203.0.113.0/24", Protocol::Ospfv2);
    let src = "case proto { \"ospf\" => accept; default => reject; }";
    assert_eq!(run(src, &mut r), EvalResult::Accept);
}

// ===== D3.5 — defined() / exists() =====

#[test]
fn defined_distinguishes_absent_from_zero_med() {
    // `route_with` always stamps LOCAL_PREF + MED, so both are
    // defined here; strip MED and only LOCAL_PREF stays defined.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.attributes.remove(AttrTag::raw(TAG_MED));
    assert_eq!(
        run("if defined(bgp.med) then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
    assert_eq!(
        run("if defined(bgp.local_pref) then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn defined_zero_med_is_still_defined() {
    // MED present with value 0 must not read as absent — the
    // whole point of the check.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if defined(bgp.med) then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn exists_alias_behaves_like_defined() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if exists(bgp.local_pref) then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    r.attributes.remove(AttrTag::raw(TAG_COMMUNITIES));
    assert_eq!(
        run("if exists(bgp.communities) then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn defined_list_fields_present_only_when_nonempty() {
    // No AS_PATH / COMMUNITIES on a fresh route -> absent.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if defined(bgp.as_path) then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
    // Prepending an AS makes the path present.
    assert_eq!(
        run(
            "bgp.as_path.prepend(65000); if defined(bgp.as_path) then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn defined_never_false_for_readonly_core_fields() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(net) && defined(proto) then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn defined_on_undefined_variable_is_false() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // A variable never bound must report not-defined instead of
    // aborting the evaluation (which would fall through).
    assert_eq!(
        run("if defined(no_such_var) then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
    assert_eq!(
        run("let x = 1; if defined(x) then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn defined_requires_exactly_one_argument() {
    let f = compile("test", "if defined(bgp.med, bgp.local_pref) then accept;");
    assert!(f.is_err(), "two-arg defined() must fail to compile");
    let f = compile("test", "if defined() then accept;");
    assert!(f.is_err(), "zero-arg defined() must fail to compile");
}

// ===== D3.4 — delete / filter / empty / count =====

fn communities_to(set: &[(u32, u16)]) -> Vec<(Asn, u16)> {
    set.iter().map(|(a, v)| (Asn(*a), *v)).collect()
}

/// Stamp a COMMUNITIES attribute onto a route (test helper).
fn with_communities(mut r: Route, set: &[(u32, u16)]) -> Route {
    let cs = communities_to(set);
    let mut v = Vec::with_capacity(cs.len() * 4);
    for (a, val) in &cs {
        v.extend_from_slice(&(a.0 as u16).to_be_bytes());
        v.extend_from_slice(&val.to_be_bytes());
    }
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_COMMUNITIES),
        flags: 0xC0,
        value: v,
    });
    r
}

#[test]
fn method_delete_removes_exact_community() {
    let mut r = with_communities(
        route_with("203.0.113.0/24", 100, 0),
        &[(64512, 100), (64512, 200), (65000, 1)],
    );
    assert_eq!(
        run("bgp.communities.delete([64512:100]); accept;", &mut r),
        EvalResult::Accept,
    );
    let cs = StubCtx.bgp_communities(&r);
    assert_eq!(cs, communities_to(&[(64512, 200), (65000, 1)]));
}

#[test]
fn method_delete_wildcard_removes_whole_asn() {
    let mut r = with_communities(
        route_with("203.0.113.0/24", 100, 0),
        &[(64512, 100), (64512, 200), (65000, 1)],
    );
    assert_eq!(
        run("bgp.communities.delete([64512:*]); accept;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(StubCtx.bgp_communities(&r), communities_to(&[(65000, 1)]));
}

#[test]
fn method_filter_keeps_only_matches() {
    let mut r = with_communities(
        route_with("203.0.113.0/24", 100, 0),
        &[(64512, 100), (64512, 200), (65000, 1)],
    );
    assert_eq!(
        run("bgp.communities.filter([*:1]); accept;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(StubCtx.bgp_communities(&r), communities_to(&[(65000, 1)]));
}

#[test]
fn delete_last_community_drops_attribute() {
    let mut r = with_communities(route_with("203.0.113.0/24", 100, 0), &[(64512, 100)]);
    assert_eq!(
        run(
            "bgp.communities.delete([64512:*]); if empty(bgp.communities) then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert!(r.attributes.get(AttrTag::raw(TAG_COMMUNITIES)).is_none());
}

#[test]
fn bird_assignment_idiom_delete_into_attribute() {
    let mut r = with_communities(
        route_with("203.0.113.0/24", 100, 0),
        &[(64512, 100), (65000, 2)],
    );
    assert_eq!(
        run(
            "bgp.communities = delete(bgp.communities, [64512:*]); accept;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(StubCtx.bgp_communities(&r), communities_to(&[(65000, 2)]));
}

#[test]
fn as_path_delete_and_filter() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
            run(
                "bgp.as_path.prepend(65001); bgp.as_path.prepend(65002); bgp.as_path.prepend(65001); accept;",
                &mut r
            ),
            EvalResult::Accept,
        );
    assert_eq!(
        StubCtx.bgp_as_path(&r),
        vec![Asn(65001), Asn(65002), Asn(65001)]
    );
    assert_eq!(
        run("bgp.as_path.delete([65001]); accept;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(StubCtx.bgp_as_path(&r), vec![Asn(65002)]);
    assert_eq!(
        run(
            "bgp.as_path.filter([65003]); if empty(bgp.as_path) then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert!(StubCtx.bgp_as_path(&r).is_empty());
}

#[test]
fn function_style_delete_filter_count_on_values() {
    let mut r = with_communities(
        route_with("203.0.113.0/24", 100, 0),
        &[(64512, 100), (64512, 200)],
    );
    // Pure-value form on a local variable (BIRD: `delete(x, [..])`).
    assert_eq!(
            run(
                "let cs = bgp.communities; let kept = delete(cs, [64512:100]); if count(kept) == 1 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    assert_eq!(
            run(
                "let cs = bgp.communities; let kept = filter(cs, [64512:*]); if count(kept) == 2 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    assert_eq!(
        run(
            "if count(bgp.communities) == 2 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        run(
            "let cs = bgp.communities; if empty(delete(cs, [64512:*])) then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn wildcard_membership_now_matches() {
    // The `~` operator gained wildcard-pattern support alongside
    // the D3.4 pattern machinery.
    let mut r = with_communities(route_with("203.0.113.0/24", 100, 0), &[(64512, 100)]);
    assert_eq!(
        run(
            "if bgp.communities ~ [64512:*] then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        run(
            "if bgp.communities ~ [65000:*] then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn append_rejects_wildcard_pattern() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("bgp.communities += [64512:*]; accept;", &mut r),
        EvalResult::Fallthrough,
    );
}

#[test]
fn append_accepts_exact_pattern_literal() {
    // The set-literal shape changed to CommPattern items; `+=`
    // must keep accepting `asn:val` literals.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("bgp.communities += [64512:100]; accept;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(StubCtx.bgp_communities(&r), communities_to(&[(64512, 100)]));
}

// ===== D3.2 — large communities (RFC 8092) =====

/// Stamp a LARGE_COMMUNITIES attribute onto a route (test helper).
fn with_large(mut r: Route, set: &[(u32, u32, u32)]) -> Route {
    let cs: Vec<lr_bgp::path::communities::LargeCommunity> = set
        .iter()
        .map(|(g, d1, d2)| lr_bgp::path::communities::LargeCommunity::new(*g, *d1, *d2))
        .collect();
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_LARGE_COMMUNITIES),
        flags: 0xC0,
        value: lr_bgp::path::communities::LargeCommunity::encode_set(&cs),
    });
    r
}

#[test]
fn large_communities_append_and_read_back() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("bgp.large_communities += [64512:100:200]; accept;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(StubCtx.bgp_large_communities(&r), vec![(64512, 100, 200)]);
    // Wire form must be the 12-byte RFC 8092 record.
    let raw = r
        .attributes
        .get(AttrTag::raw(TAG_LARGE_COMMUNITIES))
        .unwrap();
    assert_eq!(raw.value.len(), 12);
    assert_eq!(raw.value[..4], [0x00, 0x00, 0xFC, 0x00]);
}

#[test]
fn large_communities_dedup_and_delete_filter() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "bgp.large_communities += [64512:100:200, 64512:100:200, 65000:1:2]; accept;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        StubCtx.bgp_large_communities(&r),
        vec![(64512, 100, 200), (65000, 1, 2)],
    );
    assert_eq!(
        run(
            "bgp.large_communities.delete([64512:100:200]); accept;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(StubCtx.bgp_large_communities(&r), vec![(65000, 1, 2)]);
    assert_eq!(
            run(
                "bgp.large_communities.filter([65000:1:2]); if empty(bgp.large_communities) == false then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    assert_eq!(StubCtx.bgp_large_communities(&r), vec![(65000, 1, 2)]);
}

#[test]
fn large_communities_membership_and_4octet_asn() {
    // 4-octet ASNs fit without AS_TRANS (RFC 8092 §1 motivation).
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
            run(
                "bgp.large_communities += [4200000000:7:9]; if bgp.large_communities ~ [4200000000:7:9] then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    assert_eq!(StubCtx.bgp_large_communities(&r), vec![(4200000000, 7, 9)],);
}

#[test]
fn large_communities_assignment_idiom() {
    let mut r = with_large(
        route_with("203.0.113.0/24", 100, 0),
        &[(64512, 100, 200), (65000, 1, 2)],
    );
    assert_eq!(
        run(
            "bgp.large_communities = delete(bgp.large_communities, [64512:100:200]); accept;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(StubCtx.bgp_large_communities(&r), vec![(65000, 1, 2)]);
}

// ===== D3.3 — extended communities (RFC 4360) =====

#[test]
fn ext_communities_tuple_literal_appends() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "bgp.ext_communities += [(rt, 4200000000, 100)]; accept;",
            &mut r
        ),
        EvalResult::Accept,
    );
    // Route Target: transitive (0x40) 4-octet-AS specific (0x02),
    // subtype 0x02 — the canonical BIRD wire form.
    assert_eq!(
        StubCtx.bgp_ext_communities(&r),
        vec![(0x42, 0x02, 4200000000, 100)],
    );
    // IPv4 administrator form.
    assert_eq!(
        run(
            "bgp.ext_communities += [(rt, 192.0.2.1, 5)]; accept;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        StubCtx.bgp_ext_communities(&r)[1],
        (0x41, 0x02, 0xC000_0201, 5),
    );
}

#[test]
fn ext_communities_ro_soo_names_map_to_subtype_3() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "bgp.ext_communities += [(ro, 65000, 1), (soo, 65001, 2)]; accept;",
            &mut r
        ),
        EvalResult::Accept,
    );
    let cs = StubCtx.bgp_ext_communities(&r);
    assert_eq!(cs[0], (0x42, 0x03, 65000, 1));
    assert_eq!(cs[1], (0x42, 0x03, 65001, 2));
}

#[test]
fn ext_communities_delete_filter_membership() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
            run(
                "bgp.ext_communities += [(rt, 65000, 1), (rt, 65001, 2)]; if bgp.ext_communities ~ [(rt, 65000, 1)] then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    assert_eq!(
        run(
            "bgp.ext_communities.delete([(rt, 65000, 1)]); accept;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        StubCtx.bgp_ext_communities(&r),
        vec![(0x42, 0x02, 65001, 2)],
    );
    assert_eq!(
            run(
                "bgp.ext_communities.filter([(rt, 65009, 9)]); if empty(bgp.ext_communities) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    assert!(StubCtx.bgp_ext_communities(&r).is_empty());
}

#[test]
fn ext_communities_reject_v6_admin_and_bad_local() {
    let f = compile("test", "bgp.ext_communities += [(rt, 2001:db8::1, 1)];");
    assert!(f.is_err(), "IPv6 administrator form must be rejected");
    let f = compile("test", "bgp.ext_communities += [(rt, 65000, 70000)];");
    assert!(f.is_err(), "local part above u16::MAX must be rejected");
}

#[test]
fn defined_works_for_community_attributes() {
    // D3.5 interplay: the new list attributes report presence.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.large_communities) then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
    assert_eq!(
            run(
                "bgp.large_communities += [64512:1:2]; if defined(bgp.large_communities) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
}

// ===== D3.1 — user-defined functions =====

#[test]
fn user_function_returns_value() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
            run(
                "function double(n) { return n * 2; } if bgp.local_pref >= double(50) then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    assert_eq!(
            run(
                "function double(n) { return n * 2; } if bgp.local_pref >= double(51) then accept; reject;",
                &mut r
            ),
            EvalResult::Reject(None),
        );
}

#[test]
fn user_function_multiple_params_and_scoping() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
            run(
                "function clamp(v, lo, hi) { if v < lo then return lo; if v > hi then return hi; return v; } bgp.local_pref = clamp(bgp.local_pref, 150, 200); if bgp.local_pref == 150 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
}

#[test]
fn user_function_mutates_route_bird_parity() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // BIRD functions are the primary structuring tool for route
    // mutation; the body must run on the caller's route.
    assert_eq!(
            run(
                "function tag_transit() { bgp.local_pref = 50; bgp.communities += [64512:100]; } tag_transit(); if bgp.local_pref == 50 && bgp.communities ~ [64512:100] then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
}

#[test]
fn accept_inside_function_terminates_filter() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
            run(
                "function gated() { if bgp.local_pref > 50 then accept; return false; } gated(); reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    // reject inside a function likewise wins.
    let mut r2 = route_with("203.0.113.0/24", 10, 0);
    assert_eq!(
            run(
                "function gated() { if bgp.local_pref < 50 then reject; return true; } gated(); accept;",
                &mut r2
            ),
            EvalResult::Reject(None),
        );
}

#[test]
fn bare_return_and_fallthrough_yield_false() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "function bare() { return; } if bare() == false then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        run(
            "function no_return() { let x = 1; } if no_return() == false then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn runaway_recursion_is_bounded() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // spin() calls itself forever; the depth limiter must abort
    // evaluation (Fallthrough), not smash the stack.
    assert_eq!(
        run("function spin() { return spin(); } spin(); accept;", &mut r),
        EvalResult::Fallthrough,
    );
}

#[test]
fn top_level_return_is_fallthrough() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(run("return true;", &mut r), EvalResult::Fallthrough);
}

#[test]
fn duplicate_or_shadowing_functions_rejected() {
    let f = compile(
        "test",
        "function f() { return 1; } function f() { return 2; } accept;",
    );
    assert!(f.is_err(), "duplicate function name must fail");
    let f = compile("test", "function len(x) { return 1; } accept;");
    assert!(f.is_err(), "shadowing a built-in must fail");
}

#[test]
fn unknown_call_fails_at_compile_time() {
    let f = compile("test", "if no_such_fn(1) then accept; reject;");
    assert!(f.is_err(), "undeclared call must fail to compile");
    // ...including inside function bodies.
    let f = compile("test", "function g() { return also_missing(); } accept;");
    assert!(f.is_err(), "undeclared call in a function body must fail");
}

#[test]
fn builtin_function_list_matches_evaluator() {
    // The parser's BUILTIN_FUNCTIONS gate and the evaluator's
    // built-in table must agree: every listed name must compile
    // with a plausible arity (here: via a call that survives
    // compilation).
    for name in crate::filter::parser::BUILTIN_FUNCTIONS {
        let src = format!("if {name}(1) then accept; reject;");
        let compiled = compile("test", &src);
        // arity errors are runtime (BadArgCount), so compilation
        // must succeed for every built-in name.
        assert!(compiled.is_ok(), "built-in '{name}' rejected by the parser");
    }
}

// ===== D3.7 — bytecode VM equivalence =====

/// Run the same filter through the bytecode VM.
fn run_vm(filter_src: &str, route: &mut Route) -> EvalResult {
    let f = compile("test", filter_src).unwrap_or_else(|e| panic!("{e}"));
    let compiled = crate::filter::bytecode::compile(&f);
    crate::filter::bytecode::execute(&compiled, route, &StubCtx)
}

/// Every source in the equivalence table must produce identical
/// verdicts AND identical post-evaluation route state under both
/// engines.
#[test]
fn vm_matches_interpreter_on_policy_table() {
    let sources = [
            "accept;",
            "reject;",
            "reject with \"too short\";",
            "if bgp.local_pref > 100 then accept; reject;",
            "if bgp.local_pref > 200 then accept; else reject;",
            "case proto { \"bgp\" => accept; default => reject; }",
            "case bgp.local_pref { 100 => accept; 200 => reject; default => accept; }",
            "if bgp.local_pref > 50 && bgp.med < 10 then accept; reject;",
            "if bgp.local_pref > 500 || bgp.med < 10 then accept; reject;",
            "let x = bgp.local_pref * 2 + 1; if x == 201 then accept; reject;",
            "let a = 6; let b = 7; if a * b == 42 then accept; reject;",
            "bgp.local_pref = 200; bgp.med = 30; accept;",
            "bgp.as_path.prepend(65000); bgp.as_path.prepend(65010); accept;",
            "bgp.communities += [64512:100]; bgp.communities.delete([64512:*]); accept;",
            "bgp.large_communities += [64512:1:2, 65000:3:4]; if bgp.large_communities ~ [64512:1:2] then accept; reject;",
            "bgp.ext_communities += [(rt, 65000, 1)]; if bgp.ext_communities ~ [(rt, 65000, 1)] then accept; reject;",
            "if net ~ [ 203.0.113.0/24, 198.51.100.0/24 ] then accept; reject;",
            "if net ~ [ 203.0.0.0/8{16,24} ] then accept; reject;",
            "if defined(bgp.med) && !defined(bgp.as_path) then accept; reject;",
            "function double(n) { return n * 2; } if bgp.local_pref == double(50) then accept; reject;",
            "function tag() { bgp.local_pref = 7; return true; } if tag() then accept; reject;",
            "function gated() { if bgp.local_pref > 50 then accept; return false; } gated(); reject;",
            "function spin() { return spin(); } spin(); accept;",
            "return true;",
            "let n = 65000; if bgp.as_path ~ [n] then accept; reject;",
            "bgp.communities = delete(bgp.communities, [64512:*]); accept;",
            "if count(bgp.communities) == 2 && !empty(bgp.as_path) then accept; reject;",
            "if net !~ 203.0.113.0/24 then accept; reject;",
            "if net !~ [ 198.51.100.0/24, 203.0.113.0/24 ] then accept; reject;",
            "if net ~ 10.0.0.0/8 && net !~ 203.0.113.0/24 then accept; reject;",
        ];

    // Route matrix: plain BGP route, one with communities and a
    // path, one stripped of MED.
    let routes: Vec<Route> = {
        let r0 = route_with("203.0.113.0/24", 100, 0);
        let mut r1 = with_communities(
            route_with("203.0.113.0/24", 100, 5),
            &[(64512, 100), (65000, 2)],
        );
        r1.attributes.insert(Attribute {
            tag: AttrTag::raw(TAG_AS_PATH),
            flags: 0x40,
            value: vec![2u8, 1, 0, 0, 0xFD, 0xE8],
        });
        let mut r2 = route_with("198.51.100.0/24", 42, 0);
        r2.attributes.remove(AttrTag::raw(TAG_MED));
        let r3 = with_large(route_with("203.0.113.0/24", 100, 0), &[(64512, 1, 2)]);
        vec![r0, r1, r2, r3]
    };

    for src in sources {
        for (i, base) in routes.iter().enumerate() {
            let mut a = base.clone();
            let mut b = base.clone();
            let va = run(src, &mut a);
            let vb = run_vm(src, &mut b);
            assert_eq!(va, vb, "verdict mismatch on route {i} for: {src}");
            assert_eq!(
                a.attributes, b.attributes,
                "attribute mismatch on route {i} for: {src}"
            );
            assert_eq!(a.next_hop, b.next_hop);
        }
    }
}

/// #19 P0 — extend the equivalence table with the bench-sized
/// shapes (`filter_eval`/`import_pipeline`). The 27×4 table above
/// uses tiny sets; the benches use a 100-entry prefix set, a
/// 10-entry community set, and a two-function user-function chain.
/// Those shapes must keep VM == interpreter verdict + route state
/// exactly the same as the small ones, otherwise the bench
/// numbers cannot be trusted to reflect the production hot path.
#[test]
fn vm_matches_interpreter_on_bench_shapes() {
    // 100-entry prefix set: `net ~ [ 10.0.0.1/32, ..., 10.0.63.100/32 ]`.
    // Host routes so the linear scan cannot short-circuit on
    // longest-prefix-match optimization.
    let mut pfx_set = String::from("net ~ [ ");
    for i in 0..100u32 {
        if i > 0 {
            pfx_set.push_str(", ");
        }
        let a = (i / 256) as u8;
        let b = (i % 256) as u8;
        pfx_set.push_str(&format!("10.{a}.{b}.1/32"));
    }
    pfx_set.push_str(" ]");
    let large_prefix_src = format!("if {pfx_set} then accept; reject;");

    // 10-entry community set: `bgp.communities ~ [ 64512:1, ..., 64512:10 ]`.
    let mut comm_set = String::from("bgp.communities ~ [ ");
    for i in 1..=10u32 {
        if i > 1 {
            comm_set.push_str(", ");
        }
        comm_set.push_str(&format!("64512:{i}"));
    }
    comm_set.push_str(" ]");
    let large_comm_src = format!("if {comm_set} then accept; reject;");

    // User functions: two-call chain (classify + tag).
    let user_fn_src = "function tag_customer(lp) { bgp.local_pref = lp; return true; } \
             function classify(lp) { if lp >= 200 then return 300; return 100; } \
             let lp = classify(bgp.local_pref); \
             if tag_customer(lp) && bgp.local_pref == 300 then accept; reject;";

    let bench_sources = [large_prefix_src, large_comm_src, user_fn_src.to_string()];

    // Route matrix covers the hit/miss positions the bench
    // measures plus the plain route that exercises the user-fn
    // classifier's `lp < 200` branch (returns 100, tag fails).
    let routes: Vec<Route> = {
        // large_prefix_set hit_last: 10.0.63.100/32 matches the
        // 100th entry.
        let r0 = route_with("10.0.63.100/32", 150, 30);
        // large_prefix_set miss: 203.0.113.0/24 matches nothing.
        let r1 = route_with("203.0.113.0/24", 150, 30);
        // large_community_set hit_last: carries 64512:10.
        let r2 = with_communities(route_with("203.0.113.0/24", 150, 30), &[(64512, 10)]);
        // large_community_set miss: carries 64512:9999.
        let r3 = with_communities(route_with("203.0.113.0/24", 150, 30), &[(64512, 9999)]);
        // user_functions hit: local_pref=200 → classify→300, tag→300, match.
        let r4 = route_with("203.0.113.0/24", 200, 30);
        // user_functions miss: local_pref=100 → classify→100, tag→100, no match.
        let r5 = route_with("203.0.113.0/24", 100, 30);
        vec![r0, r1, r2, r3, r4, r5]
    };

    for src in bench_sources {
        for (i, base) in routes.iter().enumerate() {
            let mut a = base.clone();
            let mut b = base.clone();
            let va = run(&src, &mut a);
            let vb = run_vm(&src, &mut b);
            assert_eq!(va, vb, "verdict mismatch on route {i} for: {src}");
            assert_eq!(
                a.attributes, b.attributes,
                "attribute mismatch on route {i} for: {src}"
            );
            assert_eq!(a.next_hop, b.next_hop);
        }
    }
}

/// #19 P4 — the prefix-trie path (`MatchRhs::PrefixSet`) must
/// produce the same verdicts as the linear-scan path
/// (`MatchRhs::Set`) across a matrix of set shapes (plain
/// /32s, `ge`/`le` ranges, IPv6, mixed prefix + value sets)
/// and query prefixes (hit, miss, longer, shorter, wrong
/// family). This is the differential test the #19 process
/// guardrail calls for: the trie is a performance
/// optimisation, not a semantic change.
#[test]
fn prefix_trie_matches_linear_scan_across_set_shapes() {
    // Each entry is (filter_source, query_prefixes_that_accept,
    // query_prefixes_that_reject).
    let cases: &[(&str, &[&str], &[&str])] = &[
        // 1. Plain /32 set — exact match only.
        (
            "if net ~ [ 10.0.0.1/32, 10.0.0.2/32, 10.0.0.100/32 ] then accept; reject;",
            &["10.0.0.1/32", "10.0.0.2/32", "10.0.0.100/32"],
            &["10.0.0.3/32", "10.0.0.0/32", "10.0.0.1/31"],
        ),
        // 2. `ge`/`le` range: 10.0.0.0/8{16,24} — accepts /16
        // through /24 inside 10/8.
        (
            "if net ~ [ 10.0.0.0/8{16,24} ] then accept; reject;",
            &[
                "10.0.0.0/16",
                "10.0.0.0/24",
                "10.1.2.0/24",
                "10.255.255.0/24",
            ],
            &["10.0.0.0/8", "10.0.0.0/25", "10.0.0.0/15", "192.0.2.0/24"],
        ),
        // 3. IPv6 set with range.
        (
            "if net ~ [ 2001:db8::/32{48,64} ] then accept; reject;",
            &[
                "2001:db8::/48",
                "2001:db8::/64",
                "2001:db8:1::/64",
                "2001:db8:ffff::/64",
            ],
            &[
                "2001:db8::/32",
                "2001:db8::/65",
                "2001:db9::/48",
                "2001:dead::/48",
            ],
        ),
        // 4. Mixed prefix + value set: the trie handles the prefix
        // items; the value items stay in the linear scan.
        (
            "if net ~ [ 10.0.0.0/8, 192.0.2.0/24, 64512 ] then accept; reject;",
            &[
                "10.0.0.0/8",
                "10.1.2.3/32",
                "192.0.2.0/24",
                "192.0.2.128/25",
            ],
            &["172.16.0.0/12", "203.0.113.0/24"],
        ),
        // 5. Multiple overlapping ranges — the trie must check
        // every covering node, not just the first.
        (
            "if net ~ [ 10.0.0.0/8, 10.0.0.0/24{25,32} ] then accept; reject;",
            &[
                "10.0.0.0/8",
                "10.0.0.0/24",
                "10.0.0.128/25",
                "10.0.0.1/32",
                "10.1.0.0/25",
            ],
            &["172.16.0.0/12", "192.0.2.0/24"],
        ),
    ];

    for (src, accept_prefixes, reject_prefixes) in cases {
        for pfx in *accept_prefixes {
            let mut r = route_with(pfx, 150, 30);
            let va = run(src, &mut r);
            let mut r2 = route_with(pfx, 150, 30);
            let vb = run_vm(src, &mut r2);
            assert_eq!(va, vb, "verdict mismatch on accept prefix {pfx} for: {src}");
            assert!(
                matches!(va, EvalResult::Accept),
                "expected accept for {pfx} in: {src}, got {va:?}"
            );
        }
        for pfx in *reject_prefixes {
            let mut r = route_with(pfx, 150, 30);
            let va = run(src, &mut r);
            let mut r2 = route_with(pfx, 150, 30);
            let vb = run_vm(src, &mut r2);
            assert_eq!(va, vb, "verdict mismatch on reject prefix {pfx} for: {src}");
            assert!(
                matches!(va, EvalResult::Reject(_)),
                "expected reject for {pfx} in: {src}, got {va:?}"
            );
        }
    }
}

/// #19 P2 — user-function calls are resolved to `CallFn { idx, argc }`
/// at compile time. The compiled `CompiledFilter` carries a
/// `Vec<CompiledFunction>` (indexed by `CallFn`) and a
/// `function_index` map (name → index). This test pins both:
/// the instruction variant is `CallFn` (not `Call`), and the
/// function table is a `Vec` (not a `BTreeMap`).
#[test]
fn p2_user_function_calls_resolve_to_callfn() {
    let f = compile(
        "test-p2-callfn",
        "function double(n) { return n * 2; } \
             function tag(lp) { bgp.local_pref = lp; return true; } \
             if tag(double(50)) && bgp.local_pref == 100 then accept; reject;",
    )
    .unwrap();
    let cf = crate::filter::bytecode::compile(&f);

    // The function table is a Vec with 2 entries, indexed by
    // the CallFn instruction. `function_index` maps names to
    // indices: "double" → 0, "tag" → 1 (declaration order).
    assert_eq!(cf.functions.len(), 2);
    assert_eq!(cf.function_index.get("double"), Some(&0));
    assert_eq!(cf.function_index.get("tag"), Some(&1));

    // The body code must contain at least one `CallFn` instruction
    // (for `double(50)` or `tag(...)`). It must NOT contain a
    // `Call` with name "double" or "tag" (those are user
    // functions, not built-ins).
    let has_callfn = cf.code.iter().any(|i| matches!(i, Instr::CallFn { .. }));
    assert!(has_callfn, "body code must contain a CallFn instruction");
    let has_user_call = cf.code.iter().any(|i| {
        matches!(
            i,
            Instr::Call { name, .. } if name == "double" || name == "tag"
        )
    });
    assert!(
        !has_user_call,
        "body code must not contain a Call for user functions"
    );

    // Built-in calls (like `len`) still use `Call { name, argc }`.
    let f2 = compile(
        "test-p2-builtin",
        "if count(bgp.communities) == 2 then accept; reject;",
    )
    .unwrap();
    let cf2 = crate::filter::bytecode::compile(&f2);
    let has_builtin_call = cf2
        .code
        .iter()
        .any(|i| matches!(i, Instr::Call { name, .. } if name == "count"));
    assert!(
        has_builtin_call,
        "body code must contain a Call for the built-in `count`"
    );
    let has_callfn2 = cf2.code.iter().any(|i| matches!(i, Instr::CallFn { .. }));
    assert!(
        !has_callfn2,
        "body code must not contain a CallFn for built-in calls"
    );
}

/// #19 P2 — the `CallFn` instruction and the old `Call` fallback
/// produce identical verdicts and route state. The equivalence
/// table already covers user functions via `Call`, but this test
/// pins the `CallFn` path explicitly against the interpreter.
#[test]
fn p2_callfn_matches_interpreter_on_user_functions() {
    let sources = [
            "function double(n) { return n * 2; } if bgp.local_pref == double(50) then accept; reject;",
            "function tag() { bgp.local_pref = 7; return true; } if tag() then accept; reject;",
            "function gated() { if bgp.local_pref > 50 then accept; return false; } gated(); reject;",
            "function classify(lp) { if lp >= 200 then return 300; return 100; } let lp = classify(bgp.local_pref); if lp == 100 then accept; reject;",
        ];
    let routes: Vec<Route> = {
        let r0 = route_with("203.0.113.0/24", 100, 0);
        let r1 = route_with("203.0.113.0/24", 200, 0);
        let r2 = route_with("203.0.113.0/24", 42, 0);
        vec![r0, r1, r2]
    };
    for src in sources {
        for (i, base) in routes.iter().enumerate() {
            let mut a = base.clone();
            let mut b = base.clone();
            let va = run(src, &mut a);
            let vb = run_vm(src, &mut b);
            assert_eq!(va, vb, "verdict mismatch on route {i} for: {src}");
            assert_eq!(
                a.attributes, b.attributes,
                "attribute mismatch on route {i} for: {src}"
            );
        }
    }
}

// ----- #18 Phase 0: evaluation errors carry real positions -----

/// Drive the tree-walking evaluator directly and surface the
/// error (evaluate() itself logs + falls through).
fn run_err(filter_src: &str) -> EvalError {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let f = compile("test", filter_src).unwrap_or_else(|e| panic!("{e}"));
    let mut ev = Evaluator {
        ctx: &StubCtx,
        scopes: vec![Scope::new()],
        functions: f
            .functions
            .iter()
            .map(|f| (f.name.clone(), f.clone()))
            .collect(),
        call_depth: 0,
        pending_verdict: None,
        line_index: &f.line_index,
    };
    for stmt in &f.body.stmts {
        if let Err(e) = ev.eval_stmt(stmt, &mut r) {
            return e;
        }
    }
    panic!("filter evaluated without error: {filter_src}");
}

/// Same through the bytecode VM (run_code returns the raw error).
fn run_vm_err(filter_src: &str) -> EvalError {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let f = compile("test", filter_src).unwrap_or_else(|e| panic!("{e}"));
    let compiled = crate::filter::bytecode::compile(&f);
    let mut ev = Evaluator {
        ctx: &StubCtx,
        scopes: vec![Scope::new()],
        functions: std::collections::BTreeMap::new(),
        call_depth: 0,
        pending_verdict: None,
        line_index: &compiled.line_index,
    };
    match ev.run_code(&compiled.code, &compiled.spans, &compiled, &mut r) {
        Err(e) => e,
        other => panic!("VM did not error: {other:?}"),
    }
}

#[test]
fn eval_error_assign_undefined_carries_span() {
    let src = "accept;\nzz = 1;";
    let e = run_err(src);
    assert!(
        matches!(e.kind, EvalErrorKind::AssignToUndefined(_)),
        "{e:?}"
    );
    assert_eq!(e.span.slice(src), Some("zz = 1;"), "{e:?}");
    assert_eq!((e.line, e.col), (2, 1));
}

#[test]
fn eval_error_undefined_var_carries_span() {
    let src = "let ok = 1;\nnope;";
    let e = run_err(src);
    assert!(
        matches!(&e.kind, EvalErrorKind::UndefinedVar(v) if v == "nope"),
        "{e:?}"
    );
    assert_eq!(e.span.slice(src), Some("nope"), "{e:?}");
    assert_eq!((e.line, e.col), (2, 1));
}

#[test]
fn eval_error_type_mismatch_points_at_expression() {
    let src = "if 1 + \"x\" == 2 then accept; accept;";
    let e = run_err(src);
    assert!(
        matches!(e.kind, EvalErrorKind::TypeMismatch { .. }),
        "{e:?}"
    );
    assert_eq!(e.span.slice(src), Some("1 + \"x\""), "{e:?}");
    assert_eq!((e.line, e.col), (1, 4));
}

#[test]
fn vm_errors_match_interpreter_spans() {
    // The erroring construct must run before any `accept;` — the
    // VM (like the interpreter) terminates at the first verdict.
    let sources = [
        "zz = 1;",
        "let ok = 1;\nnope;",
        "if 1 + \"x\" == 2 then accept; accept;",
        "let a = 1;\nlet b = a + \"s\";",
    ];
    for src in sources {
        let a = run_err(src);
        let b = run_vm_err(src);
        assert_eq!(a.kind, b.kind, "{src}");
        assert_eq!(a.span, b.span, "{src}");
        assert_eq!((a.line, a.col), (b.line, b.col), "{src}");
    }
}

#[test]
fn vm_error_spans_survive_peephole_optimisation() {
    // The `1 + 2` folds to `Push(Int(3))`; the peephole passes
    // must keep the span table aligned so the later UndefinedVar
    // still points at `missing` on line 2.
    let src = "let n = 1 + 2;\nmissing;";
    let e = run_vm_err(src);
    assert!(
        matches!(&e.kind, EvalErrorKind::UndefinedVar(v) if v == "missing"),
        "{e:?}"
    );
    assert_eq!(e.span.slice(src), Some("missing"), "{e:?}");
    assert_eq!((e.line, e.col), (2, 1));
}

/// GitHub #19 P7 — the lazy-span refactor moves `run_code` to
/// take the spans slice as a parameter alongside `code`. This
/// fixes a latent bug where a user-function body would index
/// the *outer filter's* span table (`cf.spans`) instead of its
/// own (`f.spans`): the outer table is parallel to `cf.code`,
/// not to `f.code`, so an error at `f.code[ip]` read the wrong
/// span (or `Span::default()` when `ip >= cf.spans.len()`).
/// The fix threads `&f.spans` through `call_compiled_function`
/// → `run_code`, so the VM reads the function's own span at
/// every `ip`.
///
/// The test constructs a filter where the function body is
/// *longer* than the outer filter body, so the pre-fix path
/// would have indexed past the end of `cf.spans` and returned
/// `Span::default()` — the slice assertion would fail with
/// `Some(None)` vs `Some("missing")`.
#[test]
fn vm_error_inside_user_function_carries_function_span() {
    // The outer body is two statements (`bad(); accept;`); the
    // function body is three (`missing; return true; <Return>`).
    // The `missing` reference sits at index 0 of `f.code` but
    // the outer filter's span table only has entries for the
    // outer body's instructions — pre-fix, the VM read
    // `cf.spans[0]` (the span of the outer body's first
    // instruction, `CallFn`) instead of `f.spans[0]` (the span
    // of `missing`).
    let src = "function bad() {\n  missing;\n  return true;\n}\nbad();\naccept;";
    let a = run_err(src);
    let b = run_vm_err(src);
    assert_eq!(a.kind, b.kind, "kind mismatch (interpreter vs VM)");
    assert_eq!(a.span, b.span, "span mismatch (interpreter vs VM)");
    assert_eq!((a.line, a.col), (b.line, b.col), "line/col mismatch");
    assert!(
        matches!(&b.kind, EvalErrorKind::UndefinedVar(v) if v == "missing"),
        "{b:?}"
    );
    assert_eq!(b.span.slice(src), Some("missing"), "{b:?}");
    assert_eq!((b.line, b.col), (2, 3));
}
