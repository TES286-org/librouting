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

// ---- RFC 4271 §5.1.6 + RFC 4456 §8: new read-only BGP fields ----

const TAG_ATOMIC_AGGREGATE: u8 = 6;
const TAG_ORIGINATOR_ID: u8 = 9;
const TAG_CLUSTER_LIST: u8 = 10;
/// RFC 9234 §3.1: OTC attribute type code.
const TAG_OTC: u8 = 35;
/// RFC 7311 §3: AIGP attribute type code.
const TAG_AIGP: u8 = 26;
/// RFC 4271 §5.1.7: AGGREGATOR attribute type code.
const TAG_AGGREGATOR: u8 = 7;
/// RFC 6514 §5: PMSI Tunnel attribute type code (22, optional
/// transitive).
const TAG_PMSI_TUNNEL: u8 = 22;

fn route_with_atomic_aggregate() -> Route {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_ATOMIC_AGGREGATE),
        flags: 0x40,
        value: Vec::new(),
    });
    r
}

fn route_with_originator_id(id: [u8; 4]) -> Route {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_ORIGINATOR_ID),
        flags: 0x80,
        value: id.to_vec(),
    });
    r
}

fn route_with_cluster_list(ids: &[[u8; 4]]) -> Route {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    if ids.is_empty() {
        return r;
    }
    let mut v = Vec::with_capacity(ids.len() * 4);
    for id in ids {
        v.extend_from_slice(id);
    }
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_CLUSTER_LIST),
        flags: 0x80,
        value: v,
    });
    r
}

#[test]
fn bgp_atomic_aggregate_reads_as_bool_true_when_present() {
    let mut r = route_with_atomic_aggregate();
    assert_eq!(
        run("if bgp.atomic_aggregate then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_atomic_aggregate_reads_as_bool_false_when_absent() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if bgp.atomic_aggregate then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_atomic_aggregate_is_defined_iff_present() {
    let mut r_with = route_with_atomic_aggregate();
    assert_eq!(
        run(
            "if defined(bgp.atomic_aggregate) then accept; reject;",
            &mut r_with
        ),
        EvalResult::Accept,
    );
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.atomic_aggregate) then accept; reject;",
            &mut r_without
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_originator_id_reads_as_ip_when_present() {
    let mut r = route_with_originator_id([10, 0, 0, 1]);
    assert_eq!(
        run(
            "if bgp.originator_id == 10.0.0.1 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_originator_id_mismatch_rejects() {
    let mut r = route_with_originator_id([10, 0, 0, 2]);
    assert_eq!(
        run(
            "if bgp.originator_id == 10.0.0.1 then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_originator_id_is_defined_iff_present() {
    let mut r_with = route_with_originator_id([10, 0, 0, 1]);
    assert_eq!(
        run(
            "if defined(bgp.originator_id) then accept; reject;",
            &mut r_with
        ),
        EvalResult::Accept,
    );
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.originator_id) then accept; reject;",
            &mut r_without
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_cluster_list_membership_test() {
    // CLUSTER_LIST = [10.0.0.2, 10.0.0.1] (reflection order:
    // most-recently-prepended first).
    let mut r = route_with_cluster_list(&[[10, 0, 0, 2], [10, 0, 0, 1]]);
    assert_eq!(
        run(
            "if 10.0.0.1 ~ bgp.cluster_list then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    let mut r2 = route_with_cluster_list(&[[10, 0, 0, 2], [10, 0, 0, 1]]);
    assert_eq!(
        run(
            "if 10.0.0.3 ~ bgp.cluster_list then accept; reject;",
            &mut r2
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_cluster_list_is_defined_iff_present() {
    // Present and non-empty.
    let mut r_with = route_with_cluster_list(&[[10, 0, 0, 1]]);
    assert_eq!(
        run(
            "if defined(bgp.cluster_list) then accept; reject;",
            &mut r_with
        ),
        EvalResult::Accept,
    );
    // Absent.
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.cluster_list) then accept; reject;",
            &mut r_without
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_cluster_list_empty_membership_is_false() {
    // Absent CLUSTER_LIST reads as an empty Set; no IP matches.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if 10.0.0.1 ~ bgp.cluster_list then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_atomic_aggregate_is_not_assignable() {
    // The parser rejects writes to read-only fields. ATOMIC_AGGREGATE
    // is a presence marker — there's no value to set.
    let err = compile("test", "bgp.atomic_aggregate = true;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn bgp_originator_id_is_not_assignable() {
    let err = compile("test", "bgp.originator_id = 10.0.0.1;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn bgp_cluster_list_is_not_assignable() {
    let err = compile("test", "bgp.cluster_list = [10.0.0.1];").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

// ---- RFC 9234 §3.1: bgp.otc ----

fn route_with_otc(value: u32) -> Route {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_OTC),
        flags: 0xC0,
        value: value.to_be_bytes().to_vec(),
    });
    r
}

#[test]
fn bgp_otc_reads_as_int_when_present() {
    let mut r = route_with_otc(64512);
    assert_eq!(
        run("if bgp.otc == 64512 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_otc_reads_as_zero_when_absent() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // An absent OTC reads as 0 — the unwrap_or(0) semantics on the
    // int-typed field read. Matches BIRD's `bgp_otc` filter behaviour.
    assert_eq!(
        run("if bgp.otc == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_otc_mismatch_rejects() {
    let mut r = route_with_otc(64513);
    assert_eq!(
        run("if bgp.otc == 64512 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_otc_is_defined_iff_present() {
    // Present, value 64512.
    let mut r_with = route_with_otc(64512);
    assert_eq!(
        run("if defined(bgp.otc) then accept; reject;", &mut r_with),
        EvalResult::Accept,
    );
    // Absent.
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if defined(bgp.otc) then accept; reject;", &mut r_without),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_otc_defined_distinguishes_absent_from_set_to_zero() {
    // RFC 9234 §3.1: a present value of 0 ("set but zero") is
    // distinct from "absent" — `defined(bgp.otc)` reports true for
    // the former and false for the latter. This is the case the
    // `has_otc` accessor exists to make precise.
    let mut r_zero = route_with_otc(0);
    assert_eq!(
        run("if defined(bgp.otc) then accept; reject;", &mut r_zero),
        EvalResult::Accept,
    );
    let mut r_absent = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if defined(bgp.otc) then accept; reject;", &mut r_absent),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_otc_leak_detection_idiom() {
    // RFC 9234 §5 egress rule 2 in filter form: a route that
    // carries OTC (the value is set) is a "customer-only" route and
    // must not transit to a provider or peer. The filter DSL spells
    // the test the same way BIRD does — `bgp.otc != 0` — and the
    // canonical leak-detection idiom translates faithfully.
    let mut r_leak = route_with_otc(64512);
    assert_eq!(
        run("if bgp.otc != 0 then reject; accept;", &mut r_leak),
        EvalResult::Reject(None),
    );
    let mut r_clean = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if bgp.otc != 0 then reject; accept;", &mut r_clean),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_otc_is_not_assignable() {
    let err = compile("test", "bgp.otc = 64512;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn bgp_otc_peephole_fused_branch_agrees_with_unfused() {
    // The peephole pass fuses `LoadField(BgpOtc); Push(Int(c));
    // Bin(op); JumpIf*` into a single `BranchFieldIntCmp` for int
    // fields. OTC was added to `is_int_field` so the fused path
    // fires; pin the agreement between the fused and unfused paths
    // by checking the same comparison both ways.
    let mut r = route_with_otc(64512);
    // Fused: constant on the RHS, comparison op in the fuse set.
    assert_eq!(
        run("if bgp.otc == 64512 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if bgp.otc != 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    // Unfused: constant on the LHS (the peephole does not fuse
    // `Bin(Int(c), op, LoadField)`), exercises the read_route_field
    // path directly.
    assert_eq!(
        run("if 64512 == bgp.otc then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

// ---- RFC 7311: bgp.aigp ----

fn route_with_aigp(metric: u64) -> Route {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // AIGP is optional non-transitive (flags 0x80). The value is a
    // TLV stream: a single type-1 TLV carrying the 8-byte metric.
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&1u16.to_be_bytes()); // type 1
    value.extend_from_slice(&12u16.to_be_bytes()); // length 12 (4 header + 8 value)
    value.extend_from_slice(&metric.to_be_bytes());
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_AIGP),
        flags: 0x80,
        value,
    });
    r
}

#[test]
fn bgp_aigp_reads_as_int_when_present() {
    let mut r = route_with_aigp(64512);
    assert_eq!(
        run("if bgp.aigp == 64512 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_aigp_reads_as_zero_when_absent() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // An absent AIGP reads as 0 — the unwrap_or(0) semantics on the
    // int-typed field read.
    assert_eq!(
        run("if bgp.aigp == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_aigp_mismatch_rejects() {
    let mut r = route_with_aigp(64513);
    assert_eq!(
        run("if bgp.aigp == 64512 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aigp_is_defined_iff_present() {
    // Present, metric 64512.
    let mut r_with = route_with_aigp(64512);
    assert_eq!(
        run("if defined(bgp.aigp) then accept; reject;", &mut r_with),
        EvalResult::Accept,
    );
    // Absent.
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if defined(bgp.aigp) then accept; reject;", &mut r_without),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aigp_defined_distinguishes_absent_from_set_to_zero() {
    // RFC 7311: a present value of 0 ("set but zero") is distinct
    // from "absent" — `defined(bgp.aigp)` reports true for the
    // former and false for the latter. This is the case the
    // `has_aigp` accessor exists to make precise.
    let mut r_zero = route_with_aigp(0);
    assert_eq!(
        run("if defined(bgp.aigp) then accept; reject;", &mut r_zero),
        EvalResult::Accept,
    );
    let mut r_absent = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if defined(bgp.aigp) then accept; reject;", &mut r_absent),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aigp_metric_comparison_idiom() {
    // RFC 7311 §4: the accumulated metric is a distance — a filter
    // can prefer a lower-metric route. The DSL spells the test the
    // same way BIRD does — `bgp.aigp < N`.
    let mut r_low = route_with_aigp(50);
    assert_eq!(
        run("if bgp.aigp < 100 then accept; reject;", &mut r_low),
        EvalResult::Accept,
    );
    let mut r_high = route_with_aigp(150);
    assert_eq!(
        run("if bgp.aigp < 100 then accept; reject;", &mut r_high),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aigp_is_not_assignable() {
    let err = compile("test", "bgp.aigp = 100;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn bgp_aigp_unfused_read_path_agrees_both_directions() {
    // AIGP is deliberately NOT in the peephole's `is_int_field` set
    // (its read parses a TLV stream, so fusing would not save the
    // allocation the fast path exists to avoid). Both the
    // constant-RHS and constant-LHS comparison forms run the
    // unfused `read_route_field` path; pin the agreement.
    let mut r = route_with_aigp(64512);
    assert_eq!(
        run("if bgp.aigp == 64512 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if 64512 == bgp.aigp then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

// ---- RFC 4271 §5.1.7: bgp.aggregator.{asn,speaker} ----

/// Build a route carrying an AGGREGATOR attribute in the canonical
/// 4-byte-AS wire form (the stored encoding after ingress reconciles
/// AS4_AGGREGATOR). AGGREGATOR is optional transitive (flags 0xC0).
fn route_with_aggregator(asn: u32, speaker: [u8; 4]) -> Route {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let mut value = Vec::with_capacity(8);
    value.extend_from_slice(&asn.to_be_bytes());
    value.extend_from_slice(&speaker);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_AGGREGATOR),
        flags: 0xC0,
        value,
    });
    r
}

#[test]
fn bgp_aggregator_asn_reads_as_int_when_present() {
    let mut r = route_with_aggregator(64512, [10, 0, 0, 1]);
    assert_eq!(
        run(
            "if bgp.aggregator.asn == 64512 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_aggregator_asn_reads_as_zero_when_absent() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // An absent AGGREGATOR reads as 0 — the unwrap_or(0) semantics on
    // the int-typed field read. Matches BIRD's `bgp_aggregator`
    // filter behaviour on a non-aggregated route.
    assert_eq!(
        run("if bgp.aggregator.asn == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_aggregator_asn_mismatch_rejects() {
    let mut r = route_with_aggregator(64513, [10, 0, 0, 1]);
    assert_eq!(
        run(
            "if bgp.aggregator.asn == 64512 then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aggregator_speaker_reads_as_ip_when_present() {
    let mut r = route_with_aggregator(64512, [10, 0, 0, 1]);
    assert_eq!(
        run(
            "if bgp.aggregator.speaker == 10.0.0.1 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_aggregator_asn_is_defined_iff_present() {
    // Present.
    let mut r_with = route_with_aggregator(64512, [10, 0, 0, 1]);
    assert_eq!(
        run(
            "if defined(bgp.aggregator.asn) then accept; reject;",
            &mut r_with
        ),
        EvalResult::Accept,
    );
    // Absent.
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.aggregator.asn) then accept; reject;",
            &mut r_without
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aggregator_speaker_shares_presence_with_asn() {
    // Both components are present together or absent together, so
    // `defined(bgp.aggregator.speaker)` agrees with
    // `defined(bgp.aggregator.asn)` — the canonical probe.
    let mut r_with = route_with_aggregator(64512, [10, 0, 0, 1]);
    assert_eq!(
        run(
            "if defined(bgp.aggregator.speaker) then accept; reject;",
            &mut r_with
        ),
        EvalResult::Accept,
    );
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.aggregator.speaker) then accept; reject;",
            &mut r_without
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aggregator_defined_distinguishes_absent_from_set_to_zero() {
    // RFC 4271 §5.1.7: a present value of AS 0 ("set but zero") is
    // distinct from "absent" — `defined(bgp.aggregator.asn)` reports
    // true for the former and false for the latter. This is the case
    // the `has_aggregator` accessor exists to make precise.
    let mut r_zero = route_with_aggregator(0, [0, 0, 0, 0]);
    assert_eq!(
        run(
            "if defined(bgp.aggregator.asn) then accept; reject;",
            &mut r_zero
        ),
        EvalResult::Accept,
    );
    let mut r_absent = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.aggregator.asn) then accept; reject;",
            &mut r_absent
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aggregator_aggregation_aware_policy_idiom() {
    // The canonical aggregation-aware idiom: accept routes that were
    // aggregated by a known AS, fall through otherwise. The DSL
    // spells the test the same way an operator would against BIRD's
    // `bgp_aggregator`.
    let mut r_known = route_with_aggregator(64512, [10, 0, 0, 1]);
    assert_eq!(
        run(
            "if defined(bgp.aggregator.asn) && bgp.aggregator.asn == 64512 then accept; reject;",
            &mut r_known
        ),
        EvalResult::Accept,
    );
    let mut r_other = route_with_aggregator(65000, [10, 0, 0, 2]);
    assert_eq!(
        run(
            "if defined(bgp.aggregator.asn) && bgp.aggregator.asn == 64512 then accept; reject;",
            &mut r_other
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_aggregator_asn_is_not_assignable() {
    let err = compile("test", "bgp.aggregator.asn = 64512;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn bgp_aggregator_speaker_is_not_assignable() {
    let err = compile("test", "bgp.aggregator.speaker = 10.0.0.1;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn bgp_aggregator_unknown_subfield_is_a_parse_error() {
    // `bgp.aggregator.<unknown>` is rejected at parse time with
    // `UnknownBgpField` so a typo does not silently no-op.
    let err = compile("test", "if bgp.aggregator.bogus == 0 then accept; reject;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("bgp.aggregator.bogus") || msg.contains("UnknownBgpField"),
        "expected an UnknownBgpField error, got: {msg}"
    );
}

#[test]
fn bgp_aggregator_unfused_read_path_agrees_both_directions() {
    // AGGREGATOR is deliberately NOT in the peephole's `is_int_field`
    // set (its read decodes the Aggregator struct — a length check +
    // two fixed-size copies — not a single `get_u32_be`, so fusing
    // would not save the allocation the fast path exists to avoid;
    // mirrors the AIGP decision). Both the constant-RHS and
    // constant-LHS comparison forms run the unfused `read_route_field`
    // path; pin the agreement.
    let mut r = route_with_aggregator(64512, [10, 0, 0, 1]);
    assert_eq!(
        run(
            "if bgp.aggregator.asn == 64512 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        run(
            "if 64512 == bgp.aggregator.asn then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

// ---- RFC 6514 §5: bgp.pmsi_tunnel ----

/// Build a route carrying a PMSI Tunnel attribute (RFC 6514 §5) in
/// the canonical wire form: Flags + Tunnel Type + MPLS Label (3
/// bytes) + Tunnel Identifier (variable). The attribute is optional
/// transitive (flags 0xC0). The helper encodes the 20-bit MPLS label
/// in the high 20 bits of the 3-byte label field, with the low 4 bits
/// (EXP + End-of-Stack) zeroed on encode.
fn route_with_pmsi_tunnel(
    flags: u8,
    tunnel_type: u8,
    mpls_label: u32,
    tunnel_id: Vec<u8>,
) -> Route {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    let mut value = Vec::with_capacity(5 + tunnel_id.len());
    value.push(flags);
    value.push(tunnel_type);
    let label24 = (mpls_label & 0x000f_ffff) << 4;
    value.extend_from_slice(&label24.to_be_bytes()[1..4]);
    value.extend_from_slice(&tunnel_id);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_PMSI_TUNNEL),
        flags: 0xC0,
        value,
    });
    r
}

#[test]
fn bgp_pmsi_tunnel_reads_as_bool_true_when_present() {
    // RFC 6514 §5: Tunnel Type 6 (Ingress Replication), IPv4
    // endpoint, MPLS label 64512, L bit set.
    let mut r = route_with_pmsi_tunnel(0b0000_0001, 6, 64512, vec![10, 0, 0, 1]);
    assert_eq!(
        run("if bgp.pmsi_tunnel then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_pmsi_tunnel_reads_as_false_when_absent() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // An absent PMSI Tunnel reads as `false` — the presence-probe
    // shape mirrors BIRD's `defined(bgp_pmsi_tunnel)` exposure.
    assert_eq!(
        run("if bgp.pmsi_tunnel then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
    // The negation reads as `true`.
    assert_eq!(
        run("if !bgp.pmsi_tunnel then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_pmsi_tunnel_is_defined_iff_present() {
    // Present.
    let mut r_with = route_with_pmsi_tunnel(0, 0, 0, Vec::new());
    assert_eq!(
        run(
            "if defined(bgp.pmsi_tunnel) then accept; reject;",
            &mut r_with
        ),
        EvalResult::Accept,
    );
    // Absent.
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.pmsi_tunnel) then accept; reject;",
            &mut r_without
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_pmsi_tunnel_defined_distinguishes_absent_from_present_but_malformed() {
    // RFC 6514 §5: a present-but-malformed attribute (truncated
    // header — the 5-byte minimum is missing) is distinct from
    // "absent" — `defined(bgp.pmsi_tunnel)` reports true for the
    // former and false for the latter. This is the case the
    // `has_pmsi_tunnel` accessor exists to make precise.
    let mut r_bad = route_with("203.0.113.0/24", 100, 0);
    r_bad.attributes.insert(Attribute {
        tag: AttrTag::raw(TAG_PMSI_TUNNEL),
        flags: 0xC0,
        value: vec![0, 0, 0, 0], // truncated header
    });
    assert_eq!(
        run(
            "if defined(bgp.pmsi_tunnel) then accept; reject;",
            &mut r_bad
        ),
        EvalResult::Accept,
    );
    // The Bool read also reports `true` — the physical presence
    // probe, not the typed accessor's `Some/None` shape.
    assert_eq!(
        run("if bgp.pmsi_tunnel then accept; reject;", &mut r_bad),
        EvalResult::Accept,
    );
    let mut r_absent = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.pmsi_tunnel) then accept; reject;",
            &mut r_absent
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn bgp_pmsi_tunnel_canonical_idiom_translates_from_bird() {
    // RFC 6514 §5: the canonical BIRD filter idiom for a PMSI
    // Tunnel is `if defined(bgp_pmsi_tunnel) then reject;` ("a
    // route that carries a PMSI Tunnel binding is an MVPN A-D
    // route — drop it on a non-MVPN edge"). The translator renames
    // `bgp_pmsi_tunnel` to `bgp.pmsi_tunnel` and the body
    // round-trips through the daemon loader.
    let mut r_with = route_with_pmsi_tunnel(0, 0, 0, Vec::new());
    assert_eq!(
        run(
            "if defined(bgp.pmsi_tunnel) then reject; accept;",
            &mut r_with
        ),
        EvalResult::Reject(None),
    );
    let mut r_without = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(bgp.pmsi_tunnel) then reject; accept;",
            &mut r_without
        ),
        EvalResult::Accept,
    );
}

#[test]
fn bgp_pmsi_tunnel_is_not_assignable() {
    let err = compile("test", "bgp.pmsi_tunnel = true;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

// ---- RFC 2328 §16 / RFC 5340 §4.1: ospf.metric1 ----

/// Build an OSPFv2 route carrying the given primary metric in the
/// `preference.metric` slot the OSPF SPF computation populates
/// (RFC 2328 §16). The protocol kind is `Ospfv2`; the `metric1`
/// accessor reads this slot for OSPF routes and `None` for
/// everything else (mirrors BIRD's eattr semantics).
fn ospf_route_with_metric(metric: u32) -> Route {
    let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
    Route {
        key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin { proto: 3, peer: 0 },
        protocol: Protocol::Ospfv2,
        preference: Preference::new(Protocol::Ospfv2.default_admin_distance(), metric),
        next_hop: None,
        attributes: Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

/// Build an OSPFv3 route carrying the given primary metric. Mirrors
/// [`ospf_route_with_metric`] for the v3 protocol kind so the
/// `has_metric1`/`metric1` accessors cover both OSPF versions.
fn ospfv3_route_with_metric(metric: u32) -> Route {
    let prefix: Prefix = "2001:db8::/32".parse().unwrap();
    Route {
        key: RouteKey::new(prefix, NlriFamily::IPV6_UNICAST),
        origin: RouteOrigin { proto: 3, peer: 0 },
        protocol: Protocol::Ospfv3,
        preference: Preference::new(Protocol::Ospfv3.default_admin_distance(), metric),
        next_hop: None,
        attributes: Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

#[test]
fn ospf_metric1_reads_as_int_when_present_v2() {
    let mut r = ospf_route_with_metric(150);
    assert_eq!(
        run("if ospf.metric1 == 150 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_metric1_reads_as_int_when_present_v3() {
    let mut r = ospfv3_route_with_metric(220);
    assert_eq!(
        run("if ospf.metric1 == 220 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_metric1_reads_as_zero_for_non_ospf_routes() {
    // A BGP route carries a metric in the same `preference.metric`
    // slot the OSPF SPF computation populates (the LOCAL_PREF the BGP
    // decision process ranks against is in `attributes`, but
    // `preference.metric` is the cross-protocol metric). The
    // `ospf.metric1` accessor reads `None` for a non-OSPF route, so
    // the DSL read falls back to `0` — the unwrap_or(0) semantics on
    // the int-typed field read. Mirrors BIRD's eattr default for an
    // unattached `ospf_metric1` reference.
    let mut r = route_with("203.0.113.0/24", 100, 0);
    // The BGP route has `preference.metric = 100` (set by
    // `route_with`); `ospf.metric1` must NOT read that 100.
    assert_eq!(
        run("if ospf.metric1 == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.metric1 == 100 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric1_mismatch_rejects() {
    let mut r = ospf_route_with_metric(200);
    assert_eq!(
        run("if ospf.metric1 == 150 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric1_is_defined_iff_ospf_route() {
    // OSPFv2 route: defined.
    let mut r_v2 = ospf_route_with_metric(0);
    assert_eq!(
        run("if defined(ospf.metric1) then accept; reject;", &mut r_v2),
        EvalResult::Accept,
    );
    // OSPFv3 route: defined.
    let mut r_v3 = ospfv3_route_with_metric(0);
    assert_eq!(
        run("if defined(ospf.metric1) then accept; reject;", &mut r_v3),
        EvalResult::Accept,
    );
    // Non-OSPF route: not defined.
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if defined(ospf.metric1) then accept; reject;", &mut r_bgp),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric1_defined_distinguishes_non_ospf_from_metric_zero() {
    // RFC 2328 §16: an OSPF route with cost 0 (a loopback or other
    // directly-attached network OSPF originates with cost 0) is
    // distinct from "non-OSPF route" — `defined(ospf.metric1)`
    // reports true for the former and false for the latter. This
    // is the case the `has_metric1` accessor exists to make precise.
    let mut r_zero = ospf_route_with_metric(0);
    assert_eq!(
        run("if defined(ospf.metric1) then accept; reject;", &mut r_zero),
        EvalResult::Accept,
    );
    let mut r_absent = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(ospf.metric1) then accept; reject;",
            &mut r_absent
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric1_canonical_bird_idiom_translates() {
    // The canonical BIRD filter idiom for OSPF metric policy is
    // `if defined(ospf_metric1) && ospf_metric1 > 100 then reject;`
    // ("a high-cost OSPF route a redistribution pipe picks up
    // should not be re-advertised"). The translator renames
    // `ospf_metric1` to `ospf.metric1` and the body round-trips
    // through the daemon loader.
    let mut r_high = ospf_route_with_metric(200);
    assert_eq!(
        run(
            "if defined(ospf.metric1) && ospf.metric1 > 100 then reject; accept;",
            &mut r_high
        ),
        EvalResult::Reject(None),
    );
    let mut r_low = ospf_route_with_metric(50);
    assert_eq!(
        run(
            "if defined(ospf.metric1) && ospf.metric1 > 100 then reject; accept;",
            &mut r_low
        ),
        EvalResult::Accept,
    );
    // A non-OSPF route: `defined(ospf.metric1)` is false, so the
    // `&&` short-circuits and the route is accepted.
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(ospf.metric1) && ospf.metric1 > 100 then reject; accept;",
            &mut r_bgp
        ),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_metric1_is_not_assignable() {
    let err = compile("test", "ospf.metric1 = 100;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn ospf_metric1_peephole_fused_branch_agrees_with_unfused() {
    // The peephole pass fuses `LoadField(OspfMetric1); Push(Int(c));
    // Bin(op); JumpIf*` into a single `BranchFieldIntCmp` for int
    // fields. `ospf.metric1` was added to `is_int_field` so the
    // fused path fires; pin the agreement between the fused and
    // unfused paths by checking the same comparison both ways.
    let mut r = ospf_route_with_metric(150);
    // Fused: constant on the RHS, comparison op in the fuse set.
    assert_eq!(
        run("if ospf.metric1 == 150 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.metric1 != 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    // Unfused: constant on the LHS (the peephole does not fuse
    // `Bin(Int(c), op, LoadField)`), exercises the read_route_field
    // path directly.
    assert_eq!(
        run("if 150 == ospf.metric1 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_unknown_field_is_parse_error() {
    // A typo in the OSPF field name surfaces a parse error at
    // compile time, not a runtime "unknown field". The parse error
    // uses the `UnknownOspfField` variant so the diagnostic names
    // the OSPF surface (mirrors `UnknownBgpField`). `ospf.bogus`
    // is not a known OSPF field — `ospf.metric1` (RFC 2328 §16 /
    // RFC 5340 §4.1), `ospf.metric2` (RFC 2328 §16.4 / RFC 5340
    // §4.8.5) and `ospf.tag` (RFC 2328 §A.4.5 / RFC 5340 §A.4.7)
    // are the three known fields at the time of writing;
    // `ospf.router_id` is the next increment the ROADMAP names
    // (still unimplemented at the time of writing).
    let err = compile("test", "if defined(ospf.bogus) then accept; reject;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("ospf") && msg.contains("bogus"),
        "expected an UnknownOspfField diagnostic, got: {msg}"
    );
}

// ---- ospf.metric2 (RFC 2328 §16.4 / RFC 5340 §4.8.5) ----
//
// The `ospf.metric2` field surfaces the type-2 external OSPF metric
// — the E-bit-set LSA metric the §16.4 (6) type-2 preference ranks
// against. The lr `Route` data model carries the type-2 external
// metric in `preference.metric` for type-2 externals (the same
// field every protocol feeds into the cross-protocol admin-distance
// sort), but the OSPF route computation drops the `metric_type`
// marker after the §16.4 (6) selection, so the DSL has no way to
// distinguish a type-2 external from any other OSPF route by reading
// `preference.metric` alone. The `LrOspfMetric2` private path-
// attribute tag (RFC 2328 §16.4, code point 253) carries the type-2
// external metric through the Loc-RIB and is the marker
// `has_metric2` consults. The tests below pin the full path —
// parse → eval → accessor → attribute lookup — against routes the
// test stub builds with the same `Attributes::insert` shape the
// `ospf_recompute` populate step uses.

/// The path-attribute tag carrying the OSPF type-2 external metric.
/// Mirrors `lr_bgp::path::AttrType::LrOspfMetric2` (value 253) and
/// `lr_policy::ospf::LR_OSPF_METRIC2_TAG` — kept as a `u8` here so
/// the test stub does not need to depend on `lr-bgp` (the same
/// hard-coding shape the accessor in `lr-policy::ospf` uses).
const LR_OSPF_METRIC2_TAG: u8 = 253;

/// Build an OSPFv2 route carrying the `LrOspfMetric2` attribute —
/// the shape `lr-router::instance::ospf_ops::ospf_recompute`
/// attaches for a type-2 external route.
fn ospf_route_with_metric2(metric1: u32, metric2: u32) -> Route {
    let mut r = ospf_route_with_metric(metric1);
    r.attributes.insert(lr_core::attr::Attribute {
        tag: lr_core::attr::AttrTag::raw(LR_OSPF_METRIC2_TAG),
        flags: 0x80, // optional, non-transitive (matches the populate step's flag set)
        value: metric2.to_be_bytes().to_vec(),
    });
    r
}

/// Build an OSPFv3 route carrying the `LrOspfMetric2` attribute.
fn ospfv3_route_with_metric2(metric1: u32, metric2: u32) -> Route {
    let mut r = ospfv3_route_with_metric(metric1);
    r.attributes.insert(lr_core::attr::Attribute {
        tag: lr_core::attr::AttrTag::raw(LR_OSPF_METRIC2_TAG),
        flags: 0x80,
        value: metric2.to_be_bytes().to_vec(),
    });
    r
}

#[test]
fn ospf_metric2_reads_as_int_when_present_v2() {
    let mut r = ospf_route_with_metric2(10, 200);
    assert_eq!(
        run("if ospf.metric2 == 200 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_metric2_reads_as_int_when_present_v3() {
    let mut r = ospfv3_route_with_metric2(10, 220);
    assert_eq!(
        run("if ospf.metric2 == 220 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_metric2_reads_as_zero_for_non_type2_external_ospf_routes() {
    // An OSPF route with no `LrOspfMetric2` attribute — i.e. an
    // intra-area, inter-area or type-1 external route (the OSPF
    // route computation only attaches the tag for type-2 externals).
    // `ospf.metric2` reads as `0` (the unwrap_or(0) default for an
    // absent int-typed attribute read), mirroring BIRD's eattr
    // default for an unattached `ospf_metric2` reference. The
    // route's `ospf.metric1` is its `preference.metric` (42 here),
    // so the test also pins that `ospf.metric2` does not fall
    // through to `preference.metric` on a non-type-2-external
    // route — it reads `0`, not `42`.
    let mut r = ospf_route_with_metric(42);
    assert_eq!(
        run("if ospf.metric2 == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.metric2 == 42 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric2_reads_as_zero_for_non_ospf_routes_even_with_the_attribute() {
    // The accessor's protocol-kind fast path rejects a non-OSPF
    // route even if the attribute is somehow present (the OSPF
    // route computation never attaches the tag to a non-OSPF route,
    // but a hand-crafted test route that violates the invariant
    // still reads as `0` — defensive, mirrors `ospf.metric1`'s
    // protocol-kind check).
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.attributes.insert(lr_core::attr::Attribute {
        tag: lr_core::attr::AttrTag::raw(LR_OSPF_METRIC2_TAG),
        flags: 0x80,
        value: 200u32.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run("if ospf.metric2 == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.metric2 == 200 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric2_mismatch_rejects() {
    let mut r = ospf_route_with_metric2(10, 200);
    assert_eq!(
        run("if ospf.metric2 == 150 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric2_is_defined_iff_type2_external_ospf_route() {
    // OSPFv2 type-2 external: defined.
    let mut r_v2 = ospf_route_with_metric2(10, 200);
    assert_eq!(
        run("if defined(ospf.metric2) then accept; reject;", &mut r_v2),
        EvalResult::Accept,
    );
    // OSPFv3 type-2 external: defined.
    let mut r_v3 = ospfv3_route_with_metric2(10, 220);
    assert_eq!(
        run("if defined(ospf.metric2) then accept; reject;", &mut r_v3),
        EvalResult::Accept,
    );
    // OSPFv2 non-type-2-external (no attribute): not defined.
    let mut r_ospf = ospf_route_with_metric(42);
    assert_eq!(
        run("if defined(ospf.metric2) then accept; reject;", &mut r_ospf),
        EvalResult::Reject(None),
    );
    // Non-OSPF route (BGP): not defined even if the attribute is
    // somehow present (the protocol-kind fast path rejects it).
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    r_bgp.attributes.insert(lr_core::attr::Attribute {
        tag: lr_core::attr::AttrTag::raw(LR_OSPF_METRIC2_TAG),
        flags: 0x80,
        value: 200u32.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run("if defined(ospf.metric2) then accept; reject;", &mut r_bgp),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric2_defined_distinguishes_non_type2_external_from_metric_zero() {
    // RFC 2328 §16.4 (6): a type-2 external OSPF route with metric 0
    // (an E-bit-set type-5 LSA whose 24-bit external metric happens
    // to be zero, unusual but well-formed per RFC 2328 §2.3) is
    // distinct from "not a type-2 external" — `defined(ospf.metric2)`
    // reports true for the former and false for the latter. This
    // is the case the `has_metric2` accessor exists to make
    // precise.
    let mut r_zero = ospf_route_with_metric2(10, 0);
    assert_eq!(
        run("if defined(ospf.metric2) then accept; reject;", &mut r_zero),
        EvalResult::Accept,
    );
    let mut r_absent = ospf_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(ospf.metric2) then accept; reject;",
            &mut r_absent
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_metric2_canonical_bird_idiom_translates() {
    // The canonical BIRD filter idiom for OSPF type-2 external
    // metric policy is
    // `if defined(ospf_metric2) && ospf_metric2 > 100 then reject;`
    // ("a high-cost type-2 external a redistribution pipe picks up
    // should not be re-advertised"). The translator renames
    // `ospf_metric2` to `ospf.metric2` and the body round-trips
    // through the daemon loader.
    let mut r_high = ospf_route_with_metric2(10, 200);
    assert_eq!(
        run(
            "if defined(ospf.metric2) && ospf.metric2 > 100 then reject; accept;",
            &mut r_high
        ),
        EvalResult::Reject(None),
    );
    let mut r_low = ospf_route_with_metric2(10, 50);
    assert_eq!(
        run(
            "if defined(ospf.metric2) && ospf.metric2 > 100 then reject; accept;",
            &mut r_low
        ),
        EvalResult::Accept,
    );
    // A non-type-2-external OSPF route (intra-area / inter-area /
    // type-1 external): `defined(ospf.metric2)` is false, so the
    // `&&` short-circuits and the route is accepted.
    let mut r_ospf = ospf_route_with_metric(200);
    assert_eq!(
        run(
            "if defined(ospf.metric2) && ospf.metric2 > 100 then reject; accept;",
            &mut r_ospf
        ),
        EvalResult::Accept,
    );
    // A non-OSPF (BGP) route: `defined(ospf.metric2)` is false, so
    // the `&&` short-circuits and the route is accepted.
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(ospf.metric2) && ospf.metric2 > 100 then reject; accept;",
            &mut r_bgp
        ),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_metric2_is_not_assignable() {
    let err = compile("test", "ospf.metric2 = 100;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn ospf_metric2_peephole_fused_branch_agrees_with_unfused() {
    // The peephole pass fuses `LoadField(OspfMetric2); Push(Int(c));
    // Bin(op); JumpIf*` into a single `BranchFieldIntCmp` for int
    // fields. `ospf.metric2` was added to `is_int_field` so the
    // fused path fires; pin the agreement between the fused and
    // unfused paths by checking the same comparison both ways.
    let mut r = ospf_route_with_metric2(10, 150);
    // Fused: constant on the RHS, comparison op in the fuse set.
    assert_eq!(
        run("if ospf.metric2 == 150 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.metric2 != 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    // Unfused: constant on the LHS (the peephole does not fuse
    // `Bin(Int(c), op, LoadField)`), exercises the read_route_field
    // path directly.
    assert_eq!(
        run("if 150 == ospf.metric2 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_metric1_and_metric2_independent_reads() {
    // A type-2 external OSPFv2 route: `metric1` (the route's
    // `preference.metric` — the cost to the ASBR in lr's model for
    // type-2 externals — actually, lr stores the external metric
    // in `preference.metric` for type-2 externals; the cost to the
    // ASBR is the §16.4 (6) tie-breaker the OSPF route computation
    // drops after selection) and `metric2` (the `LrOspfMetric2`
    // attribute value — the same external metric for type-2
    // externals) read independently: a filter can read either
    // without the other's value leaking through.
    let mut r = ospf_route_with_metric2(200, 200);
    // Both read 200.
    assert_eq!(
        run(
            "if ospf.metric1 == 200 && ospf.metric2 == 200 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    // `metric1` is `preference.metric` (200), `metric2` is the
    // attribute value (200) — both 200, but the field reads are
    // independent.
    let mut r2 = ospf_route_with_metric(200);
    // No `LrOspfMetric2` attribute → `metric2` reads 0.
    assert_eq!(
        run(
            "if ospf.metric1 == 200 && ospf.metric2 == 0 then accept; reject;",
            &mut r2
        ),
        EvalResult::Accept,
    );
}

// ---- ospf.tag (RFC 2328 §A.4.5 bullet h / RFC 3101 §2.3 /
//      RFC 5340 §A.4.7 T bit / RFC 8362 §3.6) ----
//
// The `ospf.tag` field surfaces the route's external route tag —
// the 32-bit tag carried in type-5 / type-7 AS-external-LSA bodies.
// The lr `Route` data model carries the tag in the existing
// `Route::tag: Option<u32>` field (also written by the `SetTag`
// policy action); the OSPF route computation populates it from
// the LSA's tag for external routes (the v2 form always surfaces
// `Some(t)` — the v2 LSA body always carries a 4-byte tag, zero
// being well-formed per RFC 2328 §A.4.5; the v3 form surfaces
// `Some(t)` only when the T bit / External-Prefix sub-TLV 3 is
// present). The tests below pin the full path — parse → eval →
// accessor → `Route::tag` field read — against routes the test
// stub builds with the same `Route { tag: Some(t), .. }` shape
// the `ospf_recompute` populate step produces.

/// Build an OSPFv2 route carrying a non-`None` `Route::tag` —
/// mirrors the shape `lr-router::instance::ospf_ops::ospf_recompute`
/// attaches for a v2 external route whose LSA body carries a tag
/// (always present for v2 externals — the v2 LSA body always
/// carries a 4-byte tag field, zero being well-formed).
fn ospf_route_with_tag(metric: u32, tag: u32) -> Route {
    let mut r = ospf_route_with_metric(metric);
    r.tag = Some(tag);
    r
}

/// Build an OSPFv3 route carrying a non-`None` `Route::tag` —
/// mirrors the shape `ospf_recompute` attaches for a v3 external
/// route whose LSA carried a T-bit-set / sub-TLV tag (the v3
/// form requires the T bit to surface a tag, so this is the
/// "T bit set" case).
fn ospfv3_route_with_tag(metric: u32, tag: u32) -> Route {
    let mut r = ospfv3_route_with_metric(metric);
    r.tag = Some(tag);
    r
}

#[test]
fn ospf_tag_reads_as_int_when_present_v2() {
    let mut r = ospf_route_with_tag(10, 3735928559);
    assert_eq!(
        run("if ospf.tag == 3735928559 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_tag_reads_as_int_when_present_v3() {
    let mut r = ospfv3_route_with_tag(10, 3405705229);
    assert_eq!(
        run("if ospf.tag == 3405705229 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_tag_reads_as_zero_for_ospf_routes_without_a_tag() {
    // An OSPF route with `Route::tag = None` — i.e. an intra-area,
    // inter-area, or v3 external without the T bit set. `ospf.tag`
    // reads as `0` (the unwrap_or(0) default for an absent int-
    // typed attribute read), mirroring BIRD's eattr default for
    // an unattached `ospf_tag` reference. The route's
    // `ospf.metric1` is its `preference.metric` (42 here), so the
    // test also pins that `ospf.tag` does not fall through to
    // `preference.metric` on a non-external OSPF route — it
    // reads `0`, not `42`.
    let mut r = ospf_route_with_metric(42);
    assert_eq!(
        run("if ospf.tag == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.tag == 42 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_tag_reads_as_zero_for_non_ospf_routes_even_with_a_tag() {
    // The accessor's protocol-kind fast path rejects a non-OSPF
    // route even if `Route::tag` is `Some` (a `SetTag` action's
    // operator-side override on a non-OSPF route is the legitimate
    // case where `Route::tag` carries an operator-assigned tag for
    // OSPF redistribution — `ospf.tag` on the BGP route reads as
    // `0`, since the protocol-kind fast path rejects non-OSPF
    // routes).
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.tag = Some(99);
    assert_eq!(
        run("if ospf.tag == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.tag == 99 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_tag_mismatch_rejects() {
    let mut r = ospf_route_with_tag(10, 3735928559);
    assert_eq!(
        run("if ospf.tag == 305419896 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_tag_is_defined_iff_external_ospf_route() {
    // OSPFv2 external (v2 LSA always carries a 4-byte tag): defined.
    let mut r_v2 = ospf_route_with_tag(10, 3735928559);
    assert_eq!(
        run("if defined(ospf.tag) then accept; reject;", &mut r_v2),
        EvalResult::Accept,
    );
    // OSPFv3 external with the T bit set: defined.
    let mut r_v3 = ospfv3_route_with_tag(10, 3405705229);
    assert_eq!(
        run("if defined(ospf.tag) then accept; reject;", &mut r_v3),
        EvalResult::Accept,
    );
    // OSPFv2 non-external (intra-area / inter-area): not defined.
    let mut r_ospf = ospf_route_with_metric(42);
    assert_eq!(
        run("if defined(ospf.tag) then accept; reject;", &mut r_ospf),
        EvalResult::Reject(None),
    );
    // Non-OSPF route (BGP) with an operator-assigned tag: not
    // defined (the protocol-kind fast path rejects non-OSPF
    // routes, mirroring BIRD's eattr absence on non-OSPF routes).
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    r_bgp.tag = Some(99);
    assert_eq!(
        run("if defined(ospf.tag) then accept; reject;", &mut r_bgp),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_tag_defined_distinguishes_no_tag_from_tag_zero() {
    // RFC 2328 §A.4.5 bullet h: a v2 external route with tag 0
    // (a v2 LSA whose 4-byte tag field happens to be zero, which
    // is well-formed) is distinct from "no tag" (an intra-area /
    // inter-area OSPF route) — `defined(ospf.tag)` reports true
    // for the former and false for the latter. This is the case
    // the `has_tag` accessor exists to make precise. The v3 form
    // does NOT have this distinction — a v3 external without the
    // T bit set reads as `0` / not-defined, and a v3 external
    // with the T bit set and tag 0 reads as `0` / defined.
    let mut r_zero = ospf_route_with_tag(10, 0);
    assert_eq!(
        run("if defined(ospf.tag) then accept; reject;", &mut r_zero),
        EvalResult::Accept,
    );
    let mut r_absent = ospf_route_with_metric(42);
    assert_eq!(
        run("if defined(ospf.tag) then accept; reject;", &mut r_absent),
        EvalResult::Reject(None),
    );
    // v3 with the T bit set and tag 0 — defined.
    let mut r_v3_zero = ospfv3_route_with_tag(10, 0);
    assert_eq!(
        run("if defined(ospf.tag) then accept; reject;", &mut r_v3_zero),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_tag_canonical_bird_idiom_translates() {
    // The canonical BIRD filter idiom for OSPF external route tag
    // policy is `if defined(ospf_tag) && ospf_tag == 3735928559
    // then accept;` ("a route a redistribution pipe tagged with
    // 3735928559 on the upstream side should be admitted"). The
    // translator renames `ospf_tag` to `ospf.tag` and the body
    // round-trips through the daemon loader.
    let mut r_match = ospf_route_with_tag(10, 3735928559);
    assert_eq!(
        run(
            "if defined(ospf.tag) && ospf.tag == 3735928559 then accept; reject;",
            &mut r_match
        ),
        EvalResult::Accept,
    );
    let mut r_nomatch = ospf_route_with_tag(10, 305419896);
    assert_eq!(
        run(
            "if defined(ospf.tag) && ospf.tag == 3735928559 then accept; reject;",
            &mut r_nomatch
        ),
        EvalResult::Reject(None),
    );
    // A non-external OSPF route (intra-area / inter-area):
    // `defined(ospf.tag)` is false, so the `&&` short-circuits
    // and the route is rejected.
    let mut r_ospf = ospf_route_with_metric(200);
    assert_eq!(
        run(
            "if defined(ospf.tag) && ospf.tag == 3735928559 then accept; reject;",
            &mut r_ospf
        ),
        EvalResult::Reject(None),
    );
    // A non-OSPF (BGP) route: `defined(ospf.tag)` is false, so
    // the `&&` short-circuits and the route is rejected.
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(ospf.tag) && ospf.tag == 3735928559 then accept; reject;",
            &mut r_bgp
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_tag_is_not_assignable() {
    let err = compile("test", "ospf.tag = 100;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn ospf_tag_peephole_fused_branch_agrees_with_unfused() {
    // The peephole pass fuses `LoadField(OspfTag); Push(Int(c));
    // Bin(op); JumpIf*` into a single `BranchFieldIntCmp` for int
    // fields. `ospf.tag` was added to `is_int_field` so the fused
    // path fires; pin the agreement between the fused and unfused
    // paths by checking the same comparison both ways.
    let mut r = ospf_route_with_tag(10, 305419896);
    // Fused: constant on the RHS, comparison op in the fuse set.
    assert_eq!(
        run("if ospf.tag == 305419896 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.tag != 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    // Unfused: constant on the LHS (the peephole does not fuse
    // `Bin(Int(c), op, LoadField)`), exercises the read_route_field
    // path directly.
    assert_eq!(
        run("if 305419896 == ospf.tag then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_tag_independent_of_metric1_and_metric2() {
    // A type-2 external OSPFv2 route with a tag: `metric1`
    // (`preference.metric`), `metric2` (the `LrOspfMetric2`
    // attribute value) and `tag` (`Route::tag`) read
    // independently: a filter can read any one without the other
    // two leaking through. The three fields live on different
    // slots — `Route::preference.metric`, the private
    // `LrOspfMetric2` attribute, and `Route::tag` — and the
    // accessors do not cross-read.
    let mut r = ospf_route_with_metric2(200, 200);
    r.tag = Some(3735928559);
    // All three read independently.
    assert_eq!(
        run(
            "if ospf.metric1 == 200 && ospf.metric2 == 200 && ospf.tag == 3735928559 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    // No `Route::tag` → `tag` reads 0 even though `metric1` /
    // `metric2` are still 200.
    let mut r2 = ospf_route_with_metric2(200, 200);
    assert_eq!(
        run(
            "if ospf.metric1 == 200 && ospf.metric2 == 200 && ospf.tag == 0 then accept; reject;",
            &mut r2
        ),
        EvalResult::Accept,
    );
}

// ---- ospf.router_id (RFC 2328 §A.4 / RFC 5340 §A.4 `Advertising
//      Router` field) ----
//
// The `ospf.router_id` field surfaces the 32-bit OSPF Router-ID of the
// router that originated the LSA the route was computed from — the
// Router-LSA's advertising router for intra-area stub routes, the
// Network-LSA's advertising router (the DR) for intra-area transit
// routes, the summary-LSA's advertising router (the ABR) for
// inter-area routes, and the AS-external-LSA's advertising router
// (the ASBR) for external routes. The OSPF route computation
// (`lr-router::instance::ospf_ops::ospf_recompute`) attaches a
// private `LrOspfRouterId` path-attribute tag (code point 252) on
// every OSPFv2 / OSPFv3 route with a known originating LSA; the
// `lr_policy::ospf::router_id` / `has_router_id` accessors read it
// back. The tests below pin the full path — parse → eval → accessor
// → attribute lookup — against routes the test stub builds with the
// same `Attributes::insert` shape the `ospf_recompute` populate step
// uses.

/// The path-attribute tag carrying the OSPF advertising-router ID.
/// Mirrors `lr_bgp::path::AttrType::LrOspfRouterId` (value 252) and
/// `lr_policy::ospf::LR_OSPF_ROUTER_ID_TAG` — kept as a `u8` here so
/// the test stub does not need to depend on `lr-bgp` (the same
/// hard-coding shape the accessor in `lr-policy::ospf` uses).
const LR_OSPF_ROUTER_ID_TAG: u8 = 252;

/// Build an OSPFv2 route carrying the `LrOspfRouterId` attribute —
/// the shape `lr-router::instance::ospf_ops::ospf_recompute`
/// attaches for any OSPFv2 route with a known originating LSA
/// (intra-area stub / transit, inter-area, or external).
fn ospf_route_with_router_id(metric: u32, router_id: u32) -> Route {
    let mut r = ospf_route_with_metric(metric);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_OSPF_ROUTER_ID_TAG),
        flags: 0x80, // optional, non-transitive (matches the populate step's flag set)
        value: router_id.to_be_bytes().to_vec(),
    });
    r
}

/// Build an OSPFv3 route carrying the `LrOspfRouterId` attribute.
fn ospfv3_route_with_router_id(metric: u32, router_id: u32) -> Route {
    let mut r = ospfv3_route_with_metric(metric);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_OSPF_ROUTER_ID_TAG),
        flags: 0x80,
        value: router_id.to_be_bytes().to_vec(),
    });
    r
}

#[test]
fn ospf_router_id_reads_as_int_when_present_v2() {
    // 192.0.2.1 = 0xc000_0201 — a typical OSPF Router-ID.
    let mut r = ospf_route_with_router_id(10, 0xc000_0201);
    assert_eq!(
        run(
            "if ospf.router_id == 3221225985 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_router_id_reads_as_int_when_present_v3() {
    // 2001:db8::1's low 32 bits = 0x0000_0001 — the v3 form uses the
    // same 32-bit OSPF Router-ID dotted-quad as v2 (RFC 5340 §2.4).
    let mut r = ospfv3_route_with_router_id(10, 1);
    assert_eq!(
        run("if ospf.router_id == 1 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_router_id_reads_as_zero_for_ospf_routes_without_the_attribute() {
    // An OSPF route with no `LrOspfRouterId` attribute — i.e. a
    // synthetic test route, or a route whose OSPF computation could
    // not identify the originating LSA's advertising router (the
    // defensive fallback the OSPF route computation leaves as
    // `None`). `ospf.router_id` reads as `0` (the unwrap_or(0)
    // default for an absent int-typed attribute read), mirroring
    // BIRD's eattr default for an unattached `ospf_router_id`
    // reference. The route's `ospf.metric1` is its
    // `preference.metric` (42 here), so the test also pins that
    // `ospf.router_id` does not fall through to `preference.metric`
    // on an OSPF route without the attribute — it reads `0`, not
    // `42`.
    let mut r = ospf_route_with_metric(42);
    assert_eq!(
        run("if ospf.router_id == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.router_id == 42 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_router_id_reads_as_zero_for_non_ospf_routes_even_with_the_attribute() {
    // The accessor's protocol-kind fast path rejects a non-OSPF
    // route even if the attribute is somehow present (the OSPF
    // route computation never attaches the tag to a non-OSPF route,
    // but a hand-crafted test route that violates the invariant
    // still reads as `0` — defensive, mirrors `ospf.metric1`'s /
    // `ospf.metric2`'s protocol-kind check).
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_OSPF_ROUTER_ID_TAG),
        flags: 0x80,
        value: 0xc000_0201u32.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run("if ospf.router_id == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run(
            "if ospf.router_id == 3221225985 then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_router_id_mismatch_rejects() {
    let mut r = ospf_route_with_router_id(10, 0xc000_0201);
    assert_eq!(
        run(
            "if ospf.router_id == 3221225986 then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_router_id_is_defined_iff_ospf_route_with_attribute() {
    // OSPFv2 route with the attribute: defined.
    let mut r_v2 = ospf_route_with_router_id(10, 0xc000_0201);
    assert_eq!(
        run("if defined(ospf.router_id) then accept; reject;", &mut r_v2),
        EvalResult::Accept,
    );
    // OSPFv3 route with the attribute: defined.
    let mut r_v3 = ospfv3_route_with_router_id(10, 1);
    assert_eq!(
        run("if defined(ospf.router_id) then accept; reject;", &mut r_v3),
        EvalResult::Accept,
    );
    // OSPFv2 route without the attribute: not defined.
    let mut r_ospf = ospf_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(ospf.router_id) then accept; reject;",
            &mut r_ospf
        ),
        EvalResult::Reject(None),
    );
    // Non-OSPF route (BGP): not defined even if the attribute is
    // somehow present (the protocol-kind fast path rejects it).
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    r_bgp.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_OSPF_ROUTER_ID_TAG),
        flags: 0x80,
        value: 0xc000_0201u32.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run(
            "if defined(ospf.router_id) then accept; reject;",
            &mut r_bgp
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_router_id_defined_distinguishes_absent_from_router_id_zero() {
    // RFC 2328 §3.1.b recommends a non-zero OSPF Router-ID but does
    // not forbid 0.0.0.0. A router that carries Router-ID 0.0.0.0
    // surfaces `Some(0)` on its OSPF routes — `defined(ospf.router_id)`
    // reports true for those routes and false for OSPF routes whose
    // computation could not identify the originating LSA's
    // advertising router (the defensive fallback). This is the case
    // the `has_router_id` accessor exists to make precise.
    let mut r_zero = ospf_route_with_router_id(10, 0);
    assert_eq!(
        run(
            "if defined(ospf.router_id) then accept; reject;",
            &mut r_zero
        ),
        EvalResult::Accept,
    );
    let mut r_absent = ospf_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(ospf.router_id) then accept; reject;",
            &mut r_absent
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_router_id_canonical_bird_idiom_translates() {
    // The canonical BIRD filter idiom for OSPF router-id policy is
    // `if defined(ospf_router_id) && ospf_router_id == 192.0.2.1
    // then accept;` ("only re-advertise routes whose originating
    // LSA was sourced by 192.0.2.1"). The translator renames
    // `ospf_router_id` to `ospf.router_id` and the body round-trips
    // through the daemon loader. 192.0.2.1 = 0xc000_0201 =
    // 3221225985.
    let mut r_match = ospf_route_with_router_id(10, 0xc000_0201);
    assert_eq!(
        run(
            "if defined(ospf.router_id) && ospf.router_id == 3221225985 then accept; reject;",
            &mut r_match
        ),
        EvalResult::Accept,
    );
    let mut r_nomatch = ospf_route_with_router_id(10, 0xc000_0202);
    assert_eq!(
        run(
            "if defined(ospf.router_id) && ospf.router_id == 3221225985 then accept; reject;",
            &mut r_nomatch
        ),
        EvalResult::Reject(None),
    );
    // An OSPF route without the attribute: `defined(ospf.router_id)`
    // is false, so the `&&` short-circuits and the route is
    // rejected.
    let mut r_ospf = ospf_route_with_metric(200);
    assert_eq!(
        run(
            "if defined(ospf.router_id) && ospf.router_id == 3221225985 then accept; reject;",
            &mut r_ospf
        ),
        EvalResult::Reject(None),
    );
    // A non-OSPF (BGP) route: `defined(ospf.router_id)` is false,
    // so the `&&` short-circuits and the route is rejected.
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(ospf.router_id) && ospf.router_id == 3221225985 then accept; reject;",
            &mut r_bgp
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn ospf_router_id_is_not_assignable() {
    let err = compile("test", "ospf.router_id = 100;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn ospf_router_id_peephole_fused_branch_agrees_with_unfused() {
    // The peephole pass fuses `LoadField(OspfRouterId); Push(Int(c));
    // Bin(op); JumpIf*` into a single `BranchFieldIntCmp` for int
    // fields. `ospf.router_id` was added to `is_int_field` so the
    // fused path fires; pin the agreement between the fused and
    // unfused paths by checking the same comparison both ways.
    let mut r = ospf_route_with_router_id(10, 0xc000_0201);
    // Fused: constant on the RHS, comparison op in the fuse set.
    assert_eq!(
        run(
            "if ospf.router_id == 3221225985 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if ospf.router_id != 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    // Unfused: constant on the LHS (the peephole does not fuse
    // `Bin(Int(c), op, LoadField)`), exercises the read_route_field
    // path directly.
    assert_eq!(
        run(
            "if 3221225985 == ospf.router_id then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn ospf_router_id_independent_of_metric1_metric2_and_tag() {
    // An OSPFv2 route carrying all four per-route OSPF attribute
    // surfaces: `metric1` (`preference.metric`), `metric2` (the
    // `LrOspfMetric2` attribute), `tag` (`Route::tag`) and
    // `router_id` (the `LrOspfRouterId` attribute). The four
    // fields live on different slots and the accessors do not
    // cross-read.
    let mut r = ospf_route_with_metric2(200, 200);
    r.tag = Some(3735928559);
    // Attach the router_id attribute — `ospf_recompute` would.
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_OSPF_ROUTER_ID_TAG),
        flags: 0x80,
        value: 0xc000_0201u32.to_be_bytes().to_vec(),
    });
    // All four read independently.
    assert_eq!(
        run(
            "if ospf.metric1 == 200 && ospf.metric2 == 200 && ospf.tag == 3735928559 && ospf.router_id == 3221225985 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    // A route with `router_id` but no `metric2` or `tag`: the
    // `metric2` / `tag` reads default to 0; `router_id` reads its
    // value.
    let mut r2 = ospf_route_with_router_id(50, 0xc000_0201);
    assert_eq!(
        run(
            "if ospf.metric1 == 50 && ospf.metric2 == 0 && ospf.tag == 0 && ospf.router_id == 3221225985 then accept; reject;",
            &mut r2
        ),
        EvalResult::Accept,
    );
}

// ---- RFC 8966 §3.2 + §3.4.3 / §4.6.8 / §4.6.9: babel.{metric,seqno,router_id} ----
//
// The Babel per-route attribute surface mirrors BIRD's `babel_metric`,
// `babel_router_id` and `babel_seqno` eattrs. The codec half lives in
// `lr-bgp::path::AttrType::{LrBabelSeqno, LrBabelRouterId}` (private
// tags the Babel runtime attaches; the codec strips them at BGP
// encode). The typed accessors live in `crate::babel`; the filter DSL
// fields live in `RouteFieldKind::{BabelMetric, BabelSeqno,
// BabelRouterId}`. These tests exercise the full path — parse →
// eval → accessor — against a real Babel route shape the Babel
// runtime would publish.

/// `lr_policy::babel::LR_BABEL_SEQNO_TAG` — kept as a `u8` here so the
/// test stub does not need to depend on `lr-bgp` (the same hard-coding
/// shape the accessor in `lr-policy::babel` uses). Mirrors
/// `lr_bgp::path::AttrType::LrBabelSeqno` (value 249).
const LR_BABEL_SEQNO_TAG: u8 = 249;

/// `lr_policy::babel::LR_BABEL_ROUTER_ID_TAG` — kept as a `u8` here so
/// the test stub does not need to depend on `lr-bgp` (the same
/// hard-coding shape the accessor in `lr-policy::babel` uses). Mirrors
/// `lr_bgp::path::AttrType::LrBabelRouterId` (value 250).
const LR_BABEL_ROUTER_ID_TAG: u8 = 250;

fn babel_route_with_metric(metric: u32) -> Route {
    let prefix: Prefix = "203.0.113.0/24".parse().unwrap();
    Route {
        key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
        origin: RouteOrigin { proto: 4, peer: 0 },
        protocol: Protocol::Babel,
        preference: Preference::new(Protocol::Babel.default_admin_distance(), metric),
        next_hop: None,
        attributes: Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    }
}

fn babel_route_with_seqno(metric: u32, seqno: u16) -> Route {
    let mut r = babel_route_with_metric(metric);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_BABEL_SEQNO_TAG),
        flags: 0x80,
        value: (u32::from(seqno)).to_be_bytes().to_vec(),
    });
    r
}

fn babel_route_with_router_id(metric: u32, router_id: u64) -> Route {
    let mut r = babel_route_with_metric(metric);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_BABEL_ROUTER_ID_TAG),
        flags: 0x80,
        value: router_id.to_be_bytes().to_vec(),
    });
    r
}

#[test]
fn babel_metric_reads_as_int_when_present() {
    let mut r = babel_route_with_metric(192);
    assert_eq!(
        run("if babel.metric == 192 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn babel_metric_reads_as_zero_for_non_babel_routes() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run("if babel.metric == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if babel.metric == 100 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_metric_canonical_bird_idiom_translates() {
    let mut r_high = babel_route_with_metric(192);
    assert_eq!(
        run("if babel.metric > 100 then reject; accept;", &mut r_high),
        EvalResult::Reject(None),
    );
    let mut r_low = babel_route_with_metric(50);
    assert_eq!(
        run("if babel.metric > 100 then reject; accept;", &mut r_low),
        EvalResult::Accept,
    );
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(babel.metric) && babel.metric > 100 then reject; accept;",
            &mut r_bgp
        ),
        EvalResult::Accept,
    );
}

#[test]
fn babel_metric_zero_is_present_for_babel() {
    let mut r = babel_route_with_metric(0);
    assert_eq!(
        run(
            "if defined(babel.metric) && babel.metric == 0 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(babel.metric) && babel.metric == 0 then accept; reject;",
            &mut r_bgp
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_metric_is_not_assignable() {
    let err = compile("test", "babel.metric = 100;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn babel_metric_peephole_fused_branch_agrees_with_unfused() {
    let mut r = babel_route_with_metric(192);
    assert_eq!(
        run("if babel.metric == 192 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if babel.metric != 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if 192 == babel.metric then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn babel_seqno_reads_as_int_when_present() {
    let mut r = babel_route_with_seqno(192, 7);
    assert_eq!(
        run("if babel.seqno == 7 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn babel_seqno_reads_as_zero_for_babel_routes_without_the_attribute() {
    let mut r = babel_route_with_metric(42);
    assert_eq!(
        run("if babel.seqno == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if babel.seqno == 42 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_seqno_reads_as_zero_for_non_babel_routes_even_with_the_attribute() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_BABEL_SEQNO_TAG),
        flags: 0x80,
        value: 7u32.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run("if babel.seqno == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if babel.seqno == 7 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_seqno_mismatch_rejects() {
    let mut r = babel_route_with_seqno(192, 7);
    assert_eq!(
        run("if babel.seqno == 8 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_seqno_is_defined_iff_babel_route_with_attribute() {
    let mut r_with = babel_route_with_seqno(192, 7);
    assert_eq!(
        run("if defined(babel.seqno) then accept; reject;", &mut r_with),
        EvalResult::Accept,
    );
    let mut r_without = babel_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(babel.seqno) then accept; reject;",
            &mut r_without
        ),
        EvalResult::Reject(None),
    );
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    r_bgp.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_BABEL_SEQNO_TAG),
        flags: 0x80,
        value: 7u32.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run("if defined(babel.seqno) then accept; reject;", &mut r_bgp),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_seqno_defined_distinguishes_absent_from_seqno_zero() {
    let mut r_zero = babel_route_with_seqno(192, 0);
    assert_eq!(
        run("if defined(babel.seqno) then accept; reject;", &mut r_zero),
        EvalResult::Accept,
    );
    let mut r_absent = babel_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(babel.seqno) then accept; reject;",
            &mut r_absent
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_seqno_canonical_bird_idiom_translates() {
    let mut r_high = babel_route_with_seqno(192, 200);
    assert_eq!(
        run(
            "if defined(babel.seqno) && babel.seqno > 100 then reject; accept;",
            &mut r_high
        ),
        EvalResult::Reject(None),
    );
    let mut r_low = babel_route_with_seqno(192, 50);
    assert_eq!(
        run(
            "if defined(babel.seqno) && babel.seqno > 100 then reject; accept;",
            &mut r_low
        ),
        EvalResult::Accept,
    );
    let mut r_babel = babel_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(babel.seqno) && babel.seqno > 100 then reject; accept;",
            &mut r_babel
        ),
        EvalResult::Accept,
    );
}

#[test]
fn babel_seqno_is_not_assignable() {
    let err = compile("test", "babel.seqno = 100;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn babel_seqno_peephole_fused_branch_agrees_with_unfused() {
    let mut r = babel_route_with_seqno(192, 7);
    assert_eq!(
        run("if babel.seqno == 7 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if babel.seqno != 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if 7 == babel.seqno then accept; reject;", &mut r),
        EvalResult::Accept,
    );
}

#[test]
fn babel_router_id_reads_as_int_when_present() {
    let mut r = babel_route_with_router_id(192, 0x0102_0304_0506_0708);
    assert_eq!(
        run(
            "if babel.router_id == 72623859790382856 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn babel_router_id_reads_as_zero_for_babel_routes_without_the_attribute() {
    let mut r = babel_route_with_metric(42);
    assert_eq!(
        run("if babel.router_id == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if babel.router_id == 42 then accept; reject;", &mut r),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_router_id_reads_as_zero_for_non_babel_routes_even_with_the_attribute() {
    let mut r = route_with("203.0.113.0/24", 100, 0);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_BABEL_ROUTER_ID_TAG),
        flags: 0x80,
        value: 0x0102_0304_0506_0708u64.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run("if babel.router_id == 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run(
            "if babel.router_id == 72623859790382856 then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_router_id_mismatch_rejects() {
    let mut r = babel_route_with_router_id(192, 0x0102_0304_0506_0708);
    assert_eq!(
        run(
            "if babel.router_id == 72623859790382857 then accept; reject;",
            &mut r
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_router_id_is_defined_iff_babel_route_with_attribute() {
    let mut r_with = babel_route_with_router_id(192, 0x0102_0304_0506_0708);
    assert_eq!(
        run(
            "if defined(babel.router_id) then accept; reject;",
            &mut r_with
        ),
        EvalResult::Accept,
    );
    let mut r_without = babel_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(babel.router_id) then accept; reject;",
            &mut r_without
        ),
        EvalResult::Reject(None),
    );
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    r_bgp.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_BABEL_ROUTER_ID_TAG),
        flags: 0x80,
        value: 0x0102_0304_0506_0708u64.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run(
            "if defined(babel.router_id) then accept; reject;",
            &mut r_bgp
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_router_id_defined_distinguishes_absent_from_router_id_zero() {
    let mut r_zero = babel_route_with_router_id(192, 0);
    assert_eq!(
        run(
            "if defined(babel.router_id) then accept; reject;",
            &mut r_zero
        ),
        EvalResult::Accept,
    );
    let mut r_absent = babel_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(babel.router_id) then accept; reject;",
            &mut r_absent
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_router_id_high_bit_set_round_trips_through_i64() {
    // i64::MAX = 0x7fff_ffff_ffff_ffff — the largest positive
    // literal the lexer accepts. A 64-bit value with the high
    // bit set (>= 0x8000_0000_0000_0000) reads as a negative i64
    // through the DSL's `Int` literal surface, but the lexer's
    // `Int(i64)` token cannot represent the bit-pattern that
    // wraps to a negative number directly (it errors with
    // `InvalidNumber`). The babel.rs unit test
    // `router_id_high_bit_set_round_trips_through_i64` pins the
    // underlying accessor's losslessness directly; this eval
    // test only verifies the DSL surface agrees with the
    // accessor when the literal is expressible (i64::MAX).
    let max = 0x7fff_ffff_ffff_ffffu64; // i64::MAX
    let mut r = babel_route_with_router_id(192, max);
    assert_eq!(
        run(
            "if babel.router_id == 9223372036854775807 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn babel_router_id_canonical_bird_idiom_translates() {
    let mut r_match = babel_route_with_router_id(192, 0x0102_0304_0506_0708);
    assert_eq!(
        run(
            "if defined(babel.router_id) then accept; reject;",
            &mut r_match
        ),
        EvalResult::Accept,
    );
    let mut r_ospf = babel_route_with_metric(42);
    assert_eq!(
        run(
            "if defined(babel.router_id) then accept; reject;",
            &mut r_ospf
        ),
        EvalResult::Reject(None),
    );
    let mut r_bgp = route_with("203.0.113.0/24", 100, 0);
    assert_eq!(
        run(
            "if defined(babel.router_id) then accept; reject;",
            &mut r_bgp
        ),
        EvalResult::Reject(None),
    );
}

#[test]
fn babel_router_id_is_not_assignable() {
    let err = compile("test", "babel.router_id = 100;").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("read-only") || msg.contains("ReadOnly"),
        "expected a read-only error, got: {msg}"
    );
}

#[test]
fn babel_router_id_peephole_fused_branch_agrees_with_unfused() {
    let mut r = babel_route_with_router_id(192, 0x0102_0304_0506_0708);
    assert_eq!(
        run(
            "if babel.router_id == 72623859790382856 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    assert_eq!(
        run("if babel.router_id != 0 then accept; reject;", &mut r),
        EvalResult::Accept,
    );
    assert_eq!(
        run(
            "if 72623859790382856 == babel.router_id then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
}

#[test]
fn babel_fields_independent_of_each_other() {
    let mut r = babel_route_with_seqno(192, 7);
    r.attributes.insert(Attribute {
        tag: AttrTag::raw(LR_BABEL_ROUTER_ID_TAG),
        flags: 0x80,
        value: 0x0102_0304_0506_0708u64.to_be_bytes().to_vec(),
    });
    assert_eq!(
        run(
            "if babel.metric == 192 && babel.seqno == 7 && babel.router_id == 72623859790382856 then accept; reject;",
            &mut r
        ),
        EvalResult::Accept,
    );
    let mut r2 = babel_route_with_seqno(192, 7);
    assert_eq!(
        run(
            "if babel.metric == 192 && babel.seqno == 7 && babel.router_id == 0 then accept; reject;",
            &mut r2
        ),
        EvalResult::Accept,
    );
}

// ---- Issue #81: bgp.lrxp.* (LRXP exchange-plane filter DSL surface) ----
//
// The LRXP surface is feature-gated behind `exchange-plane`. The
// codec lives in `lr-bgp::extensions::exchange_plane`; the typed
// accessors live in `crate::lrxp`; the filter DSL fields live in
// `RouteFieldKind::Lrxp*`. These tests exercise the full path —
// parse → eval → accessor → codec — against a real verified record
// set built with the same `ExchangeKey` the production codec uses.
//
// The fallback requirement (issue #81: a filter that adjusts
// `local-pref` based on `bgp.lrxp.hint.rank` no-ops on a non-LRXP
// peer) is pinned by `lrxp_canonical_idiom_no_ops_on_non_lrxp_peer`
// — the accessor returns 0, the filter's `rank > 1` test is false,
// the local-pref write does not fire.

#[cfg(feature = "exchange-plane")]
mod lrxp_tests {
    use super::*;
    use crate::bgp::{local_pref, med};
    use lr_bgp::extensions::exchange_plane::{
        ExchangeKey, ExchangeRecord, HintRecord, OriginAttestation, PolicyIntent, Record,
        STORE_PARTIAL_RAW, STORE_VERIFIED,
    };

    /// The `LrExchangePlaneRecords` attribute tag (value 254) — the
    /// private store the ingress hook parks on the route.
    const TAG_LRXP_STORE: u8 = 254;

    fn route_with_lrxp_store(store: Option<(u8, &[u8])>) -> Route {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        if let Some((kind, payload)) = store {
            let mut value = Vec::with_capacity(1 + payload.len());
            value.push(kind);
            value.extend_from_slice(payload);
            r.attributes.insert(Attribute {
                tag: AttrTag::raw(TAG_LRXP_STORE),
                flags: 0x80,
                value,
            });
        }
        r
    }

    fn signed_record_set(records: Vec<Record>) -> Vec<u8> {
        let key = ExchangeKey::hmac_sha256(1, "test-key");
        let mut record = ExchangeRecord::new(1, key.id, [0u8; 8], 1);
        record.records = records;
        record.sign(&key);
        record.encode()
    }

    fn hint_payload(rank: u8, damp: u16, igp: u32) -> Vec<u8> {
        signed_record_set(vec![Record::Hint(HintRecord {
            rank,
            damp_fom: damp,
            igp_cost: igp,
        })])
    }

    fn policy_payload(role: u8, import: [u8; 8], export: [u8; 8]) -> Vec<u8> {
        signed_record_set(vec![Record::Policy(PolicyIntent {
            role,
            import_digest: import,
            export_digest: export,
        })])
    }

    fn origin_payload(asn: u32, max_len: u8, expiry: u32) -> Vec<u8> {
        signed_record_set(vec![Record::Origin(OriginAttestation {
            origin_as: asn,
            max_valid_len: max_len,
            expiry,
        })])
    }

    #[test]
    fn lrxp_verified_reads_as_bool_true_when_present() {
        let payload = hint_payload(1, 0, 0);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        assert_eq!(
            run("if bgp.lrxp.verified then accept; reject;", &mut r),
            EvalResult::Accept,
        );
    }

    #[test]
    fn lrxp_verified_reads_as_bool_false_when_absent() {
        // Issue #81 fallback: a route with no LRXP attribute (the
        // peer did not advertise the capability) reads as false.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("if bgp.lrxp.verified then accept; reject;", &mut r),
            EvalResult::Reject(None),
        );
    }

    #[test]
    fn lrxp_hint_rank_reads_as_int_when_present() {
        let payload = hint_payload(2, 500, 1234);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        assert_eq!(
            run("if bgp.lrxp.hint.rank == 2 then accept; reject;", &mut r),
            EvalResult::Accept,
        );
    }

    #[test]
    fn lrxp_hint_rank_reads_as_zero_when_absent() {
        // Issue #81 fallback: the accessor returns 0 on a non-LRXP
        // peer's route.
        let mut r = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run("if bgp.lrxp.hint.rank == 0 then accept; reject;", &mut r),
            EvalResult::Accept,
        );
    }

    #[test]
    fn lrxp_hint_damp_fom_and_igp_cost_round_trip() {
        let payload = hint_payload(1, 500, 1234);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        assert_eq!(
            run(
                "if bgp.lrxp.hint.damp_fom == 500 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "if bgp.lrxp.hint.igp_cost == 1234 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn lrxp_policy_role_and_digests_round_trip() {
        let payload = policy_payload(1, [0xaa; 8], [0xbb; 8]);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        assert_eq!(
            run("if bgp.lrxp.policy.role == 1 then accept; reject;", &mut r),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "if bgp.lrxp.policy.import_digest == \"aaaaaaaaaaaaaaaa\" then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "if bgp.lrxp.policy.export_digest == \"bbbbbbbbbbbbbbbb\" then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn lrxp_origin_fields_round_trip() {
        let payload = origin_payload(64512, 24, 1_700_000_000);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        assert_eq!(
            run(
                "if bgp.lrxp.origin.origin_as == 64512 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "if bgp.lrxp.origin.max_valid_len == 24 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
        assert_eq!(
            run(
                "if bgp.lrxp.origin.expiry == 1700000000 then accept; reject;",
                &mut r
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn lrxp_partial_transit_reads_as_true_on_partial_store() {
        // Design §7: a Partial-bit record crossed a non-lr hop —
        // forwarding material, not consumable. `verified` is false,
        // `partial_transit` is true.
        let raw = [0xde, 0xad, 0xbe, 0xef];
        let mut r = route_with_lrxp_store(Some((STORE_PARTIAL_RAW, &raw)));
        assert_eq!(
            run("if bgp.lrxp.partial_transit then accept; reject;", &mut r),
            EvalResult::Accept,
        );
        assert_eq!(
            run("if bgp.lrxp.verified then accept; reject;", &mut r),
            EvalResult::Reject(None),
        );
    }

    #[test]
    fn lrxp_defined_distinguishes_present_from_absent() {
        let payload = hint_payload(1, 0, 0);
        let mut r_with = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        assert_eq!(
            run(
                "if defined(bgp.lrxp.verified) then accept; reject;",
                &mut r_with
            ),
            EvalResult::Accept,
        );
        let mut r_without = route_with("203.0.113.0/24", 100, 0);
        assert_eq!(
            run(
                "if defined(bgp.lrxp.verified) then accept; reject;",
                &mut r_without
            ),
            EvalResult::Reject(None),
        );
    }

    #[test]
    fn lrxp_hint_rank_defined_iff_hint_record_present() {
        // A verified store with a policy record but no hint record:
        // `defined(bgp.lrxp.hint.rank)` is false.
        let payload = policy_payload(1, [0; 8], [0; 8]);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        assert_eq!(
            run(
                "if defined(bgp.lrxp.hint.rank) then accept; reject;",
                &mut r
            ),
            EvalResult::Reject(None),
        );
        // A verified store with a hint record: defined is true.
        let payload = hint_payload(1, 0, 0);
        let mut r2 = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        assert_eq!(
            run(
                "if defined(bgp.lrxp.hint.rank) then accept; reject;",
                &mut r2
            ),
            EvalResult::Accept,
        );
    }

    #[test]
    fn lrxp_fields_are_not_assignable() {
        let err = compile("test", "bgp.lrxp.hint.rank = 1;").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("read-only") || msg.contains("ReadOnly"),
            "expected a read-only error, got: {msg}"
        );
        let err = compile("test", "bgp.lrxp.verified = true;").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("read-only") || msg.contains("ReadOnly"),
            "expected a read-only error, got: {msg}"
        );
    }

    #[test]
    fn lrxp_unknown_class_is_a_parse_error() {
        // `bgp.lrxp.unknown` is not a valid class — the parser
        // rejects it at parse time.
        let err = compile("test", "if bgp.lrxp.unknown.foo == 1 then accept; reject;").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("UnknownBgpField") || msg.contains("bgp.lrxp.unknown"),
            "expected an UnknownBgpField error, got: {msg}"
        );
    }

    #[test]
    fn lrxp_unknown_field_is_a_parse_error() {
        // `bgp.lrxp.hint.unknown` is not a valid field under `hint`.
        let err =
            compile("test", "if bgp.lrxp.hint.unknown == 1 then accept; reject;").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("UnknownBgpField") || msg.contains("bgp.lrxp.hint.unknown"),
            "expected an UnknownBgpField error, got: {msg}"
        );
    }

    /// Issue #81 canonical idiom: a filter that deprioritises a
    /// route whose sender reports it as rank > 1 (a poor repair
    /// candidate per design §5.1). On a non-LRXP peer the accessor
    /// returns 0, the `rank > 1` test is false, the local-pref
    /// write does not fire — the graceful degradation the issue
    /// requires.
    #[test]
    fn lrxp_canonical_idiom_deprioritises_high_rank() {
        let payload = hint_payload(3, 0, 0);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        // rank 3 > 1 → local-pref set to 50, then accept.
        let f = compile(
            "test",
            "if bgp.lrxp.hint.rank > 1 then { bgp.local_pref = 50; accept; } accept;",
        )
        .unwrap();
        evaluate(&f, &mut r, &StubCtx);
        assert_eq!(local_pref(&r), Some(50));
    }

    /// Issue #81 canonical idiom: the same filter no-ops on a
    /// non-LRXP peer (rank reads as 0, the `rank > 1` test is
    /// false, local-pref stays at its original value).
    #[test]
    fn lrxp_canonical_idiom_no_ops_on_non_lrxp_peer() {
        let mut r = route_with("203.0.113.0/24", 100, 0);
        let original_lp = local_pref(&r);
        let f = compile(
            "test",
            "if bgp.lrxp.hint.rank > 1 then { bgp.local_pref = 50; accept; } accept;",
        )
        .unwrap();
        evaluate(&f, &mut r, &StubCtx);
        assert_eq!(local_pref(&r), original_lp);
    }

    /// Issue #81 — adjust MED based on the sender's IGP cost (design
    /// §5.1: the quantity inter-AS receivers otherwise cannot see).
    /// A higher IGP cost on the sender's side means the path is more
    /// expensive end-to-end; the receiver bumps its MED to reflect
    /// that.
    #[test]
    fn lrxp_canonical_idiom_med_from_igp_cost() {
        let payload = hint_payload(1, 0, 2000);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        let f = compile(
            "test",
            "if bgp.lrxp.hint.igp_cost > 1000 then { bgp.med = 200; accept; } accept;",
        )
        .unwrap();
        evaluate(&f, &mut r, &StubCtx);
        assert_eq!(med(&r), Some(200));
    }

    /// Issue #81 — boost local-pref for routes with a verified origin
    /// attestation (design §5.3: the defect-§4 mitigation for
    /// deployments that have no RPKI). The `verified` predicate is
    /// the single bool an operator gates on.
    #[test]
    fn lrxp_canonical_idiom_boost_verified_origin() {
        let payload = origin_payload(64512, 24, 1_800_000_000);
        let mut r = route_with_lrxp_store(Some((STORE_VERIFIED, &payload)));
        let f = compile(
            "test",
            "if bgp.lrxp.verified && bgp.lrxp.origin.origin_as == 64512 then { bgp.local_pref = 200; accept; } accept;",
        )
        .unwrap();
        evaluate(&f, &mut r, &StubCtx);
        assert_eq!(local_pref(&r), Some(200));
    }

    // Suppress the unused-import warning for STORE_PARTIAL_RAW and
    // STORE_VERIFIED — they are re-exported from the test helpers
    // above and the compiler sees the path through the const items,
    // but the import documents the codec surface.
    #[allow(dead_code)]
    fn _doc_anchor() -> (u8, u8) {
        (STORE_VERIFIED, STORE_PARTIAL_RAW)
    }
}
