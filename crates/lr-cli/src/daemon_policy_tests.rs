use super::*;
use crate::daemon_config::parse_toml_subset;
use crate::daemon_config::DaemonConfig;

fn parse(text: &str) -> DaemonConfig {
    let mut cfg = DaemonConfig::with_defaults();
    parse_toml_subset(text, &mut cfg).unwrap();
    cfg
}

#[test]
fn community_syntaxes() {
    assert_eq!(parse_community("64512:100"), Ok(0xFC00_0064));
    assert_eq!(parse_community("4224"), Ok(4224));
    assert_eq!(parse_community("no-export"), Ok(0xFFFFFF01));
    assert!(parse_community("70000:1").is_err());
    assert!(parse_community("garbage").is_err());
}

#[test]
fn policy_tables_compile() {
    let cfg = parse(
        "[[prefix-list]]\nname = \"doc\"\nprefix = \"198.51.100.0/24\"\n\n\
             [[route-map]]\nname = \"in\"\nentry = 10\nmatch_prefix = \"doc\"\npermit = false\n\n\
             [[route-map]]\nname = \"in\"\nentry = 20\nset_local_pref = 250\npermit = true\n",
    );
    assert_eq!(cfg.prefix_lists.len(), 1);
    assert_eq!(cfg.route_maps.len(), 2);
    let set = build_policy_set(&cfg).unwrap();
    assert!(set.route_map("in").is_some());
}

#[test]
fn unknown_references_fail_closed() {
    let cfg = parse("[[route-map]]\nname = \"x\"\nmatch_prefix = \"ghost\"\npermit = true\n");
    let err = build_policy_set(&cfg).err().expect("must fail");
    assert!(err.contains("unknown prefix-list 'ghost'"), "{err}");

    let mut cfg2 = DaemonConfig::with_defaults();
    cfg2.peers.push(crate::daemon_config::PeerSpec {
        import: Some("ghost-map".into()),
        ..Default::default()
    });
    let mut set = PolicySet::new();
    let err = bind_peer_policies(&cfg2, &mut set, |i| i as u64).unwrap_err();
    assert!(err.contains("unknown route-map 'ghost-map'"), "{err}");
}

#[test]
fn route_map_entries_apply_in_entry_order() {
    let cfg = parse(
        "[[route-map]]\nname = \"m\"\nentry = 20\npermit = true\n\n\
             [[route-map]]\nname = \"m\"\nentry = 10\npermit = false\n",
    );
    let set = build_policy_set(&cfg).unwrap();
    // Entry 10 (deny) must be first regardless of file order.
    let map = set.route_map("m").unwrap();
    assert_eq!(map.entries.len(), 2);
    assert_eq!(map.entries[0].verdict, Some(false));
}

#[test]
fn roa_table_builds_from_config() {
    let cfg = parse(
        "[[roa]]\nprefix = \"203.0.113.0/24\"\nasn = 64512\n\n\
             [[roa]]\nprefix = \"198.51.100.0/24\"\nmax_length = 26\nasn = 64513\n",
    );
    let t = build_roa_table(&cfg).unwrap();
    assert_eq!(t.len(), 2);
}

#[test]
fn roa_table_rejects_bad_config() {
    let cfg = parse("[[roa]]\nprefix = \"203.0.113.0/24\"\nmax_length = 23\nasn = 64512\n");
    let err = build_roa_table(&cfg).unwrap_err();
    assert!(err.contains("max_length"), "{err}");
}

#[test]
fn filters_compile() {
    let cfg = parse(
            "[[filter]]\nname = \"customer-in\"\nbody = \"if net ~ 203.0.113.0/24 then accept; reject;\"\n",
        );
    let filters = build_filters(&cfg).unwrap();
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].0, "customer-in");
}

#[test]
fn filter_duplicate_name_fails() {
    let cfg = parse(
        "[[filter]]\nname = \"dup\"\nbody = \"accept;\"\n\n\
             [[filter]]\nname = \"dup\"\nbody = \"reject;\"\n",
    );
    let err = build_filters(&cfg).unwrap_err();
    assert!(err.contains("declared twice"), "{err}");
}

#[test]
fn filter_parse_error_fails() {
    let cfg = parse("[[filter]]\nname = \"bad\"\nbody = \"if net ~ then accept;\"\n");
    let err = build_filters(&cfg).unwrap_err();
    assert!(err.contains("filter 'bad'"), "{err}");
}

#[test]
fn filter_with_variables_and_arithmetic_compiles() {
    // A non-trivial BIRD-style filter: variable bindings,
    // arithmetic, prefix-set range, method call, append.
    let cfg = parse(
            "[[filter]]\nname = \"complex\"\nbody = \"let p = 100; let q = p * 2; if bgp.local_pref < q && net ~ [ 10.0.0.0/8{16,24} ] then { bgp.local_pref = q; bgp.communities += [ 64512:100 ]; accept; } reject;\"\n",
        );
    let filters = build_filters(&cfg).unwrap();
    assert_eq!(filters.len(), 1);
}

/// The D12.4 hook timing: a hook built with a histogram records
/// one observation per evaluation (count and sum both move), and
/// the verdict is unchanged by the timing wrapper.
#[test]
fn filter_hook_records_latency() {
    use lr_core::rib::Route;
    use lr_policy::hooks::{HookVerdict, ImportHook};

    let f = dsl::compile("timed", "if net ~ [ 192.0.2.0/24 ] then accept; reject;").unwrap();
    let ctx = std::sync::Arc::new(DaemonFilterContext::new(std::sync::Arc::new(
        lr_bgp::RoaStore::new(),
    )));
    let hist = std::sync::Arc::new(crate::metrics::DurationHistogram::new());
    let hook = FilterImportHook {
        compiled: lr_policy::filter::bytecode::compile(&f),
        filter: f,
        ctx,
        stats: Some(std::sync::Arc::clone(&hist)),
    };

    let mut route = Route {
        key: lr_core::rib::RouteKey::new(
            lr_core::addr::Prefix::new_v4([192, 0, 2, 0], 24),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        ),
        origin: lr_core::rib::RouteOrigin { proto: 0, peer: 1 },
        protocol: lr_core::rib::Protocol::Bgp,
        preference: lr_core::rib::Preference::new(20, 100),
        next_hop: None,
        attributes: lr_core::attr::Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    };
    assert!(matches!(hook.on_import(&mut route), HookVerdict::Keep));
    assert_eq!(hist.count(), 1, "one evaluation recorded");

    let mut other = route.clone();
    other.key.prefix = lr_core::addr::Prefix::new_v4([198, 51, 100, 0], 24);
    assert!(matches!(hook.on_import(&mut other), HookVerdict::Drop));
    assert_eq!(hist.count(), 2, "second evaluation recorded");
}

/// Babel filter lookup: a named filter declared in `[[filter]]`
/// blocks resolves to a compiled BabelFilter; an unknown name
/// fails closed.
#[test]
fn babel_filter_builds_from_named_filter() {
    let cfg = parse(
            "[[filter]]\nname = \"babel-in\"\nbody = \"if net ~ [ 10.0.0.0/8 ] then accept; reject;\"\n",
        );
    let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
    let f = build_babel_filter(&cfg, &Some("babel-in".into()), &roa)
        .expect("filter must compile")
        .expect("filter must be found");
    assert_eq!(f.name, "babel-in");
}

/// Unknown babel filter name → startup error (typo protection;
/// the daemon must not silently run with no filter).
#[test]
fn babel_filter_unknown_name_fails() {
    let cfg = parse("[[filter]]\nname = \"babel-in\"\nbody = \"accept;\"\n");
    let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
    let err = build_babel_filter(&cfg, &Some("ghost".into()), &roa).unwrap_err();
    assert!(err.contains("unknown filter 'ghost'"), "{err}");
}

/// `None` filter name → no filter (the historical accept-all
/// behaviour). This is the path every existing config takes.
#[test]
fn babel_filter_none_when_unconfigured() {
    let cfg = DaemonConfig::with_defaults();
    let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
    let f = build_babel_filter(&cfg, &None, &roa).unwrap();
    assert!(f.is_none(), "no filter name → no filter");
}

/// The BabelFilterImportHook only runs the DSL against
/// `Protocol::Babel` routes; BGP/OSPF/connected routes pass
/// through unchanged (the operator's filter body does not need
/// to scope itself with `if proto == "babel"`).
#[test]
fn babel_import_hook_skips_non_babel_routes() {
    use lr_core::rib::Route;
    use lr_policy::hooks::{HookVerdict, ImportHook};

    // The filter rejects everything — but the hook must only
    // apply to Babel routes, so a BGP route passing through this
    // hook should still be kept (it never reaches the DSL).
    let cfg = parse("[[filter]]\nname = \"drop-all\"\nbody = \"reject;\"\n");
    let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
    let f = build_babel_filter(&cfg, &Some("drop-all".into()), &roa)
        .unwrap()
        .unwrap();
    let hook = BabelFilterImportHook {
        inner: BabelFilter {
            name: f.name.clone(),
            compiled: f.compiled.clone(),
            ctx: f.ctx.clone(),
        },
        stats: None,
    };

    // A BGP route: must pass through unchanged.
    let mut bgp_route = Route {
        key: lr_core::rib::RouteKey::new(
            lr_core::addr::Prefix::new_v4([192, 0, 2, 0], 24),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        ),
        origin: lr_core::rib::RouteOrigin { proto: 0, peer: 1 },
        protocol: lr_core::rib::Protocol::Bgp,
        preference: lr_core::rib::Preference::new(20, 100),
        next_hop: None,
        attributes: lr_core::attr::Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    };
    assert!(
        matches!(hook.on_import(&mut bgp_route), HookVerdict::Keep),
        "BGP route must bypass the babel filter"
    );

    // A Babel route: must be dropped by the `reject;` body.
    let mut babel_route = bgp_route.clone();
    babel_route.protocol = lr_core::rib::Protocol::Babel;
    assert!(
        matches!(hook.on_import(&mut babel_route), HookVerdict::Drop),
        "Babel route must hit the filter and be dropped"
    );
}

/// The export-side `BabelFilter::accepts` mirrors the import-side
/// verdict: accept / fallthrough → true, reject → false.
#[test]
fn babel_export_filter_accepts_routes() {
    let cfg = parse(
        "[[filter]]\nname = \"out\"\nbody = \"if net ~ [ 10.0.0.0/8 ] then accept; reject;\"\n",
    );
    let roa = std::sync::Arc::new(lr_bgp::RoaStore::new());
    let f = build_babel_filter(&cfg, &Some("out".into()), &roa)
        .unwrap()
        .unwrap();

    let mut route = lr_core::rib::Route {
        key: lr_core::rib::RouteKey::new(
            lr_core::addr::Prefix::new_v4([10, 0, 0, 0], 8),
            lr_core::nlri::NlriFamily::IPV4_UNICAST,
        ),
        origin: lr_core::rib::RouteOrigin { proto: 0, peer: 0 },
        protocol: lr_core::rib::Protocol::Bgp,
        preference: lr_core::rib::Preference::new(20, 0),
        next_hop: None,
        attributes: lr_core::attr::Attributes::new(),
        age_ms: 0,
        path_id: 0,
        tag: None,
    };
    assert!(f.accepts(&route), "10.0.0.0/8 matches → accept");

    route.key.prefix = lr_core::addr::Prefix::new_v4([192, 0, 2, 0], 24);
    assert!(!f.accepts(&route), "192.0.2.0/24 does not match → reject");
}

#[test]
fn shared_filter_function_is_callable_from_filter() {
    // A `[[filter_function]]` is prepended to every filter body,
    // so a filter can call it by name (issue #46).
    let cfg = parse(
        "[[filter_function]]\n\
             name = \"tag_customer\"\n\
             params = [\"lp\"]\n\
             body = \"bgp.local_pref = lp; return true;\"\n\
             [[filter]]\n\
             name = \"in\"\n\
             body = \"tag_customer(200); accept;\"\n",
    );
    let filters = build_filters(&cfg).expect("filter must compile");
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].0, "in");
    // The shared function lands in the compiled filter's function table.
    assert_eq!(filters[0].1.functions.len(), 1);
    assert_eq!(filters[0].1.functions[0].name, "tag_customer");
}

#[test]
fn shared_filter_function_detects_duplicate_names() {
    // Two `[[filter_function]]` blocks with the same name fail at
    // preamble render time, before the DSL parser sees them.
    let cfg = parse(
        "[[filter_function]]\n\
             name = \"dup\"\n\
             body = \"return true;\"\n\
             [[filter_function]]\n\
             name = \"dup\"\n\
             body = \"return false;\"\n\
             [[filter]]\n\
             name = \"in\"\n\
             body = \"accept;\"\n",
    );
    let err = build_filters(&cfg).unwrap_err();
    assert!(
        err.contains("filter function 'dup' declared twice"),
        "{err}"
    );
}

#[test]
fn shared_filter_function_can_call_another_shared_function() {
    // A later shared function can call an earlier one (the preamble
    // is emitted in config order).
    let cfg = parse(
        "[[filter_function]]\n\
             name = \"base\"\n\
             body = \"return true;\"\n\
             [[filter_function]]\n\
             name = \"wrapper\"\n\
             body = \"return base();\"\n\
             [[filter]]\n\
             name = \"in\"\n\
             body = \"if wrapper() then accept; reject;\"\n",
    );
    let filters = build_filters(&cfg).expect("filter must compile");
    assert_eq!(filters[0].1.functions.len(), 2);
}

#[test]
fn shared_filter_function_missing_name_fails() {
    let cfg = parse(
        "[[filter_function]]\n\
             body = \"return true;\"\n\
             [[filter]]\n\
             name = \"in\"\n\
             body = \"accept;\"\n",
    );
    let err = build_filters(&cfg).unwrap_err();
    assert!(err.contains("missing its 'name'"), "{err}");
}
