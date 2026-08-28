//! TOML policy objects for `lr-daemon`: `[[prefix-list]]`,
//! `[[as-path-list]]`, `[[community-list]]` and `[[route-map]]`
//! tables plus per-peer `import = "<route-map>"` / `export =
//! "<route-map>"` attachment, compiled into an
//! [`lr_policy::PolicySet`] wired onto the router hooks.
//!
//! Design: declarative tables mapping 1:1 onto `lr-policy` primitives
//! — no filter DSL and no embedded scripting. Entries within one
//! route-map apply in ascending `entry` order (ties keep file order),
//! mirroring FRR `route-map NAME permit N` instances.

use core::str::FromStr;
use std::process::ExitCode;

use lr_core::addr::Prefix;
use lr_policy::action::SetAction;
use lr_policy::as_path_filter::AsPathFilter;
use lr_policy::community_list::{CommunityList, CommunityListEntry};
use lr_policy::prefix_list::{PrefixList, PrefixListEntry};
use lr_policy::route_map::RouteMapEntry;
use lr_policy::{ListKind, PolicySet};

use crate::daemon_config::DaemonConfig;

/// One `[[prefix-list]]` table: `name`, `prefix`, optional
/// `ge`/`le`/`permit` (ge defaults to the prefix length, le to
/// unbounded, permit to true).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PrefixListSpec {
    pub name: String,
    pub prefix: String,
    pub ge: Option<u8>,
    pub le: Option<u8>,
    pub permit: Option<bool>,
}

/// One `[[as-path-list]]` table: `name`, `pattern`, `permit`.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct AsPathListSpec {
    pub name: String,
    pub pattern: String,
    pub permit: Option<bool>,
}

/// One `[[community-list]]` table: `name`, `communities`, `permit`.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct CommunityListSpec {
    pub name: String,
    pub communities: Vec<String>,
    pub permit: Option<bool>,
}

/// One `[[route-map]]` table instance (a single entry of the named
/// map): `name`, optional `entry` (ordering key), any of
/// `match_prefix` / `match_as_path` / `match_community` (AND), set
/// keys `set_local_pref` / `set_med` / `set_metric` / `set_next_hop` /
/// `prepend` / `add_community`, and `permit` for the verdict
/// (absent = continue to the next entry).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RouteMapSpec {
    pub name: String,
    pub entry: u32,
    pub match_prefix: Option<String>,
    pub match_as_path: Option<String>,
    pub match_community: Option<String>,
    pub set_local_pref: Option<u32>,
    pub set_med: Option<u32>,
    pub set_metric: Option<u32>,
    pub set_next_hop: Option<String>,
    /// Space-separated AS numbers, prepended in order
    /// (FRR `set as-path prepend 65001 65001`).
    pub prepend: Option<String>,
    /// One `asn:value` community (or several, space-separated).
    pub add_community: Option<String>,
    pub permit: Option<bool>,
}

/// Compile the parsed policy tables into a [`PolicySet`].
///
/// Every reference (route-map -> list, peer -> route-map) must resolve;
/// unknown names are startup errors — fail closed, never silently
/// permissive.
pub(crate) fn build_policy_set(cfg: &DaemonConfig) -> Result<PolicySet, String> {
    let mut set = PolicySet::new();

    for spec in &cfg.prefix_lists {
        let prefix = Prefix::from_str(&spec.prefix).map_err(|e| {
            format!(
                "prefix-list '{}': bad prefix '{}': {}",
                spec.name, spec.prefix, e
            )
        })?;
        let mut list = PrefixList::new();
        list.push(PrefixListEntry {
            prefix,
            ge: spec.ge.unwrap_or(prefix.prefix_len),
            le: spec.le.unwrap_or(255),
            permit: spec.permit.unwrap_or(true),
        });
        set.add_prefix_list(spec.name.clone(), list);
    }

    for spec in &cfg.as_path_lists {
        set.add_as_path_list(
            spec.name.clone(),
            vec![AsPathFilter {
                pattern: spec.pattern.clone(),
                permit: spec.permit.unwrap_or(true),
            }],
        );
    }

    for spec in &cfg.community_lists {
        let mut comms = Vec::new();
        for c in &spec.communities {
            comms.push(
                parse_community(c).map_err(|e| format!("community-list '{}': {}", spec.name, e))?,
            );
        }
        let mut list = CommunityList::new();
        list.push(CommunityListEntry {
            communities: comms,
            permit: spec.permit.unwrap_or(true),
        });
        set.add_community_list(spec.name.clone(), list);
    }

    // Route-map entries: ascending `entry`, ties in file order.
    let mut ordered: Vec<&RouteMapSpec> = cfg.route_maps.iter().collect();
    ordered.sort_by_key(|s| s.entry);
    for spec in ordered {
        let mut matches = Vec::new();
        if let Some(name) = &spec.match_prefix {
            matches.push(set.match_condition(ListKind::Prefix, name).ok_or_else(|| {
                format!("route-map '{}': unknown prefix-list '{}'", spec.name, name)
            })?);
        }
        if let Some(name) = &spec.match_as_path {
            matches.push(set.match_condition(ListKind::AsPath, name).ok_or_else(|| {
                format!("route-map '{}': unknown as-path-list '{}'", spec.name, name)
            })?);
        }
        if let Some(name) = &spec.match_community {
            matches.push(
                set.match_condition(ListKind::Community, name)
                    .ok_or_else(|| {
                        format!(
                            "route-map '{}': unknown community-list '{}'",
                            spec.name, name
                        )
                    })?,
            );
        }

        let mut sets = Vec::new();
        if let Some(v) = spec.set_local_pref {
            sets.push(SetAction::SetLocalPref(v));
        }
        if let Some(v) = spec.set_med {
            sets.push(SetAction::SetMed(v));
        }
        if let Some(v) = spec.set_metric {
            sets.push(SetAction::SetMetric(v));
        }
        if let Some(ip) = &spec.set_next_hop {
            let ip = lr_core::addr::IpAddr::from_str(ip).map_err(|e| {
                format!(
                    "route-map '{}': bad set_next_hop '{}': {}",
                    spec.name, ip, e
                )
            })?;
            sets.push(SetAction::SetNextHop(ip));
        }
        if let Some(list) = &spec.prepend {
            for token in list.split_whitespace() {
                let asn: u32 = token.parse().map_err(|_| {
                    format!("route-map '{}': bad prepend AS '{}'", spec.name, token)
                })?;
                sets.push(SetAction::PrependAs(lr_core::addr::Asn(asn)));
            }
        }
        if let Some(list) = &spec.add_community {
            for token in list.split_whitespace() {
                let c = parse_community(token)
                    .map_err(|e| format!("route-map '{}': {}", spec.name, e))?;
                sets.push(SetAction::AddCommunity(
                    lr_core::addr::Asn(c >> 16),
                    (c & 0xffff) as u16,
                ));
            }
        }

        set.push_route_map_entry(
            spec.name.clone(),
            RouteMapEntry {
                matches,
                sets,
                verdict: spec.permit,
            },
        );
    }

    Ok(set)
}

/// Parse `asn:value`, a plain decimal u32 or the well-known RFC 1997
/// names (`no-export`, `no-advertise`, `no-peer`, plus the lr
/// RFC 9494 names `llgr-stale` / `no-llgr`).
pub(crate) fn parse_community(text: &str) -> Result<u32, String> {
    let t = text.trim();
    match t {
        "no-export" => return Ok(0xFFFFFF01),
        "no-advertise" => return Ok(0xFFFFFF02),
        "no-peer" => return Ok(0xFFFFFF03),
        "llgr-stale" => return Ok(0xFFFF0000),
        "no-llgr" => return Ok(0xFFFF0001),
        _ => {}
    }
    if let Some((asn, value)) = t.split_once(':') {
        let asn: u32 = asn
            .parse()
            .map_err(|_| format!("bad community '{}' (expected asn:value)", t))?;
        let value: u16 = value
            .parse()
            .map_err(|_| format!("bad community '{}' (expected asn:value)", t))?;
        if asn > 0xFFFF {
            return Err(format!("bad community '{}' (asn part exceeds 16 bits)", t));
        }
        return Ok((asn << 16) | value as u32);
    }
    t.parse::<u32>().map_err(|_| {
        format!(
            "bad community '{}' (expected asn:value, decimal or well-known name)",
            t
        )
    })
}

/// Wire per-peer `import`/`export` route-maps onto session handles.
/// Call before [`PolicySet::hooks`]; returns a startup error when a
/// peer references an unknown route-map (fail closed).
pub(crate) fn bind_peer_policies(
    cfg: &DaemonConfig,
    set: &mut PolicySet,
    session_of_peer: impl Fn(usize) -> u64,
) -> Result<(), String> {
    for (idx, peer) in cfg.peers.iter().enumerate() {
        if let Some(name) = &peer.import {
            if set.route_map(name).is_none() {
                return Err(format!(
                    "peer {}: unknown route-map '{}'",
                    peer.label(),
                    name
                ));
            }
            set.bind_import(session_of_peer(idx), name.clone());
        }
        if let Some(name) = &peer.export {
            if set.route_map(name).is_none() {
                return Err(format!(
                    "peer {}: unknown route-map '{}'",
                    peer.label(),
                    name
                ));
            }
            set.bind_export(session_of_peer(idx), name.clone());
        }
    }
    Ok(())
}

/// Convenience wrapper used by `main` to fail with exit code 2 on
/// policy configuration errors.
pub(crate) fn policy_error(msg: String) -> ExitCode {
    eprintln!("error: {}", msg);
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
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
}
