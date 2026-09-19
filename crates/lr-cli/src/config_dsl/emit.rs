//! `lr-daemon config to-dsl <file>` — the deterministic
//! [`DaemonConfig`] → `.lr` renderer (ROADMAP-v3 D16 Phase 2,
//! GitHub #18).
//!
//! Contract (see `docs/config_dsl_grammar.md`):
//!
//! - **Deterministic.** Blocks and keys are emitted in a fixed order
//!   (schema order); `peer-template` blocks iterate a `BTreeMap` and
//!   are therefore sorted; unset fields are omitted. Rendering the
//!   same IR twice yields byte-identical output.
//! - **Never silent.** Parse warnings (unknown sections/keys the TOML
//!   frontend tolerated) make the conversion fail: the emitted file
//!   would mean less than the input. A `[[filter]]` carrying a
//!   `description` fails too — the DSL has no spelling for it yet.
//! - **Round-trip.** `parse(TOML) → to-dsl → parse(lr)` is an IR
//!   equality (`PartialEq`) identity for every file the converter
//!   accepts; the golden tests pin it, including against the shipped
//!   template.
//!
//! Emission rule for scalars: a field is emitted when its value
//! differs from [`DaemonConfig::default`]. Omitted fields therefore
//! re-parse to the same default regardless of the caller's seed
//! (`default()` or `with_defaults()`), which is what makes the
//! round-trip property hold in both contexts. Load bookkeeping
//! (`config_path`, `config_dialect`, `warnings`, `explicit_peers`)
//! is never emitted.

use crate::daemon_config::{BabelKeySpec, DaemonConfig, DampingSpec};

/// Render `cfg` into a `.lr` program.
pub(crate) fn to_dsl(cfg: &DaemonConfig) -> Result<String, String> {
    if !cfg.warnings.is_empty() {
        return Err(format!(
            "refusing to convert: the config produced {} parse warning(s) that the DSL \
             cannot represent faithfully (first: {})",
            cfg.warnings.len(),
            cfg.warnings[0]
        ));
    }
    for filter in &cfg.filters {
        if filter.description.is_some() {
            return Err(format!(
                "refusing to convert: filter '{}' carries a description, which the DSL \
                 cannot represent yet (drop it or keep that filter's TOML file)",
                filter.name.as_deref().unwrap_or("<unnamed>")
            ));
        }
    }

    let base = DaemonConfig::default();
    let mut e = Emitter::default();

    // --- top-level keys -------------------------------------------------
    if cfg.protocol != base.protocol {
        e.kv(0, "protocol", &fmt_string(&cfg.protocol));
    }
    if let Some(v) = &cfg.user {
        e.kv(0, "user", &fmt_string(v));
    }
    if let Some(v) = &cfg.group {
        e.kv(0, "group", &fmt_string(v));
    }
    if let Some(v) = &cfg.api_socket {
        e.kv(0, "api_socket", &fmt_string(v));
    }
    if let Some(v) = &cfg.metrics_addr {
        e.kv(0, "metrics_addr", &fmt_string(v));
    }
    if !cfg.networks.is_empty() {
        e.kv(0, "networks", &list_value(&cfg.networks)?);
    }
    if !cfg.labeled_networks.is_empty() {
        e.kv(0, "labeled_networks", &list_value(&cfg.labeled_networks)?);
    }
    if cfg.roa_validate != base.roa_validate {
        e.kv(0, "roa_validate", &cfg.roa_validate.to_string());
    }
    if cfg.roa_invalid_action != base.roa_invalid_action {
        e.kv(
            0,
            "roa_invalid_action",
            &fmt_string(&cfg.roa_invalid_action),
        );
    }

    // --- bgp (with the nested rpki block) -------------------------------
    let bgp_fields = bgp_block(cfg, &base)?;
    let rpki = rpki_block(cfg);
    if !bgp_fields.is_empty() || !rpki.is_empty() {
        e.open(0, "bgp", None);
        for (key, value) in &bgp_fields {
            e.kv(1, key, value);
        }
        if !rpki.is_empty() {
            e.open(1, "rpki", None);
            for (key, value) in &rpki {
                e.kv(2, key, value);
            }
            e.close(1);
        }
        e.close(0);
    }

    // --- peers and templates ---------------------------------------------
    for peer in &cfg.peers {
        let fields = peer_block(peer)?;
        e.open(0, "peer", peer.name.as_deref().map(fmt_string).as_deref());
        for (key, value) in &fields {
            e.kv(1, key, value);
        }
        e.close(0);
    }
    for (name, template) in &cfg.peer_templates {
        let fields = peer_block(template)?;
        e.open(0, "peer-template", Some(&fmt_string(name)));
        for (key, value) in &fields {
            e.kv(1, key, value);
        }
        e.close(0);
    }

    // --- policy bank ------------------------------------------------------
    for list in &cfg.prefix_lists {
        e.open(0, "prefix-list", Some(&fmt_string(&list.name)));
        e.kv(1, "prefix", &fmt_string(&list.prefix));
        if let Some(v) = list.permit {
            e.kv(1, "permit", &v.to_string());
        }
        if let Some(v) = list.ge {
            e.kv(1, "ge", &v.to_string());
        }
        if let Some(v) = list.le {
            e.kv(1, "le", &v.to_string());
        }
        e.close(0);
    }
    for list in &cfg.as_path_lists {
        e.open(0, "as-path-list", Some(&fmt_string(&list.name)));
        e.kv(1, "pattern", &fmt_string(&list.pattern));
        if let Some(v) = list.permit {
            e.kv(1, "permit", &v.to_string());
        }
        e.close(0);
    }
    for list in &cfg.community_lists {
        e.open(0, "community-list", Some(&fmt_string(&list.name)));
        if !list.communities.is_empty() {
            e.kv(1, "communities", &list_value(&list.communities)?);
        }
        if let Some(v) = list.permit {
            e.kv(1, "permit", &v.to_string());
        }
        e.close(0);
    }
    for map in &cfg.route_maps {
        e.open(0, "route-map", Some(&fmt_string(&map.name)));
        e.kv(1, "entry", &map.entry.to_string());
        if let Some(v) = &map.match_prefix {
            e.kv(1, "match_prefix", &fmt_string(v));
        }
        if let Some(v) = &map.match_as_path {
            e.kv(1, "match_as_path", &fmt_string(v));
        }
        if let Some(v) = &map.match_community {
            e.kv(1, "match_community", &fmt_string(v));
        }
        if let Some(v) = map.permit {
            e.kv(1, "permit", &v.to_string());
        }
        if let Some(v) = map.set_local_pref {
            e.kv(1, "set_local_pref", &v.to_string());
        }
        if let Some(v) = map.set_med {
            e.kv(1, "set_med", &v.to_string());
        }
        if let Some(v) = map.set_metric {
            e.kv(1, "set_metric", &v.to_string());
        }
        if let Some(v) = &map.set_next_hop {
            e.kv(1, "set_next_hop", &fmt_string(v));
        }
        if let Some(v) = &map.prepend {
            e.kv(1, "prepend", &fmt_string(v));
        }
        if let Some(v) = &map.add_community {
            e.kv(1, "add_community", &fmt_string(v));
        }
        e.close(0);
    }

    // --- filters (verbatim bodies) ----------------------------------------
    for filter in &cfg.filters {
        let Some(body) = &filter.body else {
            return Err(format!(
                "refusing to convert: filter '{}' has no body — the DSL has no \
                 spelling for a body-less filter",
                filter.name.as_deref().unwrap_or("<unnamed>")
            ));
        };
        // The body is emitted verbatim between the braces — the
        // header gets no newline of its own — so the DSL parser
        // slices it back byte-identical (grammar spec: "Filter
        // blocks").
        e.filter_block(filter.name.as_deref().map(fmt_string).as_deref(), body);
    }

    // --- roa / redistribute / aggregate ------------------------------------
    for roa in &cfg.roas {
        e.open(0, "roa", None);
        if let Some(v) = &roa.prefix {
            e.kv(1, "prefix", &fmt_string(v));
        }
        if let Some(v) = roa.max_length {
            e.kv(1, "max_len", &v.to_string());
        }
        if let Some(v) = roa.asn {
            e.kv(1, "origin_as", &v.to_string());
        }
        e.close(0);
    }
    for red in &cfg.redistributes {
        e.open(0, "redistribute", None);
        if let Some(v) = &red.source {
            e.kv(1, "source", &fmt_string(v));
        }
        if let Some(v) = &red.target {
            e.kv(1, "target", &fmt_string(v));
        }
        if let Some(v) = red.metric {
            e.kv(1, "metric", &v.to_string());
        }
        if let Some(v) = red.tag {
            e.kv(1, "tag", &v.to_string());
        }
        if !red.allow.is_empty() {
            e.kv(1, "allow", &list_value(&red.allow)?);
        }
        e.close(0);
    }
    for agg in &cfg.aggregates {
        e.open(0, "aggregate", None);
        if let Some(v) = &agg.prefix {
            e.kv(1, "prefix", &fmt_string(v));
        }
        e.close(0);
    }

    // --- ospf ---------------------------------------------------------------
    let ospf = ospf_block(cfg, &base);
    let ospf_sub = ospf_sub_blocks(cfg)?;
    if !ospf.is_empty() || !ospf_sub.is_empty() {
        e.open(0, "ospf", None);
        for (key, value) in &ospf {
            e.kv(1, key, value);
        }
        e.blocks(&ospf_sub);
        e.close(0);
    }

    // --- babel ----------------------------------------------------------------
    let babel = babel_block(cfg, &base);
    let babel_sub = babel_sub_blocks(cfg)?;
    if !babel.is_empty() || !babel_sub.is_empty() {
        e.open(0, "babel", None);
        for (key, value) in &babel {
            e.kv(1, key, value);
        }
        e.blocks(&babel_sub);
        e.close(0);
    }

    // --- ldp --------------------------------------------------------------------
    let ldp = ldp_block(cfg, &base);
    let ldp_sub = ldp_sub_blocks(cfg);
    if !ldp.is_empty() || !ldp_sub.is_empty() {
        e.open(0, "ldp", None);
        for (key, value) in &ldp {
            e.kv(1, key, value);
        }
        e.blocks(&ldp_sub);
        e.close(0);
    }

    // --- damping -------------------------------------------------------------------
    if let Some(block) = damping_block(cfg, &base) {
        e.open(0, "damping", None);
        for (key, value) in &block {
            e.kv(1, key, value);
        }
        e.close(0);
    }

    Ok(e.out)
}

// ---------------------------------------------------------------------------
// Block builders — each returns ordered (key, rendered-value) pairs.
// ---------------------------------------------------------------------------

fn bgp_block(cfg: &DaemonConfig, base: &DaemonConfig) -> Result<Vec<(String, String)>, String> {
    let mut v: Vec<(String, String)> = Vec::new();
    if cfg.local_as != base.local_as {
        v.push(("local_as".into(), cfg.local_as.to_string()));
    }
    if cfg.peer_as != base.peer_as {
        v.push(("peer_as".into(), cfg.peer_as.to_string()));
    }
    if cfg.router_id != base.router_id {
        v.push(("router_id".into(), fmt_string(&cfg.router_id)));
    }
    if let Some(x) = &cfg.peer_addr {
        v.push(("peer_addr".into(), fmt_string(x)));
    }
    if let Some(x) = &cfg.listen_addr {
        v.push(("listen_addr".into(), fmt_string(x)));
    }
    if let Some(x) = &cfg.local_address {
        v.push(("local_address".into(), fmt_string(x)));
    }
    if cfg.hold_time != base.hold_time {
        v.push(("hold_time".into(), cfg.hold_time.to_string()));
    }
    if cfg.gr_restart_time != base.gr_restart_time {
        v.push((
            "graceful_restart_time".into(),
            cfg.gr_restart_time.to_string(),
        ));
    }
    if cfg.llgr_stale_time != base.llgr_stale_time {
        v.push(("llgr_stale_time".into(), cfg.llgr_stale_time.to_string()));
    }
    if cfg.llgr_max_stale_time != base.llgr_max_stale_time {
        v.push((
            "llgr_max_stale_time".into(),
            cfg.llgr_max_stale_time.to_string(),
        ));
    }
    if let Some(x) = &cfg.md5_key {
        v.push(("md5_key".into(), fmt_string(x)));
    }
    if !cfg.tcp_ao_keys.is_empty() {
        v.push(("tcp_ao_keys".into(), list_value(&cfg.tcp_ao_keys)?));
    }
    if cfg.tcp_ao_algorithm != base.tcp_ao_algorithm {
        v.push(("tcp_ao_algorithm".into(), fmt_string(&cfg.tcp_ao_algorithm)));
    }
    if cfg.tcp_ao_maclen != base.tcp_ao_maclen {
        v.push(("tcp_ao_maclen".into(), cfg.tcp_ao_maclen.to_string()));
    }
    if cfg.install_kernel != base.install_kernel {
        v.push(("install_kernel".into(), cfg.install_kernel.to_string()));
    }
    if cfg.add_path != base.add_path {
        v.push(("add_path".into(), cfg.add_path.to_string()));
    }
    if cfg.add_path_max_paths != base.add_path_max_paths {
        v.push((
            "add_path_max_paths".into(),
            cfg.add_path_max_paths.to_string(),
        ));
    }
    if !cfg.mp_families.is_empty() {
        v.push(("mp_families".into(), list_value(&cfg.mp_families)?));
    }
    if cfg.extended_next_hop != base.extended_next_hop {
        v.push((
            "extended_next_hop".into(),
            cfg.extended_next_hop.to_string(),
        ));
    }
    if let Some(x) = &cfg.local_address_v6 {
        v.push(("local_address_v6".into(), fmt_string(x)));
    }
    if let Some(x) = cfg.gtsm_hops {
        v.push(("gtsm".into(), x.to_string()));
    }
    if let Some(x) = cfg.max_prefixes {
        v.push(("max_prefixes".into(), x.to_string()));
    }
    if cfg.max_prefix_action != base.max_prefix_action {
        v.push((
            "max_prefix_action".into(),
            fmt_string(&cfg.max_prefix_action),
        ));
    }
    if cfg.max_prefix_threshold != base.max_prefix_threshold {
        v.push((
            "max_prefix_threshold".into(),
            cfg.max_prefix_threshold.to_string(),
        ));
    }
    if cfg.bfd_enabled != base.bfd_enabled {
        v.push(("bfd".into(), cfg.bfd_enabled.to_string()));
    }
    if cfg.bfd_multihop != base.bfd_multihop {
        v.push(("bfd_multihop".into(), cfg.bfd_multihop.to_string()));
    }
    if cfg.bfd_min_tx_ms != base.bfd_min_tx_ms {
        v.push(("bfd_min_tx_ms".into(), cfg.bfd_min_tx_ms.to_string()));
    }
    if cfg.bfd_min_rx_ms != base.bfd_min_rx_ms {
        v.push(("bfd_min_rx_ms".into(), cfg.bfd_min_rx_ms.to_string()));
    }
    if cfg.bfd_multiplier != base.bfd_multiplier {
        v.push(("bfd_multiplier".into(), cfg.bfd_multiplier.to_string()));
    }
    if let Some(x) = &cfg.bmp_target {
        v.push(("bmp_target".into(), fmt_string(x)));
    }
    if cfg.ebgp_policy != base.ebgp_policy {
        v.push(("ebgp_policy".into(), fmt_string(&cfg.ebgp_policy)));
    }
    if cfg.enforce_first_as != base.enforce_first_as {
        v.push(("enforce_first_as".into(), cfg.enforce_first_as.to_string()));
    }
    if cfg.bestpath_compare_routerid != base.bestpath_compare_routerid {
        v.push((
            "bestpath_compare_routerid".into(),
            cfg.bestpath_compare_routerid.to_string(),
        ));
    }
    if cfg.default_ipv4_unicast != base.default_ipv4_unicast {
        v.push((
            "default_ipv4_unicast".into(),
            cfg.default_ipv4_unicast.to_string(),
        ));
    }
    if cfg.allow_local_as != base.allow_local_as {
        v.push(("allow_local_as".into(), cfg.allow_local_as.to_string()));
    }
    if cfg.soft_reconfig_inbound != base.soft_reconfig_inbound {
        v.push((
            "soft_reconfig_inbound".into(),
            cfg.soft_reconfig_inbound.to_string(),
        ));
    }
    if cfg.exchange_plane != base.exchange_plane {
        v.push(("exchange_plane".into(), cfg.exchange_plane.to_string()));
    }
    if !cfg.exchange_plane_keys.is_empty() {
        v.push((
            "exchange_plane_keys".into(),
            list_value(&cfg.exchange_plane_keys)?,
        ));
    }
    if cfg.graceful_shutdown != base.graceful_shutdown {
        v.push((
            "graceful_shutdown".into(),
            cfg.graceful_shutdown.to_string(),
        ));
    }
    Ok(v)
}

fn rpki_block(cfg: &DaemonConfig) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some(x) = &cfg.rpki.cache {
        v.push(("cache".into(), fmt_string(x)));
    }
    if let Some(x) = cfg.rpki.refresh_interval {
        v.push(("refresh_interval".into(), x.to_string()));
    }
    if let Some(x) = cfg.rpki.retry_interval {
        v.push(("retry_interval".into(), x.to_string()));
    }
    if let Some(x) = cfg.rpki.expire_interval {
        v.push(("expire_interval".into(), x.to_string()));
    }
    v
}

/// One peer (or template) body; `name` rides the block header.
fn peer_block(peer: &crate::daemon_config::PeerSpec) -> Result<Vec<(String, String)>, String> {
    let mut v = Vec::new();
    if let Some(x) = &peer.remote {
        v.push(("remote".into(), fmt_string(x)));
    }
    if let Some(x) = &peer.address {
        v.push(("address".into(), fmt_string(x)));
    }
    if peer.peer_as != 0 {
        v.push(("peer_as".into(), peer.peer_as.to_string()));
    }
    if let Some(x) = &peer.extends {
        v.push(("extends".into(), fmt_string(x)));
    }
    if let Some(x) = &peer.import {
        v.push(("import".into(), fmt_string(x)));
    }
    if let Some(x) = &peer.export {
        v.push(("export".into(), fmt_string(x)));
    }
    if let Some(x) = &peer.import_filter {
        v.push(("import_filter".into(), fmt_string(x)));
    }
    if let Some(x) = &peer.export_filter {
        v.push(("export_filter".into(), fmt_string(x)));
    }
    if let Some(x) = peer.hold_time {
        v.push(("hold_time".into(), x.to_string()));
    }
    if let Some(x) = peer.gr_restart_time {
        v.push(("graceful_restart_time".into(), x.to_string()));
    }
    if let Some(x) = peer.llgr_stale_time {
        v.push(("llgr_stale_time".into(), x.to_string()));
    }
    if let Some(x) = peer.llgr_max_stale_time {
        v.push(("llgr_max_stale_time".into(), x.to_string()));
    }
    if let Some(x) = &peer.local_address {
        v.push(("local_address".into(), fmt_string(x)));
    }
    if let Some(x) = &peer.local_address_v6 {
        v.push(("local_address_v6".into(), fmt_string(x)));
    }
    if let Some(x) = &peer.md5_key {
        v.push(("md5_key".into(), fmt_string(x)));
    }
    if let Some(x) = &peer.tcp_ao_keys {
        if !x.is_empty() {
            v.push(("tcp_ao_keys".into(), list_value(x)?));
        }
    }
    if let Some(x) = &peer.tcp_ao_algorithm {
        v.push(("tcp_ao_algorithm".into(), fmt_string(x)));
    }
    if let Some(x) = peer.tcp_ao_maclen {
        v.push(("tcp_ao_maclen".into(), x.to_string()));
    }
    if let Some(x) = peer.add_path {
        v.push(("add_path".into(), x.to_string()));
    }
    if let Some(x) = peer.add_path_max_paths {
        v.push(("add_path_max_paths".into(), x.to_string()));
    }
    if let Some(x) = &peer.mp_families {
        if !x.is_empty() {
            v.push(("mp_families".into(), list_value(x)?));
        }
    }
    if let Some(x) = peer.default_ipv4_unicast {
        v.push(("default_ipv4_unicast".into(), x.to_string()));
    }
    if let Some(x) = peer.allow_local_as {
        v.push(("allow_local_as".into(), x.to_string()));
    }
    if let Some(x) = peer.soft_reconfig_inbound {
        v.push(("soft_reconfig_inbound".into(), x.to_string()));
    }
    if let Some(x) = peer.extended_next_hop {
        v.push(("extended_next_hop".into(), x.to_string()));
    }
    if let Some(x) = peer.gtsm_hops {
        v.push(("gtsm".into(), x.to_string()));
    }
    if let Some(x) = peer.max_prefixes {
        v.push(("max_prefixes".into(), x.to_string()));
    }
    if let Some(x) = &peer.max_prefix_action {
        v.push(("max_prefix_action".into(), fmt_string(x)));
    }
    if let Some(x) = peer.max_prefix_threshold {
        v.push(("max_prefix_threshold".into(), x.to_string()));
    }
    if let Some(x) = peer.bfd {
        v.push(("bfd".into(), x.to_string()));
    }
    if let Some(x) = peer.bfd_multihop {
        v.push(("bfd_multihop".into(), x.to_string()));
    }
    if let Some(x) = peer.exchange_plane {
        v.push(("exchange_plane".into(), x.to_string()));
    }
    if let Some(x) = peer.graceful_shutdown {
        v.push(("graceful_shutdown".into(), x.to_string()));
    }
    Ok(v)
}

fn ospf_block(cfg: &DaemonConfig, base: &DaemonConfig) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if cfg.ospf_version != base.ospf_version {
        v.push(("version".into(), fmt_string(&cfg.ospf_version)));
    }
    if cfg.ospf_area != base.ospf_area {
        v.push(("area".into(), cfg.ospf_area.to_string()));
    }
    if cfg.ospf_hello_interval != base.ospf_hello_interval {
        v.push(("hello_interval".into(), cfg.ospf_hello_interval.to_string()));
    }
    if cfg.ospf_dead_interval != base.ospf_dead_interval {
        v.push(("dead_interval".into(), cfg.ospf_dead_interval.to_string()));
    }
    if cfg.ospf_graceful_restart != base.ospf_graceful_restart {
        v.push((
            "graceful_restart".into(),
            cfg.ospf_graceful_restart.to_string(),
        ));
    }
    if cfg.ospf_grace_period != base.ospf_grace_period {
        v.push(("grace_period".into(), cfg.ospf_grace_period.to_string()));
    }
    if cfg.ospf_gr_helper != base.ospf_gr_helper {
        v.push((
            "graceful_restart_helper".into(),
            cfg.ospf_gr_helper.to_string(),
        ));
    }
    if cfg.ospf_helper_grace_cap != base.ospf_helper_grace_cap {
        v.push((
            "helper_grace_cap".into(),
            cfg.ospf_helper_grace_cap.to_string(),
        ));
    }
    if let Some(x) = &cfg.ospf_gr_state_file {
        v.push(("gr_state_file".into(), fmt_string(x)));
    }
    if cfg.ospf_sr_receive != base.ospf_sr_receive {
        v.push(("sr_receive".into(), cfg.ospf_sr_receive.to_string()));
    }
    if cfg.ospf_srv6_receive != base.ospf_srv6_receive {
        v.push(("srv6_receive".into(), cfg.ospf_srv6_receive.to_string()));
    }
    if cfg.ospf_srv6_o_flag != base.ospf_srv6_o_flag {
        v.push(("srv6_o_flag".into(), cfg.ospf_srv6_o_flag.to_string()));
    }
    if cfg.ospf_extended_lsas != base.ospf_extended_lsas {
        v.push(("extended_lsas".into(), cfg.ospf_extended_lsas.to_string()));
    }
    if let Some(x) = cfg.ospf_srgb_base {
        v.push(("srgb_base".into(), x.to_string()));
    }
    if let Some(x) = cfg.ospf_srgb_range {
        v.push(("srgb_range".into(), x.to_string()));
    }
    if let Some(x) = cfg.ospf_srv6_max_sl {
        v.push(("srv6_max_sl".into(), x.to_string()));
    }
    if let Some(x) = cfg.ospf_srv6_max_end_pop {
        v.push(("srv6_max_end_pop".into(), x.to_string()));
    }
    if let Some(x) = cfg.ospf_srv6_max_h_encaps {
        v.push(("srv6_max_h_encaps".into(), x.to_string()));
    }
    if let Some(x) = cfg.ospf_srv6_max_end_d {
        v.push(("srv6_max_end_d".into(), x.to_string()));
    }
    v
}

/// A rendered sub-block: header (name + optional identity) and body.
struct SubBlock {
    name: &'static str,
    identity: Option<String>,
    body: Vec<(String, String)>,
}

fn ospf_sub_blocks(cfg: &DaemonConfig) -> Result<Vec<SubBlock>, String> {
    let mut v = Vec::new();
    for area in &cfg.ospf_areas {
        let mut body = Vec::new();
        if let Some(x) = &area.kind {
            body.push(("type".into(), fmt_string(x)));
        }
        if let Some(x) = area.no_summary {
            body.push(("no_summary".into(), x.to_string()));
        }
        if let Some(x) = area.stub_metric {
            body.push(("stub_metric".into(), x.to_string()));
        }
        v.push(SubBlock {
            name: "area",
            identity: area.id.map(|i| i.to_string()),
            body,
        });
    }
    for iface in &cfg.ospf_interfaces {
        let mut body = Vec::new();
        if let Some(x) = iface.area {
            body.push(("area".into(), x.to_string()));
        }
        if let Some(x) = iface.cost {
            body.push(("cost".into(), x.to_string()));
        }
        if let Some(x) = iface.hello_interval {
            body.push(("hello_interval".into(), x.to_string()));
        }
        if let Some(x) = iface.dead_interval {
            body.push(("dead_interval".into(), x.to_string()));
        }
        if let Some(x) = iface.priority {
            body.push(("priority".into(), x.to_string()));
        }
        if let Some(x) = &iface.network_type {
            body.push(("network_type".into(), fmt_string(x)));
        }
        if let Some(x) = iface.adj_sid {
            body.push(("adj_sid".into(), x.to_string()));
        }
        if let Some(x) = &iface.srv6_end_x {
            body.push(("srv6_end_x".into(), fmt_string(x)));
        }
        if let Some(x) = &iface.srv6_end_x_lan {
            body.push(("srv6_end_x_lan".into(), fmt_string(x)));
        }
        v.push(SubBlock {
            name: "interface",
            identity: iface.name.clone().map(|n| fmt_string(&n)),
            body,
        });
    }
    for psid in &cfg.ospf_prefix_sids {
        let mut body = Vec::new();
        if let Some(x) = psid.sid {
            body.push(("sid".into(), x.to_string()));
        }
        if let Some(x) = psid.node {
            body.push(("node".into(), x.to_string()));
        }
        if let Some(x) = psid.no_php {
            body.push(("no_php".into(), x.to_string()));
        }
        v.push(SubBlock {
            name: "prefix-sid",
            identity: psid.prefix.clone().map(|p| fmt_string(&p)),
            body,
        });
    }
    for ms in &cfg.ospf_mapping_servers {
        let mut body = Vec::new();
        if let Some(x) = ms.sid {
            body.push(("sid".into(), x.to_string()));
        }
        if let Some(x) = ms.range_size {
            body.push(("range_size".into(), x.to_string()));
        }
        if let Some(x) = ms.no_php {
            body.push(("no_php".into(), x.to_string()));
        }
        v.push(SubBlock {
            name: "mapping-server",
            identity: ms.prefix.clone().map(|p| fmt_string(&p)),
            body,
        });
    }
    for loc in &cfg.ospf_srv6_locators {
        let mut body = Vec::new();
        if let Some(x) = loc.algorithm {
            body.push(("algorithm".into(), x.to_string()));
        }
        if let Some(x) = loc.metric {
            body.push(("metric".into(), x.to_string()));
        }
        if let Some(x) = loc.anycast {
            body.push(("anycast".into(), x.to_string()));
        }
        if let Some(x) = &loc.sid {
            body.push(("sid".into(), fmt_string(x)));
        }
        if let Some(x) = loc.behavior {
            body.push(("behavior".into(), x.to_string()));
        }
        if let Some(x) = loc.block_len {
            body.push(("block_len".into(), x.to_string()));
        }
        if let Some(x) = loc.node_len {
            body.push(("node_len".into(), x.to_string()));
        }
        if let Some(x) = loc.function_len {
            body.push(("function_len".into(), x.to_string()));
        }
        if let Some(x) = loc.argument_len {
            body.push(("argument_len".into(), x.to_string()));
        }
        v.push(SubBlock {
            name: "srv6-locator",
            identity: loc.prefix.clone().map(|p| fmt_string(&p)),
            body,
        });
    }
    Ok(v)
}

fn babel_block(cfg: &DaemonConfig, base: &DaemonConfig) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some(x) = &cfg.babel_group {
        v.push(("group".into(), fmt_string(x)));
    }
    if cfg.babel_port != base.babel_port {
        v.push(("port".into(), cfg.babel_port.to_string()));
    }
    if cfg.babel_accept_unauthenticated != base.babel_accept_unauthenticated {
        v.push((
            "accept_unauthenticated".into(),
            cfg.babel_accept_unauthenticated.to_string(),
        ));
    }
    if cfg.babel_split_unicast_multicast != base.babel_split_unicast_multicast {
        v.push((
            "split_unicast_multicast".into(),
            cfg.babel_split_unicast_multicast.to_string(),
        ));
    }
    if cfg.babel_pc_window != base.babel_pc_window {
        v.push(("pc_window".into(), cfg.babel_pc_window.to_string()));
    }
    v
}

fn babel_sub_blocks(cfg: &DaemonConfig) -> Result<Vec<SubBlock>, String> {
    let mut v = Vec::new();
    for key in &cfg.babel_keys {
        let BabelKeySpec {
            secret,
            algorithm,
            interface,
        } = key;
        let mut body = Vec::new();
        if let Some(x) = secret {
            body.push(("secret".into(), fmt_string(x)));
        }
        if let Some(x) = algorithm {
            body.push(("algorithm".into(), fmt_string(x)));
        }
        if let Some(x) = interface {
            body.push(("interface".into(), fmt_string(x)));
        }
        v.push(SubBlock {
            name: "key",
            identity: None,
            body,
        });
    }
    for iface in &cfg.babel_interfaces {
        let mut body = Vec::new();
        if let Some(x) = &iface.kind {
            body.push(("kind".into(), fmt_string(x)));
        }
        if let Some(x) = iface.hello_interval_ms {
            body.push(("hello_interval_ms".into(), x.to_string()));
        }
        if let Some(x) = iface.update_interval_ms {
            body.push(("update_interval_ms".into(), x.to_string()));
        }
        if let Some(x) = iface.rxcost {
            body.push(("rxcost".into(), x.to_string()));
        }
        if let Some(x) = iface.rtt_cost {
            body.push(("rtt_cost".into(), x.to_string()));
        }
        if let Some(x) = iface.rtt_min_us {
            body.push(("rtt_min_us".into(), x.to_string()));
        }
        if let Some(x) = iface.rtt_max_us {
            body.push(("rtt_max_us".into(), x.to_string()));
        }
        if let Some(x) = &iface.next_hop_ipv4 {
            body.push(("next_hop_ipv4".into(), fmt_string(x)));
        }
        if let Some(x) = &iface.next_hop_ipv6 {
            body.push(("next_hop_ipv6".into(), fmt_string(x)));
        }
        if let Some(x) = iface.extended_next_hop {
            body.push(("extended_next_hop".into(), x.to_string()));
        }
        if let Some(x) = iface.check_link {
            body.push(("check_link".into(), x.to_string()));
        }
        if let Some(x) = iface.port {
            body.push(("port".into(), x.to_string()));
        }
        if let Some(x) = &iface.group {
            body.push(("group".into(), fmt_string(x)));
        }
        v.push(SubBlock {
            name: "interface",
            identity: iface.name.clone().map(|n| fmt_string(&n)),
            body,
        });
    }
    Ok(v)
}

fn ldp_block(cfg: &DaemonConfig, base: &DaemonConfig) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some(x) = &cfg.ldp_transport {
        v.push(("transport".into(), fmt_string(x)));
    }
    if let Some(x) = &cfg.ldp_transport_v6 {
        v.push(("transport_v6".into(), fmt_string(x)));
    }
    if cfg.ldp_prefer_ipv6 != base.ldp_prefer_ipv6 {
        v.push(("prefer_ipv6".into(), cfg.ldp_prefer_ipv6.to_string()));
    }
    if cfg.ldp_install_kernel != base.ldp_install_kernel {
        v.push(("install_kernel".into(), cfg.ldp_install_kernel.to_string()));
    }
    if cfg.ldp_label_min != base.ldp_label_min {
        v.push(("label_min".into(), cfg.ldp_label_min.to_string()));
    }
    if cfg.ldp_label_max != base.ldp_label_max {
        v.push(("label_max".into(), cfg.ldp_label_max.to_string()));
    }
    if cfg.ldp_transit_allocation != base.ldp_transit_allocation {
        v.push((
            "transit_allocation".into(),
            cfg.ldp_transit_allocation.to_string(),
        ));
    }
    if cfg.ldp_graceful_restart != base.ldp_graceful_restart {
        v.push((
            "graceful_restart".into(),
            cfg.ldp_graceful_restart.to_string(),
        ));
    }
    if cfg.ldp_gr_reconnect_ms != base.ldp_gr_reconnect_ms {
        v.push((
            "gr_reconnect_ms".into(),
            cfg.ldp_gr_reconnect_ms.to_string(),
        ));
    }
    if cfg.ldp_gr_recovery_ms != base.ldp_gr_recovery_ms {
        v.push(("gr_recovery_ms".into(), cfg.ldp_gr_recovery_ms.to_string()));
    }
    if cfg.ldp_port != base.ldp_port {
        v.push(("port".into(), cfg.ldp_port.to_string()));
    }
    if cfg.ldp_keepalive_time != base.ldp_keepalive_time {
        v.push(("keepalive_time".into(), cfg.ldp_keepalive_time.to_string()));
    }
    if cfg.ldp_link_hold != base.ldp_link_hold {
        v.push(("link_hold_time".into(), cfg.ldp_link_hold.to_string()));
    }
    if cfg.ldp_targeted_hold != base.ldp_targeted_hold {
        v.push((
            "targeted_hold_time".into(),
            cfg.ldp_targeted_hold.to_string(),
        ));
    }
    if cfg.ldp_loop_detection != base.ldp_loop_detection {
        v.push(("loop_detection".into(), cfg.ldp_loop_detection.to_string()));
    }
    if cfg.ldp_loop_hc_limit != base.ldp_loop_hc_limit {
        v.push((
            "loop_hop_count_limit".into(),
            cfg.ldp_loop_hc_limit.to_string(),
        ));
    }
    if cfg.ldp_loop_pv_limit != base.ldp_loop_pv_limit {
        v.push((
            "loop_path_vector_limit".into(),
            cfg.ldp_loop_pv_limit.to_string(),
        ));
    }
    v
}

fn ldp_sub_blocks(cfg: &DaemonConfig) -> Vec<SubBlock> {
    let mut v = Vec::new();
    for iface in &cfg.ldp_interfaces {
        v.push(SubBlock {
            name: "interface",
            identity: iface.name.clone().map(|n| fmt_string(&n)),
            body: Vec::new(),
        });
    }
    for t in &cfg.ldp_targeted {
        v.push(SubBlock {
            name: "targeted",
            identity: t.address.clone().map(|a| fmt_string(&a)),
            body: Vec::new(),
        });
    }
    for b in &cfg.ldp_binds {
        v.push(SubBlock {
            name: "bind",
            identity: b.prefix.clone().map(|p| fmt_string(&p)),
            body: vec![("label".into(), b.label.to_string())],
        });
    }
    v
}

/// The damping block, or `None` when nothing is set.
fn damping_block(cfg: &DaemonConfig, base: &DaemonConfig) -> Option<Vec<(String, String)>> {
    let d: &DampingSpec = &cfg.damping;
    let b: &DampingSpec = &base.damping;
    let mut v = Vec::new();
    if d.enabled != b.enabled {
        v.push(("enabled".into(), d.enabled.to_string()));
    }
    if d.config.additive_incr != b.config.additive_incr {
        v.push(("additive_incr".into(), d.config.additive_incr.to_string()));
    }
    if d.config.suppress_threshold != b.config.suppress_threshold {
        v.push((
            "suppress_threshold".into(),
            d.config.suppress_threshold.to_string(),
        ));
    }
    if d.config.reuse_threshold != b.config.reuse_threshold {
        v.push((
            "reuse_threshold".into(),
            d.config.reuse_threshold.to_string(),
        ));
    }
    if d.config.upper_limit != b.config.upper_limit {
        v.push(("upper_limit".into(), d.config.upper_limit.to_string()));
    }
    if d.config.decay_interval_s != b.config.decay_interval_s {
        v.push((
            "decay_interval_s".into(),
            d.config.decay_interval_s.to_string(),
        ));
    }
    if d.config.decay_factor_active != b.config.decay_factor_active {
        v.push((
            "decay_factor_active".into(),
            fmt_float(d.config.decay_factor_active),
        ));
    }
    if d.config.decay_factor_withdrawn != b.config.decay_factor_withdrawn {
        v.push((
            "decay_factor_withdrawn".into(),
            fmt_float(d.config.decay_factor_withdrawn),
        ));
    }
    (!v.is_empty()).then_some(v)
}

// ---------------------------------------------------------------------------
// Value formatting
// ---------------------------------------------------------------------------

/// Format a string value: a bare word when it re-lexes as a single
/// ident, otherwise a quoted, escaped string. Bare-safe excludes
/// `true`/`false` (they would lex as booleans) and anything starting
/// with a digit (numbers, addresses — quoted for clarity).
fn fmt_string(s: &str) -> String {
    fn bare_safe(s: &str) -> bool {
        let mut chars = s.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        if s == "true" || s == "false" {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':'))
    }
    if bare_safe(s) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Format a float so it re-parses to the identical value: `{:?}`
/// produces the shortest round-trip representation.
fn fmt_float(f: f64) -> String {
    let s = format!("{f:?}");
    s
}

/// Render a string array in the TOML-channel form the shared dispatch
/// expects. Elements that the channel cannot round-trip (embedded
/// commas, quotes, backslashes, surrounding whitespace) fail loudly —
/// the converter never emits a list that would parse back differently.
fn list_value(items: &[String]) -> Result<String, String> {
    for item in items {
        if item.is_empty()
            || item.contains(',')
            || item.contains('"')
            || item.contains('\\')
            || item.trim() != item
        {
            return Err(format!(
                "refusing to convert: list element {item:?} cannot round-trip through \
                 the config's array channel (commas, quotes, backslashes and \
                 leading/trailing whitespace are not representable)"
            ));
        }
    }
    Ok(format!(
        "[{}]",
        items
            .iter()
            .map(|i| fmt_string(i))
            .collect::<Vec<_>>()
            .join(",")
    ))
}

// ---------------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Emitter {
    out: String,
    indent: usize,
}

impl Emitter {
    fn kv(&mut self, indent: usize, key: &str, value: &str) {
        self.out.push_str(&"    ".repeat(indent));
        self.out.push_str(key);
        self.out.push(' ');
        self.out.push_str(value);
        self.out.push_str(";\n");
    }

    fn open(&mut self, indent: usize, name: &str, identity: Option<&str>) {
        self.indent = indent;
        self.out.push_str(&"    ".repeat(indent));
        self.out.push_str(name);
        if let Some(id) = identity {
            self.out.push(' ');
            self.out.push_str(id);
        }
        self.out.push_str(" {\n");
    }

    fn close(&mut self, indent: usize) {
        self.out.push_str(&"    ".repeat(indent));
        self.out.push_str("}\n");
    }

    /// Append pre-rendered sub-blocks (nested inside the current one).
    fn blocks(&mut self, subs: &[SubBlock]) {
        for sub in subs {
            self.open(1, sub.name, sub.identity.as_deref());
            for (key, value) in &sub.body {
                self.kv(2, key, value);
            }
            self.close(1);
        }
    }

    /// `filter [NAME] {BODY}` — the body lands verbatim between the
    /// braces with no extra whitespace, keeping the round-trip byte
    /// exact.
    fn filter_block(&mut self, identity: Option<&str>, body: &str) {
        self.out.push_str("filter");
        if let Some(id) = identity {
            self.out.push(' ');
            self.out.push_str(id);
        }
        self.out.push_str(" {");
        self.out.push_str(body);
        self.out.push_str("}\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_dsl::parse_dsl_text;
    use crate::daemon_config::parse_toml_subset;

    /// The round-trip property: parse TOML, render `.lr`, parse the
    /// `.lr`, compare IRs byte-for-byte (`PartialEq`).
    fn round_trip(toml: &str) -> (DaemonConfig, DaemonConfig) {
        let mut first = DaemonConfig::default();
        parse_toml_subset(toml, &mut first).expect("toml parses");
        let dsl = to_dsl(&first).expect("converts");
        let mut second = DaemonConfig::default();
        parse_dsl_text(&dsl, None, &mut second).expect("dsl parses");
        (first, second)
    }

    #[test]
    fn round_trips_a_multi_protocol_config() {
        let toml = r#"
protocol = "bgp,ospf"
user = "lr"
[bgp]
local_as = 64512
router_id = "10.0.0.1"
hold_time = 30
gtsm = 1
max_prefixes = 5000
networks = ["203.0.113.0/24"]
[[peer]]
name = "core-1"
remote = "192.0.2.2:179"
peer_as = 65010
import_filter = "in"
[[filter]]
name = "in"
body = "if net ~ [10.0.0.0/8+] then accept;\nelse reject;"
[ospf]
hello_interval = 10
[[ospf.interface]]
name = "eth0"
cost = 10
"#;
        let (first, second) = round_trip(toml);
        assert_eq!(first, second);
    }

    #[test]
    fn round_trips_the_shipped_template() {
        let toml = std::fs::read_to_string("../../templates/daemon.toml").expect("template exists");
        let (first, second) = round_trip(&toml);
        assert_eq!(first, second);
    }

    #[test]
    fn refuses_configs_with_parse_warnings() {
        let mut cfg = DaemonConfig::default();
        parse_toml_subset("[mystery]\nx = 1\n", &mut cfg).unwrap();
        let err = to_dsl(&cfg).unwrap_err();
        assert!(err.contains("refusing to convert"), "{err}");
    }

    #[test]
    fn refuses_filters_with_descriptions() {
        let mut cfg = DaemonConfig::default();
        parse_toml_subset(
            "[[filter]]\nname = \"f\"\nbody = \"accept;\"\ndescription = \"why\"\n",
            &mut cfg,
        )
        .unwrap();
        let err = to_dsl(&cfg).unwrap_err();
        assert!(err.contains("description"), "{err}");
    }
}
