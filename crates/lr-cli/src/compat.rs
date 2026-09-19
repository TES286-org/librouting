//! Native BIRD / FRR configuration loading — the W5.4 compat surface.
//!
//! `lr-daemon --config bird.conf` (or an FRR file) parses the source
//! dialect directly and runs the daemon in the *compatible form*: the
//! source implementation's semantics (accept-all eBGP policy, FRR's
//! enforce-first-as default, BIRD channel families) apply without the
//! operator writing lr TOML. Internally the same parse/render pipeline
//! as `lr-daemon translate` feeds the rendered TOML into the daemon's
//! regular loader, so compat mode and the converter can never drift
//! apart — there is exactly one mapping.
//!
//! lr-specific extensions ride the `lr:` comment directives (see
//! `translate::LrDirective`): invisible to real BIRD / FRR, so a
//! config carrying them still loads in the reference implementations.
//!
//! Detection: [`detect_dialect`] recognises BIRD 2 (`router id`,
//! `protocol …` stanzas), FRR (`router bgp`, `hostname`, `!`
//! comments, `neighbor … remote-as`) and lr TOML (`[bgp]`,
//! `[[peer]]`, `key = value`). An unrecognised file fails closed —
//! `--config-dialect bird|frr|toml` forces an interpretation.

use crate::daemon_config::DaemonConfig;

/// The configuration dialects the daemon loader understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dialect {
    /// lr daemon TOML (the native schema).
    Toml,
    /// The native `.lr` DSL (ROADMAP-v3 D16 Phase 2).
    Lr,
    /// BIRD 2 configuration (BGP control plane).
    Bird,
    /// FRR (bgpd) configuration (BGP control plane).
    Frr,
}

impl Dialect {
    /// Parse a `--config-dialect` value.
    pub(super) fn from_flag(value: &str) -> Result<Dialect, String> {
        match value {
            "toml" => Ok(Dialect::Toml),
            "lr" => Ok(Dialect::Lr),
            "bird" => Ok(Dialect::Bird),
            "frr" => Ok(Dialect::Frr),
            other => Err(format!(
                "bad --config-dialect '{other}' (expected lr | toml | bird | frr)"
            )),
        }
    }

    /// Name used in warnings and `status` output.
    pub(super) fn name(self) -> &'static str {
        match self {
            Dialect::Toml => "toml",
            Dialect::Lr => "lr",
            Dialect::Bird => "bird",
            Dialect::Frr => "frr",
        }
    }
}

/// Recognise the dialect of a configuration file's content. Returns
/// `None` when no marker matches (the caller fails closed with a
/// pointer to `--config-dialect`).
///
/// The heuristics key on lines only the respective dialect uses:
/// - FRR: `router <proto>` / `hostname` / `address-family` /
///   `neighbor ADDR remote-as` / `!` comment lines (`frr version`,
///   `log …` shapes ride along under the strong markers).
/// - BIRD: `router id` / `protocol <kind>` stanzas / `filter` /
///   `function` definitions.
/// - TOML: lr's own section headers (`[bgp]`, `[[peer]]`, …) and
///   `key = value` assignments.
pub(super) fn detect_dialect(text: &str) -> Option<Dialect> {
    let mut toml_assignments = 0usize;
    // The lr DSL pre-pass: block headers only the native dialect
    // uses (`bgp {`, `peer "x" {`, `ospf {`, …). `filter` is
    // deliberately absent — BIRD files open filter blocks the same
    // way, so `filter f { … }` alone stays with the BIRD heuristic
    // and filter-only `.lr` files need `--config-dialect lr`.
    for raw in text.lines() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if lr_block_header(line) {
            return Some(Dialect::Lr);
        }
        // lr includes usually carry the `.lr` extension; BIRD
        // `include` markers keep their existing meaning otherwise.
        if line.starts_with("include") && line.contains(".lr") {
            return Some(Dialect::Lr);
        }
    }
    for raw in text.lines() {
        let line = raw.trim_start();
        if line.is_empty() {
            continue;
        }
        // FRR `!` comment separator — no other dialect uses a
        // bare `!` line.
        if line.starts_with('!') {
            return Some(Dialect::Frr);
        }
        let mut tokens = line.split_whitespace();
        let t0 = tokens.next().unwrap_or("");
        let t1 = tokens.next().unwrap_or("");
        match (t0, t1) {
            // FRR: router contexts, vtysh furniture, the
            // `neighbor ADDR remote-as` shape.
            ("router", "bgp")
            | ("router", "ospf")
            | ("router", "isis")
            | ("router", "babel")
            | ("router", "static")
            | ("router", "rip") => return Some(Dialect::Frr),
            ("hostname", _) | ("address-family", _) | ("frr", _) => return Some(Dialect::Frr),
            ("neighbor", _) => {
                if line.contains(" remote-as ") {
                    return Some(Dialect::Frr);
                }
            }
            // BIRD: the router id statement, protocol stanzas and
            // filter/function/define definitions.
            ("router", "id") => return Some(Dialect::Bird),
            ("protocol", _) | ("filter", _) | ("function", _) | ("define", _) | ("include", _) => {
                return Some(Dialect::Bird)
            }
            _ => {}
        }
        // TOML shapes: section headers and assignments (BIRD/FRR
        // comments excluded).
        if (line.starts_with('[') && line.ends_with(']'))
            || (line.contains('=') && !line.starts_with('#'))
        {
            toml_assignments += 1;
        }
    }
    if toml_assignments > 0 {
        return Some(Dialect::Toml);
    }
    None
}

/// Recognise an lr-DSL block header line: an lr-exclusive block name
/// followed by `{`, a quoted identity or a bare identity — never `=`,
/// so TOML assignments like `peer = "x"` cannot false-positive.
fn lr_block_header(line: &str) -> bool {
    let word: &str = line
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .next()
        .unwrap_or("");
    let strong = matches!(
        word,
        "bgp"
            | "ospf"
            | "babel"
            | "ldp"
            | "damping"
            | "peer"
            | "peer-template"
            | "prefix-list"
            | "as-path-list"
            | "community-list"
            | "route-map"
            | "roa"
            | "redistribute"
            | "aggregate"
    );
    if !strong {
        return false;
    }
    let rest = line[word.len()..].trim_start();
    // `{` opens a bare block; `"` opens an identity argument. An `=`
    // means this is a TOML assignment (`peer = "x"`) — not ours.
    rest.starts_with('{') || rest.starts_with('"')
}

/// Load a native BIRD/FRR config: parse the dialect, render daemon
/// TOML through the shared converter, and return the TOML text plus
/// the operator-facing warnings (ignored non-BGP protocols, unmapped
/// constructs). The returned TOML is exactly what
/// `lr-daemon translate <dialect>` prints — feeding it through the
/// regular TOML loader keeps compat mode on the round-trip-tested
/// path.
pub(super) fn load_native(dialect: Dialect, text: &str) -> Result<(String, Vec<String>), String> {
    let out = match dialect {
        Dialect::Bird => crate::translate::parse_bird_config(text),
        Dialect::Frr => crate::translate::parse_frr_config(text),
        Dialect::Toml | Dialect::Lr => {
            return Err("load_native is only for the bird/frr dialects".into())
        }
    };
    let mut warnings: Vec<String> = out
        .ignored_protocols
        .iter()
        .map(|p| format!("{p}: ignored — the compat surface runs the BGP control plane only"))
        .collect();
    let toml = crate::translate::render_config(out);
    // In converter mode the UNMAPPED comments are the report the
    // operator reviews; in native-run mode there is no TOML file to
    // read, so every note becomes a startup warning instead.
    for line in toml.lines() {
        if let Some(note) = line.trim().strip_prefix("# UNMAPPED: ") {
            warnings.push(format!("unmapped: {note}"));
        }
    }
    if dialect == Dialect::Frr {
        warnings.push(
            "frr dialect defaults applied: enforce-first-as on, accept-all eBGP policy".to_string(),
        );
    } else {
        warnings.push("bird dialect defaults applied: accept-all eBGP policy".to_string());
    }
    Ok((toml, warnings))
}

/// Load `--config` content in whatever dialect it turns out to be:
/// explicit override first (`--config-dialect`), else detection, else
/// fail closed. Feeds the rendered TOML through
/// `parse_toml_subset` so every compat-mode config follows the same
/// parse path as a native one.
///
/// `source` carries the file's display name and path when the config
/// was read from disk — the native `.lr` dialect needs the path to
/// resolve `include` directives; inline text (tests) passes `None`.
pub(super) fn load_config_text(
    text: &str,
    forced: Option<Dialect>,
    source: Option<(&str, &std::path::Path)>,
    cfg: &mut DaemonConfig,
) -> Result<(), String> {
    let dialect = match forced {
        Some(d) => d,
        None => detect_dialect(text).ok_or_else(|| {
            "cannot recognise the config dialect (expected lr TOML, the .lr DSL, BIRD 2 or FRR); \
             force one with --config-dialect lr|toml|bird|frr"
                .to_string()
        })?,
    };
    if dialect == Dialect::Lr {
        return crate::config_dsl::parse_dsl_text(text, source, cfg);
    }
    if dialect == Dialect::Toml {
        crate::daemon_config::parse_toml_subset(text, cfg)?;
        return Ok(());
    }
    let (toml, warnings) = load_native(dialect, text)?;
    for w in &warnings {
        cfg.warnings.push(w.clone());
    }
    crate::daemon_config::parse_toml_subset(&toml, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bird() {
        let text = "router id 10.0.0.1;\nprotocol device {}\n";
        assert_eq!(detect_dialect(text), Some(Dialect::Bird));
    }

    #[test]
    fn detects_bird_by_protocol_stanza() {
        let text = "protocol bgp uplink {\n    local as 64512;\n}\n";
        assert_eq!(detect_dialect(text), Some(Dialect::Bird));
    }

    #[test]
    fn detects_frr() {
        let text =
            "frr version 10.3\n!\nrouter bgp 64512\n neighbor 192.0.2.2 remote-as 64513\n!\n";
        assert_eq!(detect_dialect(text), Some(Dialect::Frr));
    }

    #[test]
    fn detects_frr_by_hostname() {
        let text = "hostname r1\n!\n";
        assert_eq!(detect_dialect(text), Some(Dialect::Frr));
    }

    #[test]
    fn detects_frr_by_neighbor_remote_as() {
        let text = "neighbor 192.0.2.2 remote-as 64513\n";
        assert_eq!(detect_dialect(text), Some(Dialect::Frr));
    }

    #[test]
    fn detects_toml() {
        let text = "[bgp]\nlocal_as = 64512\nrouter_id = \"10.0.0.1\"\n";
        assert_eq!(detect_dialect(text), Some(Dialect::Toml));
    }

    #[test]
    fn detects_toml_peer_tables() {
        let text = "[[peer]]\nremote = \"192.0.2.2:179\"\npeer_as = 64513\n";
        assert_eq!(detect_dialect(text), Some(Dialect::Toml));
    }

    #[test]
    fn unknown_content_fails_closed() {
        assert_eq!(detect_dialect("hello world\n"), None);
        assert_eq!(detect_dialect(""), None);
    }

    #[test]
    fn bird_comments_do_not_trigger_frr() {
        // A BIRD file full of `#` comments must not detect as TOML
        // (assignments) or anything else.
        let text = "# librouting test config\n# just comments\n";
        assert_eq!(detect_dialect(text), None);
    }

    #[test]
    fn native_bird_config_loads_into_daemon_config() {
        let text = r#"
router id 10.0.0.1;

protocol bgp uplink {
    local as 64512;
    neighbor 192.0.2.2 as 64513;
    ipv4 { import all; export all; };
    # lr: max-prefixes 5000
}

# lr: listen 127.0.0.1:1179
# lr: install-kernel
"#;
        let mut cfg = DaemonConfig::with_defaults();
        load_config_text(text, Some(Dialect::Bird), None, &mut cfg).expect("compat load");
        cfg.finalize().expect("finalize");
        assert_eq!(cfg.router_id, "10.0.0.1");
        assert_eq!(cfg.local_as, 64512);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].peer_as, 64513);
        assert_eq!(cfg.peers[0].max_prefixes, Some(5000));
        assert_eq!(cfg.listen_addr.as_deref(), Some("127.0.0.1:1179"));
        assert!(cfg.install_kernel);
        // Dialect default: accept-all eBGP policy.
        assert_eq!(cfg.ebgp_policy, "accept-all");
        // BIRD has no enforce-first-as concept: stays off.
        assert!(!cfg.enforce_first_as);
    }

    #[test]
    fn native_frr_config_loads_with_frr_defaults() {
        let text = "frr version 10.3\n\
                   !\n\
                    router bgp 64512\n\
                     bgp router-id 10.0.0.2\n\
                     neighbor 192.0.2.2 remote-as 64513\n\
                     neighbor 192.0.2.2 password 0 s3cret\n\
                    !\n\
                    # lr: neighbor 192.0.2.2 add-path\n";
        let mut cfg = DaemonConfig::with_defaults();
        load_config_text(text, Some(Dialect::Frr), None, &mut cfg).expect("compat load");
        cfg.finalize().expect("finalize");
        assert_eq!(cfg.local_as, 64512);
        assert_eq!(cfg.router_id, "10.0.0.2");
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].peer_as, 64513);
        assert_eq!(cfg.peers[0].md5_key.as_deref(), Some("s3cret"));
        assert_eq!(cfg.peers[0].add_path, Some(true));
        // FRR dialect defaults: enforce-first-as ON (FRR's documented
        // default), accept-all eBGP policy.
        assert!(cfg.enforce_first_as);
        assert_eq!(cfg.ebgp_policy, "accept-all");
    }

    #[test]
    fn native_frr_global_directives_apply() {
        let text = "router bgp 64512\n\
                     neighbor 192.0.2.2 remote-as 64513\n\
                     ! lr: api-socket /tmp/lr-api.sock\n\
                     # lr: graceful-restart 300\n\
                     ! lr: user nobody\n";
        let mut cfg = DaemonConfig::with_defaults();
        load_config_text(text, Some(Dialect::Frr), None, &mut cfg).expect("compat load");
        assert_eq!(cfg.api_socket.as_deref(), Some("/tmp/lr-api.sock"));
        assert_eq!(cfg.gr_restart_time, 300);
        assert_eq!(cfg.user.as_deref(), Some("nobody"));
    }

    #[test]
    fn non_bgp_protocols_surface_as_warnings() {
        let text = "router id 10.0.0.1\n\
                    protocol ospf my_ospf {\n\
                        area 0 { interface \"eth0\"; }\n\
                    }\n\
                    protocol bgp p1 {\n\
                        local as 64512;\n\
                        neighbor 192.0.2.2 as 64513;\n\
                    }\n";
        let mut cfg = DaemonConfig::with_defaults();
        load_config_text(text, Some(Dialect::Bird), None, &mut cfg).expect("compat load");
        assert!(cfg
            .warnings
            .iter()
            .any(|w| w.starts_with("protocol ospf my_ospf: ignored")));
    }

    #[test]
    fn unknown_directives_are_reported_not_applied() {
        let text = "router bgp 64512\n\
                     neighbor 192.0.2.2 remote-as 64513\n\
                     # lr: warp-drive enabled\n";
        let mut cfg = DaemonConfig::with_defaults();
        load_config_text(text, Some(Dialect::Frr), None, &mut cfg).expect("compat load");
        // The unknown directive must appear in the warnings.
        assert!(cfg
            .warnings
            .iter()
            .any(|w| w.contains("unknown") && w.contains("warp_drive")));
    }

    #[test]
    fn forced_toml_dialect_skips_detection() {
        let mut cfg = DaemonConfig::with_defaults();
        // Not valid BIRD/FRR either — forcing toml makes it parse as
        // TOML (which errors on the garbage) rather than fail on
        // detection.
        let err = load_config_text("plainly not a config", Some(Dialect::Toml), None, &mut cfg);
        assert!(err.is_err());
    }

    #[test]
    fn frr_translate_and_compat_produce_identical_toml() {
        // Compat mode must ride the exact converter output — no
        // second mapping to drift.
        let text = "router bgp 64512\n\
                     bgp router-id 10.0.0.2\n\
                     neighbor 192.0.2.2 remote-as 64513\n\
                     neighbor 192.0.2.2 update-source 10.9.9.9\n";
        let (toml, _) = load_native(Dialect::Frr, text).expect("load_native");
        let converted = crate::translate::render_config(crate::translate::parse_frr_config(text));
        assert_eq!(toml, converted);
    }
}
