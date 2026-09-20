//! Parser and IR lowering for the native `.lr` configuration DSL
//! (ROADMAP-v3 D16 Phase 2, GitHub #18).
//!
//! The parser is a single recursive descent over the token stream of
//! [`crate::config_dsl::lexer`]; there is no intermediate AST. Every
//! `key value;` statement lowers *immediately* into
//! [`crate::daemon_config::apply_config_key`] — the exact dispatch the
//! TOML subset parser drives — so both frontends share one fail-closed
//! key schema and cannot drift. The block table below is the only new
//! vocabulary: DSL block names (kebab-case, optionally nested) map to
//! the dotted section paths the dispatch already knows.

use std::path::{Path, PathBuf};

use super::lexer::{lex, Tok, TokKind, Unit};
use crate::daemon_config::{
    apply_config_key, escape_toml_string, AggregateSpec, BabelInterfaceSpec, BabelKeySpec,
    DaemonConfig, FilterSpec, LdpBindSpec, LdpIfSpec, LdpTargetedSpec, OspfAreaSpec, OspfIfSpec,
    OspfMappingServerSpec, OspfPrefixSidSpec, OspfSrv6LocatorSpec, PeerSpec, RedistributeSpec,
    RoaSpec, StaticRouteSpec,
};
use crate::daemon_policy::{AsPathListSpec, CommunityListSpec, PrefixListSpec, RouteMapSpec};

/// Maximum `include` nesting depth (cycle detection runs too, but a
/// depth bound keeps even a fan-out attack bounded).
const MAX_INCLUDE_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// Block table
// ---------------------------------------------------------------------------

/// What entering a block does to the IR.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Entry {
    /// `[section]` — merge into the single table.
    Single,
    /// `[[section]]` — push a new default spec; `identity` names the
    /// key the block header's argument is sugar for (if any).
    Array { identity: Option<&'static str> },
    /// `[peer-template.<name>]` — the header argument is the template
    /// name itself.
    Template,
    /// `[[filter]]` — identity is the filter name and the body is
    /// captured verbatim between braces.
    Filter,
}

#[derive(Debug, Clone, Copy)]
struct BlockDef {
    /// Dotted section path handed to `apply_config_key`.
    section: &'static str,
    entry: Entry,
}

/// Resolve `(parent block name, block name)` to a block definition.
/// `parent` is `""` at top level. Sub-blocks are only valid inside
/// their parent — the mapping below is the whole grammar, so an
/// unknown or misplaced block name fails closed here.
fn block_def(parent: &str, name: &str) -> Option<BlockDef> {
    let single = |section: &'static str| BlockDef {
        section,
        entry: Entry::Single,
    };
    let array = |section: &'static str, identity: Option<&'static str>| BlockDef {
        section,
        entry: Entry::Array { identity },
    };
    match (parent, name) {
        ("", "bgp") => Some(single("bgp")),
        ("bgp", "rpki") => Some(single("bgp.rpki")),
        ("", "ospf") => Some(single("ospf")),
        ("ospf", "area") => Some(array("ospf.area", Some("id"))),
        ("ospf", "interface") => Some(array("ospf.interface", Some("name"))),
        ("ospf", "prefix-sid") => Some(array("ospf.prefix_sid", Some("prefix"))),
        ("ospf", "mapping-server") => Some(array("ospf.mapping_server", Some("prefix"))),
        ("ospf", "srv6-locator") => Some(array("ospf.srv6_locator", Some("prefix"))),
        ("", "babel") => Some(single("babel")),
        ("babel", "key") => Some(array("babel.key", None)),
        ("babel", "interface") => Some(array("babel.interface", Some("name"))),
        ("", "static") => Some(single("static")),
        ("static", "route") => Some(array("static.route", Some("prefix"))),
        ("", "ldp") => Some(single("ldp")),
        ("ldp", "interface") => Some(array("ldp.interface", Some("name"))),
        ("ldp", "targeted") => Some(array("ldp.targeted", Some("address"))),
        ("ldp", "bind") => Some(array("ldp.bind", Some("prefix"))),
        ("", "damping") => Some(single("damping")),
        ("", "peer") => Some(array("peer", Some("name"))),
        ("", "peer-template") => Some(BlockDef {
            section: "",
            entry: Entry::Template,
        }),
        ("", "prefix-list") => Some(array("prefix-list", Some("name"))),
        ("", "as-path-list") => Some(array("as-path-list", Some("name"))),
        ("", "community-list") => Some(array("community-list", Some("name"))),
        ("", "route-map") => Some(array("route-map", Some("name"))),
        ("", "filter") => Some(BlockDef {
            section: "filter",
            entry: Entry::Filter,
        }),
        ("", "roa") => Some(array("roa", None)),
        ("", "redistribute") => Some(array("redistribute", None)),
        ("", "aggregate") => Some(array("aggregate", None)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Unit suffix whitelist
// ---------------------------------------------------------------------------

/// What physical quantity a key's value carries — decides which unit
/// suffixes are legal and their multipliers.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Scale {
    /// seconds (s ×1, m ×60, h ×3600)
    Secs,
    /// milliseconds (ms ×1, s ×1000)
    Millis,
    /// microseconds (us ×1, ms ×1000)
    Micros,
    /// plain counts (k ×1000, M ×1_000_000)
    Count,
}

/// The (section, key) → scale whitelist. Scoped by section where the
/// same key name carries different units in different sections:
/// `hello_interval` is seconds under OSPF (RFC 2328) but an alias of
/// the millisecond `hello_interval_ms` inside a Babel interface.
fn unit_scale(section: &str, key: &str) -> Option<Scale> {
    match (section, key) {
        ("babel.interface", "hello_interval" | "update_interval") => Some(Scale::Millis),
        ("babel.interface", "rtt_min" | "rtt_max") => Some(Scale::Micros),
        _ => match key {
            "hold_time"
            | "graceful_restart_time"
            | "llgr_stale_time"
            | "llgr_max_stale_time"
            | "grace_period"
            | "helper_grace_cap"
            | "dead_interval"
            | "hello_interval"
            | "keepalive_time"
            | "link_hold_time"
            | "targeted_hold_time"
            | "decay_interval_s" => Some(Scale::Secs),
            "bfd_min_rx_ms" | "bfd_min_tx_ms" | "gr_reconnect_ms" | "gr_recovery_ms"
            | "hello_interval_ms" | "update_interval_ms" => Some(Scale::Millis),
            "max_prefixes" | "add_path_max_paths" | "label_max" | "label_min" => Some(Scale::Count),
            _ => None,
        },
    }
}

/// Expand a suffixed literal (`90s`) into the plain decimal string the
/// shared dispatch expects. A suffix on a key outside the whitelist is
/// a hard error — the DSL never guesses a unit.
fn expand_unit(
    section: &str,
    key: &str,
    digits: &str,
    unit: &Unit,
    where_: &str,
) -> Result<String, String> {
    let scale = unit_scale(section, key).ok_or_else(|| {
        format!(
            "{where_}: key '{key}' does not take a unit suffix \
             (unit suffixes are reserved for duration/scale keys)"
        )
    })?;
    let (mult, expected): (u128, &str) = match (scale, unit) {
        (Scale::Secs, Unit::S) => (1, "s | m | h"),
        (Scale::Secs, Unit::M) => (60, "s | m | h"),
        (Scale::Secs, Unit::H) => (3600, "s | m | h"),
        (Scale::Millis, Unit::Ms) => (1, "ms | s"),
        (Scale::Millis, Unit::S) => (1000, "ms | s"),
        (Scale::Micros, Unit::Us) => (1, "us | ms"),
        (Scale::Micros, Unit::Ms) => (1000, "us | ms"),
        (Scale::Count, Unit::K) => (1000, "k | M"),
        (Scale::Count, Unit::BigM) => (1_000_000, "k | M"),
        (scale, _) => {
            return Err(format!(
                "{where_}: unit not valid for key '{key}' (expected {})",
                match scale {
                    Scale::Secs => "s | m | h",
                    Scale::Millis => "ms | s",
                    Scale::Micros => "us | ms",
                    Scale::Count => "k | M",
                }
            ))
        }
    };
    let _ = expected;
    let base: u128 = digits
        .parse()
        .map_err(|_| format!("{where_}: bad number '{digits}'"))?;
    let value = base
        .checked_mul(mult)
        .ok_or_else(|| format!("{where_}: '{digits}' overflows with the unit multiplier"))?;
    Ok(value.to_string())
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// One file on the include stack: its source text, tokens, cursor and
/// the directory relative includes resolve against.
struct Frame {
    src: String,
    toks: Vec<Tok>,
    pos: usize,
    file_id: usize,
    dir: PathBuf,
}

/// A parsed scalar value, still unlowered.
enum Value {
    /// Quoted string, escapes already processed by the lexer.
    Str(String),
    /// Number / bare-ident raw text.
    Raw(String),
    Bool(bool),
    /// Number with unit suffix.
    Suff(String, Unit),
    /// `[a, b, …]` — string arrays only.
    List(Vec<Value>),
}

impl Value {
    /// The string a scalar renders to, if it has one (lists and
    /// unit-suffixed values need context to lower).
    fn scalar_text(&self) -> Option<&str> {
        match self {
            Value::Str(s) | Value::Raw(s) => Some(s),
            Value::Bool(true) => Some("true"),
            Value::Bool(false) => Some("false"),
            Value::Suff(..) | Value::List(..) => None,
        }
    }
}

pub(super) struct Parser<'a> {
    cfg: &'a mut DaemonConfig,
    frames: Vec<Frame>,
    /// Source display names for diagnostics, indexed by `file_id`.
    files: Vec<String>,
    /// Canonical paths of the active include chain, for cycle
    /// detection (top-level file first).
    chain: Vec<PathBuf>,
    /// Dotted section path stack; the back is what `apply_config_key`
    /// sees. Empty means top level (section `""`).
    sections: Vec<String>,
    /// DSL block-name stack, parallel to `sections`; the back is the
    /// parent a nested block resolves against.
    parents: Vec<String>,
}

/// Entry point: parse `.lr` configuration text and lower it into
/// `cfg`. `source` is `Some((display_name, path_of_file))` for real
/// files (drives include resolution and diagnostics); tests pass
/// `None` for inline snippets (includes resolve against the process
/// working directory).
pub(super) fn parse_dsl_text(
    text: &str,
    source: Option<(&str, &Path)>,
    cfg: &mut DaemonConfig,
) -> Result<(), String> {
    let (name, dir, canonical): (String, PathBuf, Option<PathBuf>) = match source {
        Some((name, path)) => (
            name.to_string(),
            path.parent().unwrap_or(Path::new(".")).to_path_buf(),
            std::fs::canonicalize(path).ok(),
        ),
        None => (
            "inline".to_string(),
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            None,
        ),
    };
    let toks = lex(text).map_err(|e| format!("{name}: {e}"))?;
    let chain = canonical.into_iter().collect();
    let mut parser = Parser {
        cfg,
        frames: vec![Frame {
            src: text.to_string(),
            toks,
            pos: 0,
            file_id: 0,
            dir,
        }],
        files: vec![name],
        chain,
        sections: Vec::new(),
        parents: Vec::new(),
    };
    parser.run()
}

impl<'a> Parser<'a> {
    fn frame(&self) -> &Frame {
        self.frames
            .last()
            .expect("frame stack is never empty while parsing")
    }

    fn frame_mut(&mut self) -> &mut Frame {
        self.frames
            .last_mut()
            .expect("frame stack is never empty while parsing")
    }

    fn peek(&self) -> Option<&Tok> {
        self.frame().toks.get(self.frame().pos)
    }

    fn peek_at(&self, ahead: usize) -> Option<&Tok> {
        self.frame().toks.get(self.frame().pos + ahead)
    }

    fn bump(&mut self) -> Option<Tok> {
        let tok = self.frame().toks.get(self.frame().pos).cloned();
        if tok.is_some() {
            self.frame_mut().pos += 1;
        }
        tok
    }

    /// Diagnostics location of the current cursor.
    fn where_(&self) -> String {
        let frame = self.frame();
        let line = frame.toks.get(frame.pos).map(|t| t.line).unwrap_or(1);
        format!("{}:{}", self.files[frame.file_id], line)
    }

    fn err(&self, msg: impl std::fmt::Display) -> String {
        format!("{}: {msg}", self.where_())
    }

    /// Parse statements until every frame (including includes) is
    /// exhausted. Block context spans frames: an `include` spliced
    /// mid-block continues that block, matching BIRD's textual
    /// include semantics.
    fn run(&mut self) -> Result<(), String> {
        while !self.frames.is_empty() {
            match self.peek() {
                None => {
                    self.frames.pop();
                    self.chain.pop();
                }
                Some(Tok {
                    kind: TokKind::RBrace,
                    ..
                }) => {
                    return Err(self.err("unexpected '}' (no open block)"));
                }
                Some(_) => self.parse_statement()?,
            }
        }
        // parse_block errors on EOF inside a block, so the stacks are
        // empty here by construction; the assert documents it.
        debug_assert!(self.sections.is_empty() && self.parents.is_empty());
        Ok(())
    }

    fn parse_statement(&mut self) -> Result<(), String> {
        let Some(Tok {
            kind: TokKind::Ident(name),
            ..
        }) = self.peek().cloned()
        else {
            return Err(self.err("expected a block or 'key value;' statement"));
        };
        if name == "include" {
            return self.parse_include();
        }
        let parent = self.parents.last().cloned().unwrap_or_default();
        // Block or key statement? Lookahead from the name token:
        // `name {` is a block, `name value {` is a block with
        // identity, anything else a key statement.
        let is_block = match (self.peek_at(1), self.peek_at(2)) {
            (
                Some(Tok {
                    kind: TokKind::LBrace,
                    ..
                }),
                _,
            ) => true,
            (
                Some(t1),
                Some(Tok {
                    kind: TokKind::LBrace,
                    ..
                }),
            ) => matches!(
                t1.kind,
                TokKind::Str(_) | TokKind::Ident(_) | TokKind::Number(_)
            ),
            _ => false,
        };
        if is_block {
            self.parse_block(&parent, &name)
        } else {
            self.parse_key_stmt(&name)
        }
    }

    fn parse_include(&mut self) -> Result<(), String> {
        self.bump(); // the `include` ident
        let path = match self.bump() {
            Some(Tok {
                kind: TokKind::Str(p),
                ..
            }) => p,
            Some(_) => return Err(self.err("include needs a quoted path")),
            None => return Err(self.err("unexpected end of file after 'include'")),
        };
        if !matches!(self.peek().map(|t| &t.kind), Some(TokKind::Semi)) {
            return Err(self.err("expected ';' after include"));
        }
        self.bump(); // the ';'
        if self.frames.len() >= MAX_INCLUDE_DEPTH {
            return Err(self.err(format!("include nesting deeper than {MAX_INCLUDE_DEPTH}")));
        }
        let frame = self.frame();
        let resolved = if Path::new(&path).is_absolute() {
            PathBuf::from(&path)
        } else {
            frame.dir.join(&path)
        };
        let display = resolved.display().to_string();
        let canonical = std::fs::canonicalize(&resolved)
            .map_err(|e| format!("{}: cannot include '{path}': {e}", self.where_()))?;
        if self.chain.contains(&canonical) {
            return Err(self.err(format!("include cycle via '{path}'")));
        }
        let text = std::fs::read_to_string(&resolved)
            .map_err(|e| format!("{}: cannot read include '{path}': {e}", self.where_()))?;
        let toks = lex(&text).map_err(|e| format!("{display}: {e}"))?;
        let file_id = self.files.len();
        self.files.push(display);
        self.chain.push(canonical);
        self.frames.push(Frame {
            src: text,
            toks,
            pos: 0,
            file_id,
            dir: resolved.parent().unwrap_or(Path::new(".")).to_path_buf(),
        });
        Ok(())
    }

    /// Parse `name [identity] { … }` and lower it. The name token is
    /// still under the cursor when called.
    fn parse_block(&mut self, parent: &str, name: &str) -> Result<(), String> {
        let def = block_def(parent, name).ok_or_else(|| {
            if parent.is_empty() {
                self.err(format!(
                    "unknown block '{name}' (see docs/config_dsl_grammar.md for the block list)"
                ))
            } else {
                self.err(format!("'{name}' is not a valid block inside '{parent}'"))
            }
        })?;
        self.bump(); // the block name
                     // Optional identity argument (string, bare word or number).
        let identity: Option<String> = match self.peek().map(|t| &t.kind) {
            Some(TokKind::Str(_) | TokKind::Ident(_) | TokKind::Number(_)) => {
                let v = self.bump().expect("peeked");
                match v.kind {
                    TokKind::Str(s) | TokKind::Ident(s) => Some(s),
                    TokKind::Number(n) => Some(n),
                    _ => unreachable!("identity tokens are matched above"),
                }
            }
            _ => None,
        };
        let open = match self.bump() {
            Some(
                t @ Tok {
                    kind: TokKind::LBrace,
                    ..
                },
            ) => t,
            Some(_) => unreachable!("is_block lookahead guarantees a brace"),
            None => return Err(self.err(format!("unexpected end of file in '{name}' block"))),
        };

        if def.entry == Entry::Filter {
            return self.parse_filter_block(open, identity);
        }

        match def.entry {
            Entry::Single => {
                self.sections.push(def.section.to_string());
            }
            Entry::Template => {
                let Some(tname) = identity.clone() else {
                    return Err(self.err("peer-template needs a name"));
                };
                if tname.is_empty() || tname.contains('.') {
                    return Err(self.err(format!("bad peer-template name '{tname}'")));
                }
                self.cfg.peer_templates.entry(tname.clone()).or_default();
                self.sections.push(format!("peer-template.{tname}"));
            }
            Entry::Array { identity: id_key } => {
                self.enter_array(def.section, name)?;
                self.sections.push(def.section.to_string());
                if let (Some(id_key), Some(value)) = (id_key, identity) {
                    // Identity sugar: `peer "core-1"` behaves exactly
                    // like `name "core-1";` as the first statement.
                    let section = def.section.to_string();
                    self.apply(&section, id_key, &value)?;
                }
            }
            Entry::Filter => unreachable!("handled above"),
        }
        self.parents.push(name.to_string());

        // Statements until the matching close brace. Frame
        // exhaustion inside a block pops back to the includer: an
        // `include` spliced mid-block continues that block, so EOF
        // only ends the block when every frame is gone.
        loop {
            if self.frames.is_empty() {
                let file = self.files.last().cloned().unwrap_or_default();
                return Err(format!(
                    "{file}: unexpected end of file inside '{name}' block (missing '}}')"
                ));
            }
            match self.peek() {
                None => {
                    self.frames.pop();
                    self.chain.pop();
                }
                Some(Tok {
                    kind: TokKind::RBrace,
                    ..
                }) => {
                    self.bump();
                    break;
                }
                Some(_) => self.parse_statement()?,
            }
        }
        self.parents.pop();
        self.sections.pop();
        Ok(())
    }

    /// `filter [NAME] { … }` — the body is the verbatim source text
    /// between the braces. Brace matching rides the token stream
    /// (string- and comment-aware because the lexer already folded
    /// both into their tokens), so filter syntax such as `case`
    /// blocks, prefix ranges, `#` comments and quoted strings needs no
    /// escaping. The body lowers through the same `body` key the TOML
    /// frontend uses, escaped into the TOML string channel that
    /// `apply_config_key` unescapes — escape ∘ unescape is identity,
    /// so the stored body is byte-identical to the source slice.
    fn parse_filter_block(&mut self, open: Tok, identity: Option<String>) -> Result<(), String> {
        let mut depth = 0usize;
        let close_offset = loop {
            match self.peek() {
                Some(Tok {
                    kind: TokKind::LBrace,
                    ..
                }) => {
                    depth += 1;
                    self.bump();
                }
                Some(
                    tok @ Tok {
                        kind: TokKind::RBrace,
                        ..
                    },
                ) if depth == 0 => {
                    let offset = tok.offset;
                    self.bump(); // consume the closing brace
                    break offset;
                }
                Some(Tok {
                    kind: TokKind::RBrace,
                    ..
                }) => {
                    depth -= 1;
                    self.bump();
                }
                Some(_) => {
                    self.bump();
                }
                None => {
                    return Err(format!(
                        "{}: unterminated filter body (missing '}}')",
                        self.files[self.frame().file_id]
                    ));
                }
            }
        };
        let body = self.frame().src[open.offset + 1..close_offset].to_string();
        self.enter_array("filter", "filter")?;
        if let Some(name) = identity {
            self.apply("filter", "name", &name)?;
        }
        self.apply("filter", "body", &escape_toml_string(&body))?;
        Ok(())
    }

    fn enter_array(&mut self, section: &str, block: &str) -> Result<(), String> {
        let cfg = &mut *self.cfg;
        match section {
            "peer" => {
                cfg.peers.push(PeerSpec::default());
                cfg.explicit_peers = true;
            }
            "prefix-list" => cfg.prefix_lists.push(PrefixListSpec::default()),
            "as-path-list" => cfg.as_path_lists.push(AsPathListSpec::default()),
            "community-list" => cfg.community_lists.push(CommunityListSpec::default()),
            "route-map" => cfg.route_maps.push(RouteMapSpec::default()),
            "ospf.area" => cfg.ospf_areas.push(OspfAreaSpec::default()),
            "ospf.interface" => cfg.ospf_interfaces.push(OspfIfSpec::default()),
            "ospf.prefix_sid" => cfg.ospf_prefix_sids.push(OspfPrefixSidSpec::default()),
            "ospf.mapping_server" => cfg
                .ospf_mapping_servers
                .push(OspfMappingServerSpec::default()),
            "ospf.srv6_locator" => cfg.ospf_srv6_locators.push(OspfSrv6LocatorSpec::default()),
            "babel.key" => cfg.babel_keys.push(BabelKeySpec::default()),
            "babel.interface" => cfg.babel_interfaces.push(BabelInterfaceSpec::default()),
            "static.route" => cfg.static_routes.push(StaticRouteSpec::default()),
            "ldp.interface" => cfg.ldp_interfaces.push(LdpIfSpec::default()),
            "ldp.targeted" => cfg.ldp_targeted.push(LdpTargetedSpec::default()),
            "ldp.bind" => cfg.ldp_binds.push(LdpBindSpec::default()),
            "roa" => cfg.roas.push(RoaSpec::default()),
            "filter" => cfg.filters.push(FilterSpec::default()),
            "redistribute" => cfg.redistributes.push(RedistributeSpec::default()),
            "aggregate" => cfg.aggregates.push(AggregateSpec::default()),
            _ => {
                return Err(self.err(format!(
                    "internal: unhandled array section '{section}' for block '{block}'"
                )));
            }
        }
        Ok(())
    }

    fn parse_key_stmt(&mut self, key: &str) -> Result<(), String> {
        self.bump(); // the key ident
        let value = self.parse_value()?;
        if !matches!(self.peek().map(|t| &t.kind), Some(TokKind::Semi)) {
            let shown = value_text(&value);
            return Err(self.err(format!("expected ';' after '{key} {shown}'")));
        }
        self.bump();
        let section = self.sections.last().cloned().unwrap_or_default();
        let lowered = match value {
            Value::Suff(digits, unit) => {
                expand_unit(&section, key, &digits, &unit, &self.where_())?
            }
            other => render_value(&other)
                .ok_or_else(|| self.err("array values must be strings or bare words"))?,
        };
        self.apply(&section, key, &lowered)
    }

    /// Hand one `(section, key, value)` triple to the shared dispatch.
    /// `line` is converted to the 0-based convention
    /// `apply_config_key` reports from.
    fn apply(&mut self, section: &str, key: &str, value: &str) -> Result<(), String> {
        let line = self
            .peek()
            .map(|t| t.line)
            .unwrap_or_else(|| self.frame().toks.last().map(|t| t.line).unwrap_or(1));
        let file = self.files[self.frame().file_id].clone();
        apply_config_key(self.cfg, section, key, value, line.saturating_sub(1))
            .map_err(|e| format!("{file}:{line}: {e}"))
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        let tok = self.bump().ok_or_else(|| self.err("expected a value"))?;
        match tok.kind {
            TokKind::Str(s) => Ok(Value::Str(s)),
            TokKind::Number(n) => Ok(Value::Raw(n)),
            TokKind::Suffixed { digits, unit } => Ok(Value::Suff(digits, unit)),
            TokKind::Bool(b) => Ok(Value::Bool(b)),
            TokKind::Ident(name) => Ok(Value::Raw(name)),
            TokKind::LBracket => self.parse_list(),
            other => Err(self.err(format!("expected a value, found {other:?}"))),
        }
    }

    fn parse_list(&mut self) -> Result<Value, String> {
        let mut items = Vec::new();
        loop {
            match self.peek().map(|t| &t.kind) {
                Some(TokKind::RBracket) => {
                    self.bump();
                    return Ok(Value::List(items));
                }
                None => return Err(self.err("unterminated value list (missing ']')")),
                _ => {}
            }
            let value = self.parse_value()?;
            match value {
                Value::Str(_) | Value::Raw(_) => items.push(value),
                _ => return Err(self.err("array values must be strings or bare words")),
            }
            match self.peek().map(|t| &t.kind) {
                Some(TokKind::Comma) => {
                    self.bump();
                }
                Some(TokKind::RBracket) => {}
                _ => return Err(self.err("expected ',' or ']' in value list")),
            }
        }
    }
}

fn value_text(value: &Value) -> String {
    match value {
        Value::Str(s) => format!("\"{s}\""),
        Value::Raw(s) | Value::Suff(s, _) => s.clone(),
        Value::Bool(true) => "true".into(),
        Value::Bool(false) => "false".into(),
        Value::List(_) => "[...]".into(),
    }
}

/// Render a lowered value into the exact string form the shared
/// dispatch expects (the same shape the TOML subset parser produces
/// after stripping quotes: raw inner text, arrays as TOML array
/// text).
fn render_value(value: &Value) -> Option<String> {
    match value {
        Value::Str(s) => Some(s.clone()),
        Value::Raw(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Suff(..) => None, // expanded by the caller
        Value::List(items) => {
            let mut out = String::from("[");
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                let text = item.scalar_text()?;
                out.push('"');
                out.push_str(&text.replace('\\', "\\\\").replace('"', "\\\""));
                out.push('"');
            }
            out.push(']');
            Some(out)
        }
    }
}
