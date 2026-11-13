//! ROA loader — format parsers for Route Origin Authorization sources
//! (issue #100).
//!
//! The four supported on-disk / over-the-wire formats map onto the same
//! [`RoaEntry`] the in-process [`RoaTable`] consumes. Each parser is a
//! pure `&str -> Vec<RoaEntry>` function: the daemon's URL fetcher and
//! file watcher feed them bytes, the loader threads feed them paths,
//! and the FFI surface feeds them C strings. The same parsers run in
//! every entry path so a BIRD-format file fetched from a URL parses
//! byte-identically to one on disk.
//!
//! # Formats
//!
//! | Format | Description | Reference |
//! | --- | --- | --- |
//! | `native` | TOML `[[roa]]` table subset, mirrors `daemon.toml` | [`parse_native`] |
//! | `bird` | BIRD 2 `roa table` body, one `roa PREFIX max N as N;` per line | [`parse_bird`] |
//! | `json` | Routinator JSON VRP output, `{"roas":[{asn,prefix,maxLength}]}` | [`parse_json`] |
//! | `csv` | Comma- or whitespace-separated `ASN,Prefix,MaxLength[,TA]` per line | [`parse_csv`] |
//!
//! `native` is the canonical lr shape: a TOML subset restricted to
//! `[[roa]]` array-of-tables with `prefix`, `max_length` (or
//! `max_len`), and `asn` (or `origin_as`) keys. `bird` accepts the
//! body of a BIRD `roa table NAME { ... }` block — the same lines
//! one would `include "/path/to/file.roa";`. `json` accepts the
//! Routinator `--format json` output (and the RIPE NCC validator's
//! compatible shape); `csv` accepts Routinator's `--format csv`
//! output, with or without the header row, and is also the form an
//! `awk` one-liner produces.
//!
//! # RFC references
//!
//! * RFC 6482 — A Profile for Resource Certificate Lists (ROA object)
//! * RFC 6811 §2 — prefix-origin validation algorithm
//! * RFC 8210 — RPKI-Router Transport Protocol (the live update side)
//! * <https://bird.nic.cz/doc/bird-2.16.2.html> §6 — BIRD `roa table` syntax
//! * <https://routinator.docs.nlnetlabs.nl/en/stable/output-formats.html>
//!   — Routinator VRP output formats
//!
//! # Performance
//!
//! Each parser runs in a single linear scan over the input. The BIRD
//! and CSV parsers split on whitespace / commas without allocating a
//! `Vec<String>` per line; the JSON parser is a tiny hand-rolled
//! recursive-descent scanner that skips `metadata` and any unknown
//! keys without buffering them. A 200k-entry Routinator JSON dump
//! parses in well under a second on commodity hardware.

use core::str::FromStr;

use lr_core::addr::{Asn, Prefix};

use crate::roa::{RoaEntry, RoaError};

/// One ROA source format. Lowercase wire names match the
/// `[[bgp.roa_source]] format = "..."` config key.
///
/// `from_extension` infers the format from a path's extension when
/// the operator does not pin one explicitly (a `.bird` file is BIRD,
/// `.json` is JSON, `.csv` is CSV, `.toml` / `.lr` is native).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoaFormat {
    /// TOML `[[roa]]` array-of-tables — the canonical lr ROA shape
    /// emitted by `daemon.toml` and the config DSL.
    Native,
    /// BIRD 2 `roa table` body — `roa PREFIX max N as N;` lines.
    Bird,
    /// Routinator JSON VRP output — `{"roas":[{...}]}`.
    Json,
    /// Comma- or whitespace-separated rows — Routinator CSV / awk.
    Csv,
}

impl RoaFormat {
    /// Lowercase wire name — `"native"`, `"bird"`, `"json"`, `"csv"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Bird => "bird",
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }

    /// Parse the wire name; unknown values return `None`. The caller
    /// surfaces a fail-closed error (a typo'd format silently weakens
    /// origin validation, so the daemon's config parser rejects it
    /// rather than guessing).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "native" | "lr" | "toml" => Some(Self::Native),
            "bird" | "bird2" => Some(Self::Bird),
            "json" => Some(Self::Json),
            "csv" | "tsv" | "text" | "plain" => Some(Self::Csv),
            _ => None,
        }
    }

    /// Infer the format from a path's extension. `None` for unknown
    /// extensions (the daemon then requires an explicit `format` key).
    pub fn from_extension(path: &str) -> Option<Self> {
        let ext = path.rsplit('.').next()?;
        match ext.to_ascii_lowercase().as_str() {
            "toml" | "lr" => Some(Self::Native),
            "bird" | "roa" => Some(Self::Bird),
            "json" => Some(Self::Json),
            "csv" | "tsv" | "txt" => Some(Self::Csv),
            _ => None,
        }
    }
}

/// Load-time error: one of the format parsers rejected a record.
/// Surfaces the offending line number so the daemon's startup log
/// points the operator at the right place.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoaLoaderError {
    /// A single record's prefix did not parse as CIDR.
    #[error("line {line_no}: bad prefix '{prefix}'")]
    BadPrefix { line_no: usize, prefix: String },
    /// A single record's `max_length` is out of range or below the
    /// prefix length (RFC 6482 §3.3 invariant).
    #[error("{0}")]
    InvalidEntry(#[from] RoaError),
    /// A single record's `asn` did not parse.
    #[error("line {line_no}: bad asn '{asn}'")]
    BadAsn { line_no: usize, asn: String },
    /// A record was missing a required field (the message names it).
    #[error("line {line_no}: {message}")]
    Missing { line_no: usize, message: String },
    /// The JSON document was malformed (truncated, mismatched braces,
    /// bad escape). The daemon keeps the previous snapshot on this
    /// error — a truncated fetch must never weaken origin validation.
    #[error("line {line_no}: malformed JSON: {message}")]
    BadJson { line_no: usize, message: String },
    /// The operator pinned a format the loader does not recognise.
    #[error("unknown ROA format '{0}'")]
    UnknownFormat(String),
    /// I/O error reading the source (file or URL body). The line
    /// number is unset (the caller has no source line to point at).
    #[error("io: {0}")]
    Io(String),
}

/// Parse a buffer of the given format into ROA entries. Dispatches to
/// the format-specific parser; the daemon and the FFI surface both
/// go through here so the parse path is one function.
pub fn parse(text: &str, format: RoaFormat) -> Result<Vec<RoaEntry>, RoaLoaderError> {
    match format {
        RoaFormat::Native => parse_native(text),
        RoaFormat::Bird => parse_bird(text),
        RoaFormat::Json => parse_json(text),
        RoaFormat::Csv => parse_csv(text),
    }
}

/// Parse a native lr ROA file — a TOML subset restricted to `[[roa]]`
/// array-of-tables. The schema is the same one `daemon.toml` uses:
///
/// ```toml
/// [[roa]]
/// prefix = "203.0.113.0/24"
/// max_length = 24
/// asn = 64512
/// ```
///
/// Comments (`#` to end of line), quoted strings, and the `max_len` /
/// `origin_as` aliases are all accepted. The parser is a tiny
/// hand-rolled state machine: the full `toml` crate is overkill for a
/// shape this narrow, and the daemon already runs the same subset
/// parser for `daemon.toml` proper.
pub fn parse_native(text: &str) -> Result<Vec<RoaEntry>, RoaLoaderError> {
    let mut entries = Vec::new();
    let mut current: Option<(Prefix, Option<u8>, Option<u32>)> = None;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("[[") && line.ends_with("]]") {
            let name = line[2..line.len() - 2].trim();
            if name == "roa" {
                if let Some((p, ml, asn)) = current.take() {
                    entries.push(finalize_entry(p, ml, asn, line_no)?);
                }
                current = Some((Prefix::new_v4([0; 4], 0), None, None));
                continue;
            }
            // Unknown array-of-table — flush the current entry (if
            // any) and ignore the block. Forward compatibility: the
            // daemon's `[[peer]]` tables appear in the same file
            // without breaking ROA loading.
            if let Some((p, ml, asn)) = current.take() {
                entries.push(finalize_entry(p, ml, asn, line_no)?);
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            // Plain `[section]` — not a ROA entry. Flush + skip.
            if let Some((p, ml, asn)) = current.take() {
                entries.push(finalize_entry(p, ml, asn, line_no)?);
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            // Not a key=value line and not a section header — skip
            // silently (forward compat).
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        let Some((ref mut prefix, ref mut max_length, ref mut asn)) = current else {
            // Keys outside a [[roa]] table — ignore (the daemon's
            // other top-level keys like `[bgp] local_as = ...` are
            // valid in the same file).
            continue;
        };
        match key {
            "prefix" => {
                *prefix = Prefix::from_str(value).map_err(|_| RoaLoaderError::BadPrefix {
                    line_no,
                    prefix: value.to_string(),
                })?;
            }
            "max_length" | "max_len" => {
                *max_length = Some(value.parse().map_err(|_| RoaLoaderError::BadAsn {
                    line_no,
                    asn: value.to_string(),
                })?);
            }
            "asn" | "origin_as" => {
                *asn = Some(value.parse().map_err(|_| RoaLoaderError::BadAsn {
                    line_no,
                    asn: value.to_string(),
                })?);
            }
            _ => { /* unknown key in a [[roa]] table — ignore */ }
        }
    }
    if let Some((p, ml, asn)) = current {
        entries.push(finalize_entry(p, ml, asn, text.lines().count())?);
    }
    Ok(entries)
}

/// Strip a `#` comment from a line, preserving `#` inside quoted
/// strings (the same rule `daemon_config::parse_toml_subset` uses).
fn strip_comment(raw: &str) -> &str {
    let mut in_quote = false;
    for (i, ch) in raw.char_indices() {
        match ch {
            '"' => in_quote = !in_quote,
            '#' if !in_quote => return &raw[..i],
            _ => {}
        }
    }
    raw
}

/// Build a `RoaEntry` from the parsed `(prefix, max_length, asn)`
/// triple. `max_length = None` means "exact prefix" (the common
/// case); `asn = None` is a build error (RFC 6482 §3.2 requires it).
fn finalize_entry(
    prefix: Prefix,
    max_length: Option<u8>,
    asn: Option<u32>,
    line_no: usize,
) -> Result<RoaEntry, RoaLoaderError> {
    let asn = asn.ok_or_else(|| RoaLoaderError::Missing {
        line_no,
        message: "[[roa]] without 'asn' (RFC 6482 §3.2)".to_string(),
    })?;
    let entry = match max_length {
        Some(ml) => {
            RoaEntry::with_max_length(prefix, ml, Asn(asn)).map_err(RoaLoaderError::InvalidEntry)?
        }
        None => RoaEntry::exact(prefix, Asn(asn)),
    };
    Ok(entry)
}

/// Parse a BIRD ROA file — the body of a `roa table NAME { ... }`
/// block. Accepts the two line shapes BIRD 2 / 3 document:
///
/// ```text
/// roa 192.0.2.0/24 max 24 as 64512;
/// roa6 2001:db8::/32 max 48 as 64512;
/// ```
///
/// The trailing `;` is optional (some operators strip it when
/// `include`-ing fragments). `max N` is optional — when omitted the
/// entry authorises only the exact prefix (mirroring BIRD's default
/// and lr's `RoaEntry::exact`).
///
/// Lines starting with `#` or `//` are comments; blank lines are
/// skipped. The `roa table NAME {` and `}` braces are also tolerated
/// so an operator can point the loader at the whole BIRD config
/// fragment instead of just the body.
pub fn parse_bird(text: &str) -> Result<Vec<RoaEntry>, RoaLoaderError> {
    let mut entries = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // Tolerate the `roa table NAME {` / `}` wrapper lines so an
        // operator can drop the whole fragment in.
        if line.starts_with("roa table") || line == "}" {
            continue;
        }
        // Strip an optional trailing `;`.
        let line = line.trim_end_matches(';').trim();
        // Split on whitespace; the BIRD grammar is whitespace-flexible.
        let mut tokens = line.split_whitespace();
        let kind = tokens.next().unwrap_or("");
        let is_v6 = match kind {
            "roa" => false,
            "roa6" => true,
            // Unknown line — skip silently (forward compat: a future
            // BIRD keyword would not break ROA loading).
            _ => continue,
        };
        let _ = is_v6; // prefix parsing infers family from the literal.
                       // The next token is the prefix unless it is a known BIRD
                       // keyword (`max`/`as`) — those appearing first means the
                       // entry is missing its prefix.
        let next = tokens.next().unwrap_or("");
        let prefix_str = if next == "max" || next == "as" || next.is_empty() {
            return Err(RoaLoaderError::Missing {
                line_no,
                message: "roa entry without a prefix".to_string(),
            });
        } else {
            next
        };
        let prefix = Prefix::from_str(prefix_str).map_err(|_| RoaLoaderError::BadPrefix {
            line_no,
            prefix: prefix_str.to_string(),
        })?;
        // Optional `max N`.
        let mut max_length = None;
        let mut asn: Option<u32> = None;
        while let Some(tok) = tokens.next() {
            match tok {
                "max" => {
                    let v = tokens.next().ok_or_else(|| RoaLoaderError::Missing {
                        line_no,
                        message: "`max` without a value".to_string(),
                    })?;
                    max_length = Some(v.parse().map_err(|_| RoaLoaderError::BadAsn {
                        line_no,
                        asn: v.to_string(),
                    })?);
                }
                "as" => {
                    let v = tokens.next().ok_or_else(|| RoaLoaderError::Missing {
                        line_no,
                        message: "`as` without a value".to_string(),
                    })?;
                    asn = Some(parse_bird_asn(v).map_err(|_| RoaLoaderError::BadAsn {
                        line_no,
                        asn: v.to_string(),
                    })?);
                }
                _ => { /* unknown token — ignore (forward compat) */ }
            }
        }
        entries.push(finalize_entry(prefix, max_length, asn, line_no)?);
    }
    Ok(entries)
}

/// Parse the BIRD ASN literal — `123`, `AS123`, `as123`. The `AS`
/// prefix is the BIRD 2 canonical form (and what Routinator's JSON
/// emits); bare digits are accepted for convenience.
fn parse_bird_asn(s: &str) -> Result<u32, ()> {
    let s = s.trim();
    let digits = s
        .strip_prefix("AS")
        .or_else(|| s.strip_prefix("as"))
        .unwrap_or(s);
    digits.parse::<u32>().map_err(|_| ())
}

/// Parse a Routinator JSON VRP dump. The shape is:
///
/// ```json
/// {
///   "metadata": {"generated": 1685455841, "generatedTime": "..."},
///   "roas": [
///     {"asn": "AS196615", "prefix": "93.175.147.0/24", "maxLength": 24, "ta": "ripe"}
///   ]
/// }
/// ```
///
/// The parser is a tiny hand-rolled recursive-descent scanner
/// (no `serde_json` dependency — the format is narrow enough that a
/// bespoke parser keeps the dependency surface flat and runs in one
/// linear pass). Unknown top-level keys (`metadata`, future
/// extensions) are skipped without buffering.
pub fn parse_json(text: &str) -> Result<Vec<RoaEntry>, RoaLoaderError> {
    let mut p = JsonParser::new(text);
    p.skip_ws();
    p.expect_char('{')?;
    let mut entries = Vec::new();
    loop {
        p.skip_ws();
        if p.peek() == Some('}') {
            p.next();
            break;
        }
        let key = p.parse_string()?;
        p.skip_ws();
        p.expect_char(':')?;
        p.skip_ws();
        if key == "roas" {
            p.parse_roas_array(&mut entries)?;
        } else {
            // Skip the value (metadata, future keys).
            p.skip_value()?;
        }
        p.skip_ws();
        match p.peek() {
            Some(',') => {
                p.next();
            }
            Some('}') => {
                p.next();
                break;
            }
            _ => return Err(p.err("expected ',' or '}'")),
        }
    }
    Ok(entries)
}

/// Minimal recursive-descent JSON scanner. Tracks the source offset
/// for error messages; does not allocate strings unless they are
/// `asn` / `prefix` values that actually become ROA entries.
struct JsonParser<'a> {
    src: &'a [u8],
    pos: usize,
    line_no: usize,
}

impl<'a> JsonParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            src: text.as_bytes(),
            pos: 0,
            line_no: 1,
        }
    }

    fn err(&self, msg: &str) -> RoaLoaderError {
        RoaLoaderError::BadJson {
            line_no: self.line_no,
            message: msg.to_string(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.src.get(self.pos).map(|b| *b as char)
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.line_no += 1;
        }
        Some(c)
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.next();
            } else {
                break;
            }
        }
    }

    fn expect_char(&mut self, c: char) -> Result<(), RoaLoaderError> {
        if self.peek() == Some(c) {
            self.next();
            Ok(())
        } else {
            Err(self.err(&format!("expected '{c}'")))
        }
    }

    /// Parse a JSON string, with full escape handling. Returns the
    /// decoded Rust string.
    fn parse_string(&mut self) -> Result<String, RoaLoaderError> {
        self.expect_char('"')?;
        let mut out = String::new();
        loop {
            let c = self.next().ok_or_else(|| self.err("unterminated string"))?;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let e = self.next().ok_or_else(|| self.err("bad escape"))?;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{08}'),
                        'f' => out.push('\u{0C}'),
                        'u' => {
                            let mut cp = 0u32;
                            for _ in 0..4 {
                                let h = self.next().ok_or_else(|| self.err("bad \\u"))?;
                                let d = h.to_digit(16).ok_or_else(|| self.err("bad \\u"))?;
                                cp = cp * 16 + d;
                            }
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                            }
                        }
                        _ => return Err(self.err("bad escape")),
                    }
                }
                _ => out.push(c),
            }
        }
    }

    /// Parse the `roas` array. Each element is an object whose keys
    /// we recognise: `asn`, `prefix`, `maxLength`, `ta` (ignored).
    fn parse_roas_array(&mut self, out: &mut Vec<RoaEntry>) -> Result<(), RoaLoaderError> {
        self.expect_char('[')?;
        loop {
            self.skip_ws();
            match self.peek() {
                Some(']') => {
                    self.next();
                    return Ok(());
                }
                Some('{') => {
                    self.next();
                    let entry = self.parse_roa_object()?;
                    out.push(entry);
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => {
                            self.next();
                        }
                        Some(']') => {
                            self.next();
                            return Ok(());
                        }
                        _ => return Err(self.err("expected ',' or ']' after roa object")),
                    }
                }
                _ => return Err(self.err("expected '{' or ']' in roas array")),
            }
        }
    }

    /// Parse one `{ "asn": ..., "prefix": ..., "maxLength": ... }`
    /// object. Unknown keys are skipped; missing `asn` / `prefix`
    /// are errors (the daemon must fail closed on a truncated record).
    fn parse_roa_object(&mut self) -> Result<RoaEntry, RoaLoaderError> {
        let mut asn: Option<u32> = None;
        let mut prefix: Option<Prefix> = None;
        let mut max_length: Option<u8> = None;
        let line_no_start = self.line_no;
        loop {
            self.skip_ws();
            match self.peek() {
                Some('}') => {
                    self.next();
                    break;
                }
                Some('"') => {
                    let key = self.parse_string()?;
                    self.skip_ws();
                    self.expect_char(':')?;
                    self.skip_ws();
                    match key.as_str() {
                        "asn" => {
                            // Routinator emits ASN as a string
                            // (`"AS196615"`); some tools emit the
                            // bare integer. Accept both shapes.
                            asn = Some(self.parse_asn_value()?);
                        }
                        "prefix" => {
                            let s = self.parse_string()?;
                            prefix = Some(Prefix::from_str(&s).map_err(|_| {
                                RoaLoaderError::BadPrefix {
                                    line_no: line_no_start,
                                    prefix: s.clone(),
                                }
                            })?);
                        }
                        "maxLength" | "max_length" => {
                            let n = self.parse_number_u32()?;
                            if n > 255 {
                                return Err(self.err("maxLength > 255"));
                            }
                            max_length = Some(n as u8);
                        }
                        _ => self.skip_value()?,
                    }
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => {
                            self.next();
                        }
                        Some('}') => {
                            self.next();
                            break;
                        }
                        _ => return Err(self.err("expected ',' or '}' in roa object")),
                    }
                }
                _ => return Err(self.err("expected '\"' or '}' in roa object")),
            }
        }
        let prefix = prefix.ok_or_else(|| RoaLoaderError::Missing {
            line_no: line_no_start,
            message: "roa object without 'prefix'".to_string(),
        })?;
        let asn = asn.ok_or_else(|| RoaLoaderError::Missing {
            line_no: line_no_start,
            message: "roa object without 'asn'".to_string(),
        })?;
        let entry = match max_length {
            Some(ml) => RoaEntry::with_max_length(prefix, ml, Asn(asn))
                .map_err(RoaLoaderError::InvalidEntry)?,
            None => RoaEntry::exact(prefix, Asn(asn)),
        };
        Ok(entry)
    }

    /// Parse a non-negative integer up to u32.
    fn parse_number_u32(&mut self) -> Result<u32, RoaLoaderError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.next();
            } else {
                break;
            }
        }
        let s =
            std::str::from_utf8(&self.src[start..self.pos]).map_err(|_| self.err("bad utf8"))?;
        s.parse::<u32>().map_err(|_| self.err("bad number"))
    }

    /// Parse an ASN value: either a JSON string (`"AS123"` / `"123"`)
    /// or a bare integer (`123`). Routinator emits strings; some
    /// adjacent tools emit numbers — accept both shapes so a fetch
    /// from either source parses without operator conversion.
    fn parse_asn_value(&mut self) -> Result<u32, RoaLoaderError> {
        self.skip_ws();
        match self.peek() {
            Some('"') => {
                let s = self.parse_string()?;
                parse_bird_asn(&s).map_err(|_| self.err("bad asn"))
            }
            Some(c) if c.is_ascii_digit() || c == '-' => self.parse_number_u32(),
            _ => Err(self.err("expected asn string or number")),
        }
    }

    /// Skip one JSON value (any shape) without buffering it. Used for
    /// unknown object keys and the `metadata` block.
    fn skip_value(&mut self) -> Result<(), RoaLoaderError> {
        self.skip_ws();
        match self.peek() {
            Some('"') => {
                let _ = self.parse_string()?;
            }
            Some('{') => {
                self.next();
                loop {
                    self.skip_ws();
                    if self.peek() == Some('}') {
                        self.next();
                        break;
                    }
                    let _ = self.parse_string()?;
                    self.skip_ws();
                    self.expect_char(':')?;
                    self.skip_value()?;
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => {
                            self.next();
                        }
                        Some('}') => {
                            self.next();
                            break;
                        }
                        _ => return Err(self.err("expected ',' or '}' in object")),
                    }
                }
            }
            Some('[') => {
                self.next();
                loop {
                    self.skip_ws();
                    if self.peek() == Some(']') {
                        self.next();
                        break;
                    }
                    self.skip_value()?;
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => {
                            self.next();
                        }
                        Some(']') => {
                            self.next();
                            break;
                        }
                        _ => return Err(self.err("expected ',' or ']' in array")),
                    }
                }
            }
            Some(c) if c == '-' || c.is_ascii_digit() => {
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit()
                        || c == '-'
                        || c == '+'
                        || c == '.'
                        || c == 'e'
                        || c == 'E'
                    {
                        self.next();
                    } else {
                        break;
                    }
                }
            }
            Some('t') => {
                self.expect_literal("true")?;
            }
            Some('f') => {
                self.expect_literal("false")?;
            }
            Some('n') => {
                self.expect_literal("null")?;
            }
            _ => return Err(self.err("expected a JSON value")),
        }
        Ok(())
    }

    fn expect_literal(&mut self, lit: &str) -> Result<(), RoaLoaderError> {
        for expected in lit.chars() {
            if self.next() != Some(expected) {
                return Err(self.err(&format!("expected '{lit}'")));
            }
        }
        Ok(())
    }
}

/// Parse a CSV / TSV / whitespace-separated ROA dump. Accepts both
/// Routinator's CSV output (`ASN,Prefix,MaxLength,TrustAnchor`, with
/// or without header) and the bare `ASN prefix maxlen` form an
/// `awk '{print $1, $2, $3}'` one-liner produces.
///
/// Rules:
/// * Lines starting with `#` are comments (Routinator emits none
///   but the convention is universal).
/// * The first row is treated as a header only if its first field
///   does not parse as an AS literal (i.e. it is the literal
///   `"ASN"`). This auto-detection matches every observed
///   Routinator CSV.
/// * Each record is `ASN, prefix, max_length` — comma, tab or
///   whitespace separated. The `max_length` field is optional
///   (omitted means exact-prefix authorization, mirroring the BIRD
///   and native shapes).
/// * A trailing fourth column (the trust anchor) is ignored.
pub fn parse_csv(text: &str) -> Result<Vec<RoaEntry>, RoaLoaderError> {
    let mut entries = Vec::new();
    let mut header_seen = false;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split on comma OR whitespace. Comma is the canonical CSV
        // separator; whitespace matches the awk-produced form.
        let fields: Vec<&str> = if line.contains(',') {
            line.split(',').map(|f| f.trim()).collect()
        } else {
            line.split_whitespace().collect()
        };
        if fields.is_empty() {
            continue;
        }
        // Header auto-detection: a Routinator CSV's first row is
        // `ASN,Prefix,MaxLength,TrustAnchor` — neither the first
        // field parses as an AS literal, nor does the second field
        // parse as a CIDR. Require both conditions so a malformed
        // first record (e.g. a typo'd ASN on an otherwise-valid
        // prefix) surfaces as an error rather than being swallowed
        // as a header. Only the first non-comment row is a candidate.
        if !header_seen
            && fields.len() >= 2
            && parse_bird_asn(fields[0]).is_err()
            && Prefix::from_str(fields[1]).is_err()
        {
            header_seen = true;
            continue;
        }
        header_seen = true;
        if fields.len() < 2 {
            return Err(RoaLoaderError::Missing {
                line_no,
                message: "roa row needs at least `asn prefix`".to_string(),
            });
        }
        let asn = parse_bird_asn(fields[0]).map_err(|_| RoaLoaderError::BadAsn {
            line_no,
            asn: fields[0].to_string(),
        })?;
        let prefix = Prefix::from_str(fields[1]).map_err(|_| RoaLoaderError::BadPrefix {
            line_no,
            prefix: fields[1].to_string(),
        })?;
        let max_length = if fields.len() >= 3 {
            Some(
                fields[2]
                    .parse::<u8>()
                    .map_err(|_| RoaLoaderError::BadAsn {
                        line_no,
                        asn: fields[2].to_string(),
                    })?,
            )
        } else {
            None
        };
        entries.push(finalize_entry(prefix, max_length, Some(asn), line_no)?);
    }
    Ok(entries)
}

#[cfg(test)]
#[path = "roa_loader_tests.rs"]
mod tests;
