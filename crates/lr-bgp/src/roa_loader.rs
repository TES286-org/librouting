//! ROA loader — format parsers for Route Origin Authorization sources
//! (issue #100).
//!
//! The loader recognises four on-the-wire formats. Two are pure parsers
//! that run directly on the source bytes:
//!
//! | Format | Description | Reference |
//! | --- | --- | --- |
//! | `native` | TOML `[[roa]]` array-of-tables, mirrors `daemon.toml` | [`parse_native`] |
//! | `bird` | BIRD 2 `roa table` body, `roa PREFIX max N as N;` per line | [`parse_bird`] |
//!
//! The other two are **transform formats**: they run an operator-supplied
//! `jq` or `awk` program against the source bytes, then parse the program's
//! **stdout** as BIRD-format lines. This lets the operator load ROA data
//! from *any* JSON shape (via `jq`) or *any* plain-text shape (via `awk`),
//! not just the fixed Routinator JSON / CSV layouts.
//!
//! | Format | Description | Transformer |
//! | --- | --- | --- |
//! | `jq` | Arbitrary JSON, transformed by a user `jq` program into BIRD lines | [jqlang/jq](https://github.com/jqlang/jq) |
//! | `awk` | Arbitrary text, transformed by a user `awk` program into BIRD lines | [onetrueawk/awk](https://github.com/onetrueawk/awk) |
//!
//! The `jq` / `awk` programs are invoked by the daemon's loader thread
//! (see `daemon_roa_loader`); the pure `parse()` function in this module
//! only handles `native` and `bird`. The transform formats surface a
//! clear error when `parse()` is called directly, so the FFI surface
//! cannot accidentally bypass the daemon's subprocess discipline.
//!
//! `native` is the canonical lr shape: a TOML subset restricted to
//! `[[roa]]` array-of-tables with `prefix`, `max_length` (or
//! `max_len`), and `asn` (or `origin_as`) keys. `bird` accepts the
//! body of a BIRD `roa table NAME { ... }` block — the same lines
//! one would `include "/path/to/file.roa";`.
//!
//! # Why jq / awk expressions, not fixed parsers
//!
//! The first iteration of this feature (commits `3e0896b..9655409`)
//! shipped hand-rolled `parse_json` and `parse_csv` that only accepted
//! Routinator's fixed output shape. Real-world ROA sources come in
//! many shapes: RIPE NCC validator's JSON, custom YAML converted to
//! JSON, RIR TXT dumps, vendor-specific CSV columns. Hard-coding a
//! parser for every observed shape does not scale; asking the operator
//! to convert their data into a fixed shape before pointing `lr-daemon`
//! at it is what BIRD and FRR do today, and it is exactly the friction
//! this feature exists to remove.
//!
//! `jq` and `awk` are the standard, ubiquitous tools for ad-hoc data
//! transformation. Letting the operator write a one-line `jq` filter
//! (`.roas[] | "roa \(.prefix) max \(.maxLength) as \(.asn);"`) or an
//! `awk` one-liner (`{ printf "roa %s max %s as %s;\n", $2, $3, $1 }`)
//! turns every possible ROA source shape into a one-line config entry.
//! The transform programs output BIRD-format lines, which the existing
//! [`parse_bird`] parser handles — the same parser that accepts BIRD's
//! own `roa table` fragments.
//!
//! # RFC references
//!
//! * RFC 6482 — A Profile for Resource Certificate Lists (ROA object)
//! * RFC 6811 §2 — prefix-origin validation algorithm
//! * RFC 8210 — RPKI-Router Transport Protocol (the live update side)
//! * <https://bird.nic.cz/doc/bird-2.16.2.html> §6 — BIRD `roa table` syntax
//! * <https://stedolan.github.io/jq/manual/> — jq program syntax
//! * <https://www.gnu.org/software/gawk/manual/gawk.html> — awk program syntax
//!
//! # Performance
//!
//! Each pure parser runs in a single linear scan over the input. The BIRD
//! parser splits on whitespace without allocating a `Vec<String>` per line.
//! A 200k-entry BIRD file parses in well under a second on commodity
//! hardware. The `jq` / `awk` transform formats add one process spawn
//! per load — negligible for a source that refreshes every 3600 s.

use core::str::FromStr;

use lr_core::addr::{Asn, Prefix};

use crate::roa::{RoaEntry, RoaError};

/// One ROA source format. Lowercase wire names match the
/// `[[bgp.roa_source]] format = "..."` config key.
///
/// `native` and `bird` are pure parsers handled by [`parse`]. `jq` and
/// `awk` are **transform formats**: they run an operator-supplied program
/// (see `daemon_roa_loader::run_jq` / `run_awk`) whose stdout is parsed
/// as BIRD-format lines. Calling [`parse`] with `Jq` or `Awk` returns
/// [`RoaLoaderError::TransformFormatDirect`] — the transform step must
/// happen before the bytes reach the pure parser.
///
/// `from_extension` infers the format from a path's extension when
/// the operator does not pin one explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoaFormat {
    /// TOML `[[roa]]` array-of-tables — the canonical lr ROA shape
    /// emitted by `daemon.toml` and the config DSL.
    Native,
    /// BIRD 2 `roa table` body — `roa PREFIX max N as N;` lines.
    /// Also the canonical **intermediate format** that `jq` / `awk`
    /// transform programs are expected to emit.
    Bird,
    /// Arbitrary JSON transformed by a user-supplied `jq` program
    /// (issue #100). The program reads the source JSON on stdin and
    /// writes BIRD-format lines on stdout. The daemon's loader thread
    /// runs the program; the pure [`parse`] function does not handle
    /// this variant directly.
    Jq,
    /// Arbitrary text transformed by a user-supplied `awk` program
    /// (issue #100). The program reads the source text on stdin and
    /// writes BIRD-format lines on stdout. The daemon's loader thread
    /// runs the program; the pure [`parse`] function does not handle
    /// this variant directly.
    Awk,
}

impl RoaFormat {
    /// Lowercase wire name — `"native"`, `"bird"`, `"jq"`, `"awk"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Bird => "bird",
            Self::Jq => "jq",
            Self::Awk => "awk",
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
            "jq" | "json" => Some(Self::Jq),
            "awk" | "csv" | "tsv" | "text" | "plain" => Some(Self::Awk),
            _ => None,
        }
    }

    /// Infer the format from a path's extension. `None` for unknown
    /// extensions (the daemon then requires an explicit `format` key).
    ///
    /// `.json` maps to `jq` and `.csv` / `.txt` map to `awk` because
    /// the transform formats are the superset of the old fixed parsers:
    /// a `.json` file needs a `jq` program to extract its ROA records,
    /// and a `.csv` / `.txt` file needs an `awk` program. The operator
    /// can always pin `format = "bird"` to skip the transform step.
    pub fn from_extension(path: &str) -> Option<Self> {
        let ext = path.rsplit('.').next()?;
        match ext.to_ascii_lowercase().as_str() {
            "toml" | "lr" => Some(Self::Native),
            "bird" | "roa" => Some(Self::Bird),
            "json" => Some(Self::Jq),
            "csv" | "tsv" | "txt" => Some(Self::Awk),
            _ => None,
        }
    }

    /// Whether this format requires an operator-supplied transform
    /// program (`jq` or `awk`). The daemon's loader thread checks this
    /// to decide whether to spawn a subprocess before parsing.
    pub fn requires_program(self) -> bool {
        matches!(self, Self::Jq | Self::Awk)
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
    /// The operator pinned a format the loader does not recognise.
    #[error("unknown ROA format '{0}'")]
    UnknownFormat(String),
    /// I/O error reading the source (file or URL body). The line
    /// number is unset (the caller has no source line to point at).
    #[error("io: {0}")]
    Io(String),
    /// A transform format (`jq` or `awk`) was passed to the pure
    /// [`parse`] function. The transform step runs in the daemon's
    /// loader thread (`daemon_roa_loader::run_jq` / `run_awk`),
    /// *before* the bytes reach this parser. Calling `parse` with a
    /// transform format is a programming error — the caller must run
    /// the transform first and pass the resulting BIRD text with
    /// [`RoaFormat::Bird`].
    #[error("transform format '{0}' cannot be parsed directly; run the jq/awk program first and parse its output as 'bird'")]
    TransformFormatDirect(&'static str),
}

/// Parse a buffer of the given format into ROA entries.
///
/// Only `Native` and `Bird` are handled here — they are pure parsers
/// that run directly on the source bytes. `Jq` and `Awk` are transform
/// formats that require an operator-supplied program; the daemon's
/// loader thread runs the program and passes its stdout back through
/// this function as `RoaFormat::Bird`. Calling `parse` with a
/// transform format returns [`RoaLoaderError::TransformFormatDirect`].
pub fn parse(text: &str, format: RoaFormat) -> Result<Vec<RoaEntry>, RoaLoaderError> {
    match format {
        RoaFormat::Native => parse_native(text),
        RoaFormat::Bird => parse_bird(text),
        RoaFormat::Jq => Err(RoaLoaderError::TransformFormatDirect("jq")),
        RoaFormat::Awk => Err(RoaLoaderError::TransformFormatDirect("awk")),
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
///
/// `prefix` is required (RFC 6482 §3.1 — a ROA without a prefix is
/// meaningless). A `[[roa]]` block that sets `asn` but omits `prefix`
/// is rejected at finalize time: the parser cannot default to
/// `0.0.0.0/0` because that would silently authorise the entire IPv4
/// unicast space for the configured ASN (a fail-open bug exactly the
/// kind the loader's snapshot discipline exists to prevent).
pub fn parse_native(text: &str) -> Result<Vec<RoaEntry>, RoaLoaderError> {
    let mut entries = Vec::new();
    // `prefix` is `Option<Prefix>` so a `[[roa]]` block that omits the
    // `prefix = "..."` key is rejected at finalize time rather than
    // silently defaulting to `0.0.0.0/0`.
    let mut current: Option<(Option<Prefix>, Option<u8>, Option<u32>)> = None;
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
                current = Some((None, None, None));
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
        let value = unquote_toml_value(value);
        let Some((ref mut prefix, ref mut max_length, ref mut asn)) = current else {
            // Keys outside a [[roa]] table — ignore (the daemon's
            // other top-level keys like `[bgp] local_as = ...` are
            // valid in the same file).
            continue;
        };
        match key {
            "prefix" => {
                *prefix = Some(
                    Prefix::from_str(value).map_err(|_| RoaLoaderError::BadPrefix {
                        line_no,
                        prefix: value.to_string(),
                    })?,
                );
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

/// Strip one pair of surrounding quotes from a TOML scalar value.
///
/// Handles both basic (`"..."`) and literal (`'...'`) string forms
/// per TOML §"Strings". A value without surrounding quotes is returned
/// unchanged (bare values like `true` and `123` are accepted). Unlike
/// `str::trim_matches('"')`, this strips at most one matching pair, so
/// a value like `"hello\"world"` is correctly stripped to `hello\"world`
/// (not `hello\`), and a literal string `'.roas[] | "x";'` is stripped
/// to `.roas[] | "x";` verbatim.
///
/// The native ROA loader uses this for `prefix`, `max_length` and `asn`
/// values inside `[[roa]]` tables, which previously rejected literal
/// strings because the parser only stripped `"` via `trim_matches`.
fn unquote_toml_value(value: &str) -> &str {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && bytes[0] == bytes[bytes.len() - 1]
        && (bytes[0] == b'"' || bytes[0] == b'\'')
    {
        return &value[1..value.len() - 1];
    }
    value
}

/// Strip a `#` comment from a line, preserving `#` inside quoted
/// strings (the same rule `daemon_config::parse_toml_subset` uses).
fn strip_comment(raw: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match (ch, quote) {
            (c, Some(q)) if c == q => quote = None,
            ('\\', Some('"')) => escaped = true,
            ('"' | '\'', None) => quote = Some(ch),
            ('#', None) => return &raw[..i],
            _ => {}
        }
    }
    raw
}

/// Build a `RoaEntry` from the parsed `(prefix, max_length, asn)`
/// triple. `prefix = None` (the `[[roa]]` block omitted the `prefix`
/// key) is a build error — RFC 6482 §3.1 requires the `prefix` field
/// and the parser must not default to `0.0.0.0/0` (which would
/// silently authorise the entire IPv4 unicast space for the configured
/// ASN). `max_length = None` means "exact prefix" (the common case);
/// `asn = None` is a build error (RFC 6482 §3.2 requires it).
fn finalize_entry(
    prefix: Option<Prefix>,
    max_length: Option<u8>,
    asn: Option<u32>,
    line_no: usize,
) -> Result<RoaEntry, RoaLoaderError> {
    let prefix = prefix.ok_or_else(|| RoaLoaderError::Missing {
        line_no,
        message: "[[roa]] without 'prefix' (RFC 6482 §3.1 — would default to 0.0.0.0/0)"
            .to_string(),
    })?;
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
///
/// This is also the **canonical intermediate format** that `jq` and
/// `awk` transform programs are expected to emit: a `jq` program that
/// reads Routinator JSON writes `roa PREFIX max N as N;` lines, and
/// an `awk` program that reads a CSV does the same. The output is
/// fed back into this parser.
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
        entries.push(finalize_entry(Some(prefix), max_length, asn, line_no)?);
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

#[cfg(test)]
#[path = "roa_loader_tests.rs"]
mod tests;
