//! Minimal JSON serializer for `lrctl --json` output.
//!
//! `serde_json` is not pulled in to keep the `lrctl` binary's
//! dependency surface small (the same stance the metrics module
//! takes on HTTP — hand-rolled rather than `hyper`). The shapes
//! `lrctl` emits are narrow:
//!
//! - `null`, `bool`, integer, float, string
//! - `{"k": v, ...}` object (insertion-ordered)
//! - `[v, ...]` array
//!
//! Nothing else. ~80 lines of code covers it with no allocation
//! beyond the output `String` itself.
//!
//! The crate boundary is `JValue::to_string()` / `JValue::to_pretty()`;
//! the per-command parsers in `lrctl.rs` build `JValue`s with the
//! `JObject` / `JArray` helpers and let the caller format. A single
//! `escape_string` helper handles the JSON-string escape rules
//! (control chars + `" + `\` + `/` left alone).

/// A minimal JSON value.
///
/// Insertion-ordered objects (the order in which `JObject::push`
/// was called) so a JSON output for `status` is rendered in the
/// same order the daemon emits its key=value lines — an operator
/// grepping for `"router-id"` after `"local-as"` finds them in the
/// same shape across the line-oriented and JSON forms.
///
/// Every counter the daemon emits today is an integer, but the
/// daemon's status lines may grow a fractional field in the future
/// (e.g. `cpu-percent 12.3` or `load-average 1.5`). The `Float`
/// variant lets `push_typed` surface such a value as a JSON number
/// instead of falling back to a `Str` — and the writer guards the
/// non-finite cases (`NaN`, `±Infinity`) the JSON grammar forbids
/// (ECMA-404 §9) by emitting `null`, matching ECMAScript's
/// `JSON.stringify(Infinity)` / `JSON.stringify(NaN)`.
#[derive(Debug, Clone)]
pub enum JValue {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    /// A fractional number. Constructed by `push_typed` when the
    /// value parses as `f64` but not as an integer (i.e. it carries
    /// a decimal point or an exponent). Non-finite values (`NaN`,
    /// `±Infinity`) are never constructed by `push_typed` (the parser
    /// falls back to `Str`), but the writer still guards the wire —
    /// see the `write_compact` arm for `Float`.
    Float(f64),
    Str(String),
    Array(JArray),
    Object(JObject),
}

/// A JSON object (insertion-ordered).
#[derive(Debug, Clone, Default)]
pub struct JObject {
    entries: Vec<(String, JValue)>,
}

impl JObject {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub fn push<K: Into<String>>(&mut self, key: K, value: JValue) -> &mut Self {
        self.entries.push((key.into(), value));
        self
    }
    /// Convenience: push a string value without wrapping it in
    /// `JValue::Str(..)` by hand. Most fields the parsers emit are
    /// strings; this keeps the call sites short.
    pub fn push_str<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) -> &mut Self {
        self.entries.push((key.into(), JValue::Str(value.into())));
        self
    }
    /// Convenience: push an unsigned-integer value. Used for AS
    /// numbers, byte counters, uptime.
    pub fn push_uint<K: Into<String>>(&mut self, key: K, value: u64) -> &mut Self {
        self.entries.push((key.into(), JValue::UInt(value)));
        self
    }
    /// Convenience: push a floating-point value. Used for fractional
    /// status fields (`cpu-percent`, `load-average`, …) once the
    /// daemon emits one. Non-finite values (`NaN`, `±Infinity`) are
    /// accepted here for symmetry with `push_uint` / `push_bool`, but
    /// the writer guards them at the wire (it emits `null`).
    pub fn push_float<K: Into<String>>(&mut self, key: K, value: f64) -> &mut Self {
        self.entries.push((key.into(), JValue::Float(value)));
        self
    }
    pub fn push_bool<K: Into<String>>(&mut self, key: K, value: bool) -> &mut Self {
        self.entries.push((key.into(), JValue::Bool(value)));
        self
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &JValue)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

/// A JSON array.
#[derive(Debug, Clone, Default)]
pub struct JArray {
    items: Vec<JValue>,
}

impl JArray {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }
    pub fn push<V: Into<JValue>>(&mut self, value: V) -> &mut Self {
        self.items.push(value.into());
        self
    }
    /// Number of items in the array. Used by tests that assert an
    /// exact array length (e.g. "exactly one session after `pump`")
    /// and by `parse_show_status_body` to detect the empty-array case
    /// before constructing the wrapping `JValue::Array`. Mirrors
    /// `Vec::len` / `slice::len` so callers can use it the same way
    /// they would a `Vec`.
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &JValue> {
        self.items.iter()
    }
}

impl JValue {
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(64);
        self.write_compact(&mut out);
        out
    }
    pub fn to_pretty(&self) -> String {
        let mut out = String::with_capacity(128);
        self.write_pretty(&mut out, 0);
        out
    }
    fn write_compact(&self, out: &mut String) {
        match self {
            JValue::Null => out.push_str("null"),
            JValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JValue::Int(n) => {
                use std::fmt::Write as _;
                let _ = write!(out, "{n}");
            }
            JValue::UInt(n) => {
                use std::fmt::Write as _;
                let _ = write!(out, "{n}");
            }
            JValue::Float(f) => {
                // JSON (ECMA-404 §9) admits only finite numbers —
                // `NaN` / `±Infinity` are not legal in a JSON document.
                // ECMAScript's `JSON.stringify` maps them to `null`;
                // mirror that here so a `JValue::Float(f64::NAN)` (which
                // `push_typed` never constructs but a direct call to
                // `push_float` might) does not silently produce invalid
                // JSON. The finite-path rendering uses `Display` for
                // `f64`, which round-trips the value the parser
                // accepted (Rust's `Display` for `f64` is lossless for
                // finite values that fit in the JSON grammar).
                use std::fmt::Write as _;
                if f.is_finite() {
                    let _ = write!(out, "{f}");
                } else {
                    out.push_str("null");
                }
            }
            JValue::Str(s) => {
                out.push('"');
                escape_string(s, out);
                out.push('"');
            }
            JValue::Array(a) => {
                out.push('[');
                let mut first = true;
                for v in a.iter() {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    v.write_compact(out);
                }
                out.push(']');
            }
            JValue::Object(o) => {
                out.push('{');
                let mut first = true;
                for (k, v) in o.iter() {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    out.push('"');
                    escape_string(k, out);
                    out.push_str("\":");
                    v.write_compact(out);
                }
                out.push('}');
            }
        }
    }
    fn write_pretty(&self, out: &mut String, indent: usize) {
        match self {
            JValue::Null
            | JValue::Bool(_)
            | JValue::Int(_)
            | JValue::UInt(_)
            | JValue::Float(_) => {
                self.write_compact(out);
            }
            JValue::Str(s) => {
                out.push('"');
                escape_string(s, out);
                out.push('"');
            }
            JValue::Array(a) => {
                if a.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                let mut first = true;
                for v in a.iter() {
                    if !first {
                        out.push_str(",\n");
                    }
                    first = false;
                    push_indent(out, indent + 1);
                    v.write_pretty(out, indent + 1);
                }
                out.push('\n');
                push_indent(out, indent);
                out.push(']');
            }
            JValue::Object(o) => {
                if o.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                let mut first = true;
                for (k, v) in o.iter() {
                    if !first {
                        out.push_str(",\n");
                    }
                    first = false;
                    push_indent(out, indent + 1);
                    out.push('"');
                    escape_string(k, out);
                    out.push_str("\": ");
                    v.write_pretty(out, indent + 1);
                }
                out.push('\n');
                push_indent(out, indent);
                out.push('}');
            }
        }
    }
}

/// Push `n` two-space indents into `out` (the JSON pretty-printer's
/// indent unit). Lives here so the pretty printer does not carry the
/// "how many spaces?" decision at every call site.
fn push_indent(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push_str("  ");
    }
}

/// Escape a string for inclusion in a JSON string literal. The
/// JSON spec (`rfc8259 §7`) defines the escapes for `"`, `\`, and
/// the control characters; `/` is left alone (the spec allows
/// escaping it but does not require it). Output goes to `out`
/// rather than returning a `String` so the caller can amortise
/// allocation across many fields.
pub fn escape_string(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_emits_compact_json() {
        let mut o = JObject::new();
        o.push_str("a", "1").push_uint("b", 2).push_bool("c", true);
        let v = JValue::Object(o);
        assert_eq!(v.to_json(), r#"{"a":"1","b":2,"c":true}"#);
    }

    #[test]
    fn array_emits_compact_json() {
        let mut a = JArray::new();
        a.push(JValue::UInt(1))
            .push(JValue::UInt(2))
            .push(JValue::UInt(3));
        let v = JValue::Array(a);
        assert_eq!(v.to_json(), "[1,2,3]");
    }

    #[test]
    fn pretty_indents_two_spaces() {
        let mut inner = JObject::new();
        inner.push_uint("k", 1);
        let mut a = JArray::new();
        a.push(JValue::Object(inner));
        let v = JValue::Array(a);
        assert_eq!(v.to_pretty(), "[\n  {\n    \"k\": 1\n  }\n]");
    }

    #[test]
    fn escapes_quotes_and_control_chars() {
        let mut s = String::new();
        escape_string("a\"b\\c\n\r\t", &mut s);
        assert_eq!(s, r#"a\"b\\c\n\r\t"#);
    }

    #[test]
    fn empty_object_and_array_render_compact() {
        assert_eq!(JValue::Object(JObject::new()).to_json(), "{}");
        assert_eq!(JValue::Array(JArray::new()).to_json(), "[]");
        assert_eq!(JValue::Object(JObject::new()).to_pretty(), "{}");
        assert_eq!(JValue::Array(JArray::new()).to_pretty(), "[]");
    }

    #[test]
    fn null_and_bool_render_verbatim() {
        assert_eq!(JValue::Null.to_json(), "null");
        assert_eq!(JValue::Bool(true).to_json(), "true");
        assert_eq!(JValue::Bool(false).to_json(), "false");
    }

    // ---- `JValue::Float` — the previously-dead-code path the
    // `push_typed` change below now reaches. The write arms must
    // produce JSON-grammar-conformant output for finite values and
    // degrade to `null` for `NaN` / `±Infinity` (ECMA-404 §9 forbids
    // non-finite numbers; ECMAScript's `JSON.stringify` does the same
    // `null`-mapping).

    #[test]
    fn float_finite_renders_as_json_number() {
        // Plain fractional value — the canonical "cpu-percent=12.3"
        // case the docstring points at.
        assert_eq!(JValue::Float(12.3).to_json(), "12.3");
        // Whole-number floats render without a trailing `.0` (Rust's
        // `Display` for `f64` shortens `1.0` to `1`); JSON treats
        // integers and floats as the same number grammar so this is
        // legal, and a JSON consumer parsing the value back as a
        // float gets `1.0` either way.
        assert_eq!(JValue::Float(1.0).to_json(), "1");
        // Negative finite floats round-trip through `Display`.
        assert_eq!(JValue::Float(-0.5).to_json(), "-0.5");
        // Pretty form delegates to `write_compact` for scalars, so
        // the same shape holds.
        assert_eq!(JValue::Float(12.3).to_pretty(), "12.3");
    }

    #[test]
    fn float_non_finite_renders_as_null() {
        // `NaN` and `±Infinity` are not legal JSON numbers; the
        // writer maps them to `null` so a `JValue::Float(f64::NAN)`
        // (which `push_typed` never constructs but a direct
        // `push_float` call might) does not produce invalid JSON.
        assert_eq!(JValue::Float(f64::NAN).to_json(), "null");
        assert_eq!(JValue::Float(f64::INFINITY).to_json(), "null");
        assert_eq!(JValue::Float(f64::NEG_INFINITY).to_json(), "null");
        // The pretty form goes through `write_compact` for scalars,
        // so the same null-mapping applies.
        assert_eq!(JValue::Float(f64::NAN).to_pretty(), "null");
        assert_eq!(JValue::Float(f64::INFINITY).to_pretty(), "null");
    }

    #[test]
    fn push_float_round_trips_through_object() {
        // The convenience helper on `JObject` constructs a `Float`
        // entry the same way `push_uint` / `push_bool` do for their
        // shapes — the resulting JSON carries the value as a number,
        // not a quoted string.
        let mut o = JObject::new();
        o.push_float("cpu-percent", 12.3)
            .push_float("load-average", 1.5);
        let v = JValue::Object(o);
        assert_eq!(v.to_json(), r#"{"cpu-percent":12.3,"load-average":1.5}"#);
    }

    #[test]
    fn push_float_non_finite_emits_null_through_object() {
        // The object helper does not pre-reject non-finite values —
        // the writer does, so a caller that builds a Float from a
        // pre-validated source can still hand a non-finite value
        // without crashing the serializer. This mirrors what
        // ECMAScript's `JSON.stringify({x: Infinity})` does
        // (`{"x":null}`).
        let mut o = JObject::new();
        o.push_float("x", f64::INFINITY);
        assert_eq!(JValue::Object(o).to_json(), r#"{"x":null}"#);
    }

    // ---- `JArray::len` — the previously-dead-code accessor. The
    // `push_typed` change below now uses it to short-circuit the
    // empty-array case, and the unit test here pins the contract.

    #[test]
    fn array_len_counts_pushed_items() {
        let mut a = JArray::new();
        assert_eq!(a.len(), 0);
        assert!(a.is_empty());
        a.push(JValue::UInt(1));
        assert_eq!(a.len(), 1);
        assert!(!a.is_empty());
        a.push(JValue::UInt(2)).push(JValue::UInt(3));
        assert_eq!(a.len(), 3);
        // A nested empty array still counts as one item — `len`
        // counts top-level entries, not transitively.
        a.push(JValue::Array(JArray::new()));
        assert_eq!(a.len(), 4);
    }
}
