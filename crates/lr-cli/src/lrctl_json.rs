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
/// `Float` is currently unused by the `lrctl` parsers (every
/// counter is an integer), but kept on the enum so a future
/// parser (e.g. for a float field the daemon emits) does not have
/// to extend the type — the surface stays stable.
#[derive(Debug, Clone)]
pub enum JValue {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    /// Kept for forward compatibility — no `lrctl` parser emits a
    /// float today, but the daemon's status may grow a fractional
    /// field in the future (e.g. `cpu-percent 12.3`).
    #[allow(dead_code)]
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
    /// Number of items. Currently unused by the `lrctl` parsers
    /// (the array is iterated by the serializer, not by client
    /// code), but kept public so a future caller (e.g. a test
    /// asserting "exactly one session") does not have to extend
    /// the type.
    #[allow(dead_code)]
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
                use std::fmt::Write as _;
                let _ = write!(out, "{f}");
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
}
