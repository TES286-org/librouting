//! Source spans and diagnostic rendering for the filter DSL.
//!
//! Every token, AST node and error produced by the filter front end
//! carries a [`Span`] — a half-open byte range into the filter body
//! source it was parsed from. Spans are what turns "parse error"
//! messages into positioned, editor-clickable diagnostics and what
//! the `#18` config-DSL migration builds on (Phase 0: spans +
//! structured diagnostics).
//!
//! Columns are **byte columns** (1-indexed), matching the lexer's
//! cursor, which advances one column per byte. Filter bodies are
//! overwhelmingly ASCII (identifiers, punctuation, prefixes); a
//! multi-byte UTF-8 sequence inside a string literal counts as one
//! column per byte, the same convention the C toolchain uses for
//! its diagnostics.

use core::fmt;
use core::fmt::Write as _;

/// A half-open byte range `[start, end)` into the filter source.
///
/// `start == end` is a *point* span (e.g. the EOF token, or an error
/// with no meaningful extent). The default span is the empty span at
/// offset 0 — used as a placeholder where no source position is
/// known (synthetic nodes in tests, programmatic construction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Span {
    /// Byte offset of the first byte of the range.
    pub start: u32,
    /// Byte offset one past the last byte of the range.
    pub end: u32,
}

impl Span {
    /// Build a span from a half-open byte range. An inverted range
    /// (`end < start`) is swapped so the span always covers both
    /// endpoints — callers computing `end` from a lookahead can
    /// never produce an empty garbage span.
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start: start.min(end) as u32,
            end: end.max(start) as u32,
        }
    }

    /// A point span covering the single byte at `offset`.
    pub fn point(offset: usize) -> Self {
        Self::new(offset, offset + 1)
    }

    /// The span covering the union of two spans (for composite nodes:
    /// an expression spans from its first token to its last).
    pub fn merge(self, other: Span) -> Span {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    /// `true` when the span covers no bytes.
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// The span length in bytes.
    pub fn len(self) -> usize {
        (self.end - self.start) as usize
    }

    /// Slice the source with this span. Returns `None` when the span
    /// is out of bounds or does not land on a UTF-8 character
    /// boundary (a defensive guard — lexer-produced spans always
    /// do).
    pub fn slice(self, src: &str) -> Option<&str> {
        src.get(self.start as usize..self.end as usize)
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

/// Byte offset of every line start in a source text — the
/// offset `(line, col)` translation table.
///
/// Built once per filter body at parse time and carried on the
/// compiled [`crate::filter::ast::Filter`], so runtime errors can
/// render `line:col` without keeping the whole source alive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LineIndex {
    /// Byte offset of the first byte of each line. `line_starts[0]`
    /// is always 0.
    line_starts: Vec<u32>,
    /// Total byte length of the indexed source — past-end offsets
    /// clamp to the EOF position (end of the last line).
    len: u32,
}

impl LineIndex {
    /// Index a source text. O(n), one pass.
    pub fn new(src: &str) -> Self {
        let mut line_starts = vec![0u32];
        for (i, b) in src.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i as u32 + 1);
            }
        }
        Self {
            line_starts,
            len: src.len() as u32,
        }
    }

    /// Translate a byte offset to a 1-indexed `(line, col)` pair.
    /// Offsets past the end clamp to the EOF position (the end of
    /// the last line). Columns are byte columns, matching the lexer.
    pub fn line_col(&self, offset: u32) -> (u32, u32) {
        let offset = offset.min(self.len);
        let line = match self.line_starts.binary_search(&offset) {
            Ok(i) => i + 1, // offset is a line start; the *next* line
            Err(i) => i,    // offset falls on line i (0-indexed)
        };
        let line = line.max(1).min(self.line_starts.len());
        let line_start = self.line_starts[line - 1];
        let col = offset.saturating_sub(line_start) + 1;
        (line as u32, col)
    }

    /// Byte offset of the first byte of a 1-indexed line. Lines past
    /// the end clamp to the last line.
    pub fn line_start_of(&self, line: u32) -> u32 {
        let last = self.line_starts.len() as u32;
        let line = line.max(1).min(last);
        self.line_starts[line as usize - 1]
    }

    /// Number of lines in the indexed source.
    pub fn len(&self) -> usize {
        self.line_starts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.line_starts.len() <= 1
    }
}

/// Render a one-line diagnostic with a source snippet and caret:
///
/// ```text
///   |
/// 2 | if net ~ [ 10.0.0.0/8{16,24} ] then accept
///   |          ^^^^^^^^^^^^^^
/// ```
///
/// `message` is printed after the snippet (the caller prefixes the
/// error kind — e.g. `parse error:`). Multi-line spans are clamped to
/// their first line. The renderer never panics: out-of-bounds spans
/// are clamped to the source, `\r\n` line endings are handled, and
/// tabs in the snippet are preserved as-is (the caret line aligns by
/// byte column, the same approximation every byte-column diagnostic
/// uses).
pub fn render_snippet(src: &str, span: Span, message: &str) -> String {
    let index = LineIndex::new(src);
    let src_len = src.len() as u32;
    let start = span.start.min(src_len);
    let end = span.end.min(src_len).max(start);

    let (line_no, col) = index.line_col(start);
    let line_start = index.line_start_of(line_no);
    // End the quoted line at the first newline after the span start.
    let line_end = src[line_start as usize..]
        .find('\n')
        .map_or(src.len(), |i| line_start as usize + i);

    let line_text = src
        .get(line_start as usize..line_end)
        .unwrap_or("")
        .trim_end_matches('\r');

    let caret_col = (col as usize).saturating_sub(1).min(line_text.len());
    // Underline the span extent within this line (at least one caret).
    let span_in_line = end.saturating_sub(start).max(1) as usize;
    let caret_len = span_in_line
        .min(line_text.len().saturating_sub(caret_col))
        .max(1);

    let gutter = line_no.to_string();
    let pad = " ".repeat(gutter.len());
    let mut out = String::with_capacity(line_text.len() + message.len() + 64);
    let _ = writeln!(out, "{pad} |");
    let _ = writeln!(out, "{gutter} | {line_text}");
    let _ = write!(out, "{pad} | ");
    let _ = write!(out, "{}{}", " ".repeat(caret_col), "^".repeat(caret_len));
    if !message.is_empty() {
        let _ = write!(out, " {message}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_new_swaps_inverted_range() {
        let s = Span::new(10, 4);
        assert_eq!((s.start, s.end), (4, 10), "inverted range is swapped");
        let p = Span::new(7, 7);
        assert!(p.is_empty(), "equal endpoints stay a point span");
    }

    #[test]
    fn span_merge_covers_union() {
        let a = Span::new(2, 5);
        let b = Span::new(7, 9);
        assert_eq!(a.merge(b), Span::new(2, 9));
        assert_eq!(b.merge(a), Span::new(2, 9));
    }

    #[test]
    fn span_slice_round_trips() {
        let src = "if net ~ 10.0.0.0/8 { accept; }";
        let span = Span::new(9, 19);
        assert_eq!(span.slice(src), Some("10.0.0.0/8"));
    }

    #[test]
    fn line_index_basic() {
        let idx = LineIndex::new("ab\ncde\n\nf");
        assert_eq!(idx.len(), 4);
        assert_eq!(idx.line_col(0), (1, 1));
        assert_eq!(idx.line_col(1), (1, 2));
        assert_eq!(idx.line_col(3), (2, 1));
        assert_eq!(idx.line_col(5), (2, 3));
        assert_eq!(idx.line_col(8), (4, 1));
        // One past the last byte is the EOF position: end of line 4.
        assert_eq!(idx.line_col(9), (4, 2));
        assert_eq!(idx.line_col(10), (4, 2));
    }

    #[test]
    fn line_index_clamps_past_end() {
        let idx = LineIndex::new("abc");
        assert_eq!(idx.line_col(100), (1, 4));
    }

    #[test]
    fn line_index_crlf() {
        // \r is part of the line content; \n starts the next line.
        let idx = LineIndex::new("ab\r\ncd");
        assert_eq!(idx.line_col(0), (1, 1));
        assert_eq!(idx.line_col(4), (2, 1));
        assert_eq!(idx.line_col(5), (2, 2));
    }

    #[test]
    fn snippet_renders_caret_under_span() {
        let src = "let x = 1;\nif y > 2 { accept; }";
        // Span covers `y` on line 2 (offset 14..15).
        let span = Span::new(14, 15);
        let out = render_snippet(src, span, "undefined variable 'y'");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("if y > 2 { accept; }"));
        assert!(lines[1].starts_with("2 | "));
        // The caret sits under the `y`.
        assert!(lines[2].contains("^ undefined variable 'y'"));
        assert_eq!(lines[2].find('^'), lines[1].find('y'));
    }

    #[test]
    fn snippet_never_panics_on_out_of_bounds() {
        let src = "abc";
        let _ = render_snippet(src, Span::new(0, 100), "boom");
        let _ = render_snippet("", Span::default(), "empty");
        let _ = render_snippet("x", Span::new(usize::MAX, usize::MAX), "far");
    }

    #[test]
    fn snippet_accepts_max_offsets() {
        // Same as above but through the public Span type with u32::MAX
        // round-tripped through usize — guards the usize casts.
        let far = Span::new(u32::MAX as usize, u32::MAX as usize);
        assert_eq!(far.start as usize, u32::MAX as usize);
    }

    #[test]
    fn snippet_handles_crlf() {
        let src = "let a = 1;\r\naccept;";
        let out = render_snippet(src, Span::new(4, 5), "here");
        assert!(!out.contains('\r'));
        assert!(out.contains("let a = 1;"));
    }

    #[test]
    fn snippet_multiline_span_clamps_to_first_line() {
        let src = "if a {\n  accept;\n}";
        let span = Span::new(3, src.len());
        let out = render_snippet(src, span, "block");
        assert!(out.contains("if a {"));
    }
}
