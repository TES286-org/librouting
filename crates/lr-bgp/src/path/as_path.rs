//! AS_PATH attribute (RFC 4271 §5.1.2 + RFC 4893 §7 AS4_PATH).

use core::fmt;
use lr_core::addr::Asn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AsPathType {
    /// AS_SET: an unordered set of ASes.
    Set = 1,
    /// AS_SEQUENCE: an ordered list of ASes.
    Sequence = 2,
    /// RFC 6793: AS_CONFED_SEQUENCE
    ConfedSequence = 3,
    /// RFC 6793: AS_CONFED_SET
    ConfedSet = 4,
}

impl AsPathType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Set,
            2 => Self::Sequence,
            3 => Self::ConfedSequence,
            4 => Self::ConfedSet,
            _ => return None,
        })
    }
}

/// A single AS_PATH segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPathSegment {
    pub kind: AsPathType,
    pub ases: Vec<Asn>,
}

/// AS_PATH attribute. Stored as a list of segments. The wire encoding is
/// `[seg-type:1, seg-len:1, asn..., asn...]` repeated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_sequence(ases: impl IntoIterator<Item = Asn>) -> Self {
        Self {
            segments: vec![AsPathSegment {
                kind: AsPathType::Sequence,
                ases: ases.into_iter().collect(),
            }],
        }
    }

    /// Length of the AS_PATH in number of AS hops per RFC 4271 §9.1.2.2(a):
    /// each AS in an AS_SEQUENCE counts as one and an AS_SET counts as 1
    /// regardless of how many ASes it contains. AS_CONFED_SEQUENCE and
    /// AS_CONFED_SET segments are not counted (RFC 5065 §5.3).
    pub fn length(&self) -> usize {
        self.segments
            .iter()
            .map(|s| match s.kind {
                AsPathType::Sequence => s.ases.len(),
                AsPathType::Set => 1,
                AsPathType::ConfedSequence | AsPathType::ConfedSet => 0,
            })
            .sum()
    }

    /// Length of the AS_PATH counting every member of every segment
    /// (used when the operator opts into counting confederation segments
    /// via `BestPathConfig::count_confed_in_path_len`; the AS_SET rule
    /// from RFC 4271 §9.1.2.2(a) still applies).
    pub fn length_with_confed(&self) -> usize {
        self.segments
            .iter()
            .map(|s| match s.kind {
                AsPathType::Sequence | AsPathType::ConfedSequence => s.ases.len(),
                AsPathType::Set | AsPathType::ConfedSet => 1,
            })
            .sum()
    }

    /// The sequence of ASes (flattening only sequence segments). Useful for
    /// loop detection.
    pub fn as_sequence(&self) -> Vec<Asn> {
        self.segments
            .iter()
            .filter(|s| s.kind == AsPathType::Sequence || s.kind == AsPathType::ConfedSequence)
            .flat_map(|s| s.ases.clone())
            .collect()
    }

    /// True if `my_as` appears in any sequence segment (AS loop, RFC 4271
    /// §9.1.2.15).
    pub fn loop_check(&self, my_as: Asn) -> bool {
        self.segments
            .iter()
            .filter(|s| s.kind == AsPathType::Sequence || s.kind == AsPathType::ConfedSequence)
            .any(|s| s.ases.contains(&my_as))
    }

    /// Prepend `as` to the leftmost sequence segment, creating one if none.
    /// (Standard BGP behavior when advertising to eBGP peers.)
    pub fn prepend(&mut self, as_: Asn) {
        for seg in &mut self.segments {
            if seg.kind == AsPathType::Sequence {
                seg.ases.insert(0, as_);
                return;
            }
        }
        self.segments.insert(
            0,
            AsPathSegment {
                kind: AsPathType::Sequence,
                ases: vec![as_],
            },
        );
    }

    /// Prepend `as` as an `AS_CONFED_SEQUENCE` segment (RFC 5065 §4.1(b)):
    /// used when advertising to a peer in another Member-AS of the same
    /// confederation. The local AS is recorded in a confederation segment so
    /// it is invisible to peers outside the confederation after the
    /// confederation identifier is substituted on egress (see
    /// [`AsPath::strip_confed`]).
    ///
    /// An existing leftmost `AS_CONFED_SEQUENCE` is extended in place so the
    /// path keeps one confed segment (mirrors the `prepend` rule for
    /// `AS_SEQUENCE`); otherwise a fresh segment is inserted at the head.
    pub fn prepend_confed(&mut self, as_: Asn) {
        for seg in &mut self.segments {
            if seg.kind == AsPathType::ConfedSequence {
                seg.ases.insert(0, as_);
                return;
            }
        }
        self.segments.insert(
            0,
            AsPathSegment {
                kind: AsPathType::ConfedSequence,
                ases: vec![as_],
            },
        );
    }

    /// Remove every `AS_CONFED_SEQUENCE` / `AS_CONFED_SET` segment in place
    /// (RFC 5065 §4.1(c)(1)). A speaker advertising to a peer outside its
    /// confederation MUST strip the confederation-private segments: leaving
    /// them on the wire is a malformed-AS_PATH error that resets the session
    /// (RFC 4271 §6.3, RFC 5065 §5). Returns `true` if any segment was
    /// removed so the caller can decide whether to re-encode.
    pub fn strip_confed(&mut self) -> bool {
        let before = self.segments.len();
        self.segments
            .retain(|s| !matches!(s.kind, AsPathType::ConfedSequence | AsPathType::ConfedSet));
        self.segments.len() != before
    }

    /// True if the path carries any confederation-private segment
    /// (`AS_CONFED_SEQUENCE` / `AS_CONFED_SET`). Used by the ingress
    /// validator: a peer that is not a member of the local confederation
    /// MUST NOT send these (RFC 5065 §5).
    pub fn has_confed(&self) -> bool {
        self.segments
            .iter()
            .any(|s| matches!(s.kind, AsPathType::ConfedSequence | AsPathType::ConfedSet))
    }

    /// Decode 2-byte-AS AS_PATH.
    pub fn decode(b: &[u8]) -> Option<Self> {
        Self::decode_inner(b, false)
    }

    /// Decode 4-byte-AS AS4_PATH (RFC 4893).
    pub fn decode_4(b: &[u8]) -> Option<Self> {
        Self::decode_inner(b, true)
    }

    fn decode_inner(b: &[u8], wide: bool) -> Option<Self> {
        let mut out = Self::new();
        let mut i = 0;
        let as_width = if wide { 4 } else { 2 };
        while i < b.len() {
            if i + 2 > b.len() {
                return None;
            }
            let kind = AsPathType::from_u8(b[i])?;
            let count = b[i + 1] as usize;
            i += 2;
            if i + count * as_width > b.len() {
                return None;
            }
            let mut ases = Vec::with_capacity(count);
            for _ in 0..count {
                let a = if wide {
                    Asn(u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]))
                } else {
                    Asn(u16::from_be_bytes([b[i], b[i + 1]]) as u32)
                };
                ases.push(a);
                i += as_width;
            }
            out.segments.push(AsPathSegment { kind, ases });
        }
        Some(out)
    }

    /// Encode with 2-byte ASNs (legacy AS_PATH).
    pub fn encode_2(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for seg in &self.segments {
            out.push(seg.kind as u8);
            out.push(seg.ases.len() as u8);
            for a in &seg.ases {
                let v = a.0.min(0xffff) as u16;
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        out
    }

    /// Encode with 4-byte ASNs (AS4_PATH, RFC 4893).
    pub fn encode_4(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for seg in &self.segments {
            out.push(seg.kind as u8);
            out.push(seg.ases.len() as u8);
            for a in &seg.ases {
                out.extend_from_slice(&a.0.to_be_bytes());
            }
        }
        out
    }
}

/// Reconstruct the canonical (4-byte) AS path from the 2-byte AS_PATH and
/// the AS4_PATH attributes per RFC 6793 §4.2.3.
///
/// Rules applied:
/// - If `as4` is absent, the wire path is the answer.
/// - If the AS_PATH count is smaller than the AS4_PATH count, the AS4_PATH
///   is ignored and the wire path is used.
/// - Otherwise the leading `count(AS_PATH) − count(AS4_PATH)` AS numbers
///   (whole leading segments, per the RFC's segment rule) are taken from
///   the wire path and prepended to the AS4_PATH.
///
/// Both inputs are already decoded; `wire` is the AS_PATH decoded at the
/// session's negotiated width (2-byte when talking to an OLD speaker).
pub fn reconcile_as4(wire: &AsPath, as4: Option<&AsPath>) -> AsPath {
    let as4 = match as4 {
        Some(a) if !a.segments.is_empty() => a,
        _ => return wire.clone(),
    };
    let wire_count = as_path_count(wire);
    let as4_count = as_path_count(as4);
    if wire_count < as4_count {
        return wire.clone();
    }
    if wire_count == as4_count {
        return as4.clone();
    }

    // Take whole leading segments from the wire path until we have taken
    // `need` AS numbers, then prepend them to the AS4_PATH.
    let need = wire_count - as4_count;
    let mut taken = Vec::new();
    let mut taken_count = 0usize;
    for seg in &wire.segments {
        if taken_count >= need {
            break;
        }
        // Only sequence/set segments carry count; confed segments are
        // prepended when adjacent per the RFC, so include them whole.
        let seg_count = match seg.kind {
            AsPathType::Sequence | AsPathType::ConfedSequence => seg.ases.len(),
            AsPathType::Set | AsPathType::ConfedSet => 1,
        };
        if taken_count + seg_count > need {
            break;
        }
        taken.push(seg.clone());
        taken_count += seg_count;
    }
    // If whole segments were not enough (mid-segment split needed), fall
    // back to prepending the remainder of the path count via a truncated
    // leading sequence — the RFC allows taking "as many ... as necessary".
    let mut result = AsPath { segments: taken };
    if taken_count < need {
        let deficit = need - taken_count;
        for seg in &wire.segments {
            if seg.kind != AsPathType::Sequence {
                continue;
            }
            let take = seg.ases.len().min(deficit);
            if take > 0 {
                result.segments.push(AsPathSegment {
                    kind: AsPathType::Sequence,
                    ases: seg.ases[..take].to_vec(),
                });
                break;
            }
        }
    }
    result.segments.extend(as4.segments.clone());
    result
}

/// RFC 4271 §9.1.2.2(a) AS count: AS_SEQUENCE members + 1 per AS_SET;
/// confederation segments count per RFC 5065 §5.3(3) as zero.
fn as_path_count(path: &AsPath) -> usize {
    path.segments
        .iter()
        .map(|s| match s.kind {
            AsPathType::Sequence => s.ases.len(),
            AsPathType::Set => 1,
            AsPathType::ConfedSequence | AsPathType::ConfedSet => 0,
        })
        .sum()
}

impl fmt::Display for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, seg) in self.segments.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            match seg.kind {
                AsPathType::Set | AsPathType::ConfedSet => {
                    f.write_str("{")?;
                    for (j, a) in seg.ases.iter().enumerate() {
                        if j > 0 {
                            f.write_str(",")?;
                        }
                        write!(f, "{}", a)?;
                    }
                    f.write_str("}")?;
                }
                AsPathType::Sequence | AsPathType::ConfedSequence => {
                    for (j, a) in seg.ases.iter().enumerate() {
                        if j > 0 {
                            f.write_str(" ")?;
                        }
                        write!(f, "{}", a)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "as_path_tests.rs"]
mod tests;
