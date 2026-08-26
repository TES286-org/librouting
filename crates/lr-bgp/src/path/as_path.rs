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

    /// Length of the AS_PATH in number of AS hops (counting only sequence
    /// segments, per RFC 4271 §9.1.2.2).
    pub fn length(&self) -> usize {
        self.segments
            .iter()
            .filter(|s| s.kind == AsPathType::Sequence || s.kind == AsPathType::ConfedSequence)
            .map(|s| s.ases.len())
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
mod tests {
    use super::*;

    #[test]
    fn roundtrip_2byte() {
        let mut p = AsPath::from_sequence([Asn(100), Asn(200)]);
        p.prepend(Asn(50));
        let enc = p.encode_2();
        let dec = AsPath::decode(&enc).unwrap();
        assert_eq!(dec, p);
        assert_eq!(dec.length(), 3);
        assert!(dec.loop_check(Asn(200)));
        assert!(!dec.loop_check(Asn(999)));
    }

    #[test]
    fn roundtrip_4byte() {
        let p = AsPath::from_sequence([Asn(70000), Asn(80000)]);
        let enc = p.encode_4();
        let dec = AsPath::decode_4(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn set_and_sequence() {
        let p = AsPath {
            segments: vec![
                AsPathSegment {
                    kind: AsPathType::Sequence,
                    ases: vec![Asn(1), Asn(2)],
                },
                AsPathSegment {
                    kind: AsPathType::Set,
                    ases: vec![Asn(3), Asn(4)],
                },
            ],
        };
        let enc = p.encode_4();
        let dec = AsPath::decode_4(&enc).unwrap();
        assert_eq!(dec, p);
        // length counts only sequence segments
        assert_eq!(p.length(), 2);
    }
}
