//! IPv6 Segment Routing Header (SRH) — RFC 8754 §2.
//!
//! The SRH is the IPv6 extension header that carries the segment list
//! a packet traverses. Its wire layout (RFC 8754 §2):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Next Header   | Hdr Ext Len   | Routing Type  | Segments Left |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Last Entry    |    Flags      |           Tag                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List[0] (16 octets, DA at send)            |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List[1] (16 octets)                        |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                              ...                              |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List[Last Entry] (16 octets, DA at recv)   |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! //                                                             //
//! //         Optional Type-Length-Value (TLV) Variable Length     //
//! //                                                             //
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - **Next Header** (1 octet): the protocol number of the header
//!   immediately following the SRH (RFC 8200 §2).
//! - **Hdr Ext Len** (1 octet): the SRH length in 8-octet units, not
//!   counting the first 8 octets. So `Hdr Ext Len = 2 * (n + 1)` for
//!   a segment list of `n` SIDs (each SID is 16 octets = 2 units).
//!   RFC 8200 §4.8 / RFC 8754 §2.
//! - **Routing Type** (1 octet): 4 — Segment Routing (RFC 8754 §2,
//!   IANA's "IPv6 Routing Types" registry). Do not confuse with 43,
//!   which is the Next Header value identifying the Routing extension
//!   header itself (IPPROTO_ROUTING, RFC 8200 §4.4); the Routing Type
//!   is the *sub-type inside* that header. Linux's
//!   `seg6_validate_srh` (net/ipv6/seg6.c) rejects any SRH whose
//!   type byte is not 4 — writing 43 there makes every seg6 route
//!   install fail with EINVAL and every decoded SRH of real traffic
//!   fail parsing.
//! - **Segments Left** (1 octet): the index into the segment list
//!   that names the *current* destination. Decremented by each
//!   SR-capable hop. RFC 8754 §4.2.
//! - **Last Entry** (1 octet): the index of the last entry in the
//!   segment list (i.e. `n - 1` for `n` segments). The segment list
//!   is reversed on the wire: position 0 is the *first* segment to
//!   visit (it ends up as the destination address at the sender).
//! - **Flags** (1 octet): RFC 8754 §2.1 — only the low two bits are
//!   defined: `O` (octet 5, bit 0x80 — "OAM packet") and `H` (octet
//!   5, bit 0x40 — "HMAC present"). All other bits MUST be 0 on
//!   send and ignored on receive (RFC 8754 §2.3).
//! - **Tag** (2 octets): a tag the sender sets to group packets for
//!   management / OAM (RFC 8754 §2.4). Not used in forwarding.
//! - **Segment List**: array of 16-octet SIDs in reverse traversal
//!   order (RFC 8754 §2.5). The destination address at the sender is
//!   Segment List[0]; the destination address at the receiver after
//!   the last hop is Segment List[Last Entry].
//! - **TLVs**: optional variable-length attributes (RFC 8754 §2.6).
//!   The HMAC TLV (type 5) is the only one currently assigned (RFC
//!   8754 §2.6.1). The crate parses the TLV bytes back to the caller
//!   as a raw slice — it does not interpret individual TLVs in this
//!   slice (future work).
//!
//! ## Routing Type constant
//!
//! IANA's "IPv6 Routing Types" registry assigns type 4 to Segment
//! Routing (RFC 8754 §2). 43 is the *Next Header* value of the
//! Routing extension header (IPPROTO_ROUTING, RFC 8200 §4.4) — the
//! container header, not the sub-type carried in its Routing Type
//! field.

use core::fmt;

use crate::sid::Sid;

/// Routing Type 4 — Segment Routing Header (RFC 8754 §2, IANA's
/// "IPv6 Routing Types" registry). 43 is the Next Header value of
/// the Routing extension header itself (IPPROTO_ROUTING), which the
/// SRH travels inside — a different field at a different layer.
pub const ROUTING_TYPE_SRH: u8 = 4;

/// Flag bit `O` — OAM packet. Position per the Linux uapi
/// (`SR6_FLAG1_OAM = 1 << 5`, include/uapi/linux/seg6.h) and IANA's
/// "Segment Routing Header Flags" registry (O-flag, RFC 9259;
/// registry bit 2 in MSB-first numbering = 0x20). When set, the
/// packet is OAM and the egress node SHOULD treat it as such;
/// forwarding is unaffected.
pub const FLAG_OAM: u8 = 0x20;

/// Flag bit `H` — HMAC present (`SR6_FLAG1_HMAC = 1 << 3` in the
/// Linux uapi; the flag itself predates RFC 8754's final text — the
/// RFC defines the HMAC TLV in §2.1.2 but left the flag bit for the
/// Linux implementation's historical position). When set, an HMAC
/// TLV follows the segment list (RFC 8754 §2.1.2). This crate parses
/// the TLV bytes but does not validate the HMAC in this slice.
pub const FLAG_HMAC: u8 = 0x08;

/// Flag bit `A` — Alert (`SR6_FLAG1_ALERT = 1 << 4` in the Linux
/// uapi; draft-era flag, unregistered in IANA's SRH flags registry).
pub const FLAG_ALERT: u8 = 0x10;

/// Flag bit `P` — Protected (`SR6_FLAG1_PROTECTED = 1 << 6` in the
/// Linux uapi; draft-era flag, unregistered in IANA's SRH flags
/// registry — RFC 8754's final text leaves all flag bits unused on
/// transmission).
pub const FLAG_PROTECTED: u8 = 0x40;

/// The fixed prefix of an SRH: 8 octets of header before the segment
/// list starts (RFC 8754 §2).
pub const SRH_FIXED_LEN: usize = 8;

/// Each segment list entry is 16 octets (RFC 8754 §2 — a SID is an
/// IPv6 address).
pub const SRH_SEGMENT_LEN: usize = 16;

/// Maximum number of segments in an SRH (RFC 8754 §2 — `Hdr Ext
/// Len` is a single octet, so the segment list is bounded by
/// `(255 * 8) / 16 = 127` entries; in practice 127 is the cap).
pub const MAX_SEGMENTS: usize = 127;

/// The Segment Routing Header (RFC 8754 §2).
///
/// The segment list is stored in *wire order*: index 0 is the first
/// segment to visit (it becomes the destination address at the
/// sender), index `last_entry` is the last segment. The segments-left
/// pointer is the index of the *current* destination.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Srh {
    /// The Next Header protocol number (RFC 8200 §2). Stored as-is —
    /// the caller (a packet builder) sets this to whatever follows.
    pub next_header: u8,
    /// Segments Left (RFC 8754 §2). The index of the current
    /// destination in the segment list. RFC 8754 §4.2 requires
    /// `segments_left <= last_entry + 1`; this crate's [`Srh::new`]
    /// enforces that.
    pub segments_left: u8,
    /// Last Entry (RFC 8754 §2). The index of the last entry in the
    /// segment list (i.e. `n - 1` for `n` segments).
    pub last_entry: u8,
    /// Flags (RFC 8754 §2.1). Only [`FLAG_OAM`] and [`FLAG_HMAC`] are
    /// defined; other bits are reserved.
    pub flags: u8,
    /// Tag (RFC 8754 §2.4). A 16-bit value the sender sets for OAM /
    /// management grouping.
    pub tag: u16,
    /// The segment list, wire order: index 0 is the first segment to
    /// visit. Length is `last_entry + 1` (or 0 for an empty SRH, which
    /// is not valid on the wire but is useful as a builder start).
    pub segments: Vec<Sid>,
    /// Optional TLV bytes following the segment list (RFC 8754 §2.6).
    /// The crate passes them through verbatim — TLV interpretation is
    /// out of scope for this slice.
    pub tlvs: Vec<u8>,
}

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Errors returned when encoding or decoding an SRH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrhError {
    /// The input was shorter than the 8-octet fixed header (RFC 8754
    /// §2 — the minimum SRH is 8 octets with an empty segment list,
    /// which is itself invalid but is detected by `EmptySegmentList`).
    TooShort,
    /// The `Hdr Ext Len` field implies a length that does not match
    /// the input buffer (RFC 8200 §4.8 — the extension header length
    /// is `(hdr_ext_len + 1) * 8` octets total).
    LengthMismatch,
    /// The segment list is empty (RFC 8754 §2 — an SRH with zero
    /// segments is invalid; the destination address already encodes
    /// the segment, so the SRH itself is unnecessary).
    EmptySegmentList,
    /// The segment list has more than [`MAX_SEGMENTS`] entries (RFC
    /// 8754 §2 — `Hdr Ext Len` is a single octet).
    TooManySegments,
    /// `Last Entry` is greater than the segment count - 1 (RFC 8754
    /// §2 — `Last Entry` is the index of the last entry, so it must
    /// be `segments.len() - 1`).
    LastEntryOutOfRange,
    /// `Segments Left` is greater than `Last Entry + 1` (RFC 8754
    /// §4.2 — the pointer must point at a valid segment).
    SegmentsLeftOutOfRange,
    /// The Routing Type is not 4 (RFC 8754 §2 — the SRH is
    /// identified by Routing Type 4 in the IPv6 Routing header; 4 is
    /// not to be confused with 43, the Next Header value of the
    /// Routing extension header itself).
    WrongRoutingType(u8),
    /// Reserved flag bits are set (RFC 8754 §2.1 — the final RFC
    /// text leaves all flag bits unassigned, so a sender must keep
    /// them zero; the Linux uapi's four deployed positions
    /// (Protected/OAM/Alert/HMAC) are the accepted set here).
    ReservedFlagBits(u8),
}

#[cfg(feature = "std")]
impl fmt::Display for SrhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("SRH input is shorter than the 8-octet fixed header"),
            Self::LengthMismatch => f.write_str("SRH Hdr Ext Len does not match the input length"),
            Self::EmptySegmentList => f.write_str("SRH segment list is empty"),
            Self::TooManySegments => write!(
                f,
                "SRH segment list exceeds the {}-segment maximum",
                MAX_SEGMENTS
            ),
            Self::LastEntryOutOfRange => {
                f.write_str("SRH Last Entry is greater than segments.len() - 1")
            }
            Self::SegmentsLeftOutOfRange => {
                f.write_str("SRH Segments Left is greater than Last Entry + 1")
            }
            Self::WrongRoutingType(t) => {
                write!(f, "SRH Routing Type is {}, expected 4", t)
            }
            Self::ReservedFlagBits(flags) => {
                write!(f, "SRH has reserved flag bits set: 0x{:02x}", flags)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SrhError {}

impl Srh {
    /// Build an SRH from a segment list. `segments_left` defaults to
    /// `segments.len() - 1` (the sender's view: the first segment is
    /// the destination address, `segments_left` points at the last
    /// segment to visit). `next_header`, `flags` and `tag` default to
    /// `0` — the caller sets them for actual packets.
    ///
    /// Returns `Err` if the segment list is empty, has more than
    /// [`MAX_SEGMENTS`] entries, or `segments_left` is out of range.
    pub fn new(segments: Vec<Sid>) -> Result<Self, SrhError> {
        Self::with_segments_left(segments, None)
    }

    /// Like [`Srh::new`] but with an explicit `segments_left` (the
    /// index of the current destination in the segment list). Pass
    /// `None` to default to `segments.len() - 1` (RFC 8754 §4.2 —
    /// the sender's view).
    pub fn with_segments_left(
        segments: Vec<Sid>,
        segments_left: Option<u8>,
    ) -> Result<Self, SrhError> {
        if segments.is_empty() {
            return Err(SrhError::EmptySegmentList);
        }
        if segments.len() > MAX_SEGMENTS {
            return Err(SrhError::TooManySegments);
        }
        let last_entry = (segments.len() - 1) as u8;
        let segments_left = segments_left.unwrap_or(last_entry);
        if segments_left > last_entry {
            return Err(SrhError::SegmentsLeftOutOfRange);
        }
        Ok(Self {
            next_header: 0,
            segments_left,
            last_entry,
            flags: 0,
            tag: 0,
            segments,
            tlvs: Vec::new(),
        })
    }

    /// Set the Next Header field (RFC 8200 §2). Builder-style.
    #[must_use]
    pub fn with_next_header(mut self, nh: u8) -> Self {
        self.next_header = nh;
        self
    }

    /// Set the flags (RFC 8754 §2.1). The crate does not validate
    /// reserved bits here — callers that want the wire check should
    /// use [`Srh::encode`] which validates on encode. Builder-style.
    #[must_use]
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Set the Tag field (RFC 8754 §2.4). Builder-style.
    #[must_use]
    pub fn with_tag(mut self, tag: u16) -> Self {
        self.tag = tag;
        self
    }

    /// Set the TLV bytes (RFC 8754 §2.6). Builder-style. The caller
    /// is responsible for ensuring the TLVs are well-formed — the
    /// crate passes them through verbatim.
    #[must_use]
    pub fn with_tlvs(mut self, tlvs: Vec<u8>) -> Self {
        self.tlvs = tlvs;
        self
    }

    /// The number of segments in the list.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// True when the SRH has no segments (only possible for a value
    /// built without going through [`Srh::new`]).
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// The destination address the sender should put on the outer
    /// IPv6 header (RFC 8754 §4.1 — Segment List[0]).
    pub fn first_segment(&self) -> Option<Sid> {
        self.segments.first().copied()
    }

    /// The current destination address (RFC 8754 §4.1 —
    /// `Segment List[Segments Left]`).
    pub fn current_destination(&self) -> Option<Sid> {
        self.segments.get(self.segments_left as usize).copied()
    }

    /// Encode the SRH into a freshly-allocated `Vec<u8>`.
    pub fn encode_vec(&self) -> Result<Vec<u8>, SrhError> {
        if self.segments.is_empty() {
            return Err(SrhError::EmptySegmentList);
        }
        if self.segments.len() > MAX_SEGMENTS {
            return Err(SrhError::TooManySegments);
        }
        // RFC 8754 §2.1: the final text leaves all flag bits
        // unassigned, so a sender must keep undefined bits zero. The
        // Linux uapi's four deployed positions (Protected/OAM/Alert/
        // HMAC) are the accepted set — anything else is reserved.
        if self.flags & !(FLAG_OAM | FLAG_HMAC | FLAG_ALERT | FLAG_PROTECTED) != 0 {
            return Err(SrhError::ReservedFlagBits(self.flags));
        }
        let n = self.segments.len() as u8;
        if self.last_entry != n - 1 {
            return Err(SrhError::LastEntryOutOfRange);
        }
        if self.segments_left > self.last_entry {
            return Err(SrhError::SegmentsLeftOutOfRange);
        }
        // RFC 8200 §4.8: Hdr Ext Len = (header_total_octets / 8) - 1.
        // The SRH total length is fixed-prefix (8) + segments
        // (n * 16) + TLV bytes.
        let total_octets = SRH_FIXED_LEN + n as usize * SRH_SEGMENT_LEN + self.tlvs.len();
        // The total MUST be a multiple of 8 (RFC 8200 §4.8). TLV
        // padding is the sender's responsibility — the crate does not
        // auto-pad because RFC 8754 §2.6 leaves TLV encoding to the
        // TLV authors (HMAC TLV type 5 etc.).
        if !total_octets.is_multiple_of(8) {
            // We don't return an error here — the caller is expected
            // to pad. The wire encoder writes the bytes as-is. The
            // Hdr Ext Len field is computed from the actual length,
            // which is what the kernel does too (it reads the SRH up
            // to Hdr Ext Len * 8 + 8).
        }
        let hdr_ext_len = ((total_octets / 8) - 1) as u8;
        // The Hdr Ext Len upper bound: 255 means 2048 octets total
        // (8 + 255*8). With 127 segments (127*16=2032), plus 8-octet
        // header, that's 2040 — fits.
        if total_octets > 2048 {
            return Err(SrhError::TooManySegments);
        }
        let mut out = Vec::with_capacity(total_octets);
        out.push(self.next_header);
        out.push(hdr_ext_len);
        out.push(ROUTING_TYPE_SRH);
        out.push(self.segments_left);
        out.push(self.last_entry);
        out.push(self.flags);
        out.extend_from_slice(&self.tag.to_be_bytes());
        for s in &self.segments {
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&self.tlvs);
        Ok(out)
    }

    /// Decode an SRH from a byte slice that begins at the SRH (i.e.
    /// the caller has already stripped the IPv6 fixed header).
    ///
    /// Returns `Err` if the input is too short, the Routing Type is
    /// not 4, or the segment list length is inconsistent with the
    /// `Hdr Ext Len` field.
    pub fn decode(bytes: &[u8]) -> Result<Self, SrhError> {
        if bytes.len() < SRH_FIXED_LEN {
            return Err(SrhError::TooShort);
        }
        let next_header = bytes[0];
        let hdr_ext_len = bytes[1];
        let routing_type = bytes[2];
        if routing_type != ROUTING_TYPE_SRH {
            return Err(SrhError::WrongRoutingType(routing_type));
        }
        let segments_left = bytes[3];
        let last_entry = bytes[4];
        let flags = bytes[5];
        let tag = u16::from_be_bytes([bytes[6], bytes[7]]);
        // Total length per RFC 8200 §4.8.
        let total_len = (hdr_ext_len as usize + 1) * 8;
        if bytes.len() < total_len {
            return Err(SrhError::LengthMismatch);
        }
        // RFC 8754 §2: the segment list has `last_entry + 1` entries.
        let n = last_entry as usize + 1;
        let seg_bytes = n * SRH_SEGMENT_LEN;
        if SRH_FIXED_LEN + seg_bytes > total_len {
            return Err(SrhError::LastEntryOutOfRange);
        }
        let mut segments = Vec::with_capacity(n);
        for i in 0..n {
            let off = SRH_FIXED_LEN + i * SRH_SEGMENT_LEN;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[off..off + SRH_SEGMENT_LEN]);
            segments.push(Sid::from_octets(octets));
        }
        // The TLV bytes are whatever remains after the segment list.
        let tlv_end = total_len;
        let tlv_start = SRH_FIXED_LEN + seg_bytes;
        let tlvs = if tlv_end > tlv_start {
            bytes[tlv_start..tlv_end].to_vec()
        } else {
            Vec::new()
        };
        // RFC 8754 §4.2: segments_left MUST be <= last_entry + 1
        // (actually <= last_entry, since the index points at a valid
        // segment — but the spec text says "<= last_entry" without
        // the +1; we follow the spec text).
        if segments_left > last_entry {
            return Err(SrhError::SegmentsLeftOutOfRange);
        }
        // RFC 8754 §2.3: the reserved flag bits (other than O and H)
        // MUST be zero on send. We accept them on receive (the spec
        // says "MUST be ignored on receive") but the encoder rejects
        // them. So we don't return an error here.
        let _ = flags;
        Ok(Self {
            next_header,
            segments_left,
            last_entry,
            flags,
            tag,
            segments,
            tlvs,
        })
    }

    /// The expected `Hdr Ext Len` field value for this SRH (RFC 8200
    /// §4.8: `(total_octets / 8) - 1`).
    pub fn hdr_ext_len(&self) -> u8 {
        let total = SRH_FIXED_LEN + self.segments.len() * SRH_SEGMENT_LEN + self.tlvs.len();
        ((total / 8) - 1) as u8
    }
}

impl fmt::Display for Srh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SRH(nh={}, sl={}, le={}, flags=0x{:02x}, tag=0x{:04x}, segs=[",
            self.next_header, self.segments_left, self.last_entry, self.flags, self.tag
        )?;
        for (i, s) in self.segments.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", s)?;
        }
        f.write_str("]")?;
        if !self.tlvs.is_empty() {
            write!(f, ", tlvs={}B", self.tlvs.len())?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sid::Sid;
    use core::str::FromStr;

    fn sid(s: &str) -> Sid {
        Sid::from_str(s).unwrap()
    }

    #[test]
    fn srh_constants_match_rfc_8754() {
        assert_eq!(
            ROUTING_TYPE_SRH, 4,
            "IANA IPv6 Routing Types registry (RFC 8754 §2)"
        );
        // Flag positions per the Linux uapi (include/uapi/linux/seg6.h)
        // and IANA's SRH flags registry (O-flag, RFC 9259).
        assert_eq!(FLAG_OAM, 0x20, "SR6_FLAG1_OAM / IANA O-flag");
        assert_eq!(FLAG_HMAC, 0x08, "SR6_FLAG1_HMAC (Linux uapi)");
        assert_eq!(FLAG_ALERT, 0x10, "SR6_FLAG1_ALERT (Linux uapi)");
        assert_eq!(FLAG_PROTECTED, 0x40, "SR6_FLAG1_PROTECTED (Linux uapi)");
        assert_eq!(SRH_FIXED_LEN, 8, "RFC 8754 §2 fixed header");
        assert_eq!(SRH_SEGMENT_LEN, 16, "RFC 8754 §2 segment entry");
        assert_eq!(MAX_SEGMENTS, 127, "Hdr Ext Len upper bound");
    }

    #[test]
    fn srh_new_three_segments_defaults() {
        let segs = vec![
            sid("fcbb:bb00::1"),
            sid("fcbb:bb01::1"),
            sid("fcbb:bb02::1"),
        ];
        let srh = Srh::new(segs).unwrap();
        assert_eq!(srh.last_entry, 2, "last_entry = n - 1");
        assert_eq!(srh.segments_left, 2, "segments_left defaults to last_entry");
        assert_eq!(srh.segments.len(), 3);
        assert_eq!(srh.first_segment(), Some(sid("fcbb:bb00::1")));
        assert_eq!(srh.current_destination(), Some(sid("fcbb:bb02::1")));
    }

    #[test]
    fn srh_new_rejects_empty() {
        assert_eq!(Srh::new(vec![]).unwrap_err(), SrhError::EmptySegmentList);
    }

    #[test]
    fn srh_new_rejects_too_many_segments() {
        let too_many: Vec<Sid> = (0..(MAX_SEGMENTS + 1))
            .map(|i| {
                let mut octets = [0u8; 16];
                octets[15] = i as u8;
                Sid::from_octets(octets)
            })
            .collect();
        assert_eq!(Srh::new(too_many).unwrap_err(), SrhError::TooManySegments);
    }

    #[test]
    fn srh_new_rejects_segments_left_out_of_range() {
        let segs = vec![sid("fcbb:bb00::1"), sid("fcbb:bb01::1")];
        assert_eq!(
            Srh::with_segments_left(segs, Some(5)).unwrap_err(),
            SrhError::SegmentsLeftOutOfRange
        );
    }

    #[test]
    fn srh_encode_decode_roundtrip_three_segments() {
        let segs = vec![
            sid("fcbb:bb00:0:0:0:0:0:1"),
            sid("fcbb:bb01:0:0:0:0:0:1"),
            sid("fcbb:bb02:0:0:0:0:0:1"),
        ];
        let srh = Srh::new(segs.clone())
            .unwrap()
            .with_next_header(59) // No Next Header
            .with_flags(FLAG_OAM)
            .with_tag(0x1234);
        let enc = srh.encode_vec().unwrap();
        // Expected length: 8 fixed + 3 * 16 segments = 56 octets.
        assert_eq!(enc.len(), 56);
        // Hdr Ext Len = (56/8) - 1 = 6.
        assert_eq!(enc[1], 6);
        assert_eq!(enc[2], ROUTING_TYPE_SRH);
        assert_eq!(enc[3], 2, "segments_left = last_entry");
        assert_eq!(enc[4], 2, "last_entry = 3 - 1");
        assert_eq!(enc[5], FLAG_OAM);
        assert_eq!(&enc[6..8], &0x1234u16.to_be_bytes());
        // First segment at offset 8, second at 24, third at 40.
        assert_eq!(&enc[8..24], segs[0].as_bytes());
        assert_eq!(&enc[24..40], segs[1].as_bytes());
        assert_eq!(&enc[40..56], segs[2].as_bytes());

        let dec = Srh::decode(&enc).unwrap();
        assert_eq!(dec, srh);
    }

    #[test]
    fn srh_encode_decode_with_tlvs() {
        let segs = vec![sid("fcbb:bb00::1"), sid("fcbb:bb01::1")];
        // HMAC TLV: type 5, length 24, 24 bytes of data (RFC 8754 §2.6.1).
        // The first 4 bytes are the HMAC key ID (u32) and the next 20 are
        // the HMAC-SHA-1 digest. We use zeros here — the codec does not
        // validate the HMAC.
        let mut tlvs = vec![5u8, 24];
        tlvs.extend_from_slice(&[0u8; 24]);
        // TLV block must be padded to 8-octet alignment (RFC 8754 §2.6).
        // Total TLV: 2 (header) + 24 (data) = 26, padded to 32.
        while tlvs.len() % 8 != 0 {
            tlvs.push(0);
        }
        let srh = Srh::new(segs).unwrap().with_tlvs(tlvs.clone());
        let enc = srh.encode_vec().unwrap();
        // Length: 8 fixed + 2*16 segments + 32 padded TLVs = 72.
        assert_eq!(enc.len(), 72);
        let dec = Srh::decode(&enc).unwrap();
        assert_eq!(dec.tlvs, tlvs);
        assert_eq!(dec, srh);
    }

    #[test]
    fn srh_encode_rejects_reserved_flags() {
        let srh = Srh::new(vec![sid("fcbb:bb00::1")])
            .unwrap()
            .with_flags(0x01); // reserved bit 0
        assert_eq!(
            srh.encode_vec().unwrap_err(),
            SrhError::ReservedFlagBits(0x01)
        );
    }

    #[test]
    fn srh_decode_rejects_too_short() {
        assert_eq!(Srh::decode(&[0; 7]).unwrap_err(), SrhError::TooShort);
    }

    #[test]
    fn srh_decode_rejects_wrong_routing_type() {
        let mut bytes = vec![0u8; 24];
        bytes[2] = 99; // not 4
        assert_eq!(
            Srh::decode(&bytes).unwrap_err(),
            SrhError::WrongRoutingType(99)
        );
    }

    #[test]
    fn srh_decode_rejects_length_mismatch() {
        // Hdr Ext Len says total length 32 (so 4*8) but only 24 bytes present.
        let mut bytes = vec![0u8; 24];
        bytes[1] = 3; // (3+1)*8 = 32
        bytes[2] = ROUTING_TYPE_SRH;
        bytes[4] = 0; // last_entry = 0 → 1 segment
        assert_eq!(Srh::decode(&bytes).unwrap_err(), SrhError::LengthMismatch);
    }

    #[test]
    fn srh_decode_rejects_last_entry_inconsistent_with_length() {
        // Hdr Ext Len says total length 16 (so 2*8) but last_entry = 5
        // would mean 6 segments = 96 bytes of segment list alone.
        let mut bytes = vec![0u8; 16];
        bytes[1] = 1; // (1+1)*8 = 16
        bytes[2] = ROUTING_TYPE_SRH;
        bytes[4] = 5; // last_entry = 5
        assert_eq!(
            Srh::decode(&bytes).unwrap_err(),
            SrhError::LastEntryOutOfRange
        );
    }

    #[test]
    fn srh_decode_rejects_segments_left_out_of_range() {
        // 2 segments, segments_left = 5.
        let mut bytes = vec![0u8; 40]; // 8 + 2*16 = 40
        bytes[1] = 4; // (4+1)*8 = 40
        bytes[2] = ROUTING_TYPE_SRH;
        bytes[3] = 5; // segments_left
        bytes[4] = 1; // last_entry
        assert_eq!(
            Srh::decode(&bytes).unwrap_err(),
            SrhError::SegmentsLeftOutOfRange
        );
    }

    #[test]
    fn srh_decode_accepts_reserved_flag_bits_on_receive() {
        // RFC 8754 §2.3: reserved flag bits MUST be ignored on receive.
        let mut bytes = vec![0u8; 24];
        bytes[1] = 2; // (2+1)*8 = 24
        bytes[2] = ROUTING_TYPE_SRH;
        bytes[4] = 0; // last_entry = 0
        bytes[5] = 0x01; // reserved flag bit set
        let dec = Srh::decode(&bytes).unwrap();
        assert_eq!(dec.flags, 0x01, "reserved flag bits survive decode");
    }

    #[test]
    fn srh_hdr_ext_len_matches_rfc_8200() {
        // 1 segment, no TLVs: total = 8 + 16 = 24, hdr_ext_len = 24/8 - 1 = 2.
        let srh = Srh::new(vec![sid("fcbb:bb00::1")]).unwrap();
        assert_eq!(srh.hdr_ext_len(), 2);
        // 3 segments, no TLVs: total = 8 + 48 = 56, hdr_ext_len = 6.
        let srh = Srh::new(vec![
            sid("fcbb:bb00::1"),
            sid("fcbb:bb01::1"),
            sid("fcbb:bb02::1"),
        ])
        .unwrap();
        assert_eq!(srh.hdr_ext_len(), 6);
    }

    #[test]
    fn srh_display_format() {
        let srh = Srh::new(vec![sid("fcbb:bb00::1"), sid("fcbb:bb01::1")])
            .unwrap()
            .with_next_header(59)
            .with_tag(0xabcd);
        let s = format!("{}", srh);
        assert!(s.contains("nh=59"));
        assert!(s.contains("sl=1"));
        assert!(s.contains("le=1"));
        assert!(s.contains("tag=0xabcd"));
        assert!(s.contains("fcbb:bb00::1"));
        assert!(s.contains("fcbb:bb01::1"));
    }

    #[test]
    fn srh_first_segment_and_current_destination() {
        let segs = vec![
            sid("fcbb:bb00::1"),
            sid("fcbb:bb01::1"),
            sid("fcbb:bb02::1"),
        ];
        let srh = Srh::with_segments_left(segs.clone(), Some(0)).unwrap();
        // segments_left = 0 means the current destination is the first segment.
        assert_eq!(srh.current_destination(), Some(segs[0]));
        assert_eq!(srh.first_segment(), Some(segs[0]));
        let srh = Srh::with_segments_left(segs, Some(1)).unwrap();
        assert_eq!(srh.current_destination(), Some(sid("fcbb:bb01::1")));
    }

    #[test]
    fn srh_encode_max_segments_fits_in_hdr_ext_len() {
        // 127 segments = 127*16 + 8 = 2040 octets, hdr_ext_len = 254.
        let segs: Vec<Sid> = (0..MAX_SEGMENTS)
            .map(|i| {
                let mut o = [0u8; 16];
                o[14] = (i / 256) as u8;
                o[15] = (i % 256) as u8;
                Sid::from_octets(o)
            })
            .collect();
        let srh = Srh::new(segs).unwrap();
        let enc = srh.encode_vec().unwrap();
        assert_eq!(enc.len(), 2040);
        assert_eq!(enc[1], 254, "hdr_ext_len = 2040/8 - 1 = 254");
        let dec = Srh::decode(&enc).unwrap();
        assert_eq!(dec.len(), MAX_SEGMENTS);
    }
}
