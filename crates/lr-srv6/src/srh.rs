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
//! |    Segment List[0] (16 octets — the LAST segment, §2)         |
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
//! | Segment List[Last Entry] (16 octets — FIRST segment, DA send) |
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
//! - **Segments Left** (1 octet): the index into the WIRE segment
//!   list that names the *current* destination. Decremented by each
//!   SR-capable hop (RFC 8754 §4.3.1 S15/S16: SL = SL - 1, DA =
//!   Segment List[SL]). The source sets SL = n - 1 (§4.1).
//! - **Last Entry** (1 octet): contains the index (zero based), in
//!   the Segment List, of the last element of the list — `n - 1`
//!   for `n` segments (RFC 8754 §2).
//! - **Flags** (1 octet): RFC 8754 §2 defines NO flags for the SRH
//!   — the figure shows eight unused bits that "MUST be 0 on
//!   transmission and ignored on receipt". The only value IANA has
//!   since registered is the O-flag at bit 2 (mask 0x20, RFC 9259);
//!   this crate's `FLAG_OAM` carries it. The other mask constants
//!   (`FLAG_HMAC`, `FLAG_ALERT`, `FLAG_PROTECTED`) mirror the Linux
//!   uapi's deployed bit positions and are accepted on receive, but
//!   no RFC assigns them.
//! - **Tag** (2 octets): a tag the sender sets to group packets for
//!   management / OAM (RFC 8754 §2.4). Not used in forwarding.
//! - **Segment List**: array of 16-octet SIDs, **encoded starting
//!   from the last segment of the SR Policy** (RFC 8754 §2): "the
//!   first element of the Segment List (Segment List[0]) contains
//!   the last segment of the SR Policy, the second element contains
//!   the penultimate segment of the SR Policy, and so on." The
//!   destination address at the sender is therefore Segment
//!   List[Last Entry] (the first segment visited); the packet's
//!   final destination is Segment List[0].
//!
//! This crate stores the list in **visit order** (index 0 = the
//! first segment visited) — the order `ip route ... encap seg6 segs
//! A,B,C` uses on its command line — and reverses it on the wire:
//! [`Srh::encode_vec`] writes `segments[n-1]` at wire position 0,
//! and [`Srh::decode`] reverses back. Linux's `seg6_do_srh` arms
//! the outer DA from `segments[segments_left]` of the wire list
//! (`net/ipv6/seg6_iptunnel.c`), so a multi-segment SRH encoded
//! without the reversal is forwarded straight to its final segment,
//! skipping every intermediate hop.
//! - **TLVs**: optional variable-length attributes (RFC 8754 §2.1).
//!   The registry (§8.2) assigns Pad1 (type 0, §2.1.1.1), PadN
//!   (type 4, §2.1.1.2) and HMAC (type 5, §2.1.3); values 1-3 are
//!   Reserved from earlier draft versions. The crate parses the TLV
//!   bytes back to the caller as a raw slice — it does not interpret
//!   individual TLVs in this slice (future work).
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

/// TLV option type `Pad1` (RFC 8200 §4.4.1 — the single-octet padding
/// option, no length or value field). Used by the SRH encoder to insert
/// exactly one padding octet when the unpadded TLV tail is seven octets
/// short of an 8-octet boundary.
pub const TLV_PAD1: u8 = 0;

/// TLV type `PadN` (RFC 8754 §2.1.1.2 — Type 4 in the SRH TLV
/// registry; values 1-3 are Reserved from earlier drafts, and the
/// RFC 8200 §4.4.2 numbering the drafts borrowed applies to the
/// Hop-by-Hop/Destination options, not the SRH). Two header octets
/// plus `length` zero-octet value bytes. Used by the SRH encoder for
/// alignment deltas of two through seven octets. A `PadN` with
/// `length = 0` pads two octets; `length = 5` pads the full seven.
pub const TLV_PADN: u8 = 4;

/// Maximum number of segments in an SRH (RFC 8754 §2 — `Hdr Ext
/// Len` is a single octet, so the segment list is bounded by
/// `(255 * 8) / 16 = 127` entries; in practice 127 is the cap).
pub const MAX_SEGMENTS: usize = 127;

/// The Segment Routing Header (RFC 8754 §2).
///
/// The segment list is stored in **visit order**: index 0 is the
/// first segment to visit (it becomes the destination address at the
/// sender), index `last_entry` is the final segment. The wire order
/// is the reverse (RFC 8754 §2 — Segment List[0] carries the *last*
/// segment of the SR Policy); [`Srh::encode_vec`] /
/// [`Srh::decode`] do the reversal in both directions. The
/// segments-left pointer is a WIRE index — the index into the
/// reversed list — exactly as it appears on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Srh {
    /// The Next Header protocol number (RFC 8200 §2). Stored as-is —
    /// the caller (a packet builder) sets this to whatever follows.
    pub next_header: u8,
    /// Segments Left (RFC 8754 §2). The index of the current
    /// destination in the segment list. RFC 8754 §4.3.1.1 S11
    /// requires `segments_left <= last_entry + 1`; this crate's
    /// [`Srh::new`] enforces that.
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
    /// The segment list, visit order: index 0 is the first segment to
    /// visit (the DA at the sender), the last element is the final
    /// segment. Length is `last_entry + 1` (or 0 for an empty SRH,
    /// which is not valid on the wire but is useful as a builder
    /// start). The wire order is the reverse (RFC 8754 §2).
    pub segments: Vec<Sid>,
    /// Optional TLV bytes following the segment list (RFC 8754 §2.1).
    /// The crate passes them through verbatim — TLV interpretation is
    /// out of scope for this slice. The encoder auto-appends Pad1 /
    /// PadN TLVs (RFC 8200 §4.4) so the SRH total length is always a
    /// multiple of 8 (RFC 8754 §2.2); callers that already pad
    /// correctly see no change.
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
    /// §4.3.1.1 S11 — the pointer must name a segment of the list
    /// or, at `Last Entry + 1`, the reduced-SRH state whose active
    /// segment the DA carries).
    SegmentsLeftOutOfRange,
    /// The Routing Type is not 4 (RFC 8754 §2 — the SRH is
    /// identified by Routing Type 4 in the IPv6 Routing header; 4 is
    /// not to be confused with 43, the Next Header value of the
    /// Routing extension header itself).
    WrongRoutingType(u8),
    /// Reserved flag bits are set (RFC 8754 §2 — the RFC text
    /// leaves all flag bits unassigned, so a sender must keep them
    /// zero; the IANA O-flag (RFC 9259, bit 0x20) and the Linux
    /// uapi's deployed positions (Protected/OAM/Alert/HMAC) are the
    /// accepted set here).
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
    /// Build an SRH from a segment list in visit order (index 0 =
    /// the first segment to visit, the DA at the sender — the same
    /// order `ip route ... encap seg6 segs A,B,C` takes on its
    /// command line). `segments_left` defaults to `segments.len() -
    /// 1` (RFC 8754 §4.1 — the source sets SL = n - 1, which names
    /// the first segment on the wire list). `next_header`, `flags`
    /// and `tag` default to `0` — the caller sets them for actual
    /// packets.
    ///
    /// Returns `Err` if the segment list is empty, has more than
    /// [`MAX_SEGMENTS`] entries, or `segments_left` is out of range.
    pub fn new(segments: Vec<Sid>) -> Result<Self, SrhError> {
        Self::with_segments_left(segments, None)
    }

    /// Like [`Srh::new`] but with an explicit `segments_left` — a
    /// WIRE index (RFC 8754 §2: the index into the reversed on-wire
    /// list; SL names the current destination). Pass `None` to
    /// default to `segments.len() - 1` (RFC 8754 §4.1 — the source
    /// view, naming the first segment).
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
        // RFC 8754 §4.3.1.1 S11 (identically RFC 8986 §4.1 S10):
        // discard only when Segments Left is GREATER than
        // Last Entry + 1 — SL == LE + 1 is the reduced-SRH source
        // state (§4.1.1: the DA already carries the active segment,
        // the list starts one further down the path; the RFC's own
        // §6.3.2 examples carry `SL=1` over one list entry).
        if segments_left > last_entry.saturating_add(1) {
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

    /// Set the TLV bytes (RFC 8754 §2.1). Builder-style. The caller
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

    /// The destination address the sender puts on the outer IPv6
    /// header: the first segment to visit (RFC 8754 §4.1 — "The DA
    /// of the packet is set with the value of the first segment").
    /// On the wire that value sits at `Segment List[Last Entry]`
    /// (§2); in this crate's visit-order storage it is simply
    /// `segments[0]`.
    pub fn first_segment(&self) -> Option<Sid> {
        self.segments.first().copied()
    }

    /// The current destination address: the segment the packet is
    /// being sent to right now. RFC 8754 §4.3.1 S16 —
    /// `Segment List[Segments Left]` on the WIRE (reversed) list —
    /// which in visit-order storage is
    /// `segments[len - 1 - segments_left]`. At the source
    /// (`segments_left == len - 1`) this is the first segment, same
    /// as [`Srh::first_segment`]; each SR-capable hop decrements
    /// `segments_left`, advancing the destination one segment
    /// further down the visit order.
    pub fn current_destination(&self) -> Option<Sid> {
        let len = self.segments.len();
        if len == 0 {
            return None;
        }
        // `segments_left <= last_entry + 1 = len` is enforced by the
        // constructors and `decode`. At `segments_left == len` (the
        // reduced-SRH source state, RFC 8754 §4.1.1) the active
        // segment is the one the IPv6 DA already carries — it is not
        // in this list, so there is nothing to return.
        if self.segments_left as usize >= len {
            return None;
        }
        let idx = (len - 1) - self.segments_left as usize;
        self.segments.get(idx).copied()
    }

    /// Encode the SRH into a freshly-allocated `Vec<u8>`.
    pub fn encode_vec(&self) -> Result<Vec<u8>, SrhError> {
        if self.segments.is_empty() {
            return Err(SrhError::EmptySegmentList);
        }
        if self.segments.len() > MAX_SEGMENTS {
            return Err(SrhError::TooManySegments);
        }
        // RFC 8754 §2: the RFC text leaves all flag bits unassigned,
        // so a sender must keep undefined bits zero. The IANA O-flag
        // (RFC 9259, bit 0x20) and the Linux uapi's four deployed
        // positions (Protected/OAM/Alert/HMAC) are the accepted set
        // — anything else is reserved.
        if self.flags & !(FLAG_OAM | FLAG_HMAC | FLAG_ALERT | FLAG_PROTECTED) != 0 {
            return Err(SrhError::ReservedFlagBits(self.flags));
        }
        let n = self.segments.len() as u8;
        if self.last_entry != n - 1 {
            return Err(SrhError::LastEntryOutOfRange);
        }
        // RFC 8754 §4.3.1.1 S11: only SL > Last Entry + 1 is invalid
        // (SL == LE + 1 is the reduced-SRH source state, §4.1.1).
        if self.segments_left > self.last_entry.saturating_add(1) {
            return Err(SrhError::SegmentsLeftOutOfRange);
        }
        // RFC 8200 §4.8: Hdr Ext Len = (header_total_octets / 8) - 1.
        // The SRH total length is fixed-prefix (8) + segments
        // (n * 16) + TLV bytes.
        let unpadded_octets = SRH_FIXED_LEN + n as usize * SRH_SEGMENT_LEN + self.tlvs.len();
        // RFC 8200 §4.8 / RFC 8754 §2.2: the SRH total length MUST be
        // a multiple of 8 octets. The encoder auto-pads the TLV tail
        // with Pad1 (RFC 8200 §4.4.1) for a single missing octet or
        // PadN (§4.4.2) for two through seven octets — the wire never
        // leaves the crate misaligned, so callers do not need to
        // pre-pad their TLVs. A caller that already padded correctly
        // hits `pad == 0` and the output is byte-for-byte unchanged.
        let pad = (8 - (unpadded_octets % 8)) % 8;
        let total_octets = unpadded_octets + pad;
        let hdr_ext_len = ((total_octets / 8) - 1) as u8;
        // The Hdr Ext Len upper bound: 255 means 2048 octets total
        // (8 + 255*8). With 127 segments (127*16=2032), plus 8-octet
        // header, that's 2040 — fits even before TLV padding.
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
        // RFC 8754 §2: the wire list is encoded starting from the
        // LAST segment of the SR Policy — Segment List[0] carries
        // the final destination, Segment List[Last Entry] the first
        // segment visited. The crate stores visit order (index 0 =
        // first visited), so the encode walk emits the segments in
        // reverse. Emitting them in storage order put the first
        // visited segment at wire position 0, so a compliant
        // receiver (or the Linux kernel, `seg6_do_srh`) read the
        // FINAL segment out of `Segment List[Segments Left]` and
        // forwarded the packet straight to the end of the path,
        // skipping every intermediate hop.
        for s in self.segments.iter().rev() {
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&self.tlvs);
        // Append the auto-padding TLV (RFC 8200 §4.4.1 Pad1 for d=1,
        // §4.4.2 PadN for d>=2). The decode path treats the bytes as
        // part of the TLV region verbatim, so a round-trip is stable:
        // the next encode sees the PadN inside `tlvs`, computes
        // `unpadded_octets % 8 == 0` and appends nothing.
        match pad {
            0 => {}
            1 => out.push(TLV_PAD1),
            d => {
                out.push(TLV_PADN);
                out.push((d - 2) as u8);
                // PadN value: `d - 2` zero octets. `resize` extends
                // the Vec in one grow, no per-octet push loop.
                out.resize(out.len() + d - 2, 0);
            }
        }
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
        // RFC 8754 §2: wire position 0 carries the LAST segment of
        // the SR Policy. Reverse into visit order (index 0 = the
        // first segment visited = the DA at the sender) so the
        // decoded struct round-trips through `encode_vec` and reads
        // the way the builder wrote it.
        let mut segments = Vec::with_capacity(n);
        for i in 0..n {
            let off = SRH_FIXED_LEN + i * SRH_SEGMENT_LEN;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[off..off + SRH_SEGMENT_LEN]);
            segments.push(Sid::from_octets(octets));
        }
        segments.reverse();
        // The TLV bytes are whatever remains after the segment list.
        let tlv_end = total_len;
        let tlv_start = SRH_FIXED_LEN + seg_bytes;
        let tlvs = if tlv_end > tlv_start {
            bytes[tlv_start..tlv_end].to_vec()
        } else {
            Vec::new()
        };
        // RFC 8754 §4.3.1.1 S11 (identically RFC 8986 §4.1 S10):
        // discard only when Segments Left is greater than
        // (Last Entry + 1). SL == LE + 1 is the reduced-SRH source
        // state (§4.1.1: the DA carries the active segment and the
        // list starts one further down the path).
        if segments_left > last_entry.saturating_add(1) {
            return Err(SrhError::SegmentsLeftOutOfRange);
        }
        // RFC 8754 §2: the flag bits are unused and "MUST be ignored
        // on receipt" — accept them here; the encoder rejects the
        // unassigned ones on send.
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
    /// §4.8: `(total_octets / 8) - 1`). The total includes the
    /// auto-padding [`Srh::encode_vec`] appends to reach the 8-octet
    /// alignment RFC 8754 §2.2 requires, so the value matches the
    /// bytes the encoder actually writes.
    pub fn hdr_ext_len(&self) -> u8 {
        let unpadded = SRH_FIXED_LEN + self.segments.len() * SRH_SEGMENT_LEN + self.tlvs.len();
        let pad = (8 - (unpadded % 8)) % 8;
        ((unpadded + pad) / 8 - 1) as u8
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
        // RFC 8754 §4.1: at the source (SL = n-1) the current
        // destination is the FIRST segment — the same address the
        // sender puts on the outer IPv6 header.
        assert_eq!(srh.current_destination(), Some(sid("fcbb:bb00::1")));
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
        // RFC 8754 §2: "The Segment List is encoded starting from
        // the last segment of the SR Policy" — wire position 0 (offset
        // 8) carries the FINAL segment, wire position Last Entry
        // (offset 40) carries the FIRST segment visited. The builder's
        // visit order [segs[0], segs[1], segs[2]] therefore lands on
        // the wire as [segs[2], segs[1], segs[0]].
        assert_eq!(&enc[8..24], segs[2].as_bytes(), "wire [0] = final segment");
        assert_eq!(&enc[24..40], segs[1].as_bytes());
        assert_eq!(
            &enc[40..56],
            segs[0].as_bytes(),
            "wire [Last Entry] = first visited (the DA at the sender)"
        );

        let dec = Srh::decode(&enc).unwrap();
        assert_eq!(dec, srh);
    }

    #[test]
    fn srh_wire_bytes_match_rfc_8754_two_segment_example() {
        // The exact wire shape a compliant sender produces for the
        // two-segment path 2001:db8:a::1 (first visited) ->
        // 2001:db8:b::1 (final). Pinned against the RFC 8754 §2
        // encoding rule and Linux/iproute2: `ip -6 route add ...
        // encap seg6 mode encap segs 2001:db8:a::1,2001:db8:b::1`
        // builds this SRH (iproute2's parse_encap_seg6 reverses the
        // user-given visit order into the wire list).
        let first = sid("2001:db8:a::1");
        let last = sid("2001:db8:b::1");
        let srh = Srh::new(vec![first, last]).unwrap();
        let enc = srh.encode_vec().unwrap();
        assert_eq!(enc.len(), 40, "8 fixed + 2 segments");
        assert_eq!(enc[0], 0, "next header");
        assert_eq!(enc[1], 4, "hdr ext len = (40/8) - 1");
        assert_eq!(enc[2], ROUTING_TYPE_SRH);
        assert_eq!(enc[3], 1, "segments left = n - 1");
        assert_eq!(enc[4], 1, "last entry = n - 1");
        // Wire list: [last, first] — Segment List[0] is the FINAL
        // segment (RFC 8754 §2), Segment List[Last Entry] is the
        // first visited (the DA at the sender).
        assert_eq!(&enc[8..24], last.as_bytes());
        assert_eq!(&enc[24..40], first.as_bytes());

        // A compliant receiver decodes back to visit order.
        let dec = Srh::decode(&enc).unwrap();
        assert_eq!(dec.segments, vec![first, last]);
        assert_eq!(dec.current_destination(), Some(first));
        // SL = 0 names the wire Segment List[0] — the final segment.
        let done = Srh::with_segments_left(vec![first, last], Some(0)).unwrap();
        assert_eq!(done.current_destination(), Some(last));
    }

    #[test]
    fn srh_hop_walk_advances_the_destination() {
        // Simulate the per-hop processing of RFC 8754 §4.3.1
        // (S15/S16): each SR-capable hop decrements Segments Left and
        // sets DA = wire Segment List[SL]. With visit-order storage
        // the walk must visit the segments in builder order and end
        // at the final segment.
        let segs = vec![
            sid("fcbb:bb00::1"),
            sid("fcbb:bb01::1"),
            sid("fcbb:bb02::1"),
        ];
        let mut srh = Srh::new(segs.clone()).unwrap();
        let mut hop = 0;
        loop {
            let da = srh.current_destination().expect("a live destination");
            assert_eq!(da, segs[hop], "hop {hop} heads for the right segment");
            if srh.segments_left == 0 {
                break;
            }
            srh.segments_left -= 1; // S15
            hop += 1;
        }
        assert_eq!(hop, 2, "three segments = two intermediate hops");
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
        // RFC 8754 §2: the flag bits are unused and MUST be ignored on receive.
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
        // segments_left is a WIRE index (RFC 8754 §2: the reversed
        // list). SL = 2 = Last Entry names the wire Segment
        // List[Last Entry] — the first segment visited, the DA at
        // the sender.
        let srh = Srh::with_segments_left(segs.clone(), Some(2)).unwrap();
        assert_eq!(srh.current_destination(), Some(segs[0]));
        assert_eq!(srh.first_segment(), Some(segs[0]));
        // SL = 1 names the wire Segment List[1] — the middle segment.
        let srh = Srh::with_segments_left(segs.clone(), Some(1)).unwrap();
        assert_eq!(srh.current_destination(), Some(sid("fcbb:bb01::1")));
        // SL = 0 names the wire Segment List[0] — the FINAL segment
        // (RFC 8754 §2: wire position 0 carries the last segment of
        // the SR Policy).
        let srh = Srh::with_segments_left(segs, Some(0)).unwrap();
        assert_eq!(srh.current_destination(), Some(sid("fcbb:bb02::1")));
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

    // Regression for the SRH 8-octet alignment bug. Before the fix,
    // `encode_vec` left the TLV tail misaligned when the caller's TLVs
    // did not themselves pad to an 8-octet boundary — RFC 8200 §4.8 /
    // RFC 8754 §2.2 require the SRH total length to be a multiple of 8.
    #[test]
    fn srh_encode_pads_unaligned_tlv_tail() {
        let segs = vec![sid("fcbb:bb00::1")];
        // TLV tail of 3 octets: total = 8 + 16 + 3 = 27 — needs 5
        // octets of padding to reach 32. RFC 8754 §2.1.1.2 PadN
        // (type 4) with length=3: two header octets plus 3 zero-octet
        // value bytes. The pre-correction encoder wrote type 1 — a
        // Reserved value in the SRH TLV registry that draft versions
        // used.
        let srh = Srh::new(segs).unwrap().with_tlvs(vec![0xaa, 0xbb, 0xcc]);
        let enc = srh.encode_vec().unwrap();
        assert_eq!(
            enc.len(),
            32,
            "encoder must pad to the next 8-octet boundary"
        );
        assert_eq!(enc[1], 3, "hdr_ext_len = 32/8 - 1 = 3");
        // Fixed header (8) + one segment (16) = 24, then TLVs start at 24.
        // Caller's TLV (3 octets): 0xaa 0xbb 0xcc at indices 24..27.
        assert_eq!(&enc[24..27], &[0xaa, 0xbb, 0xcc]);
        // PadN TLV at indices 27..32: type 4, length 3, 3 zero octets.
        assert_eq!(enc[27], TLV_PADN);
        assert_eq!(enc[28], 3);
        assert_eq!(&enc[29..32], &[0, 0, 0]);
        // The decoder treats the PadN bytes as part of the TLV region
        // verbatim, so a round-trip is stable: re-encoding the decoded
        // SRH sees `tlvs.len() % 8 == 0` and appends nothing extra.
        let dec = Srh::decode(&enc).unwrap();
        assert_eq!(dec.tlvs, vec![0xaa, 0xbb, 0xcc, TLV_PADN, 3, 0, 0, 0]);
        let enc2 = dec.encode_vec().unwrap();
        assert_eq!(enc2, enc, "round-trip is byte-stable");
    }

    #[test]
    fn srh_encode_pads_single_octet_with_pad1() {
        let segs = vec![sid("fcbb:bb00::1")];
        // TLV tail of 7 octets: total = 8 + 16 + 7 = 31 — needs 1
        // octet of Pad1 (RFC 8200 §4.4.1) to reach 32.
        let srh = Srh::new(segs).unwrap().with_tlvs(vec![0xaa; 7]);
        let enc = srh.encode_vec().unwrap();
        assert_eq!(enc.len(), 32);
        assert_eq!(enc[31], TLV_PAD1, "trailing Pad1 octet");
        assert_eq!(enc[1], 3, "hdr_ext_len = 32/8 - 1 = 3");
    }

    #[test]
    fn srh_encode_no_padding_when_already_aligned() {
        let segs = vec![sid("fcbb:bb00::1")];
        // TLV tail of 8 octets: total = 8 + 16 + 8 = 32 — already
        // aligned, no padding appended.
        let srh = Srh::new(segs).unwrap().with_tlvs(vec![0xaa; 8]);
        let enc = srh.encode_vec().unwrap();
        assert_eq!(enc.len(), 32);
        assert_eq!(&enc[24..32], &[0xaa; 8], "no auto-padding bytes appended");
    }

    #[test]
    fn srh_encode_pads_every_delta_from_1_to_7() {
        // For each delta from 1 to 7, an unpadded tail of `8 - delta`
        // octets must round up to 8 — so total TLV (caller bytes +
        // auto-pad) is always 8 octets.
        for delta in 1..=7usize {
            let segs = vec![sid("fcbb:bb00::1")];
            let caller_len = 8 - delta;
            let srh = Srh::new(segs).unwrap().with_tlvs(vec![0x55; caller_len]);
            let enc = srh.encode_vec().unwrap();
            assert_eq!(
                enc.len(),
                8 + 16 + 8,
                "delta={delta}: encoder must pad to 8-octet alignment"
            );
            // hdr_ext_len = (8 + 16 + 8) / 8 - 1 = 3.
            assert_eq!(enc[1], 3);
        }
    }
}

// ---------------------------------------------------------------------------
// Audit H65 batch: the PadN TLV type, the reduced-SRH Segments Left
// bound and the padding-aware Hdr Ext Len.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod audit_tests {
    use super::*;

    fn sid(s: &str) -> Sid {
        s.parse().unwrap()
    }

    #[test]
    fn padn_tlv_type_is_4() {
        // RFC 8754 §2.1.1.2: "Type: 4". Value 1 is Reserved in the
        // SRH TLV registry (a draft-version number); the Linux
        // uapi's SR6_TLV_PADDING is likewise 4, so kernel-validated
        // SRHs never carried the pre-correction type 1.
        assert_eq!(TLV_PADN, 4);
    }

    #[test]
    fn reduced_srh_segments_left_eq_last_entry_plus_one_round_trips() {
        // RFC 8754 §4.1.1 + §6.3.2 (e.g. P6: "(A3,S7)(S4; SL=1)" —
        // one list entry, SL=1): the reduced SRH omits the first
        // segment (it is the DA), sets Last Entry = n-2 and leaves
        // Segments Left one past the list. §4.3.1.1 S11 discards
        // only when SL is GREATER than Last Entry + 1.
        let srh = Srh::with_segments_left(vec![sid("2001:db8:a::4")], Some(1)).unwrap();
        assert_eq!(srh.segments_left, 1);
        assert_eq!(srh.last_entry, 0);
        let enc = srh.encode_vec().unwrap();
        let dec = Srh::decode(&enc).unwrap();
        assert_eq!(dec, srh);
        // The active segment is the one the DA carries, not a list
        // entry.
        assert_eq!(dec.current_destination(), None);
        // SL past LE+1 is still rejected.
        assert!(matches!(
            Srh::with_segments_left(vec![sid("2001:db8:a::4")], Some(2)),
            Err(SrhError::SegmentsLeftOutOfRange)
        ));
    }

    #[test]
    fn hdr_ext_len_accounts_for_auto_padding() {
        // RFC 8200 §4.8: Hdr Ext Len = total_octets/8 - 1 over the
        // bytes the encoder writes — including the auto-padding that
        // reaches the 8-octet alignment RFC 8754 §2.2 requires. With
        // one segment and a 3-octet TLV tail the padded total is 32,
        // so Hdr Ext Len is 3 (the pre-fix method reported 2).
        let srh = Srh::new(vec![sid("fcbb:bb00::1")])
            .unwrap()
            .with_tlvs(vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(srh.hdr_ext_len(), 3);
        let enc = srh.encode_vec().unwrap();
        assert_eq!(enc[1], 3);
        assert_eq!(enc[1], srh.hdr_ext_len());
    }
}
