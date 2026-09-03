//! MRT routing information export format (RFC 6396).
//!
//! MRT is *the* interchange format for routing tables: BIRD (`protocol
//! mrt`), FRR (`bgpd -M mrt`), RouteViews collectors and every
//! route-analysis tool speak it. This crate is the format half of the
//! operational tooling — the counterpart of [`lr_bmp`]:
//!
//! - **Reading** ([`MrtReader`], `parse_file`): streaming decoder for
//!   `TABLE_DUMP_V2` (peer index tables + per-prefix RIB records, IPv4
//!   and IPv6, plain and RFC 7911 Add-Path) and `BGP4MP` (state changes
//!   and messages, 2- and 4-byte AS). Unknown records surface as
//!   [`MrtRecord::Unknown`] so a forward-compatible tool keeps going.
//! - **Writing** ([`MrtRibDump`]): a full RIB dump — one peer index
//!   table plus one `RIB_IPV{4,6}_UNICAST[_ADDPATH]` record per prefix —
//!   the same shape BIRD's `protocol mrt` emits, verified against
//!   BIRD 2.17 output by the interop suite.
//!
//! Path attributes are carried as raw bytes (`flags | type | len |
//! value` TLVs); with the default `bgp` feature, [`AttrSummary`]
//! interprets them (AS path, next hop, communities, LOCAL_PREF, MED)
//! using the `lr-bgp` decoders.
//!
//! Layout reference (RFC 6396 §4.3 / §4.4), little detail worth
//! repeating: a `RIB_*` record is `sequence(4) | prefix_len(1) |
//! prefix(packed) | entry_count(2) | entries[]`, and each entry is
//! `peer_index(2) | originated_time(4) | [path_id(4)] |
//! attr_len(2) | attrs`. A `BGP4MP_MESSAGE` entry carries a *complete*
//! BGP message including the 16-byte marker.

#![cfg_attr(not(feature = "std"), forbid(unsafe_code))]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use lr_core::addr::{Asn, IpAddr, Prefix};
use lr_core::buf::ReadBuf;
use lr_core::codec::Decoder;
use lr_core::error::{EncodeError, ParseError};

/// MRT record types (RFC 6396 §4). Only the types librouting consumes
/// are named; everything else decodes as [`MrtRecord::Unknown`].
pub mod msg_type {
    /// Legacy TABLE_DUMP (v1) — superseded by `TABLE_DUMP_V2`.
    pub const TABLE_DUMP: u16 = 12;
    /// TABLE_DUMP_V2 — peer index tables and per-prefix RIB records.
    pub const TABLE_DUMP_V2: u16 = 13;
    /// BGP4MP — BGP message and state-change log (2-byte AS).
    pub const BGP4MP: u16 = 16;
    /// BGP4MP with microsecond timestamps.
    pub const BGP4MP_ET: u16 = 17;
}

/// TABLE_DUMP_V2 subtypes (RFC 6396 §4.3).
pub mod tdv2_subtype {
    pub const PEER_INDEX_TABLE: u16 = 1;
    pub const RIB_IPV4_UNICAST: u16 = 2;
    pub const RIB_IPV4_MULTICAST: u16 = 3;
    pub const RIB_IPV6_UNICAST: u16 = 4;
    pub const RIB_IPV6_MULTICAST: u16 = 5;
    pub const RIB_GENERIC: u16 = 6;
    pub const RIB_IPV4_UNICAST_ADDPATH: u16 = 7;
    pub const RIB_IPV4_MULTICAST_ADDPATH: u16 = 8;
    pub const RIB_IPV6_UNICAST_ADDPATH: u16 = 9;
    pub const RIB_IPV6_MULTICAST_ADDPATH: u16 = 10;
    pub const RIB_GENERIC_ADDPATH: u16 = 11;
}

/// BGP4MP subtypes (RFC 6396 §4.4).
pub mod bgp4mp_subtype {
    pub const STATE_CHANGE: u16 = 0;
    pub const MESSAGE: u16 = 1;
    /// Deprecated pre-publication layout (Zebra `BGP4MP_ENTRY`) — decodes
    /// as [`MrtRecord::Unknown`].
    pub const ENTRY: u16 = 2;
    /// Deprecated pre-publication layout (Zebra `BGP4MP_SNAPSHOT`) —
    /// decodes as [`MrtRecord::Unknown`].
    pub const SNAPSHOT: u16 = 3;
    pub const MESSAGE_AS4: u16 = 4;
    pub const STATE_CHANGE_AS4: u16 = 5;
    /// Deprecated — decodes as [`MrtRecord::Unknown`].
    pub const MESSAGE_LOCAL: u16 = 6;
    /// Deprecated — decodes as [`MrtRecord::Unknown`].
    pub const MESSAGE_AS4_LOCAL: u16 = 7;
}

/// One peer of a [`PeerIndexTable`]. Peers are referenced from RIB
/// entries by index; index 0 is conventionally a synthetic local peer
/// for non-BGP routes (BIRD does exactly that).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// BGP identifier of the peer (0 for the synthetic local peer).
    pub bgp_id: u32,
    /// Peer IP address.
    pub ip: IpAddr,
    /// Peer AS number.
    pub asn: Asn,
}

/// TABLE_DUMP_V2 `PEER_INDEX_TABLE` (subtype 1): the collector's BGP
/// ID, the view name and the peer list RIB entries reference.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerIndexTable {
    /// BGP ID of the collector producing the dump.
    pub collector_bgp_id: u32,
    /// View name (BIRD: the table name, e.g. `"master4"`; may be empty).
    pub view_name: String,
    /// Peers, indexed by position (entry `peer_index` refers here).
    pub peers: Vec<PeerEntry>,
}

/// One RIB entry: the path attributes one peer contributed for a prefix.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RibEntry {
    /// Index into the dump's [`PeerIndexTable`].
    pub peer_index: u16,
    /// Unix time the route was originated/received.
    pub originated_time: u32,
    /// RFC 7911 path identifier (Add-Path records only; else 0).
    pub path_id: u32,
    /// Raw path attributes (`flags | type | len | value` TLVs).
    pub attributes: Vec<u8>,
}

/// One `RIB_*` record: every path (entry) one or more peers hold for a
/// single prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RibTable {
    /// Dump sequence number (increments per record).
    pub sequence: u32,
    /// The prefix this record describes.
    pub prefix: Prefix,
    /// True when the entries carry RFC 7911 path identifiers (the
    /// `_ADDPATH` subtypes).
    pub add_path: bool,
    /// One entry per contributing peer path.
    pub entries: Vec<RibEntry>,
}

/// The BGP4MP per-message header common to state changes and messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bgp4MpCommon {
    pub peer_as: Asn,
    pub local_as: Asn,
    /// Interface index the message was seen on.
    pub ifindex: u16,
    /// Address family (`1` = IPv4, `2` = IPv6).
    pub af: u16,
    pub peer_ip: IpAddr,
    pub local_ip: IpAddr,
}

/// `BGP4MP_STATE_CHANGE[_AS4]`: a BGP session transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bgp4MpStateChange {
    pub common: Bgp4MpCommon,
    pub old_state: u16,
    pub new_state: u16,
}

/// `BGP4MP_MESSAGE[_AS4]`: a complete BGP message (marker included)
/// sent or received by the monitored session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bgp4MpMessage {
    pub common: Bgp4MpCommon,
    /// Complete BGP message — 16-byte marker + length + type + body.
    pub message: Vec<u8>,
}

/// One decoded MRT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MrtRecord {
    PeerIndexTable(PeerIndexTable),
    Rib(RibTable),
    Bgp4MpStateChange(Bgp4MpStateChange),
    Bgp4MpMessage(Bgp4MpMessage),
    /// A recognized-but-unsupported record (legacy TABLE_DUMP, BGP4MP_ET
    /// microsecond variants, ...). Parsing continues past it.
    Unknown {
        msg_type: u16,
        subtype: u16,
    },
}

impl MrtRecord {
    /// Whether this is one of the `RIB_*` subtypes.
    pub fn is_rib(&self) -> bool {
        matches!(self, MrtRecord::Rib(_))
    }
}

/// Fixed MRT header length: timestamp(4) + type(2) + subtype(2) +
/// length(4).
const HEADER_LEN: usize = 12;

/// Upper bound on a single MRT record body (RFC 6396 §3). A RIB record
/// carries one BGP UPDATE per entry (≤ 4096 bytes), so 64 KiB is
/// generous; a malicious declared length must not grow the carryover
/// unboundedly.
const MAX_RECORD_BODY: usize = 65535;

/// Streaming MRT decoder. Feed arbitrary chunks; complete records come
/// out one at a time (the same contract as `lr_bmp::BmpCodec`).
#[derive(Default)]
pub struct MrtReader {
    carryover: Vec<u8>,
}

impl MrtReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer raw bytes.
    fn feed(&mut self, bytes: &[u8]) {
        self.carryover.extend_from_slice(bytes);
    }

    /// Decode the next complete buffered record, if any.
    fn next(&mut self) -> Result<Option<MrtRecord>, ParseError> {
        if self.carryover.len() < HEADER_LEN {
            return Ok(None);
        }
        let length = u32::from_be_bytes([
            self.carryover[8],
            self.carryover[9],
            self.carryover[10],
            self.carryover[11],
        ]) as usize;
        // A declared length beyond the record-size bound is malformed;
        // drop the buffer so one bad header cannot wedge the stream.
        if length > MAX_RECORD_BODY {
            self.carryover.clear();
            return Err(ParseError::bad_length(8, "mrt.length"));
        }
        if self.carryover.len() < HEADER_LEN + length {
            return Ok(None);
        }
        let record = decode_record(&self.carryover[..HEADER_LEN + length])?;
        self.carryover.drain(0..HEADER_LEN + length);
        Ok(Some(record))
    }

    /// Feed `bytes` and try to decode the next complete record.
    /// `Ok(None)` = need more bytes.
    pub fn decode_slice(&mut self, bytes: &[u8]) -> Result<Option<MrtRecord>, ParseError> {
        self.feed(bytes);
        self.next()
    }
}

impl Decoder<MrtRecord> for MrtReader {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<MrtRecord>, ParseError> {
        let chunk = src.chunk();
        let n = chunk.len();
        let record = self.decode_slice(chunk)?;
        src.advance(n);
        Ok(record)
    }
}

/// Decode one complete record (header + body).
fn decode_record(buf: &[u8]) -> Result<MrtRecord, ParseError> {
    let msg_type = u16::from_be_bytes([buf[4], buf[5]]);
    let subtype = u16::from_be_bytes([buf[6], buf[7]]);
    let body = &buf[HEADER_LEN..];
    match msg_type {
        msg_type::TABLE_DUMP_V2 => decode_tdv2(subtype, body),
        msg_type::TABLE_DUMP => Ok(MrtRecord::Unknown { msg_type, subtype }),
        msg_type::BGP4MP => decode_bgp4mp(subtype, body, false),
        msg_type::BGP4MP_ET => {
            // Same layout with a microsecond timestamp: the extra 4
            // bytes sit between the MRT header and the body.
            if body.len() < 4 {
                return Ok(MrtRecord::Unknown { msg_type, subtype });
            }
            decode_bgp4mp(subtype, &body[4..], true)
        }
        _ => Ok(MrtRecord::Unknown { msg_type, subtype }),
    }
}

/// TABLE_DUMP_V2 body decoder.
fn decode_tdv2(subtype: u16, body: &[u8]) -> Result<MrtRecord, ParseError> {
    if subtype == tdv2_subtype::PEER_INDEX_TABLE {
        return Ok(MrtRecord::PeerIndexTable(decode_peer_index_table(body)?));
    }
    let add_path = matches!(
        subtype,
        tdv2_subtype::RIB_IPV4_UNICAST_ADDPATH
            | tdv2_subtype::RIB_IPV4_MULTICAST_ADDPATH
            | tdv2_subtype::RIB_IPV6_UNICAST_ADDPATH
            | tdv2_subtype::RIB_IPV6_MULTICAST_ADDPATH
            | tdv2_subtype::RIB_GENERIC_ADDPATH
    );
    match subtype {
        tdv2_subtype::RIB_IPV4_UNICAST
        | tdv2_subtype::RIB_IPV4_UNICAST_ADDPATH
        | tdv2_subtype::RIB_IPV6_UNICAST
        | tdv2_subtype::RIB_IPV6_UNICAST_ADDPATH => {
            Ok(MrtRecord::Rib(decode_rib_table(subtype, body, add_path)?))
        }
        // Multicast/generic RIBs share the entry layout but carry
        // different AFI/SAFI semantics; treat them as opaque for now.
        _ => Ok(MrtRecord::Unknown {
            msg_type: msg_type::TABLE_DUMP_V2,
            subtype,
        }),
    }
}

/// `PEER_INDEX_TABLE` body: collector id, view name, peers.
fn decode_peer_index_table(body: &[u8]) -> Result<PeerIndexTable, ParseError> {
    let ctx = "mrt.peer_index_table";
    let mut r = Reader::new(body);
    let collector_bgp_id = r.u32(ctx)?;
    let name_len = r.u16(ctx)? as usize;
    let view_name = r.bytes(name_len, ctx)?;
    let view_name = String::from_utf8_lossy(view_name).into_owned();
    let peer_count = r.u16(ctx)? as usize;
    let mut peers = Vec::with_capacity(peer_count.min(1024));
    for i in 0..peer_count {
        let pctx = "mrt.peer_index_table.peer";
        let flags = r.u8(pctx)?;
        let ipv6 = flags & 0x01 != 0;
        let asn4 = flags & 0x02 != 0;
        let bgp_id = r.u32(pctx)?;
        let ip = if ipv6 {
            let b = r.bytes(16, pctx)?;
            IpAddr::V6([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
                b[13], b[14], b[15],
            ])
        } else {
            let b = r.bytes(4, pctx)?;
            IpAddr::V4([b[0], b[1], b[2], b[3]])
        };
        let asn = if asn4 {
            Asn(r.u32(pctx)?)
        } else {
            Asn(u32::from(r.u16(pctx)?))
        };
        let _ = i;
        peers.push(PeerEntry { bgp_id, ip, asn });
    }
    Ok(PeerIndexTable {
        collector_bgp_id,
        view_name,
        peers,
    })
}

/// `RIB_*` body: sequence, prefix, entry count, entries.
fn decode_rib_table(subtype: u16, body: &[u8], add_path: bool) -> Result<RibTable, ParseError> {
    let ctx = "mrt.rib_table";
    let ipv6 = matches!(
        subtype,
        tdv2_subtype::RIB_IPV6_UNICAST | tdv2_subtype::RIB_IPV6_UNICAST_ADDPATH
    );
    let mut r = Reader::new(body);
    let sequence = r.u32(ctx)?;
    let prefix = r.prefix(ipv6, ctx)?;
    let entry_count = r.u16(ctx)? as usize;
    let mut entries = Vec::with_capacity(entry_count.min(4096));
    for _ in 0..entry_count {
        let ectx = "mrt.rib_table.entry";
        let peer_index = r.u16(ectx)?;
        let originated_time = r.u32(ectx)?;
        let path_id = if add_path { r.u32(ectx)? } else { 0 };
        let attr_len = r.u16(ectx)? as usize;
        let attributes = r.bytes(attr_len, ectx)?.to_vec();
        entries.push(RibEntry {
            peer_index,
            originated_time,
            path_id,
            attributes,
        });
    }
    Ok(RibTable {
        sequence,
        prefix,
        add_path,
        entries,
    })
}

/// BGP4MP body decoder (header already consumed for `_ET` variants).
fn decode_bgp4mp(subtype: u16, body: &[u8], _et: bool) -> Result<MrtRecord, ParseError> {
    let ctx = "mrt.bgp4mp";
    let asn4 = matches!(
        subtype,
        bgp4mp_subtype::MESSAGE_AS4 | bgp4mp_subtype::STATE_CHANGE_AS4
    );
    let mut r = Reader::new(body);
    let common = read_bgp4mp_common(&mut r, asn4, ctx)?;
    match subtype {
        bgp4mp_subtype::STATE_CHANGE | bgp4mp_subtype::STATE_CHANGE_AS4 => {
            let old_state = r.u16(ctx)?;
            let new_state = r.u16(ctx)?;
            Ok(MrtRecord::Bgp4MpStateChange(Bgp4MpStateChange {
                common,
                old_state,
                new_state,
            }))
        }
        bgp4mp_subtype::MESSAGE | bgp4mp_subtype::MESSAGE_AS4 => {
            Ok(MrtRecord::Bgp4MpMessage(Bgp4MpMessage {
                common,
                message: r.rest().to_vec(),
            }))
        }
        _ => Ok(MrtRecord::Unknown {
            msg_type: msg_type::BGP4MP,
            subtype,
        }),
    }
}

/// The common BGP4MP prefix: peer/local AS, interface index, AF, IPs.
fn read_bgp4mp_common(
    r: &mut Reader<'_>,
    asn4: bool,
    ctx: &'static str,
) -> Result<Bgp4MpCommon, ParseError> {
    let peer_as = if asn4 {
        Asn(r.u32(ctx)?)
    } else {
        Asn(u32::from(r.u16(ctx)?))
    };
    let local_as = if asn4 {
        Asn(r.u32(ctx)?)
    } else {
        Asn(u32::from(r.u16(ctx)?))
    };
    let ifindex = r.u16(ctx)?;
    let af = r.u16(ctx)?;
    let ipv6 = af == 2;
    let peer_ip = r.ip(ipv6, ctx)?;
    let local_ip = r.ip(ipv6, ctx)?;
    Ok(Bgp4MpCommon {
        peer_as,
        local_as,
        ifindex,
        af,
        peer_ip,
        local_ip,
    })
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// A full RIB dump being written: the peer index table plus one record
/// per prefix. Mirrors the shape BIRD's `protocol mrt` produces.
#[derive(Debug, Clone, Default)]
pub struct MrtRibDump {
    pub collector_bgp_id: u32,
    pub view_name: String,
    pub peers: Vec<PeerEntry>,
    pub tables: Vec<RibTable>,
}

impl MrtRibDump {
    pub fn new(collector_bgp_id: u32, view_name: impl Into<String>) -> Self {
        Self {
            collector_bgp_id,
            view_name: view_name.into(),
            peers: Vec::new(),
            tables: Vec::new(),
        }
    }

    /// Append a peer and return its index.
    pub fn add_peer(&mut self, peer: PeerEntry) -> u16 {
        self.peers.push(peer);
        (self.peers.len() - 1) as u16
    }

    /// Append a per-prefix record.
    pub fn add_table(&mut self, table: RibTable) {
        self.tables.push(table);
    }

    /// Encode the whole dump: `PEER_INDEX_TABLE` first, then one
    /// `RIB_*` record per table (sequence numbers assigned in order).
    pub fn encode(&self, timestamp: u32) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        out.extend_from_slice(&encode_peer_index_table(
            timestamp,
            self.collector_bgp_id,
            &self.view_name,
            &self.peers,
        )?);
        for table in &self.tables {
            out.extend_from_slice(&encode_rib_table(timestamp, table)?);
        }
        Ok(out)
    }
}

/// Encode one complete record (header + body).
fn encode_record(subtype: u16, msg_type: u16, timestamp: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&subtype.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Encode a `PEER_INDEX_TABLE` record.
pub fn encode_peer_index_table(
    timestamp: u32,
    collector_bgp_id: u32,
    view_name: &str,
    peers: &[PeerEntry],
) -> Result<Vec<u8>, EncodeError> {
    let mut body = Vec::new();
    body.extend_from_slice(&collector_bgp_id.to_be_bytes());
    let name = view_name.as_bytes();
    let name = &name[..name.len().min(65535)];
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name);
    body.extend_from_slice(&(peers.len() as u16).to_be_bytes());
    for peer in peers {
        // Both BIRD and FRR always mark dumps 4-byte-AS these days; it
        // keeps the writer branch-free and matches the reference output.
        let flags: u8 = 0x02 | u32::from(peer.ip.is_ipv6()) as u8;
        body.push(flags);
        body.extend_from_slice(&peer.bgp_id.to_be_bytes());
        match &peer.ip {
            IpAddr::V4(b) => body.extend_from_slice(&b[..4]),
            IpAddr::V6(b) => body.extend_from_slice(&b[..16]),
        }
        body.extend_from_slice(&peer.asn.0.to_be_bytes());
    }
    Ok(encode_record(
        tdv2_subtype::PEER_INDEX_TABLE,
        msg_type::TABLE_DUMP_V2,
        timestamp,
        &body,
    ))
}

/// Encode one `RIB_*` record. The subtype is derived from the prefix
/// family and `table.add_path`.
pub fn encode_rib_table(timestamp: u32, table: &RibTable) -> Result<Vec<u8>, EncodeError> {
    let subtype = match (table.prefix.is_ipv4(), table.add_path) {
        (true, false) => tdv2_subtype::RIB_IPV4_UNICAST,
        (true, true) => tdv2_subtype::RIB_IPV4_UNICAST_ADDPATH,
        (false, false) => tdv2_subtype::RIB_IPV6_UNICAST,
        (false, true) => tdv2_subtype::RIB_IPV6_UNICAST_ADDPATH,
    };
    if table.attributes_len() > u16::MAX as usize {
        return Err(EncodeError::InvalidValue(
            "RIB entry attribute set exceeds 65535 bytes",
        ));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&table.sequence.to_be_bytes());
    put_prefix(&mut body, &table.prefix);
    body.extend_from_slice(&(table.entries.len() as u16).to_be_bytes());
    for entry in &table.entries {
        body.extend_from_slice(&entry.peer_index.to_be_bytes());
        body.extend_from_slice(&entry.originated_time.to_be_bytes());
        if table.add_path {
            body.extend_from_slice(&entry.path_id.to_be_bytes());
        }
        body.extend_from_slice(&(entry.attributes.len() as u16).to_be_bytes());
        body.extend_from_slice(&entry.attributes);
    }
    Ok(encode_record(
        subtype,
        msg_type::TABLE_DUMP_V2,
        timestamp,
        &body,
    ))
}

/// Write `prefix_len` + the packed prefix octets.
fn put_prefix(out: &mut Vec<u8>, prefix: &Prefix) {
    out.push(prefix.prefix_len);
    let n = (prefix.prefix_len as usize).div_ceil(8);
    match &prefix.addr {
        IpAddr::V4(b) => out.extend_from_slice(&b[..n.min(4)]),
        IpAddr::V6(b) => out.extend_from_slice(&b[..n.min(16)]),
    }
}

/// Path-attribute flags octet: extended-length bit (RFC 4271 §4.3, bit 4).
const ATTR_FLAG_EXT_LEN: u8 = 0x10;

/// Encode core [`Attributes`] as the raw path-attribute TLV sequence
/// RIB entries carry: each attribute is `flags | type | len[1|3] |
/// value` on the wire already.
pub fn encode_attributes(attrs: &lr_core::attr::Attributes) -> Vec<u8> {
    let mut out = Vec::new();
    for a in attrs.iter() {
        // librouting-private tags (the RFC 8277 label stack and the W6.3
        // exchange-plane record store) live in the Loc-RIB only and must
        // never appear in a dump: MRT attribute sets hold wire-form path
        // attributes, and a dump is byte-compared against reference
        // implementations by the parity harness.
        if a.tag.0 >= 254 {
            continue;
        }
        // RFC 4271 §4.3: values longer than 255 octets use the
        // extended-length form — a 3-octet length AND the extended-length
        // flag bit (0x10) set in the flags octet. A decoder honoring the
        // flag would otherwise read the 0xff marker as a 1-byte length.
        let extended = a.value.len() > 255;
        out.push(if extended {
            a.flags | ATTR_FLAG_EXT_LEN
        } else {
            a.flags
        });
        out.push(a.tag.0);
        if extended {
            out.push(0xff); // extended-length marker
            out.extend_from_slice(&(a.value.len() as u16).to_be_bytes());
        } else {
            out.push(a.value.len() as u8);
        }
        out.extend_from_slice(&a.value);
    }
    out
}

// ---------------------------------------------------------------------------
// Small cursor helper (body offsets make ParseError messages useful)
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize, ctx: &'static str) -> Result<&'a [u8], ParseError> {
        if self.pos + n > self.buf.len() {
            return Err(ParseError::truncated(ctx)
                .with_detail(format!("need {n} bytes at offset {}", self.pos)));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self, ctx: &'static str) -> Result<u8, ParseError> {
        Ok(self.take(1, ctx)?[0])
    }

    fn u16(&mut self, ctx: &'static str) -> Result<u16, ParseError> {
        let b = self.take(2, ctx)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, ctx: &'static str) -> Result<u32, ParseError> {
        let b = self.take(4, ctx)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn bytes(&mut self, n: usize, ctx: &'static str) -> Result<&'a [u8], ParseError> {
        self.take(n, ctx)
    }

    fn ip(&mut self, ipv6: bool, ctx: &'static str) -> Result<IpAddr, ParseError> {
        if ipv6 {
            let b = self.take(16, ctx)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(b);
            Ok(IpAddr::V6(o))
        } else {
            let b = self.take(4, ctx)?;
            Ok(IpAddr::V4([b[0], b[1], b[2], b[3]]))
        }
    }

    /// Read `prefix_len` + packed octets into a [`Prefix`].
    fn prefix(&mut self, ipv6: bool, ctx: &'static str) -> Result<Prefix, ParseError> {
        let len = self.u8(ctx)?;
        let max = if ipv6 { 128 } else { 32 };
        if len > max {
            return Err(ParseError::invalid(self.pos, ctx)
                .with_detail(format!("prefix length {len} > {max}")));
        }
        let n = (len as usize).div_ceil(8);
        let b = self.take(n, ctx)?;
        if ipv6 {
            let mut o = [0u8; 16];
            o[..n].copy_from_slice(b);
            Ok(Prefix::new_v6(o, len))
        } else {
            let mut o = [0u8; 4];
            o[..n].copy_from_slice(b);
            Ok(Prefix::new_v4(o, len))
        }
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

impl RibTable {
    /// Total encoded size of all entry attribute sets (bounds check).
    fn attributes_len(&self) -> usize {
        self.entries.iter().map(|e| e.attributes.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Typed attribute interpretation (feature `bgp`)
// ---------------------------------------------------------------------------

#[cfg(feature = "bgp")]
mod interpret;

#[cfg(feature = "bgp")]
pub use interpret::{walk_attributes, AttrSummary};

// ---------------------------------------------------------------------------
// File helpers (std)
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
mod file {
    use super::{MrtReader, MrtRecord};

    /// Parse a complete MRT file (any chunking is fine — records are
    /// length-framed). Trailing truncation is reported as an error.
    pub fn parse_file(path: &str) -> Result<Vec<MrtRecord>, lr_core::error::ParseError> {
        let bytes = std::fs::read(path).map_err(|e| {
            lr_core::error::ParseError::truncated("mrt.file").with_detail(e.to_string())
        })?;
        let mut reader = MrtReader::new();
        reader.feed(&bytes);
        let mut records = Vec::new();
        while let Some(record) = reader.next()? {
            records.push(record);
        }
        Ok(records)
    }

    impl MrtReader {
        /// Bytes buffered but not yet consumed (diagnostic helper).
        pub fn remaining(&self) -> usize {
            self.carryover.len()
        }
    }
}

#[cfg(feature = "std")]
pub use file::parse_file;

#[cfg(test)]
mod tests;
