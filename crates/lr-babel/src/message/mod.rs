//! Concrete Babel message TLVs (RFC 8966 §4.6).
//!
//! Every body layout below follows RFC 8966 §4.6 byte-for-byte, including
//! the Reserved fields that MUST be sent as zero and ignored on reception.
//! Source-specific routing (RFC 9079) is carried as a mandatory Source
//! Prefix sub-TLV (type 128) inside Update, Route Request and Seqno
//! Request TLVs — see [`SourcePrefixSubTlv`].

use lr_core::addr::{IpAddr, Prefix};

/// The RFC 9079 Source Prefix sub-TLV (type 128, mandatory bit set).
/// Body: `Source Plen(1) | Source Prefix(ceil(Plen/8))`.
pub const SOURCE_PREFIX_SUBTLV: u8 = 128;

/// Parse the trailing sub-TLVs of a self-terminating TLV body and return
/// the source-prefix sub-TLV's (plen, octets) if present. Unknown sub-TLVs
/// are silently ignored (RFC 8966 §4.4); a second Source Prefix sub-TLV
/// invalidates the enclosing TLV (RFC 9079 §7.1).
fn parse_source_subtlv(tail: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut src: Option<(u8, Vec<u8>)> = None;
    let mut i = 0;
    while i < tail.len() {
        if tail[i] == 0 {
            i += 1; // Pad1
            continue;
        }
        if i + 2 > tail.len() {
            return None; // truncated sub-TLV → corrupt enclosing TLV
        }
        let kind = tail[i];
        let len = tail[i + 1] as usize;
        let end = i + 2 + len;
        if end > tail.len() {
            return None; // truncated sub-TLV
        }
        if kind == SOURCE_PREFIX_SUBTLV {
            let body = &tail[i + 2..end];
            if body.is_empty() || (body[0] as usize).div_ceil(8) + 1 > body.len() {
                return None; // corrupt Source Prefix sub-TLV
            }
            if src.is_some() {
                return None; // multiple Source Prefix sub-TLVs → ignore TLV
            }
            src = Some((body[0], body[1..].to_vec()));
        }
        i = end;
    }
    src
}

/// Serialize a Source Prefix sub-TLV.
fn encode_source_subtlv(plen: u8, octets: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + octets.len());
    out.push(SOURCE_PREFIX_SUBTLV);
    out.push((1 + octets.len()) as u8);
    out.push(plen);
    out.extend_from_slice(octets);
    out
}

/// Hello TLV body (RFC 8966 §4.6.5): `Flags(2) | Seqno(2) | Interval(2)`.
///
/// Only the Unicast flag (0x8000) is defined; all other flag bits MUST be
/// sent as zero and silently ignored on reception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    pub flags: u16,
    pub seqno: u16,
    pub interval_cs: u16,
}

impl Hello {
    pub const UNICAST: u16 = 0x8000;

    pub fn new(seqno: u16, interval_cs: u16) -> Self {
        Self {
            flags: 0,
            seqno,
            interval_cs,
        }
    }

    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 6 {
            return None;
        }
        Some(Self {
            flags: u16::from_be_bytes([v[0], v[1]]),
            seqno: u16::from_be_bytes([v[2], v[3]]),
            interval_cs: u16::from_be_bytes([v[4], v[5]]),
        })
    }

    pub fn encode(&self) -> [u8; 6] {
        let mut a = [0u8; 6];
        a[..2].copy_from_slice(&self.flags.to_be_bytes());
        a[2..4].copy_from_slice(&self.seqno.to_be_bytes());
        a[4..].copy_from_slice(&self.interval_cs.to_be_bytes());
        a
    }
}

/// IHU TLV body (RFC 8966 §4.6.6):
/// `AE(1) | Reserved(1) | Rxcost(2) | Interval(2) | Address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ihu {
    pub ae: u8,
    pub rxcost: u16,
    pub interval_cs: u16,
    pub address: Option<IpAddr>,
}

impl Ihu {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 6 {
            return None;
        }
        let ae = v[0];
        let rxcost = u16::from_be_bytes([v[2], v[3]]);
        let interval_cs = u16::from_be_bytes([v[4], v[5]]);
        let address = match ae {
            0 => None, // wildcard: no address octets
            1 => IpAddr::from_bytes(v.get(6..10)?),
            2 => IpAddr::from_bytes(v.get(6..22)?),
            3 => {
                // Link-local IPv6: 8 octets with an implied fe80::/64.
                let b = v.get(6..14)?;
                let mut a = [0u8; 16];
                a[..8].copy_from_slice(b);
                Some(IpAddr::V6(a))
            }
            _ => return None, // unknown AE → silently ignored
        };
        Some(Self {
            ae,
            rxcost,
            interval_cs,
            address,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(6 + 16);
        a.push(self.ae);
        a.push(0); // Reserved
        a.extend_from_slice(&self.rxcost.to_be_bytes());
        a.extend_from_slice(&self.interval_cs.to_be_bytes());
        if let Some(addr) = &self.address {
            match (self.ae, addr) {
                (1, IpAddr::V4(b)) => a.extend_from_slice(b),
                (2, IpAddr::V6(b)) => a.extend_from_slice(b),
                (3, IpAddr::V6(b)) => a.extend_from_slice(&b[..8]),
                _ => {} // cannot encode; caller should not construct this
            }
        }
        a
    }
}

/// Router-Id TLV body (RFC 8966 §4.6.7): `Reserved(2) | Router-Id(8)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterId {
    pub id: [u8; 8],
}

impl RouterId {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 10 {
            return None;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&v[2..10]);
        Some(Self { id })
    }

    pub fn encode(&self) -> [u8; 10] {
        let mut a = [0u8; 10];
        a[2..].copy_from_slice(&self.id);
        a
    }
}

/// Next Hop TLV body (RFC 8966 §4.6.8): `AE(1) | Reserved(1) | Next hop`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    pub ae: u8,
    pub address: IpAddr,
}

impl NextHop {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 2 {
            return None;
        }
        let ae = v[0];
        let address = match ae {
            1 => IpAddr::from_bytes(v.get(2..6)?)?,
            2 => IpAddr::from_bytes(v.get(2..18)?)?,
            3 => {
                let b = v.get(2..10)?;
                let mut a = [0u8; 16];
                a[..8].copy_from_slice(b);
                IpAddr::V6(a)
            }
            _ => return None, // AE 0 is forbidden; unknown AEs ignored
        };
        Some(Self { ae, address })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(2 + 16);
        a.push(self.ae);
        a.push(0); // Reserved
        match (&self.address, self.ae) {
            (IpAddr::V4(b), 1) => a.extend_from_slice(b),
            (IpAddr::V6(b), 2) => a.extend_from_slice(b),
            (IpAddr::V6(b), 3) => a.extend_from_slice(&b[..8]),
            _ => {}
        }
        a
    }
}

/// Update TLV body (RFC 8966 §4.6.9):
/// `AE(1) | Flags(1) | Plen(1) | Omitted(1) | Interval(2) | Seqno(2) |
/// Metric(2) | Prefix`, optionally followed by sub-TLVs (RFC 9079 Source
/// Prefix).
///
/// `prefix_len` is the advertised length in bits; `prefix` carries
/// `ceil(Plen/8) - Omitted` octets (with `Omitted` taken from the previous
/// Prefix-flagged Update). Metric 0xFFFF is infinity (retraction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub ae: u8,
    pub flags: u8,
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Octets omitted at the start of the prefix (taken from a previous
    /// Update with the Prefix flag set).
    pub omitted: u8,
    /// Upper bound on the update interval, in centiseconds.
    pub interval_cs: u16,
    pub seqno: u16,
    pub metric: u16,
    /// The advertised prefix octets (without omitted octets).
    pub prefix: Vec<u8>,
    /// RFC 9079 source prefix length in bits (0 = not source-specific).
    pub src_prefix_len: u8,
    /// RFC 9079 source prefix octets.
    pub src_prefix: Vec<u8>,
}

impl Update {
    pub const FLAG_PREFIX: u8 = 0x80;
    pub const FLAG_ROUTER_ID: u8 = 0x40;

    pub fn new(prefix_len: u8, prefix: Vec<u8>, seqno: u16, metric: u16) -> Self {
        Self {
            ae: 1,
            flags: 0,
            prefix_len,
            omitted: 0,
            interval_cs: 0,
            seqno,
            metric,
            prefix,
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        }
    }

    pub fn decode(v: &[u8]) -> Option<Self> {
        // Fixed header is 10 bytes: AE Flags Plen Omitted Interval Seqno
        // Metric; the Prefix follows.
        if v.len() < 10 {
            return None;
        }
        let ae = v[0];
        let flags = v[1];
        let prefix_len = v[2];
        let omitted = v[3];
        let interval_cs = u16::from_be_bytes([v[4], v[5]]);
        let seqno = u16::from_be_bytes([v[6], v[7]]);
        let metric = u16::from_be_bytes([v[8], v[9]]);
        if prefix_len > 128 {
            return None;
        }
        // Prefix size is ceil(Plen/8) - Omitted octets.
        let full_octets = (prefix_len as usize).div_ceil(8);
        let pfx_octets = full_octets.checked_sub(omitted as usize)?;
        let mut i = 10usize;
        if i + pfx_octets > v.len() {
            return None;
        }
        let prefix = v[i..i + pfx_octets].to_vec();
        i += pfx_octets;
        // Remaining bytes are sub-TLVs.
        let (src_prefix_len, src_prefix) = parse_source_subtlv(&v[i..]).unwrap_or((0, Vec::new()));
        Some(Self {
            ae,
            flags,
            prefix_len,
            omitted,
            interval_cs,
            seqno,
            metric,
            prefix,
            src_prefix_len,
            src_prefix,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(10 + self.prefix.len() + self.src_prefix.len() + 3);
        a.push(self.ae);
        a.push(self.flags);
        a.push(self.prefix_len);
        a.push(self.omitted);
        a.extend_from_slice(&self.interval_cs.to_be_bytes());
        a.extend_from_slice(&self.seqno.to_be_bytes());
        a.extend_from_slice(&self.metric.to_be_bytes());
        a.extend_from_slice(&self.prefix);
        if self.src_prefix_len > 0 {
            a.extend_from_slice(&encode_source_subtlv(self.src_prefix_len, &self.src_prefix));
        }
        a
    }

    /// The destination prefix of this Update, if AE is known and the
    /// prefix is fully in-band (`omitted == 0`).
    pub fn prefix_value(&self) -> Option<Prefix> {
        if self.omitted != 0 {
            return None; // needs the previous Prefix-flagged Update
        }
        match self.ae {
            1 => {
                let mut addr = [0u8; 4];
                let n = self.prefix.len().min(4);
                addr[..n].copy_from_slice(&self.prefix[..n]);
                Some(Prefix::new_v4(addr, self.prefix_len))
            }
            2 | 3 => {
                let mut addr = [0u8; 16];
                let n = self.prefix.len().min(16);
                addr[..n].copy_from_slice(&self.prefix[..n]);
                Some(Prefix::new_v6(addr, self.prefix_len))
            }
            _ => None,
        }
    }
}

/// Route-Request TLV body (RFC 8966 §4.6.10): `AE(1) | Plen(1) | Prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequest {
    pub ae: u8,
    /// Requested prefix length in bits (0 with AE=0 = full dump).
    pub prefix_len: u8,
    pub prefix: Vec<u8>,
}

impl RouteRequest {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 2 {
            return None;
        }
        let ae = v[0];
        let prefix_len = v[1];
        if ae == 0 && prefix_len != 0 {
            return None; // wildcard request with non-zero Plen MUST be ignored
        }
        let n = (prefix_len as usize).div_ceil(8);
        if 2 + n > v.len() {
            return None;
        }
        Some(Self {
            ae,
            prefix_len,
            prefix: v[2..2 + n].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(2 + self.prefix.len());
        a.push(self.ae);
        a.push(self.prefix_len);
        a.extend_from_slice(&self.prefix);
        a
    }
}

/// Seqno-Request TLV body (RFC 8966 §4.6.11):
/// `AE(1) | Plen(1) | Seqno(2) | Hop Count(1) | Reserved(1) | Router-Id(8)
/// | Prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqnoRequest {
    pub ae: u8,
    pub prefix_len: u8,
    pub prefix: Vec<u8>,
    pub seqno: u16,
    pub hop_count: u8,
    pub router_id: [u8; 8],
}

impl SeqnoRequest {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 14 {
            return None;
        }
        let ae = v[0];
        let prefix_len = v[1];
        let seqno = u16::from_be_bytes([v[2], v[3]]);
        let hop_count = v[4];
        let mut rid = [0u8; 8];
        rid.copy_from_slice(&v[6..14]);
        let n = (prefix_len as usize).div_ceil(8);
        if 14 + n > v.len() {
            return None;
        }
        let prefix = v[14..14 + n].to_vec();
        Some(Self {
            ae,
            prefix_len,
            prefix,
            seqno,
            hop_count,
            router_id: rid,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(14 + self.prefix.len());
        a.push(self.ae);
        a.push(self.prefix_len);
        a.extend_from_slice(&self.seqno.to_be_bytes());
        a.push(self.hop_count);
        a.push(0); // Reserved
        a.extend_from_slice(&self.router_id);
        a.extend_from_slice(&self.prefix);
        a
    }
}

/// Acknowledgment Request TLV body (RFC 8966 §4.6.3):
/// `Reserved(2) | Opaque(2) | Interval(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckReq {
    pub opaque: u16,
    pub interval_cs: u16,
}

impl AckReq {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 6 {
            return None;
        }
        Some(Self {
            opaque: u16::from_be_bytes([v[2], v[3]]),
            interval_cs: u16::from_be_bytes([v[4], v[5]]),
        })
    }

    pub fn encode(&self) -> [u8; 6] {
        let mut a = [0u8; 6];
        a[2..4].copy_from_slice(&self.opaque.to_be_bytes());
        a[4..].copy_from_slice(&self.interval_cs.to_be_bytes());
        a
    }
}

/// Acknowledgment TLV body (RFC 8966 §4.6.4): `Opaque(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub opaque: u16,
}

impl Ack {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() != 2 {
            return None;
        }
        Some(Self {
            opaque: u16::from_be_bytes([v[0], v[1]]),
        })
    }

    pub fn encode(&self) -> [u8; 2] {
        self.opaque.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let h = Hello {
            flags: 0,
            seqno: 42,
            interval_cs: 1000,
        };
        let enc = h.encode();
        assert_eq!(enc, [0, 0, 0, 42, 0x03, 0xe8]);
        assert_eq!(Hello::decode(&enc).unwrap(), h);
    }

    #[test]
    fn ihu_roundtrip_v4() {
        let ihu = Ihu {
            ae: 1,
            rxcost: 256,
            interval_cs: 400,
            address: Some(IpAddr::V4([192, 0, 2, 1])),
        };
        let enc = ihu.encode();
        assert_eq!(enc[0], 1); // AE
        assert_eq!(enc[1], 0); // Reserved
        assert_eq!(Ihu::decode(&enc).unwrap(), ihu);
    }

    #[test]
    fn ihu_wildcard_no_address() {
        let ihu = Ihu {
            ae: 0,
            rxcost: 100,
            interval_cs: 200,
            address: None,
        };
        let enc = ihu.encode();
        assert_eq!(enc.len(), 6);
        assert_eq!(Ihu::decode(&enc).unwrap(), ihu);
    }

    #[test]
    fn router_id_roundtrip() {
        let rid = RouterId {
            id: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let enc = rid.encode();
        assert_eq!(enc.len(), 10);
        assert_eq!(&enc[..2], &[0, 0]); // Reserved
        assert_eq!(RouterId::decode(&enc).unwrap(), rid);
    }

    #[test]
    fn next_hop_roundtrip() {
        let nh = NextHop {
            ae: 2,
            address: IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        };
        let enc = nh.encode();
        assert_eq!(enc[0], 2);
        assert_eq!(enc[1], 0); // Reserved
        assert_eq!(NextHop::decode(&enc).unwrap(), nh);
    }

    #[test]
    fn update_roundtrip() {
        let u = Update {
            ae: 1,
            flags: 0,
            prefix_len: 24,
            omitted: 0,
            interval_cs: 500,
            seqno: 5,
            metric: 100,
            prefix: vec![203, 0, 113],
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        };
        let enc = u.encode();
        assert_eq!(u8::from_be_bytes([enc[0]]), 1);
        assert_eq!(u16::from_be_bytes([enc[4], enc[5]]), 500); // Interval
        assert_eq!(u16::from_be_bytes([enc[6], enc[7]]), 5); // Seqno
        assert_eq!(u16::from_be_bytes([enc[8], enc[9]]), 100); // Metric
        let dec = Update::decode(&enc).unwrap();
        assert_eq!(dec, u);
        assert_eq!(u.prefix_value(), Some(Prefix::new_v4([203, 0, 113, 0], 24)));
    }

    #[test]
    fn update_with_source_prefix_subtlv() {
        // RFC 9079 source-specific update: Source Prefix sub-TLV 128.
        let u = Update {
            ae: 1,
            flags: 0,
            prefix_len: 24,
            omitted: 0,
            interval_cs: 0,
            seqno: 9,
            metric: 0xFFFF,
            prefix: vec![192, 0, 2],
            src_prefix_len: 8,
            src_prefix: vec![10],
        };
        let enc = u.encode();
        // The Source Prefix sub-TLV follows the 10-byte header + prefix.
        assert_eq!(enc[13], SOURCE_PREFIX_SUBTLV);
        assert_eq!(enc[14], 2); // 1 plen byte + 1 octet
        let dec = Update::decode(&enc).unwrap();
        assert_eq!(dec, u);
    }

    #[test]
    fn update_ignores_invalid_source_subtlv() {
        // Corrupt Source Prefix sub-TLV (length too short) → src cleared.
        let u = Update {
            ae: 1,
            flags: 0,
            prefix_len: 8,
            omitted: 0,
            interval_cs: 0,
            seqno: 1,
            metric: 1,
            prefix: vec![10],
            src_prefix_len: 0,
            src_prefix: Vec::new(),
        };
        let mut enc = u.encode();
        enc.extend_from_slice(&[SOURCE_PREFIX_SUBTLV, 1, 8]); // plen says 1 octet but len=1
        let dec = Update::decode(&enc).unwrap();
        assert_eq!(dec.src_prefix_len, 0);
        assert!(dec.src_prefix.is_empty());
    }

    #[test]
    fn route_request_roundtrip() {
        let r = RouteRequest {
            ae: 1,
            prefix_len: 24,
            prefix: vec![203, 0, 113],
        };
        let enc = r.encode();
        assert_eq!(RouteRequest::decode(&enc).unwrap(), r);
    }

    #[test]
    fn route_request_rejects_wildcard_with_plen() {
        let v = [0u8, 8];
        assert!(RouteRequest::decode(&v).is_none());
    }

    #[test]
    fn seqno_request_roundtrip() {
        let r = SeqnoRequest {
            ae: 1,
            prefix_len: 24,
            prefix: vec![198, 51, 100],
            seqno: 42,
            hop_count: 3,
            router_id: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let enc = r.encode();
        assert_eq!(SeqnoRequest::decode(&enc).unwrap(), r);
    }

    #[test]
    fn ack_req_roundtrip() {
        let a = AckReq {
            opaque: 0xbeef,
            interval_cs: 100,
        };
        let enc = a.encode();
        assert_eq!(&enc[..2], &[0, 0]); // Reserved
        assert_eq!(AckReq::decode(&enc).unwrap(), a);
    }

    #[test]
    fn ack_roundtrip() {
        let a = Ack { opaque: 0x1234 };
        assert_eq!(Ack::decode(&a.encode()).unwrap(), a);
    }
}
