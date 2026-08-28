//! Concrete Babel message sub-TLVs (RFC 8966 §4.4 + RFC 9079 §3).

use lr_core::addr::{IpAddr, Prefix};

/// Hello TLV body (RFC 8966 §4.4.1). Variable length; the first 4 bytes are
/// `seqno:2` (hello sequence number) + `interval:2` (centiseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    pub seqno: u16,
    pub interval_cs: u16,
}

impl Hello {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 4 {
            return None;
        }
        Some(Self {
            seqno: u16::from_be_bytes([v[0], v[1]]),
            interval_cs: u16::from_be_bytes([v[2], v[3]]),
        })
    }

    pub fn encode(&self) -> [u8; 4] {
        let mut a = [0u8; 4];
        a[..2].copy_from_slice(&self.seqno.to_be_bytes());
        a[2..].copy_from_slice(&self.interval_cs.to_be_bytes());
        a
    }
}

/// IHU (I Heard You) TLV body (RFC 8966 §4.6.3):
/// `ae:1` + `rxcost:2` + `interval:2` + `address:0..16`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ihu {
    pub ae: u8,
    pub rxcost: u16,
    pub interval_cs: u16,
    pub address: IpAddr,
}

impl Ihu {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 5 {
            return None;
        }
        let ae = v[0];
        let rxcost = u16::from_be_bytes([v[1], v[2]]);
        let interval_cs = u16::from_be_bytes([v[3], v[4]]);
        let addr = if ae == 0 {
            IpAddr::V4([0, 0, 0, 0])
        } else {
            IpAddr::from_bytes(&v[5..])?
        };
        Some(Self {
            ae,
            rxcost,
            interval_cs,
            address: addr,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(5 + self.address.octets().len());
        a.push(self.ae);
        a.extend_from_slice(&self.rxcost.to_be_bytes());
        a.extend_from_slice(&self.interval_cs.to_be_bytes());
        if self.ae != 0 {
            a.extend_from_slice(self.address.octets());
        }
        a
    }
}

/// Router-Id TLV body. RFC 8966 §4.4.3: 8-byte router-id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterId {
    pub id: [u8; 8],
}

impl RouterId {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() != 8 {
            return None;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(v);
        Some(Self { id })
    }

    pub fn encode(&self) -> [u8; 8] {
        self.id
    }
}

/// Next Hop TLV body (RFC 8966 §4.6.5): `ae:1` + `address:0..16`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    pub ae: u8,
    pub address: IpAddr,
}

impl NextHop {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.is_empty() {
            return None;
        }
        let ae = v[0];
        let address = if ae == 0 {
            IpAddr::V4([0, 0, 0, 0])
        } else {
            IpAddr::from_bytes(&v[1..])?
        };
        Some(Self { ae, address })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(1 + self.address.octets().len());
        a.push(self.ae);
        if self.ae != 0 {
            a.extend_from_slice(self.address.octets());
        }
        a
    }
}

/// Update TLV body (RFC 8966 §4.6.9):
/// `ae:1` + `src_prefix_len:1` + `src_prefix:0..4` + `prefix_len:1` +
/// `prefix:0..16` + `metric:2` + `seqno:2`.
///
/// Prefix lengths are in *bits*; the encoded prefix carries ceil(len/8)
/// octets (trailing zero octets elided). Metric 0xFFFF is infinity
/// (retraction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub ae: u8,
    /// Source prefix length in bits (0 = no source prefix).
    pub src_prefix_len: u8,
    /// Source prefix octets (RFC 9079 source-specific routing).
    pub src_prefix: Vec<u8>,
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Prefix octets (ceil(prefix_len / 8), no embedded length byte).
    pub prefix: Vec<u8>,
    pub metric: u16,
    pub seqno: u16,
}

impl Update {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 6 {
            return None;
        }
        let ae = v[0];
        let src_prefix_len = v[1];
        let mut i = 2usize;
        let src_octets = if ae == 0 || src_prefix_len == 0 {
            0
        } else {
            (src_prefix_len as usize).div_ceil(8)
        };
        if i + src_octets >= v.len() {
            return None;
        }
        let src_prefix = v[i..i + src_octets].to_vec();
        i += src_octets;
        let prefix_len = v[i];
        i += 1;
        let pfx_octets = (prefix_len as usize).div_ceil(8);
        // metric(2) + seqno(2) follow the prefix.
        if i + pfx_octets + 4 > v.len() {
            return None;
        }
        let prefix = v[i..i + pfx_octets].to_vec();
        i += pfx_octets;
        let metric = u16::from_be_bytes([v[i], v[i + 1]]);
        let seqno = u16::from_be_bytes([v[i + 2], v[i + 3]]);
        Some(Self {
            ae,
            src_prefix_len,
            src_prefix,
            prefix_len,
            prefix,
            metric,
            seqno,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(6 + self.prefix.len() + self.src_prefix.len());
        a.push(self.ae);
        a.push(self.src_prefix_len);
        if self.ae != 0 && self.src_prefix_len > 0 {
            a.extend_from_slice(&self.src_prefix);
        }
        a.push(self.prefix_len);
        a.extend_from_slice(&self.prefix);
        a.extend_from_slice(&self.metric.to_be_bytes());
        a.extend_from_slice(&self.seqno.to_be_bytes());
        a
    }

    /// The destination prefix of this Update, if AE is known.
    pub fn prefix_value(&self) -> Option<Prefix> {
        match self.ae {
            1 => {
                let mut addr = [0u8; 4];
                let n = self.prefix.len().min(4);
                addr[..n].copy_from_slice(&self.prefix[..n]);
                Some(Prefix::new_v4(addr, self.prefix_len))
            }
            2 => {
                let mut addr = [0u8; 16];
                let n = self.prefix.len().min(16);
                addr[..n].copy_from_slice(&self.prefix[..n]);
                Some(Prefix::new_v6(addr, self.prefix_len))
            }
            _ => None,
        }
    }
}

/// Route-Request TLV body (RFC 8966 §4.4.6): `ae:1` + `prefix_len:1` + `prefix:0..`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequest {
    pub ae: u8,
    pub prefix: Vec<u8>,
}

impl RouteRequest {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 2 {
            return None;
        }
        Some(Self {
            ae: v[0],
            prefix: v[2..].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(2 + self.prefix.len());
        a.push(self.ae);
        a.push(self.prefix.len() as u8);
        a.extend_from_slice(&self.prefix);
        a
    }
}

/// Seqno-Request TLV body (RFC 8966 §4.4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqnoRequest {
    pub ae: u8,
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
        // skip v[1] plen, v[2] seqno hi
        let seqno = u16::from_be_bytes([v[2], v[3]]);
        let hop_count = v[4];
        // skip v[5] reserved
        let mut rid = [0u8; 8];
        rid.copy_from_slice(&v[6..14]);
        let prefix = v[14..].to_vec();
        Some(Self {
            ae,
            prefix,
            seqno,
            hop_count,
            router_id: rid,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(14 + self.prefix.len());
        a.push(self.ae);
        a.push(self.prefix.len() as u8);
        a.extend_from_slice(&self.seqno.to_be_bytes());
        a.push(self.hop_count);
        a.push(0); // reserved
        a.extend_from_slice(&self.router_id);
        a.extend_from_slice(&self.prefix);
        a
    }
}

/// Source-specific Route-Request TLV body (RFC 9079 §4.4):
/// `ae:1` + `src_prefix_len:1` + `src_prefix:0..` + `prefix_len:1` + `prefix:0..`.
///
/// Asks the peer to send Updates for the given (destination, source)
/// tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsRouteRequest {
    pub ae: u8,
    pub src_prefix_len: u8,
    pub src_prefix: Vec<u8>,
    pub prefix_len: u8,
    pub prefix: Vec<u8>,
}

impl SsRouteRequest {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 2 {
            return None;
        }
        let ae = v[0];
        let src_prefix_len = v[1];
        let mut i = 2usize;
        let src_octets = if ae == 0 || src_prefix_len == 0 {
            0
        } else {
            (src_prefix_len as usize).div_ceil(8)
        };
        if i + src_octets >= v.len() {
            return None;
        }
        let src_prefix = v[i..i + src_octets].to_vec();
        i += src_octets;
        if i >= v.len() {
            return None;
        }
        let prefix_len = v[i];
        i += 1;
        let prefix = v[i..].to_vec();
        Some(Self {
            ae,
            src_prefix_len,
            src_prefix,
            prefix_len,
            prefix,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(4 + self.src_prefix.len() + self.prefix.len());
        a.push(self.ae);
        a.push(self.src_prefix_len);
        if self.ae != 0 && self.src_prefix_len > 0 {
            a.extend_from_slice(&self.src_prefix);
        }
        a.push(self.prefix_len);
        a.extend_from_slice(&self.prefix);
        a
    }
}

/// Source-specific Seqno-Request TLV body (RFC 9079 §4.5):
/// `ae:1` + `src_prefix_len:1` + `src_prefix:0..` + `prefix_len:1` +
/// `prefix:0..` + `seqno:2` + `hop_count:1` + `reserved:1` + `router_id:8`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsSeqnoRequest {
    pub ae: u8,
    pub src_prefix_len: u8,
    pub src_prefix: Vec<u8>,
    pub prefix_len: u8,
    pub prefix: Vec<u8>,
    pub seqno: u16,
    pub hop_count: u8,
    pub router_id: [u8; 8],
}

impl SsSeqnoRequest {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 4 {
            return None;
        }
        let ae = v[0];
        let src_prefix_len = v[1];
        let mut i = 2usize;
        let src_octets = if ae == 0 || src_prefix_len == 0 {
            0
        } else {
            (src_prefix_len as usize).div_ceil(8)
        };
        if i + src_octets + 12 > v.len() {
            return None;
        }
        let src_prefix = v[i..i + src_octets].to_vec();
        i += src_octets;
        let prefix_len = v[i];
        i += 1;
        let pfx_octets = (prefix_len as usize).div_ceil(8);
        if i + pfx_octets + 12 > v.len() {
            return None;
        }
        let prefix = v[i..i + pfx_octets].to_vec();
        i += pfx_octets;
        let seqno = u16::from_be_bytes([v[i], v[i + 1]]);
        let hop_count = v[i + 2];
        // v[i+3] is reserved
        let mut rid = [0u8; 8];
        rid.copy_from_slice(&v[i + 4..i + 12]);
        Some(Self {
            ae,
            src_prefix_len,
            src_prefix,
            prefix_len,
            prefix,
            seqno,
            hop_count,
            router_id: rid,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(4 + self.src_prefix.len() + self.prefix.len() + 12);
        a.push(self.ae);
        a.push(self.src_prefix_len);
        if self.ae != 0 && self.src_prefix_len > 0 {
            a.extend_from_slice(&self.src_prefix);
        }
        a.push(self.prefix_len);
        a.extend_from_slice(&self.prefix);
        a.extend_from_slice(&self.seqno.to_be_bytes());
        a.push(self.hop_count);
        a.push(0); // reserved
        a.extend_from_slice(&self.router_id);
        a
    }
}

/// AckReq TLV body (RFC 8966 §4.4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckReq {
    pub nonce: u16,
    pub interval_cs: u16,
}

impl AckReq {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() != 4 {
            return None;
        }
        Some(Self {
            nonce: u16::from_be_bytes([v[0], v[1]]),
            interval_cs: u16::from_be_bytes([v[2], v[3]]),
        })
    }

    pub fn encode(&self) -> [u8; 4] {
        let mut a = [0u8; 4];
        a[..2].copy_from_slice(&self.nonce.to_be_bytes());
        a[2..].copy_from_slice(&self.interval_cs.to_be_bytes());
        a
    }
}

/// Ack TLV body (RFC 8966 §4.4.9): just a 2-byte nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub nonce: u16,
}

impl Ack {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() != 2 {
            return None;
        }
        Some(Self {
            nonce: u16::from_be_bytes([v[0], v[1]]),
        })
    }

    pub fn encode(&self) -> [u8; 2] {
        self.nonce.to_be_bytes()
    }
}

/// Decode an address-encoding (RFC 8966 §4.5.1) into a Prefix.
pub fn decode_ae(ae: u8, value: &[u8]) -> Option<Prefix> {
    match ae {
        0 => None, // wildcard
        1 => {
            // IPv4 + prefix length in first byte
            if value.is_empty() {
                return None;
            }
            let pl = value[0];
            let n = (pl as usize).div_ceil(8);
            if value.len() < 1 + n {
                return None;
            }
            let mut a = [0u8; 4];
            a[..n].copy_from_slice(&value[1..1 + n]);
            Some(Prefix::new_v4(a, pl))
        }
        2 => {
            // IPv6 + prefix length
            if value.is_empty() {
                return None;
            }
            let pl = value[0];
            let n = (pl as usize).div_ceil(8);
            if value.len() < 1 + n {
                return None;
            }
            let mut a = [0u8; 16];
            a[..n].copy_from_slice(&value[1..1 + n]);
            Some(Prefix::new_v6(a, pl))
        }
        3 => {
            // IPv6 link-local (same encoding as 2)
            decode_ae(2, value)
        }
        _ => None,
    }
}

/// Encode a Prefix into Babel's `(ae, prefix_bytes)` form. The bytes start
/// with the prefix length, then the network octets.
pub fn encode_ae(prefix: &Prefix) -> (u8, Vec<u8>) {
    match &prefix.addr {
        IpAddr::V4(b) => {
            let pl = prefix.prefix_len;
            let n = (pl as usize).div_ceil(8);
            let mut v = Vec::with_capacity(1 + n);
            v.push(pl);
            v.extend_from_slice(&b[..n]);
            (1, v)
        }
        IpAddr::V6(b) => {
            let pl = prefix.prefix_len;
            let n = (pl as usize).div_ceil(8);
            let mut v = Vec::with_capacity(1 + n);
            v.push(pl);
            v.extend_from_slice(&b[..n]);
            (2, v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let h = Hello {
            seqno: 42,
            interval_cs: 1000,
        };
        let enc = h.encode();
        let dec = Hello::decode(&enc).unwrap();
        assert_eq!(dec, h);
    }

    #[test]
    fn update_roundtrip() {
        let u = Update {
            ae: 1,
            src_prefix_len: 0,
            src_prefix: Vec::new(),
            prefix_len: 24,
            prefix: vec![203, 0, 113],
            metric: 100,
            seqno: 5,
        };
        let enc = u.encode();
        let dec = Update::decode(&enc).unwrap();
        assert_eq!(dec, u);
        assert_eq!(u.prefix_value(), Some(Prefix::new_v4([203, 0, 113, 0], 24)));
    }

    #[test]
    fn update_with_source_prefix_roundtrip() {
        // RFC 9079 source-specific update.
        let u = Update {
            ae: 1,
            src_prefix_len: 8,
            src_prefix: vec![10],
            prefix_len: 24,
            prefix: vec![192, 0, 2],
            metric: 0xFFFF,
            seqno: 9,
        };
        let enc = u.encode();
        let dec = Update::decode(&enc).unwrap();
        assert_eq!(dec, u);
    }

    #[test]
    fn encode_decode_ae_v4() {
        let p = Prefix::new_v4([10, 0, 0, 0], 8);
        let (ae, bytes) = encode_ae(&p);
        assert_eq!(ae, 1);
        assert_eq!(bytes, vec![8u8, 10]);
        let dec = decode_ae(ae, &bytes).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn encode_decode_ae_v6() {
        let p = Prefix::new_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        );
        let (ae, bytes) = encode_ae(&p);
        assert_eq!(ae, 2);
        let dec = decode_ae(ae, &bytes).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn ss_route_request_roundtrip() {
        let r = super::SsRouteRequest {
            ae: 1,
            src_prefix_len: 8,
            src_prefix: vec![10],
            prefix_len: 24,
            prefix: vec![192, 0, 2],
        };
        let enc = r.encode();
        let dec = super::SsRouteRequest::decode(&enc).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn ss_route_request_ipv6_roundtrip() {
        let r = super::SsRouteRequest {
            ae: 2,
            src_prefix_len: 64,
            src_prefix: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
            prefix_len: 48,
            prefix: vec![0xfe, 0x80, 0, 0, 0, 0],
        };
        let enc = r.encode();
        let dec = super::SsRouteRequest::decode(&enc).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn ss_seqno_request_roundtrip() {
        let r = super::SsSeqnoRequest {
            ae: 1,
            src_prefix_len: 8,
            src_prefix: vec![10],
            prefix_len: 24,
            prefix: vec![192, 0, 2],
            seqno: 42,
            hop_count: 3,
            router_id: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let enc = r.encode();
        let dec = super::SsSeqnoRequest::decode(&enc).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn ss_seqno_request_ipv6_roundtrip() {
        let r = super::SsSeqnoRequest {
            ae: 2,
            src_prefix_len: 128,
            src_prefix: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            prefix_len: 64,
            prefix: vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0],
            seqno: 100,
            hop_count: 2,
            router_id: [0xff; 8],
        };
        let enc = r.encode();
        let dec = super::SsSeqnoRequest::decode(&enc).unwrap();
        assert_eq!(dec, r);
    }
}
