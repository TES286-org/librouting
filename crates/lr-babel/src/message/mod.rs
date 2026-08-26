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

/// IHU (I Heard You) TLV body. `rxcost:2` + `interval:2` + address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ihu {
    pub rxcost: u16,
    pub interval_cs: u16,
    pub address: IpAddr,
}

impl Ihu {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 4 {
            return None;
        }
        let rxcost = u16::from_be_bytes([v[0], v[1]]);
        let interval_cs = u16::from_be_bytes([v[2], v[3]]);
        let addr = IpAddr::from_bytes(&v[4..])?;
        Some(Self {
            rxcost,
            interval_cs,
            address: addr,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(4 + self.address.octets().len());
        a.extend_from_slice(&self.rxcost.to_be_bytes());
        a.extend_from_slice(&self.interval_cs.to_be_bytes());
        a.extend_from_slice(self.address.octets());
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

/// Next Hop TLV body. Carries the next-hop address for subsequent Updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHop {
    pub address: IpAddr,
}

impl NextHop {
    pub fn decode(v: &[u8]) -> Option<Self> {
        Some(Self {
            address: IpAddr::from_bytes(v)?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.address.octets().to_vec()
    }
}

/// Update TLV body (RFC 8966 §4.4.5). Variable length, at minimum 10 bytes:
/// `metric:4` + `flags:1` + `prefix_len:1` + `prefix:0..`.
/// Also `seqno:2` comes BEFORE metric, so the actual layout is:
/// `ae:1` + `srcplen:1` + `reserved:1` + `metric:4` + `seqno:2` + `prefix:0..`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub ae: u8, // Address Encoding (RFC 8966 §4.5.1)
    pub src_prefix_len: u8,
    pub metric: u32,
    pub seqno: u16,
    pub prefix: Vec<u8>,
}

impl Update {
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.len() < 10 {
            return None;
        }
        let ae = v[0];
        let src_prefix_len = v[1];
        // skip reserved v[2]
        let metric = u32::from_be_bytes([v[3], v[4], v[5], v[6]]);
        let seqno = u16::from_be_bytes([v[7], v[8]]);
        let prefix = v[9..].to_vec();
        Some(Self {
            ae,
            src_prefix_len,
            metric,
            seqno,
            prefix,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(9 + self.prefix.len());
        a.push(self.ae);
        a.push(self.src_prefix_len);
        a.push(0); // reserved
        a.extend_from_slice(&self.metric.to_be_bytes());
        a.extend_from_slice(&self.seqno.to_be_bytes());
        a.extend_from_slice(&self.prefix);
        a
    }

    pub fn prefix_value(&self) -> Option<Prefix> {
        decode_ae(self.ae, &self.prefix)
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
            metric: 100,
            seqno: 5,
            prefix: {
                let mut v = vec![8u8]; // /8
                v.push(10);
                v
            },
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
}
