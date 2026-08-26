//! MP-BGP NLRI (RFC 4760): MP_REACH_NLRI (type 14) and MP_UNREACH_NLRI (type 15).

use lr_core::addr::IpAddr;
use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;

/// NEXT_HOP encoding for MP-BGP. RFC 4760 §3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MpNextHop {
    V4([u8; 4]),
    V6Global([u8; 16]),
    V6LinkLocal([u8; 16]),
    V6GlobalLinkLocal([u8; 16], [u8; 16]),
    /// RFC 5549: 4-byte IPv4-over-IPv6 next-hop.
    V4OverV6([u8; 16]),
}

impl MpNextHop {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::V4(b) => b.to_vec(),
            Self::V6Global(b) | Self::V4OverV6(b) => b.to_vec(),
            Self::V6LinkLocal(b) => b.to_vec(),
            Self::V6GlobalLinkLocal(g, l) => {
                let mut v = Vec::with_capacity(32);
                v.extend_from_slice(g);
                v.extend_from_slice(l);
                v
            }
        }
    }

    pub fn primary(&self) -> IpAddr {
        match self {
            Self::V4(b) => IpAddr::V4(*b),
            Self::V6Global(b) | Self::V4OverV6(b) | Self::V6LinkLocal(b) => IpAddr::V6(*b),
            Self::V6GlobalLinkLocal(g, _) => IpAddr::V6(*g),
        }
    }
}

/// MP_REACH_NLRI attribute (RFC 4760 §3). Family, next-hop(s), NLRI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpReach {
    pub family: NlriFamily,
    pub next_hop: MpNextHop,
    pub nlri: Vec<Prefix>,
}

impl MpReach {
    pub fn new(family: NlriFamily, next_hop: MpNextHop, nlri: Vec<Prefix>) -> Self {
        Self {
            family,
            next_hop,
            nlri,
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 3 + 1 {
            return None;
        }
        let afi = u16::from_be_bytes([b[0], b[1]]);
        let safi = b[2];
        let family = NlriFamily { afi, safi };
        let nh_len = b[3] as usize;
        if b.len() < 4 + nh_len {
            return None;
        }
        let nh_bytes = &b[4..4 + nh_len];
        let next_hop = decode_next_hop(nh_bytes, family)?;
        let mut i = 4 + nh_len;
        if i >= b.len() {
            return Some(Self {
                family,
                next_hop,
                nlri: vec![],
            });
        }
        // 1 reserved byte (RFC 4760 §3) — skip
        i += 1;
        let mut nlri = Vec::new();
        while i < b.len() {
            // Prefix-length (1) + ceil(pl / 8) bytes
            let pl = b[i];
            i += 1;
            let n = (pl as usize).div_ceil(8);
            if i + n > b.len() {
                return None;
            }
            let p = match family.afi {
                1 => {
                    let mut bytes = [0u8; 4];
                    bytes[..n].copy_from_slice(&b[i..i + n]);
                    i += n;
                    Prefix::new_v4(bytes, pl)
                }
                2 => {
                    let mut bytes = [0u8; 16];
                    bytes[..n].copy_from_slice(&b[i..i + n]);
                    i += n;
                    Prefix::new_v6(bytes, pl)
                }
                _ => return None,
            };
            nlri.push(p);
        }
        Some(Self {
            family,
            next_hop,
            nlri,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.family.afi.to_be_bytes());
        out.push(self.family.safi);
        let nh = self.next_hop.encode();
        out.push(nh.len() as u8);
        out.extend_from_slice(&nh);
        out.push(0); // reserved
        for p in &self.nlri {
            out.push(p.prefix_len);
            let pl = p.prefix_len as usize;
            let n = pl.div_ceil(8);
            // Zero host bits per RFC 4271 §5.1.3.
            let mut octets = match &p.addr {
                IpAddr::V4(b) => b.to_vec(),
                IpAddr::V6(b) => b.to_vec(),
            };
            octets.truncate(n);
            // Mask the last octet's host bits.
            if !pl.is_multiple_of(8) {
                if let Some(last) = octets.last_mut() {
                    let mask = 0xffu8 << (8 - pl % 8);
                    *last &= mask;
                }
            }
            out.extend_from_slice(&octets);
        }
        out
    }
}

/// MP_UNREACH_NLRI attribute (RFC 4760 §4). Family + NLRI to withdraw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpUnreach {
    pub family: NlriFamily,
    pub nlri: Vec<Prefix>,
}

impl MpUnreach {
    pub fn new(family: NlriFamily, nlri: Vec<Prefix>) -> Self {
        Self { family, nlri }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 3 {
            return None;
        }
        let afi = u16::from_be_bytes([b[0], b[1]]);
        let safi = b[2];
        let family = NlriFamily { afi, safi };
        let mut i = 3;
        let mut nlri = Vec::new();
        while i < b.len() {
            let pl = b[i];
            i += 1;
            let n = (pl as usize).div_ceil(8);
            if i + n > b.len() {
                return None;
            }
            let p = match family.afi {
                1 => {
                    let mut bytes = [0u8; 4];
                    bytes[..n].copy_from_slice(&b[i..i + n]);
                    i += n;
                    Prefix::new_v4(bytes, pl)
                }
                2 => {
                    let mut bytes = [0u8; 16];
                    bytes[..n].copy_from_slice(&b[i..i + n]);
                    i += n;
                    Prefix::new_v6(bytes, pl)
                }
                _ => return None,
            };
            nlri.push(p);
        }
        Some(Self { family, nlri })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.family.afi.to_be_bytes());
        out.push(self.family.safi);
        for p in &self.nlri {
            out.push(p.prefix_len);
            let pl = p.prefix_len as usize;
            let n = pl.div_ceil(8);
            let mut octets = match &p.addr {
                IpAddr::V4(b) => b.to_vec(),
                IpAddr::V6(b) => b.to_vec(),
            };
            octets.truncate(n);
            if !pl.is_multiple_of(8) {
                if let Some(last) = octets.last_mut() {
                    let mask = 0xffu8 << (8 - pl % 8);
                    *last &= mask;
                }
            }
            out.extend_from_slice(&octets);
        }
        out
    }
}

fn decode_next_hop(b: &[u8], family: NlriFamily) -> Option<MpNextHop> {
    match (family.afi, b.len()) {
        (1, 4) => {
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            Some(MpNextHop::V4(a))
        }
        (2, 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(MpNextHop::V6Global(a))
        }
        (2, 32) => {
            let mut g = [0u8; 16];
            let mut l = [0u8; 16];
            g.copy_from_slice(&b[..16]);
            l.copy_from_slice(&b[16..]);
            Some(MpNextHop::V6GlobalLinkLocal(g, l))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mp_reach_ipv6_roundtrip() {
        let mp = MpReach::new(
            NlriFamily::IPV6_UNICAST,
            MpNextHop::V6Global([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            vec![Prefix::new_v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                64,
            )],
        );
        let enc = mp.encode();
        let dec = MpReach::decode(&enc).unwrap();
        assert_eq!(dec, mp);
    }

    #[test]
    fn mp_unreach_roundtrip() {
        let mp = MpUnreach::new(
            NlriFamily::IPV6_UNICAST,
            vec![
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    64,
                ),
                Prefix::new_v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                    65,
                ),
            ],
        );
        let enc = mp.encode();
        let dec = MpUnreach::decode(&enc).unwrap();
        assert_eq!(dec, mp);
    }
}
