//! MP-BGP NLRI (RFC 4760): MP_REACH_NLRI (type 14) and MP_UNREACH_NLRI (type 15),
//! with RFC 7911 Add-Path NLRI encoding.

use lr_core::addr::IpAddr;
use lr_core::addr::Prefix;
use lr_core::nlri::NlriFamily;

use crate::message::update::Nlri;

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
    pub nlri: Vec<Nlri>,
}

impl MpReach {
    pub fn new(family: NlriFamily, next_hop: MpNextHop, nlri: Vec<Nlri>) -> Self {
        Self {
            family,
            next_hop,
            nlri,
        }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        Self::decode_ex(b, false)
    }

    /// Decode only the fixed MP_REACH_NLRI header — family and next-hop —
    /// without touching the NLRI. Unlike [`Self::decode`], this works for
    /// every family with a defined next-hop wire form, including RFC 8277
    /// labelled-unicast families whose NLRI the plain decoder cannot
    /// parse. Helpers that only need the family or next-hop (UPDATE
    /// inspection, FFI readers) use this.
    pub fn decode_header(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        let family = NlriFamily {
            afi: u16::from_be_bytes([b[0], b[1]]),
            safi: b[2],
        };
        let nh_len = b[3] as usize;
        if b.len() < 4 + nh_len {
            return None;
        }
        let next_hop = decode_next_hop(&b[4..4 + nh_len], family)?;
        Some(Self {
            family,
            next_hop,
            nlri: Vec::new(),
        })
    }

    /// Decode with RFC 7911 Add-Path: when `add_path` is true every NLRI
    /// entry is prefixed by a 4-octet path identifier.
    pub fn decode_ex(b: &[u8], add_path: bool) -> Option<Self> {
        if b.len() < 3 + 1 {
            return None;
        }
        let afi = u16::from_be_bytes([b[0], b[1]]);
        let safi = b[2];
        let family = NlriFamily { afi, safi };
        // RFC 8277 §3: labelled NLRI carries its label stack inside the
        // prefix-length octets. The plain decoder would read those label
        // bits as prefix bits and install a bogus prefix; reject the
        // family so callers dispatch to `labeled_nlri` instead.
        if family.is_labeled_unicast() {
            return None;
        }
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
            // Prefix-length (1) + ceil(pl / 8) bytes, optionally after a
            // 4-octet Add-Path identifier (RFC 7911 §4.3). The entry
            // needs the path-id *plus* the length byte; a path-id that
            // ends the buffer is a truncated entry, not a length byte.
            let path_id = if add_path {
                if i + 5 > b.len() {
                    return None;
                }
                let id = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
                i += 4;
                id
            } else {
                0
            };
            let pl = b[i];
            i += 1;
            let n = (pl as usize).div_ceil(8);
            if i + n > b.len() {
                return None;
            }
            // Reject prefix lengths that exceed the family's address width
            // (defensive — see `MpUnreach::decode_ex`). Labelled families
            // are decoded by `labeled_nlri`.
            let max_octets = match family.afi {
                1 => 4usize,
                2 => 16usize,
                _ => return None,
            };
            if n > max_octets {
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
            nlri.push(Nlri::new(path_id, p));
        }
        Some(Self {
            family,
            next_hop,
            nlri,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_ex(false)
    }

    /// Encode with RFC 7911 Add-Path: when `add_path` is true every NLRI
    /// entry is prefixed by its 4-octet path identifier.
    pub fn encode_ex(&self, add_path: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.family.afi.to_be_bytes());
        out.push(self.family.safi);
        let nh = self.next_hop.encode();
        out.push(nh.len() as u8);
        out.extend_from_slice(&nh);
        out.push(0); // reserved
        for entry in &self.nlri {
            if add_path {
                out.extend_from_slice(&entry.path_id.to_be_bytes());
            }
            let p = &entry.prefix;
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
    pub nlri: Vec<Nlri>,
}

impl MpUnreach {
    pub fn new(family: NlriFamily, nlri: Vec<Nlri>) -> Self {
        Self { family, nlri }
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        Self::decode_ex(b, false)
    }

    /// Decode with RFC 7911 Add-Path path identifiers on each NLRI entry.
    pub fn decode_ex(b: &[u8], add_path: bool) -> Option<Self> {
        if b.len() < 3 {
            return None;
        }
        let afi = u16::from_be_bytes([b[0], b[1]]);
        let safi = b[2];
        let family = NlriFamily { afi, safi };
        // RFC 8277 §3: see `MpReach::decode_ex` — labelled NLRI is not
        // `<plen><prefix>` and must go through `labeled_nlri`.
        if family.is_labeled_unicast() {
            return None;
        }
        let mut i = 3;
        let mut nlri = Vec::new();
        while i < b.len() {
            // See `MpReach::decode_ex`: the Add-Path entry needs the
            // 4-byte path-id plus the prefix-length byte after it.
            let path_id = if add_path {
                if i + 5 > b.len() {
                    return None;
                }
                let id = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
                i += 4;
                id
            } else {
                0
            };
            let pl = b[i];
            i += 1;
            let n = (pl as usize).div_ceil(8);
            if i + n > b.len() {
                return None;
            }
            // Reject prefix lengths that exceed the family's address width
            // (defensive — a malformed peer could otherwise panic the slice
            // bounds below). Labelled families carry label octets inside the
            // prefix-length budget and are decoded by `labeled_nlri`; the
            // plain decoder rejects them so the EoR / withdrawal paths
            // dispatch to the labelled decoder.
            let max_octets = match family.afi {
                1 => 4usize,
                2 => 16usize,
                _ => return None,
            };
            if n > max_octets {
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
            nlri.push(Nlri::new(path_id, p));
        }
        Some(Self { family, nlri })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_ex(false)
    }

    /// Encode with RFC 7911 Add-Path path identifiers on each NLRI entry.
    pub fn encode_ex(&self, add_path: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.family.afi.to_be_bytes());
        out.push(self.family.safi);
        for entry in &self.nlri {
            if add_path {
                out.extend_from_slice(&entry.path_id.to_be_bytes());
            }
            let p = &entry.prefix;
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

pub(crate) fn decode_next_hop(b: &[u8], family: NlriFamily) -> Option<MpNextHop> {
    match (family.afi, b.len()) {
        (1, 4) => {
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            Some(MpNextHop::V4(a))
        }
        // RFC 5549: IPv4 NLRI (AFI=1) carried over an IPv6 next-hop. The
        // peer must have advertised the Extended Next-Hop capability for
        // (1, 1, 2); the codec cannot enforce that here, so we accept the
        // wire form and let the FSM / safety net reject unexpected
        // families downstream.
        (1, 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(MpNextHop::V4OverV6(a))
        }
        (2, 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            // draft-ietf-idr-linklocal-capability-06 §3: a 16-octet
            // next hop in fe80::/10 is a Link-Local-only next hop;
            // otherwise it is the RFC 2545 global form.
            if crate::extensions::link_local_next_hop::is_link_local(&a) {
                Some(MpNextHop::V6LinkLocal(a))
            } else {
                Some(MpNextHop::V6Global(a))
            }
        }
        (2, 32) => {
            let mut g = [0u8; 16];
            let mut l = [0u8; 16];
            g.copy_from_slice(&b[..16]);
            l.copy_from_slice(&b[16..]);
            // draft-ietf-idr-linklocal-capability-06 §6: the second
            // slot carries the link-local address. When the first is
            // also link-local, or unspecified (::/LL), forward via the
            // second — that is the address the sender intended. A
            // 32-octet field whose second slot is not link-local is
            // malformed per RFC 2545 and is rejected so the caller can
            // treat the UPDATE as withdraw.
            if !crate::extensions::link_local_next_hop::is_link_local(&l) {
                return None;
            }
            if crate::extensions::link_local_next_hop::is_link_local(&g)
                || crate::extensions::link_local_next_hop::is_unspecified(&g)
            {
                Some(MpNextHop::V6LinkLocal(l))
            } else {
                Some(MpNextHop::V6GlobalLinkLocal(g, l))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "mp_nlri_tests.rs"]
mod tests;
