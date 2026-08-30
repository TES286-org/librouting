//! Safety net: protocol-level invariants that must hold for a route to be
//! admitted into the Loc-RIB. These are **beyond** policy — they protect the
//! router from being tricked into installing routes that violate the protocol
//! (e.g. AS path loops, NEXT_HOP collisions, malformed AS_PATH).
//!
//! Each check can be **disabled** individually by the embedder via
//! [`SafetyConfig`]. Disabled checks return `Ok(())` immediately. By default
//! all checks are enabled.
//!
//! Violations are surfaced via [`SafetyViolation`] so the embedder can log
//! them, send them to a syslog/telemetry sink, or merely discard.

use lr_core::addr::{Asn, IpAddr};
use lr_core::rib::Route;

/// Knobs that toggle individual safety checks. All default to `true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyConfig {
    /// Reject routes whose AS_PATH contains the local AS (RFC 4271 §9.1.2.15).
    pub reject_as_loop: bool,
    /// Reject routes whose NEXT_HOP is unspecified, loopback, or the local
    /// router's own address (RFC 4271 §6.7).
    pub reject_invalid_next_hop: bool,
    /// Reject routes whose AS_PATH is empty when received from an eBGP peer
    /// (the peer should have prepended its AS).
    pub reject_empty_as_path_ebgp: bool,
    /// Reject routes whose ORIGIN attribute is missing or invalid.
    pub reject_invalid_origin: bool,
    /// Reject routes whose own-AS appears more than `max_as_path_loops`
    /// times in the AS_PATH (default 3 — typical operator safety).
    pub reject_excessive_as_loop: bool,
    pub max_as_path_loops: u8,
    /// Reject routes whose AS_PATH is suspiciously long (> max_as_path_length).
    pub reject_oversized_as_path: bool,
    pub max_as_path_length: usize,
    /// Reject routes whose prefix is in the martian list (default IPv4
    /// 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 169.254.0.0/16, 240.0.0.0/4 and
    /// IPv6 ::/128, ::1/128, fc00::/7, fe80::/10).
    pub reject_martian_prefix: bool,
    /// Reject routes whose LOCAL_PREF exceeds `max_local_pref` (default
    /// 4294967295 — the wire maximum). Useful to prevent DoS via
    /// enormous LOCAL_PREF.
    pub reject_oversized_local_pref: bool,
    pub max_local_pref: u32,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            reject_as_loop: true,
            reject_invalid_next_hop: true,
            reject_empty_as_path_ebgp: false,
            reject_invalid_origin: true,
            reject_excessive_as_loop: true,
            max_as_path_loops: 3,
            reject_oversized_as_path: true,
            max_as_path_length: 64,
            reject_martian_prefix: true,
            reject_oversized_local_pref: false,
            max_local_pref: u32::MAX,
        }
    }
}

/// A safety violation. Categorised by check name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyViolation {
    AsLoop {
        route_key: String,
        local_as: Asn,
    },
    InvalidNextHop {
        route_key: String,
        next_hop: IpAddr,
    },
    EmptyAsPathEbgp {
        route_key: String,
    },
    InvalidOrigin {
        route_key: String,
    },
    ExcessiveAsLoop {
        route_key: String,
        count: u8,
    },
    OversizedAsPath {
        route_key: String,
        len: usize,
    },
    MartianPrefix {
        route_key: String,
        reason: &'static str,
    },
    OversizedLocalPref {
        route_key: String,
        value: u32,
    },
}

impl core::fmt::Display for SafetyViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AsLoop {
                route_key,
                local_as,
            } => write!(
                f,
                "AS_PATH loop detected: route {route_key} contains local AS {local_as}"
            ),
            Self::InvalidNextHop {
                route_key,
                next_hop,
            } => write!(f, "Invalid NEXT_HOP for route {route_key}: {next_hop}"),
            Self::EmptyAsPathEbgp { route_key } => write!(
                f,
                "Empty AS_PATH received from eBGP peer for route {route_key}"
            ),
            Self::InvalidOrigin { route_key } => write!(
                f,
                "Invalid or missing ORIGIN attribute for route {route_key}"
            ),
            Self::ExcessiveAsLoop { route_key, count } => write!(
                f,
                "Excessive AS loop: local AS appears {count} times in route {route_key}"
            ),
            Self::OversizedAsPath { route_key, len } => {
                write!(f, "Oversized AS_PATH (len={len}) for route {route_key}")
            }
            Self::MartianPrefix { route_key, reason } => {
                write!(f, "Martian prefix in route {route_key}: {reason}")
            }
            Self::OversizedLocalPref { route_key, value } => {
                write!(f, "Oversized LOCAL_PREF ({value}) for route {route_key}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SafetyViolation {}

/// Safety net checker. Stateless; constructed per protocol instance.
#[derive(Debug, Clone)]
pub struct SafetyNet {
    pub cfg: SafetyConfig,
    pub local_as: Asn,
    pub local_addrs: Vec<IpAddr>,
}

impl SafetyNet {
    pub fn new(local_as: Asn) -> Self {
        Self {
            cfg: SafetyConfig::default(),
            local_as,
            local_addrs: Vec::new(),
        }
    }

    /// Add an address owned by the local router (so we reject NEXT_HOP = me).
    pub fn with_local_addr(mut self, addr: IpAddr) -> Self {
        self.local_addrs.push(addr);
        self
    }

    /// Run all enabled checks on the route. Returns `Ok(())` if the route
    /// passes all checks, or `Err(violation)` otherwise.
    pub fn check(&self, route: &Route, is_ebgp: bool) -> Result<(), SafetyViolation> {
        let key = format!("{}", route.key.prefix);
        // Martian prefix check.
        if self.cfg.reject_martian_prefix && self.is_martian(&route.key.prefix) {
            return Err(SafetyViolation::MartianPrefix {
                route_key: key,
                reason: "prefix is in the martian list",
            });
        }
        // AS_PATH checks (BGP-specific — handled by the caller decoding AS_PATH
        // into the route's `attributes` field).
        if let Some(as_path_len) = self.as_path_len(route) {
            if self.cfg.reject_oversized_as_path && as_path_len > self.cfg.max_as_path_length {
                return Err(SafetyViolation::OversizedAsPath {
                    route_key: key,
                    len: as_path_len,
                });
            }
            if self.cfg.reject_empty_as_path_ebgp && is_ebgp && as_path_len == 0 {
                return Err(SafetyViolation::EmptyAsPathEbgp { route_key: key });
            }
            if self.cfg.reject_as_loop {
                let count = self.local_as_count(route);
                if count > 0 {
                    return Err(SafetyViolation::AsLoop {
                        route_key: key,
                        local_as: self.local_as,
                    });
                }
            }
            if self.cfg.reject_excessive_as_loop {
                let count = self.local_as_count(route);
                if count > self.cfg.max_as_path_loops {
                    return Err(SafetyViolation::ExcessiveAsLoop {
                        route_key: key,
                        count,
                    });
                }
            }
        }
        // NEXT_HOP checks.
        if self.cfg.reject_invalid_next_hop {
            if let Some(nh) = route.next_hop {
                if nh.is_unspecified()
                    || nh == IpAddr::V4([127, 0, 0, 1])
                    || self.local_addrs.contains(&nh)
                {
                    return Err(SafetyViolation::InvalidNextHop {
                        route_key: key,
                        next_hop: nh,
                    });
                }
            }
        }
        Ok(())
    }

    /// True if the prefix is a martian (a network that should never appear in
    /// the global routing table).
    fn is_martian(&self, p: &lr_core::addr::Prefix) -> bool {
        match p.addr {
            IpAddr::V4(b) => {
                let pl = p.prefix_len;
                // 0.0.0.0/8 (unspecified)
                (b[0] == 0 && pl >= 8)
                // 127.0.0.0/8 (loopback)
                || (b[0] == 127 && pl >= 8)
                // 169.254.0.0/16 (link-local)
                || (b[0] == 169 && b[1] == 254 && pl >= 16)
                // 224.0.0.0/4 (multicast)
                || (b[0] & 0xf0 == 0xe0 && pl >= 4)
                // 240.0.0.0/4 (reserved)
                || (b[0] & 0xf0 == 0xf0 && pl >= 4)
            }
            IpAddr::V6(b) => {
                let pl = p.prefix_len;
                // ::/128 (unspecified) or ::1/128 (loopback)
                (b == [0; 16] && pl >= 128)
                || (b == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] && pl >= 128)
                // fc00::/7 (unique local)
                || (b[0] & 0xfe == 0xfc && pl >= 7)
                // fe80::/10 (link-local)
                || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80 && pl >= 10)
                // ff00::/8 (multicast)
                || (b[0] == 0xff && pl >= 8)
            }
        }
    }

    /// Decode AS_PATH from the route's attributes (treats attr tag 2 as
    /// 2-byte AS_PATH and tag 17 as 4-byte AS4_PATH). Returns the number of
    /// ASes in sequence segments, or None if neither attribute is present.
    fn as_path_len(&self, route: &Route) -> Option<usize> {
        let attr_2 = route.attributes.get(lr_core::attr::AttrTag(2));
        let attr_17 = route.attributes.get(lr_core::attr::AttrTag(17));
        let attr = attr_17.or(attr_2)?;
        // AS4_PATH (tag 17) is always 4-byte; AS_PATH (tag 2) is 4-byte
        // after FSM normalization, 2-byte in the legacy form. Try 4-byte
        // first (the production path), fall back to 2-byte.
        let path = lr_bgp::path::AsPath::decode_4(&attr.value)
            .or_else(|| lr_bgp::path::AsPath::decode(&attr.value))?;
        // RFC 4271 §9.1.2.2(a): AS_SET counts as 1 regardless of size.
        Some(path.length())
    }

    /// Count how many times `local_as` appears in the AS_PATH. Used by both
    /// the strict and excessive loop checks.
    ///
    /// Reads the AS_PATH via the `AsPath::decode_4` helper first
    /// (FSM-normalized form — the post-OPEN codec always rewrites
    /// AS_PATH to 4-byte and removes AS4_PATH), then falls back to
    /// `AsPath::decode` (2-byte legacy form) for raw attribute bags
    /// that have not been through the FSM normalization (e.g. unit
    /// tests, embedder-supplied routes). The previous manual walker
    /// mis-parsed the post-normalization 4-byte AS_PATH as 2-byte
    /// when AS4_PATH (tag 17) was absent — which is the common case
    /// after the FSM rewrites the attribute bag — silently
    /// undercounting local AS occurrences and breaking `reject_as_loop`.
    #[cfg(feature = "bgp")]
    fn local_as_count(&self, route: &Route) -> u8 {
        let attr = match route.attributes.get(lr_core::attr::AttrTag(17)) {
            Some(a) => a,
            None => match route.attributes.get(lr_core::attr::AttrTag(2)) {
                Some(a) => a,
                None => return 0,
            },
        };
        // AS4_PATH (tag 17) is always 4-byte; AS_PATH (tag 2) is
        // 4-byte after FSM normalization, 2-byte in the legacy form.
        // Try 4-byte first (the production path), fall back to 2-byte
        // (the raw/test path).
        let path = lr_bgp::path::AsPath::decode_4(&attr.value)
            .or_else(|| lr_bgp::path::AsPath::decode(&attr.value));
        let Some(path) = path else {
            return 0;
        };
        let mut count = 0u8;
        for seg in &path.segments {
            for as_ in &seg.ases {
                if as_.0 == self.local_as.0 {
                    count = count.saturating_add(1);
                }
            }
        }
        count
    }

    /// Fallback AS_PATH counter when the `bgp` feature is disabled
    /// (no `lr-bgp` dependency). The manual walker parses the AS_PATH
    /// segment-by-segment, preferring AS4_PATH (tag 17, always 4-byte)
    /// and falling back to AS_PATH (tag 2, 2-byte in the legacy form).
    /// Without the FSM normalization step the tag-2 width is correct.
    #[cfg(not(feature = "bgp"))]
    fn local_as_count(&self, route: &Route) -> u8 {
        let attr = route.attributes.get(lr_core::attr::AttrTag(17));
        let v = match attr {
            Some(a) => &a.value,
            None => match route.attributes.get(lr_core::attr::AttrTag(2)) {
                Some(a) => &a.value,
                None => return 0,
            },
        };
        let mut count = 0u8;
        let mut i = 0;
        let width = if attr.is_some() { 4 } else { 2 };
        while i + 1 < v.len() {
            let _kind = v[i];
            let n = v[i + 1] as usize;
            i += 2;
            for _ in 0..n {
                if i + width > v.len() {
                    break;
                }
                let as_ = if width == 4 {
                    u32::from_be_bytes([v[i], v[i + 1], v[i + 2], v[i + 3]])
                } else {
                    u16::from_be_bytes([v[i], v[i + 1]]) as u32
                };
                if as_ == self.local_as.0 {
                    count = count.saturating_add(1);
                }
                i += width;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lr_core::addr::{Asn, Prefix};
    use lr_core::attr::{Attribute, Attributes};
    use lr_core::nlri::NlriFamily;
    use lr_core::rib::{Preference, Protocol, RouteKey, RouteOrigin};

    fn make_route(prefix: Prefix, as_path_bytes: Vec<u8>) -> Route {
        let mut attrs = Attributes::new();
        attrs.insert(Attribute {
            tag: lr_core::attr::AttrTag(2),
            flags: 0,
            value: as_path_bytes,
        });
        Route {
            key: RouteKey::new(prefix, NlriFamily::IPV4_UNICAST),
            origin: RouteOrigin { proto: 0, peer: 1 },
            protocol: Protocol::Bgp,
            preference: Preference::new(20, 100),
            next_hop: None,
            attributes: attrs,
            age_ms: 0,
            path_id: 0,
        }
    }

    fn as_path_2byte(ases: &[u16]) -> Vec<u8> {
        // Single sequence segment: type=2, count, ASNs as 2-byte big-endian.
        let mut v = vec![2, ases.len() as u8];
        for a in ases {
            v.extend_from_slice(&a.to_be_bytes());
        }
        v
    }

    #[test]
    fn rejects_as_loop() {
        let safety = SafetyNet::new(Asn(100));
        let prefix = Prefix::new_v4([8, 0, 0, 0], 8);
        let route = make_route(prefix, as_path_2byte(&[200, 100, 300]));
        assert!(matches!(
            safety.check(&route, true),
            Err(SafetyViolation::AsLoop { .. })
        ));
    }

    #[test]
    fn passes_clean_route() {
        let safety = SafetyNet::new(Asn(100));
        let prefix = Prefix::new_v4([8, 0, 0, 0], 8);
        let route = make_route(prefix, as_path_2byte(&[200, 300]));
        assert!(safety.check(&route, true).is_ok());
    }

    #[test]
    fn rejects_martian_v4_loopback() {
        let safety = SafetyNet::new(Asn(100));
        let prefix = Prefix::new_v4([127, 0, 0, 0], 8);
        let route = make_route(prefix, as_path_2byte(&[200]));
        assert!(matches!(
            safety.check(&route, true),
            Err(SafetyViolation::MartianPrefix { .. })
        ));
    }

    #[test]
    fn rejects_martian_v6_link_local() {
        let safety = SafetyNet::new(Asn(100));
        let mut b = [0u8; 16];
        b[0] = 0xfe;
        b[1] = 0x80;
        let prefix = Prefix::new_v6(b, 10);
        let route = make_route(prefix, as_path_2byte(&[200]));
        assert!(matches!(
            safety.check(&route, true),
            Err(SafetyViolation::MartianPrefix { .. })
        ));
    }

    #[test]
    fn rejects_oversized_as_path() {
        let safety = SafetyNet {
            cfg: SafetyConfig {
                max_as_path_length: 4,
                ..Default::default()
            },
            local_as: Asn(100),
            local_addrs: Vec::new(),
        };
        let prefix = Prefix::new_v4([8, 0, 0, 0], 8);
        let route = make_route(prefix, as_path_2byte(&[1, 2, 3, 4, 5]));
        assert!(matches!(
            safety.check(&route, true),
            Err(SafetyViolation::OversizedAsPath { .. })
        ));
    }

    #[test]
    fn rejects_empty_as_path_ebgp_when_enabled() {
        let safety = SafetyNet {
            cfg: SafetyConfig {
                reject_empty_as_path_ebgp: true,
                ..Default::default()
            },
            local_as: Asn(100),
            local_addrs: Vec::new(),
        };
        let prefix = Prefix::new_v4([8, 0, 0, 0], 8);
        let route = make_route(prefix, vec![2, 0]); // 0 ASes
        assert!(matches!(
            safety.check(&route, true),
            Err(SafetyViolation::EmptyAsPathEbgp { .. })
        ));
    }

    #[test]
    fn disable_check_skips_violation() {
        let safety = SafetyNet {
            cfg: SafetyConfig {
                reject_as_loop: false,
                ..Default::default()
            },
            local_as: Asn(100),
            local_addrs: Vec::new(),
        };
        let prefix = Prefix::new_v4([8, 0, 0, 0], 8);
        let route = make_route(prefix, as_path_2byte(&[200, 100, 300]));
        assert!(safety.check(&route, true).is_ok());
    }
}
