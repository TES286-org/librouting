//! Codec methods for the BGP capability codes added in the 2.x
//! capability block (issue #101): ORF (RFC 5291), Extended Message
//! (RFC 8654), BGP Role (RFC 9234), FQDN/Hostname
//! (draft-walton-bgp-hostname-capability-01), BFD Strict-Mode
//! (draft-ietf-idr-bgp-bfd-strict-mode-13), Software Version
//! (draft-abraitis-bgp-version-capability-11), PATHS-LIMIT
//! (draft-abraitis-idr-addpath-paths-limit-00) and Link-Local Next
//! Hop (draft-white-linklocal-capability-04).
//!
//! These methods live on [`crate::capabilities::Capability`] but are
//! split into their own file so the core RFC 5492 / 4760 / 4893 / 7911
//! / 4724 / 9494 surface stays readable. The file is included from
//! `capabilities.rs` via `mod capabilities_extra;` — the methods are
//! `impl Capability` blocks, so callers see one type.

use crate::capabilities::{Capability, CapabilityCode};

/// One RFC 5291 §3 ORF entry: `(afi, safi, list of (orf_type,
/// send_recv_mode))`. The send/recv mode is 1 = RECEIVE (willing to
/// receive ORF entries from peer), 2 = SEND (wants to send ORF
/// entries), 3 = BOTH.
pub type OrfEntry = (u16, u8, Vec<(u8, u8)>);

impl Capability {
    /// RFC 5291 §3 ORF capability (code 3). The value is a sequence of
    /// per-address-family entries:
    ///
    /// ```text
    /// +---+---+---+---+---+---+
    /// | AFI (2) | R | SAFI | N | N × <Type:1, Send/Recv:1>
    /// +---+---+---+---+---+---+
    /// ```
    ///
    /// `entries` carries the `(afi, safi, [(orf_type, mode), ...])`
    /// triples to encode. `mode` is 1 = RECEIVE (willing to receive
    /// ORF entries from peer), 2 = SEND (wants to send ORF entries),
    /// 3 = BOTH. The wire layout matches FRR `bgp_open.c`
    /// `bgp_capability_orf_entry` and BIRD 2.x; both reject a value
    /// whose `num_types` field does not match the remaining bytes.
    pub fn orf(entries: &[OrfEntry]) -> Self {
        let mut v = Vec::new();
        for (afi, safi, types) in entries {
            v.extend_from_slice(&afi.to_be_bytes());
            v.push(0); // reserved
            v.push(*safi);
            v.push(types.len() as u8);
            for (orf_type, mode) in types {
                v.push(*orf_type);
                v.push(*mode);
            }
        }
        Self::new(CapabilityCode::Orf, v)
    }

    /// Decode the RFC 5291 ORF capability into per-family
    /// `(afi, safi, [(orf_type, mode), ...])` triples. Returns `None`
    /// on any structural violation: a header shorter than 5 octets,
    /// a `num_types` field that runs past the entry's bytes, or a
    /// trailing partial entry. Matches FRR's reject-then-NOTIFY
    /// posture (`bgp_capability_orf_entry` returns -1 and sends
    /// `BGP_NOTIFY_OPEN_MALFORMED_ATTR` for the same shapes).
    pub fn as_orf(&self) -> Option<Vec<OrfEntry>> {
        if self.code != CapabilityCode::Orf {
            return None;
        }
        let mut out = Vec::new();
        let mut i = 0;
        let bytes = &self.value;
        while i + 5 <= bytes.len() {
            let afi = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
            let safi = bytes[i + 3];
            let num = bytes[i + 4] as usize;
            i += 5;
            if i + num * 2 > bytes.len() {
                return None;
            }
            let mut types = Vec::with_capacity(num);
            for _ in 0..num {
                types.push((bytes[i], bytes[i + 1]));
                i += 2;
            }
            out.push((afi, safi, types));
        }
        if i != bytes.len() {
            return None;
        }
        Some(out)
    }

    /// RFC 8654 §3 Extended Message capability (code 6). The value is
    /// empty — presence alone signals that the speaker can send and
    /// receive BGP messages up to 65535 octets (the per-message length
    /// field is 2 bytes; without this capability the ceiling is 4096
    /// per RFC 4271 §4.1).
    pub fn extended_message() -> Self {
        Self::new(CapabilityCode::ExtendedMessage, Vec::new())
    }

    /// True when the capability carries an Extended Message
    /// advertisement. The value field is ignored on reception — RFC
    /// 8654 §3 defines the capability with `Capability Length 0`; a
    /// peer that ships bytes anyway is in violation but not harmful,
    /// so the negotiation accepts the capability whenever the code
    /// matches (mirrors FRR's `bgp_capability_ext_message` which
    /// only checks the code).
    pub fn is_extended_message(&self) -> bool {
        self.code == CapabilityCode::ExtendedMessage
    }

    /// RFC 9234 §4.1 BGP Role capability (code 9). The value is
    /// exactly one octet encoding the speaker's role for this
    /// session:
    ///
    /// | Value | Role |
    /// | --- | --- |
    /// | 0 | Provider |
    /// | 1 | RS (Route Server) |
    /// | 2 | RS-Client |
    /// | 3 | Customer |
    /// | 4 | Peer (Lateral Peer) |
    ///
    /// The "strict" mode is a local policy, not a wire field: RFC
    /// 9234 §4.2 says an operator may require receipt of the peer's
    /// role capability and reject the session with the Role Mismatch
    /// NOTIFICATION when it is absent. It is carried in
    /// [`crate::peer::PeerConfig::bgp_role`] alongside the role and
    /// never encoded here.
    pub fn bgp_role(role: u8) -> Self {
        Self::new(CapabilityCode::BgpRole, vec![role & 0x0f])
    }

    /// Decode the RFC 9234 BGP Role capability into its one-octet
    /// role value. Returns `None` when the value is not exactly one
    /// octet — RFC 9234 §4.1 fixes the length at 1, and accepting a
    /// longer value would make the role ambiguous.
    pub fn as_bgp_role(&self) -> Option<u8> {
        if self.code != CapabilityCode::BgpRole || self.value.len() != 1 {
            return None;
        }
        Some(self.value[0] & 0x0f)
    }

    /// draft-walton-bgp-hostname-capability-01 FQDN capability (code
    /// 73). The value is two length-prefixed UTF-8 strings:
    ///
    /// ```text
    /// +------------------------+---+
    /// | Hostname Length (1)    | H |
    /// +------------------------+---+
    /// | Domain Name Length (1)| D |
    /// +------------------------+---+
    /// ```
    ///
    /// Either length may be 0. The total value length is
    /// `2 + hostname.len() + domain.len()`; the receiver rejects
    /// values whose trailing length byte does not match the
    /// remaining bytes.
    pub fn fqdn(hostname: &str, domain: &str) -> Self {
        let h = truncate_u8(hostname.as_bytes());
        let d = truncate_u8(domain.as_bytes());
        let mut v = Vec::with_capacity(2 + h.len() + d.len());
        v.push(h.len() as u8);
        v.extend_from_slice(h);
        v.push(d.len() as u8);
        v.extend_from_slice(d);
        Self::new(CapabilityCode::Fqdn, v)
    }

    /// Decode the FQDN capability into `(hostname, domain)` UTF-8
    /// strings. Returns `None` when the lengths do not add up, or
    /// when either string is not valid UTF-8 (the draft specifies
    /// UTF-8; a peer that ships bytes that are not UTF-8 is in
    /// violation and the capability is refused).
    pub fn as_fqdn(&self) -> Option<(String, String)> {
        if self.code != CapabilityCode::Fqdn {
            return None;
        }
        let bytes = &self.value;
        if bytes.is_empty() {
            return None;
        }
        let hlen = bytes[0] as usize;
        if 1 + hlen >= bytes.len() {
            return None;
        }
        let hostname = core::str::from_utf8(&bytes[1..1 + hlen]).ok()?;
        let dlen = bytes[1 + hlen] as usize;
        if 1 + hlen + 1 + dlen != bytes.len() {
            return None;
        }
        let domain = core::str::from_utf8(&bytes[2 + hlen..]).ok()?;
        Some((hostname.to_string(), domain.to_string()))
    }

    /// draft-ietf-idr-bgp-bfd-strict-mode-13 BFD Strict-Mode capability
    /// (code 74). The value is empty — presence alone signals that the
    /// speaker does not fall back to the hold timer when BFD is down:
    /// the session stays down until BFD reports Up.
    pub fn bfd_strict_mode() -> Self {
        Self::new(CapabilityCode::BfdStrictMode, Vec::new())
    }

    /// True when the capability carries a BFD Strict-Mode advertisement.
    /// The value is ignored on reception per the draft.
    pub fn is_bfd_strict_mode(&self) -> bool {
        self.code == CapabilityCode::BfdStrictMode
    }

    /// draft-abraitis-bgp-version-capability-11 Software Version
    /// capability (code 75). The value is one length-prefixed UTF-8
    /// string. The draft recommends the identifier format
    /// `product/product-version` (e.g. `frrouting/8.4.2`, `lr/2.0`).
    /// Strings longer than 255 bytes are truncated to fit the 1-octet
    /// length; the draft's SHOULD clause caps the value at 64 bytes.
    pub fn software_version(version: &str) -> Self {
        let v = truncate_u8(version.as_bytes());
        let mut out = Vec::with_capacity(1 + v.len());
        out.push(v.len() as u8);
        out.extend_from_slice(v);
        Self::new(CapabilityCode::SoftwareVersion, out)
    }

    /// Decode the Software Version capability into a UTF-8 string.
    /// Returns `None` when the length byte does not match the
    /// remaining bytes, or when the string is not valid UTF-8.
    pub fn as_software_version(&self) -> Option<String> {
        if self.code != CapabilityCode::SoftwareVersion || self.value.is_empty() {
            return None;
        }
        let len = self.value[0] as usize;
        if 1 + len != self.value.len() {
            return None;
        }
        core::str::from_utf8(&self.value[1..])
            .ok()
            .map(String::from)
    }

    /// draft-abraitis-idr-addpath-paths-limit-00 PATHS-LIMIT capability
    /// (code 76). The value is a sequence of 5-byte tuples
    /// `<AFI:2, SAFI:1, Paths-Limit:2>`. The draft scopes the
    /// capability to AddPath-negotiated families — a peer that ships
    /// the capability without AddPath is ignored (the extension
    /// module enforces that).
    pub fn paths_limit(families: &[(u16, u8, u16)]) -> Self {
        let mut v = Vec::with_capacity(families.len() * 5);
        for (afi, safi, limit) in families {
            v.extend_from_slice(&afi.to_be_bytes());
            v.push(*safi);
            v.extend_from_slice(&limit.to_be_bytes());
        }
        Self::new(CapabilityCode::PathsLimit, v)
    }

    /// Decode the PATHS-LIMIT capability into `(afi, safi, limit)`
    /// triples. Returns `None` when the value length is not a
    /// multiple of 5 (FRR's `cap_modsizes[CAPABILITY_CODE_PATHS_LIMIT]
    /// = 5` enforces the same rule).
    pub fn as_paths_limit(&self) -> Option<Vec<(u16, u8, u16)>> {
        if self.code != CapabilityCode::PathsLimit || !self.value.len().is_multiple_of(5) {
            return None;
        }
        let mut out = Vec::with_capacity(self.value.len() / 5);
        for t in self.value.as_chunks::<5>().0 {
            let afi = u16::from_be_bytes([t[0], t[1]]);
            let safi = t[2];
            let limit = u16::from_be_bytes([t[3], t[4]]);
            out.push((afi, safi, limit));
        }
        Some(out)
    }

    /// draft-white-linklocal-capability-04 Link-Local Next Hop
    /// capability (code 77). The value is empty — presence alone
    /// signals that the speaker can accept a link-local IPv6
    /// next-hop in MP_REACH_NLRI for the negotiated families. The
    /// actual next-hop data rides MP_REACH_NLRI's Next Hop field
    /// with the length the draft defines (16 octets for a
    /// link-local-only next hop, 32 octets for a link-local + global
    /// pair).
    pub fn link_local_next_hop() -> Self {
        Self::new(CapabilityCode::LinkLocalNextHop, Vec::new())
    }

    /// True when the capability carries a Link-Local Next Hop
    /// advertisement. The value is ignored on reception per the
    /// draft.
    pub fn is_link_local_next_hop(&self) -> bool {
        self.code == CapabilityCode::LinkLocalNextHop
    }
}

/// Truncate a byte slice to the maximum length a 1-octet capability
/// field can carry. Used by the FQDN and Software Version encoders so
/// a long operator-supplied string cannot overflow the value field.
fn truncate_u8(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(u8::MAX as usize)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orf_roundtrip_single_family_single_type() {
        let cap = Capability::orf(&[(1, 1, vec![(64, 3)])]); // IPv4 unicast, prefix-ORF, both
        assert_eq!(cap.code.to_u8(), 3);
        assert_eq!(cap.value, vec![0, 1, 0, 1, 1, 64, 3]);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].as_orf(), Some(vec![(1, 1, vec![(64, 3)])]));
    }

    #[test]
    fn orf_roundtrip_multiple_families_and_types() {
        let cap = Capability::orf(&[(1, 1, vec![(64, 1), (65, 2)]), (2, 1, vec![(64, 3)])]);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(
            dec[0].as_orf(),
            Some(vec![(1, 1, vec![(64, 1), (65, 2)]), (2, 1, vec![(64, 3)])])
        );
    }

    #[test]
    fn orf_rejects_truncated_header_and_partial_types() {
        // 3 bytes — header needs 5.
        let cap = Capability::new(CapabilityCode::Orf, vec![0, 1, 0]);
        assert!(cap.as_orf().is_none());

        // num_types=2 but only one type pair follows.
        let cap = Capability::new(CapabilityCode::Orf, vec![0, 1, 0, 1, 2, 64, 3]);
        assert!(cap.as_orf().is_none());

        // Trailing partial entry (3 leftover bytes after a full entry).
        let cap = Capability::new(CapabilityCode::Orf, vec![0, 1, 0, 1, 1, 64, 3, 0, 2, 0]);
        assert!(cap.as_orf().is_none());
    }

    #[test]
    fn extended_message_has_empty_value() {
        let cap = Capability::extended_message();
        assert_eq!(cap.code.to_u8(), 6);
        assert!(cap.value.is_empty());
        assert!(cap.is_extended_message());
    }

    #[test]
    fn bgp_role_roundtrip_customer() {
        let cap = Capability::bgp_role(3); // Customer
        assert_eq!(cap.code.to_u8(), 9);
        assert_eq!(cap.value, vec![3]);
        assert_eq!(cap.as_bgp_role(), Some(3));
    }

    #[test]
    fn bgp_role_roundtrip_provider() {
        let cap = Capability::bgp_role(0); // Provider
        assert_eq!(cap.value, vec![0]);
        assert_eq!(cap.as_bgp_role(), Some(0));
    }

    /// RFC 9234 §4.1 fixes the value length at 1 octet. A longer
    /// value is not a valid role capability and is refused rather
    /// than silently truncated.
    #[test]
    fn bgp_role_rejects_empty_and_too_long() {
        let cap = Capability::new(CapabilityCode::BgpRole, vec![]);
        assert!(cap.as_bgp_role().is_none());
        let cap = Capability::new(CapabilityCode::BgpRole, vec![3, 0]);
        assert!(cap.as_bgp_role().is_none());
        let cap = Capability::new(CapabilityCode::BgpRole, vec![3, 0, 0]);
        assert!(cap.as_bgp_role().is_none());
    }

    /// The role octet is masked to its low 4 bits so a peer that
    /// ships extra high bits does not corrupt the role value.
    #[test]
    fn bgp_role_masks_high_bits() {
        let cap = Capability::new(CapabilityCode::BgpRole, vec![0x13]);
        assert_eq!(cap.as_bgp_role(), Some(3));
    }

    #[test]
    fn fqdn_roundtrip_hostname_and_domain() {
        let cap = Capability::fqdn("border-r1", "example.net");
        assert_eq!(cap.code.to_u8(), 73);
        let mut expected = Vec::new();
        expected.push(9); // "border-r1"
        expected.extend_from_slice(b"border-r1");
        expected.push(11); // "example.net"
        expected.extend_from_slice(b"example.net");
        assert_eq!(cap.value, expected);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(
            dec[0].as_fqdn(),
            Some(("border-r1".to_string(), "example.net".to_string()))
        );
    }

    #[test]
    fn fqdn_roundtrip_empty_strings() {
        let cap = Capability::fqdn("", "");
        assert_eq!(cap.value, vec![0, 0]);
        assert_eq!(cap.as_fqdn(), Some((String::new(), String::new())));
    }

    #[test]
    fn fqdn_roundtrip_hostname_only() {
        let cap = Capability::fqdn("rr-hk01", "");
        assert_eq!(cap.value.len(), 1 + 7 + 1);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(
            dec[0].as_fqdn(),
            Some(("rr-hk01".to_string(), String::new()))
        );
    }

    #[test]
    fn fqdn_rejects_truncated_length_and_bad_utf8() {
        // Empty value — at least the hostname length byte is required.
        let cap = Capability::new(CapabilityCode::Fqdn, vec![]);
        assert!(cap.as_fqdn().is_none());

        // hostname length 5 but only 3 bytes follow.
        let cap = Capability::new(CapabilityCode::Fqdn, vec![5, b'a', b'b', b'c']);
        assert!(cap.as_fqdn().is_none());

        // Trailing bytes after the declared domain length.
        let cap = Capability::new(CapabilityCode::Fqdn, vec![0, 0, b'x']);
        assert!(cap.as_fqdn().is_none());

        // Invalid UTF-8 in the hostname.
        let cap = Capability::new(CapabilityCode::Fqdn, vec![2, 0xff, 0xfe, 0]);
        assert!(cap.as_fqdn().is_none());
    }

    #[test]
    fn bfd_strict_mode_has_empty_value() {
        let cap = Capability::bfd_strict_mode();
        assert_eq!(cap.code.to_u8(), 74);
        assert!(cap.value.is_empty());
        assert!(cap.is_bfd_strict_mode());
    }

    #[test]
    fn software_version_roundtrip() {
        let cap = Capability::software_version("lr/2.0");
        assert_eq!(cap.code.to_u8(), 75);
        let mut expected = Vec::new();
        expected.push(6);
        expected.extend_from_slice(b"lr/2.0");
        assert_eq!(cap.value, expected);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].as_software_version(), Some("lr/2.0".to_string()));
    }

    #[test]
    fn software_version_roundtrip_empty_string() {
        let cap = Capability::software_version("");
        assert_eq!(cap.value, vec![0]);
        assert_eq!(cap.as_software_version(), Some(String::new()));
    }

    #[test]
    fn software_version_truncates_to_255() {
        let long = "x".repeat(300);
        let cap = Capability::software_version(&long);
        assert_eq!(cap.value.len(), 1 + 255);
        assert_eq!(cap.value[0], 255);
    }

    #[test]
    fn software_version_rejects_bad_length_and_utf8() {
        // Empty value — at least the length byte is required.
        let cap = Capability::new(CapabilityCode::SoftwareVersion, vec![]);
        assert!(cap.as_software_version().is_none());

        // length byte 5 but only 3 bytes follow.
        let cap = Capability::new(CapabilityCode::SoftwareVersion, vec![5, b'a', b'b', b'c']);
        assert!(cap.as_software_version().is_none());

        // Trailing bytes after the declared length.
        let cap = Capability::new(
            CapabilityCode::SoftwareVersion,
            vec![3, b'a', b'b', b'c', b'd'],
        );
        assert!(cap.as_software_version().is_none());

        // Invalid UTF-8.
        let cap = Capability::new(CapabilityCode::SoftwareVersion, vec![2, 0xff, 0xfe]);
        assert!(cap.as_software_version().is_none());
    }

    #[test]
    fn paths_limit_roundtrip_single_family() {
        let cap = Capability::paths_limit(&[(1, 1, 16)]);
        assert_eq!(cap.code.to_u8(), 76);
        assert_eq!(cap.value, vec![0, 1, 1, 0, 16]);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].as_paths_limit(), Some(vec![(1, 1, 16)]));
    }

    #[test]
    fn paths_limit_roundtrip_multiple_families() {
        let cap = Capability::paths_limit(&[(1, 1, 16), (2, 1, 32)]);
        assert_eq!(cap.value.len(), 10);
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec[0].as_paths_limit(), Some(vec![(1, 1, 16), (2, 1, 32)]));
    }

    #[test]
    fn paths_limit_rejects_non_multiple_of_5() {
        let cap = Capability::new(CapabilityCode::PathsLimit, vec![0, 1, 1, 0]);
        assert!(cap.as_paths_limit().is_none());
    }

    #[test]
    fn link_local_next_hop_has_empty_value() {
        let cap = Capability::link_local_next_hop();
        assert_eq!(cap.code.to_u8(), 77);
        assert!(cap.value.is_empty());
        assert!(cap.is_link_local_next_hop());
    }

    /// A peer that ships the new capability codes through the
    /// generic OPEN decoder must round-trip them — the decoder
    /// stores the raw value, and the typed accessors recover it.
    /// This is the property the daemon's OPEN handler relies on
    /// when it walks the peer's capabilities after `decode_set`.
    #[test]
    fn new_capabilities_roundtrip_through_open_decoder() {
        let caps = vec![
            Capability::orf(&[(1, 1, vec![(64, 3)])]),
            Capability::extended_message(),
            Capability::bgp_role(3),
            Capability::fqdn("border-r1", "example.net"),
            Capability::bfd_strict_mode(),
            Capability::software_version("lr/2.0"),
            Capability::paths_limit(&[(1, 1, 16)]),
            Capability::link_local_next_hop(),
        ];
        let wire = Capability::encode_set(&caps);
        let decoded = Capability::decode_set(&wire);
        assert_eq!(decoded.len(), caps.len());
        assert_eq!(decoded[0].as_orf(), Some(vec![(1, 1, vec![(64, 3)])]));
        assert!(decoded[1].is_extended_message());
        assert_eq!(decoded[2].as_bgp_role(), Some(3));
        assert_eq!(
            decoded[3].as_fqdn(),
            Some(("border-r1".to_string(), "example.net".to_string()))
        );
        assert!(decoded[4].is_bfd_strict_mode());
        assert_eq!(decoded[5].as_software_version(), Some("lr/2.0".to_string()));
        assert_eq!(decoded[6].as_paths_limit(), Some(vec![(1, 1, 16)]));
        assert!(decoded[7].is_link_local_next_hop());
    }
}
