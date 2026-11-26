//! Codec methods for the BGP capability codes added in the 2.x
//! capability block (issue #101): ORF (RFC 5291), Extended Message
//! (RFC 8654), BGP Role (RFC 9234), FQDN/Hostname
//! (draft-walton-bgp-hostname-capability-02), BFD Strict-Mode
//! (draft-ietf-idr-bgp-bfd-strict-mode-19), Software Version
//! (draft-abraitis-bgp-version-capability-18), PATHS-LIMIT
//! (draft-ietf-idr-addpath-paths-limit-00) and Link-Local Next
//! Hop (draft-ietf-idr-linklocal-capability-06).
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

/// Wire encoding of the Software Version capability (code 75).
///
/// The draft changed the value layout between revisions. The
/// encoder follows the selected variant; the decoder accepts both,
/// because a peer may run either implementation.
///
/// - [`Draft11`](Self::Draft11): draft-abraitis-bgp-version-capability-11
///   and earlier prepend a one-octet length to the UTF-8 string.
/// - [`Latest`](Self::Latest): draft-abraitis-bgp-version-capability-18
///   and later carry the UTF-8 string as the whole value; the
///   capability length already gives its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SoftwareVersionEncoding {
    /// draft-abraitis-bgp-version-capability-11: one-octet length
    /// prefix followed by the UTF-8 string.
    Draft11,
    /// draft-abraitis-bgp-version-capability-18 and later: the value
    /// is the UTF-8 string itself. This is the default, matching the
    /// latest draft.
    #[default]
    Latest,
}

impl SoftwareVersionEncoding {
    /// The configuration spelling: `"latest"` or `"draft-11"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft11 => "draft-11",
            Self::Latest => "latest",
        }
    }
}

impl core::str::FromStr for SoftwareVersionEncoding {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(Self::Latest),
            "draft-11" => Ok(Self::Draft11),
            _ => Err("expected 'latest' or 'draft-11'"),
        }
    }
}

impl core::fmt::Display for SoftwareVersionEncoding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

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

    /// draft-walton-bgp-hostname-capability-02 FQDN capability (code
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
    ///
    /// The capability length is a single octet (RFC 5492 §3), so the
    /// two strings share 253 octets. Long strings are truncated on a
    /// UTF-8 character boundary; the hostname is kept in full before
    /// the domain is shortened.
    pub fn fqdn(hostname: &str, domain: &str) -> Self {
        const MAX_STRINGS: usize = u8::MAX as usize - 2;
        let h = truncate_utf8(hostname.as_bytes(), MAX_STRINGS);
        let d = truncate_utf8(domain.as_bytes(), MAX_STRINGS - h.len());
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

    /// draft-ietf-idr-bgp-bfd-strict-mode-19 BFD Strict-Mode capability
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

    /// draft-abraitis-bgp-version-capability-18 Software Version
    /// capability (code 75) in the latest encoding. The value is the
    /// UTF-8 string itself; the capability length carries its size.
    /// The draft recommends the identifier format
    /// `product/product-version` (e.g. `frrouting/8.4.2`, `lr/2.0`).
    ///
    /// The draft's SHOULD clause caps the value at 64 bytes; a longer
    /// string is truncated on a UTF-8 character boundary. An empty
    /// string produces an empty value, which the draft says a receiver
    /// MUST treat as an encoding error and ignore; the FSM helper
    /// [`crate::extensions::software_version::open_capability`] does
    /// not advertise such a capability.
    pub fn software_version(version: &str) -> Self {
        Self::software_version_with(version, SoftwareVersionEncoding::Latest)
    }

    /// Build the Software Version capability with an explicit draft
    /// encoding. See [`SoftwareVersionEncoding`] for the two layouts.
    pub fn software_version_with(version: &str, encoding: SoftwareVersionEncoding) -> Self {
        let v = truncate_utf8(version.as_bytes(), 64);
        let mut out = Vec::with_capacity(1 + v.len());
        if encoding == SoftwareVersionEncoding::Draft11 {
            out.push(v.len() as u8);
        }
        out.extend_from_slice(v);
        Self::new(CapabilityCode::SoftwareVersion, out)
    }

    /// Decode the Software Version capability into a UTF-8 string.
    ///
    /// Both draft encodings are accepted, because the draft's
    /// implementations coexist:
    ///
    /// - When the first octet plus one equals the value length, the
    ///   value is the draft-11 length-prefixed form.
    /// - Otherwise the whole value is the latest form's UTF-8 string.
    ///
    /// Returns `None` for an empty value (the latest draft calls this
    /// an encoding error and says to ignore the capability) or when
    /// the selected slice is not valid UTF-8. The ambiguous case — a
    /// latest-form string whose first octet happens to equal
    /// `len - 1` — is resolved in favour of the draft-11 form, the
    /// same tie-break FRR uses.
    pub fn as_software_version(&self) -> Option<String> {
        if self.code != CapabilityCode::SoftwareVersion || self.value.is_empty() {
            return None;
        }
        let first = self.value[0] as usize;
        let bytes = if first + 1 == self.value.len() {
            &self.value[1..]
        } else {
            &self.value[..]
        };
        core::str::from_utf8(bytes).ok().map(String::from)
    }

    /// draft-ietf-idr-addpath-paths-limit-00 PATHS-LIMIT capability
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

    /// draft-ietf-idr-linklocal-capability-06 Link-Local Next Hop
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

/// Truncate a UTF-8 byte slice to at most `max` bytes without
/// splitting a character. The Software Version capability is capped
/// at 64 bytes by a SHOULD, and the FQDN value is capped by the
/// one-octet capability length; a mid-character cut would turn a
/// valid string into an invalid one.
fn truncate_utf8(bytes: &[u8], max: usize) -> &[u8] {
    if bytes.len() <= max {
        return bytes;
    }
    let mut end = max;
    while end > 0 && !is_utf8_boundary(bytes, end) {
        end -= 1;
    }
    &bytes[..end]
}

/// True when `index` starts a UTF-8 character (or is the end of the
/// slice): the byte at `index` is not a continuation byte.
fn is_utf8_boundary(bytes: &[u8], index: usize) -> bool {
    index == bytes.len() || (bytes[index] & 0xc0) != 0x80
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

    /// The capability value is `2 + hostname + domain` and the RFC 5492
    /// §3 length is one octet: 253 octets total for the two strings.
    /// The hostname takes priority and a character boundary is kept.
    #[test]
    fn fqdn_total_value_never_exceeds_255_octets() {
        let hostname = "h".repeat(300);
        let domain = "example.net".repeat(40);
        let cap = Capability::fqdn(&hostname, &domain);
        assert_eq!(cap.value.len(), 255);
        let wire = Capability::try_encode_set(std::slice::from_ref(&cap)).unwrap();
        assert_eq!(wire[1], 255);
        let decoded = Capability::decode_set(&wire);
        assert_eq!(decoded.len(), 1);
        let (h, d) = decoded[0].as_fqdn().unwrap();
        assert_eq!(h, "h".repeat(253));
        // 253 octets went to the hostname, leaving none for the domain.
        assert!(d.is_empty());
    }

    #[test]
    fn fqdn_truncates_domain_when_hostname_is_short() {
        let domain = "d".repeat(300);
        let cap = Capability::fqdn("r1", &domain);
        assert_eq!(cap.value.len(), 255);
        let (h, d) = cap.as_fqdn().unwrap();
        assert_eq!(h, "r1");
        assert_eq!(d, "d".repeat(251));
    }

    #[test]
    fn fqdn_truncates_at_utf8_character_boundary() {
        // 252 one-byte characters + a two-byte character cannot fit in
        // the 253-octet budget; the two-byte character is dropped whole.
        let mut hostname = "a".repeat(252);
        hostname.push('é');
        let cap = Capability::fqdn(&hostname, "");
        assert_eq!(cap.value.len(), 254); // 2 + 252
        let (h, d) = cap.as_fqdn().unwrap();
        assert_eq!(h, "a".repeat(252));
        assert!(d.is_empty());
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
    fn software_version_latest_encoding_roundtrip() {
        let cap = Capability::software_version("lr/2.0");
        assert_eq!(cap.code.to_u8(), 75);
        // draft-18: the value is the UTF-8 string, with no inner
        // length byte.
        assert_eq!(cap.value, b"lr/2.0");
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].as_software_version(), Some("lr/2.0".to_string()));
    }

    #[test]
    fn software_version_draft11_encoding_roundtrip() {
        let cap = Capability::software_version_with("lr/2.0", SoftwareVersionEncoding::Draft11);
        assert_eq!(cap.value, b"\x06lr/2.0");
        let v = Capability::encode_set(&[cap]);
        let dec = Capability::decode_set(&v);
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].as_software_version(), Some("lr/2.0".to_string()));
    }

    /// The decoder accepts the latest form and the draft-11 form,
    /// so two implementations on different revisions still exchange
    /// the version string.
    #[test]
    fn software_version_decodes_both_encodings() {
        let latest = Capability::new(
            CapabilityCode::SoftwareVersion,
            b"frrouting/10.5.1".to_vec(),
        );
        assert_eq!(
            latest.as_software_version(),
            Some("frrouting/10.5.1".to_string())
        );
        let old = Capability::new(
            CapabilityCode::SoftwareVersion,
            b"\x0efrrouting/10.5".to_vec(),
        );
        assert_eq!(
            old.as_software_version(),
            Some("frrouting/10.5".to_string())
        );
    }

    /// draft-18 §3: the length must be greater than zero; a zero
    /// length is an encoding error and the capability is ignored.
    #[test]
    fn software_version_empty_value_is_ignored() {
        let cap = Capability::software_version("");
        assert!(cap.value.is_empty());
        assert!(cap.as_software_version().is_none());
        let cap = Capability::new(CapabilityCode::SoftwareVersion, vec![]);
        assert!(cap.as_software_version().is_none());
    }

    /// The draft's SHOULD caps the value at 64 bytes. A longer
    /// string is truncated at a character boundary, so the encoded
    /// value stays valid UTF-8.
    #[test]
    fn software_version_truncates_to_64_bytes_on_a_char_boundary() {
        let long = "x".repeat(300);
        let cap = Capability::software_version(&long);
        assert_eq!(cap.value.len(), 64);

        // A 2-byte character straddling the 64-byte limit must be
        // dropped whole, leaving 63 bytes of valid UTF-8.
        let mut s = "a".repeat(63);
        s.push('é'); // 2 bytes in UTF-8
        let cap = Capability::software_version(&s);
        assert_eq!(cap.value.len(), 63);
        assert_eq!(cap.as_software_version(), Some("a".repeat(63)));
    }

    #[test]
    fn software_version_rejects_invalid_utf8() {
        // Latest form with invalid UTF-8.
        let cap = Capability::new(CapabilityCode::SoftwareVersion, vec![0xff, 0xfe]);
        assert!(cap.as_software_version().is_none());

        // Draft-11 form whose declared body is invalid UTF-8.
        let cap = Capability::new(CapabilityCode::SoftwareVersion, vec![2, 0xff, 0xfe]);
        assert!(cap.as_software_version().is_none());
    }

    /// A latest-form string whose first octet happens to be
    /// `len - 1` is indistinguishable from draft-11. The decoder
    /// follows FRR and reads it as draft-11.
    #[test]
    fn software_version_ambiguous_value_prefers_draft11() {
        let cap = Capability::new(CapabilityCode::SoftwareVersion, vec![2, b'A', b'B']);
        assert_eq!(cap.as_software_version(), Some("AB".to_string()));
    }

    #[test]
    fn software_version_encoding_parses_config_spelling() {
        assert_eq!(
            "latest".parse::<SoftwareVersionEncoding>(),
            Ok(SoftwareVersionEncoding::Latest)
        );
        assert_eq!(
            "draft-11".parse::<SoftwareVersionEncoding>(),
            Ok(SoftwareVersionEncoding::Draft11)
        );
        assert!("draft-18".parse::<SoftwareVersionEncoding>().is_err());
        assert_eq!(SoftwareVersionEncoding::Latest.to_string(), "latest");
        assert_eq!(SoftwareVersionEncoding::Draft11.to_string(), "draft-11");
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
