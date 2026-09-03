//! The lr Exchange Plane (LRXP) — W6.3 prototype (feature
//! `exchange-plane`).
//!
//! A capability-negotiated private data plane that lr speakers run
//! alongside standard BGP to exchange state the base protocol cannot
//! carry: feasibility hints, policy intent, and provenance proofs.
//! Design: `docs/research/EXCHANGE-PLANE.md` (W6.2); this module is
//! the prototype slice — the full codec, the OPEN negotiation rule,
//! the replay tracker, and the FSM advertisement hook. The decision
//! process is untouched; records are produced and consumed by the
//! embedder through the codec API below.
//!
//! Ground rules (from the design document):
//!
//! 1. Standards compliance by default: the plane is off until both
//!    OPENs carry the capability (RFC 5492 §3 makes an unknown
//!    capability inert for other speakers — the transparent fallback).
//! 2. Additive, never load-bearing: every record may be dropped,
//!    forged, or replayed without affecting route correctness.
//! 3. Bounded growth: scope-1 records are consumed by the immediate
//!    receiver; provenance records are re-signed per lr hop with an
//!    explicit hop budget.
//!
//! Code points: capability **251** and path-attribute type **251**,
//! both in the ranges the IANA registries hold out of the standards
//! space ("Capability Codes" 239-254 Reserved for Experimental Use;
//! path attributes 244-254 unassigned). Production code points go
//! through RFC 7120 early allocation once the prototype settles.

#![allow(dead_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::capabilities::Capability;

type HmacSha256 = Hmac<Sha256>;

/// Capability code claimed by the prototype (IANA experimental range
/// 239-254; see the module documentation).
pub const CAPABILITY_CODE: u8 = 251;
/// Path-attribute type claimed by the prototype (unassigned range;
/// see the module documentation).
pub const ATTRIBUTE_TYPE: u8 = 251;
/// Wire version of the record format. A mismatch deactivates the
/// plane for the session — never the session itself.
pub const VERSION: u8 = 0;
/// OPEN-nonce length (design §3) — session-instance binding.
pub const NONCE_LEN: usize = 8;
/// Authentication tag length (HMAC-SHA256).
pub const TAG_LEN: usize = 32;

// Record classes (design §5).
/// Feasibility hint (scope 1 — never propagated).
pub const CLASS_HINT: u8 = 0;
/// Policy intent (scope 1 — never propagated).
pub const CLASS_POLICY: u8 = 1;
/// Provenance proof (scope N — re-signed per lr hop).
pub const CLASS_PROVENANCE: u8 = 2;
/// Authentication tag over everything before it.
pub const CLASS_AUTH_TAG: u8 = 3;

// Capability flag bits (design §3).
/// The speaker can verify provenance signatures.
pub const FLAG_PROVENANCE_CAPABLE: u8 = 0x01;
/// The speaker consumes feasibility hints.
pub const FLAG_HINTS_CAPABLE: u8 = 0x02;

/// Scope of a record that is consumed by the immediate receiver and
/// stripped before re-advertisement.
pub const SCOPE_LINK_LOCAL: u8 = 1;

/// Key algorithm identifier (design §3 key block).
pub const ALG_HMAC_SHA256: u8 = 0;

/// RFC 9234 role vocabulary values re-used by the policy-intent
/// record (design §5.2).
pub const ROLE_PROVIDER: u8 = 0;
pub const ROLE_CUSTOMER: u8 = 1;
pub const ROLE_RS: u8 = 2;
pub const ROLE_RS_CLIENT: u8 = 3;
pub const ROLE_PEER: u8 = 4;
pub const ROLE_UNSET: u8 = 255;

/// Decode error. None of these ever touch the BGP session: the
/// attribute is discarded and the route's standard content survives
/// (design §8 — fail-open for route data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangePlaneError {
    /// The body ended mid-field or mid-TLV.
    Truncated,
    /// A version other than [`VERSION`].
    BadVersion,
    /// A TLV length inconsistent with its class, or a duplicate
    /// authentication tag.
    BadLength,
    /// A key-block algorithm the parser does not know.
    UnknownAlg,
}

/// Record authentication algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    HmacSha256,
}

impl KeyAlg {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            ALG_HMAC_SHA256 => Some(Self::HmacSha256),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::HmacSha256 => ALG_HMAC_SHA256,
        }
    }

    fn tag_len(self) -> usize {
        match self {
            Self::HmacSha256 => TAG_LEN,
        }
    }
}

/// One verification key the local speaker is configured with.
/// Distribution is configuration (design §8): the same shape as the
/// Babel RFC 8967 and TCP-AO key blocks elsewhere in the project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeKey {
    pub id: u16,
    pub alg: KeyAlg,
    pub secret: Vec<u8>,
}

impl ExchangeKey {
    pub fn hmac_sha256(id: u16, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            id,
            alg: KeyAlg::HmacSha256,
            secret: secret.into(),
        }
    }
}

/// Local per-session configuration: what this speaker advertises in
/// OPEN and how it signs records it originates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangePlaneConfig {
    /// Advertise/consume feasibility hints (design §5.1).
    pub hints: bool,
    /// Advertise/verify provenance proofs (design §5.3).
    pub provenance: bool,
    /// Random per-session nonce; binds every record to this session
    /// instance (design §6).
    pub nonce: [u8; NONCE_LEN],
    /// Verification/signing keys, ordered by key id.
    pub keys: Vec<ExchangeKey>,
}

impl ExchangePlaneConfig {
    pub fn new(nonce: [u8; NONCE_LEN]) -> Self {
        Self {
            hints: true,
            provenance: true,
            nonce,
            keys: Vec::new(),
        }
    }

    fn flags(&self) -> u8 {
        let mut f = 0;
        if self.hints {
            f |= FLAG_HINTS_CAPABLE;
        }
        if self.provenance {
            f |= FLAG_PROVENANCE_CAPABLE;
        }
        f
    }

    /// The RFC 5492 capability this configuration advertises.
    pub fn capability(&self) -> Capability {
        let mut value = Vec::with_capacity(2 + NONCE_LEN + 4 * self.keys.len());
        value.push(VERSION);
        value.push(self.flags());
        value.extend_from_slice(&self.nonce);
        for key in &self.keys {
            value.extend_from_slice(&key.id.to_be_bytes());
            value.push(key.alg.to_u8());
            value.push(0); // reserved
        }
        Capability::new(
            crate::capabilities::CapabilityCode::Other(CAPABILITY_CODE),
            value,
        )
    }
}

/// The peer's parsed exchange-plane capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangePlaneOpen {
    pub version: u8,
    pub flags: u8,
    pub nonce: [u8; NONCE_LEN],
    /// The key ids + algorithms the peer is willing to receive
    /// records under (no secrets travel on the wire).
    pub offered_keys: Vec<(u16, KeyAlg)>,
}

/// Parse the peer's capability from its OPEN. `None` when the
/// capability is absent or malformed — the plane stays off either
/// way.
pub fn parse_capability(cap: &Capability) -> Option<ExchangePlaneOpen> {
    if cap.code.to_u8() != CAPABILITY_CODE {
        return None;
    }
    let v = &cap.value;
    if v.len() < 2 + NONCE_LEN {
        return None;
    }
    let version = v[0];
    let flags = v[1];
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&v[2..2 + NONCE_LEN]);
    let mut rest = &v[2 + NONCE_LEN..];
    let mut offered_keys = Vec::new();
    while rest.len() >= 4 {
        let id = u16::from_be_bytes([rest[0], rest[1]]);
        let alg = KeyAlg::from_u8(rest[2])?;
        offered_keys.push((id, alg));
        rest = &rest[4..];
    }
    if !rest.is_empty() {
        return None;
    }
    Some(ExchangePlaneOpen {
        version,
        flags,
        nonce,
        offered_keys,
    })
}

/// The negotiation result stored on a session (design §3 activation
/// rule): both sides advertise the same version and share at least
/// one key id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangePlaneSession {
    pub version: u8,
    pub peer_flags: u8,
    /// The peer's OPEN nonce — records we SEND echo this value.
    pub peer_nonce: [u8; NONCE_LEN],
    /// Our own OPEN nonce — records we RECEIVE must echo it.
    pub local_nonce: [u8; NONCE_LEN],
    /// The key intersection: local secrets whose ids the peer
    /// offered, sorted by key id.
    pub keys: Vec<ExchangeKey>,
}

/// Activate the plane for a session, or `None` to keep it off. The
/// rule (design §3): same version, non-empty key intersection. A
/// one-sided advertisement is deliberately not honored.
pub fn negotiate(
    local: &ExchangePlaneConfig,
    peer: &ExchangePlaneOpen,
) -> Option<ExchangePlaneSession> {
    if peer.version != VERSION {
        return None;
    }
    let mut keys: Vec<ExchangeKey> = local
        .keys
        .iter()
        .filter(|k| {
            peer.offered_keys
                .iter()
                .any(|(id, alg)| *id == k.id && *alg == k.alg)
        })
        .cloned()
        .collect();
    if keys.is_empty() {
        return None;
    }
    keys.sort_by_key(|k| k.id);
    Some(ExchangePlaneSession {
        version: peer.version,
        peer_flags: peer.flags,
        peer_nonce: peer.nonce,
        local_nonce: local.nonce,
        keys,
    })
}

// ---------------------------------------------------------------------------
// Record codec (design §4-§5)
// ---------------------------------------------------------------------------

/// Feasibility hint for one announced prefix (design §5.1). Scope 1:
/// consumed by the immediate receiver, stripped before
/// re-advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HintRecord {
    /// The sender's best-path rank of this path among its alternates
    /// (1 = the path the sender itself uses).
    pub rank: u8,
    /// The sender's route-flap figure of merit (0 when damping is
    /// off) — RFC 2439 shape, advisory only.
    pub damp_fom: u16,
    /// The sender's IGP cost from its decision point to this path's
    /// next hop.
    pub igp_cost: u32,
}

/// Policy intent for one address family (design §5.2). Scope 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyIntent {
    /// The sender's RFC 9234 role claim for this session (advisory;
    /// the receiver cross-checks against its own configuration).
    pub role: u8,
    /// SipHash-2-4 (keyed per session) over the sender's canonical
    /// sorted import filter set.
    pub import_digest: [u8; 8],
    /// Same over the export filter set.
    pub export_digest: [u8; 8],
}

/// Origin attestation (design §5.3) — the ROA idea without the PKI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginAttestation {
    pub origin_as: u32,
    /// The maximum prefix length the origin authorizes for this
    /// announcement set (RFC 6811 §3 maxLength).
    pub max_valid_len: u8,
    /// Absolute timestamp after which downstream speakers stop
    /// trusting the record.
    pub expiry: u32,
}

/// One per-lr-hop signature over the record chain (design §5.3) —
/// the BGPsec shape with modern primitives and lr-only hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSegmentSig {
    /// The signing hop's AS.
    pub asn: u32,
    /// The hop's digest over (its AS, the received attribute digest,
    /// the peer it learned from) — the prototype signs the canonical
    /// encoding of the record set it received.
    pub digest: [u8; 32],
}

/// A single record (one TLV value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    Hint(HintRecord),
    Policy(PolicyIntent),
    Origin(OriginAttestation),
    Segment(PathSegmentSig),
}

impl Record {
    fn class(&self) -> u8 {
        match self {
            Record::Hint(_) => CLASS_HINT,
            Record::Policy(_) => CLASS_POLICY,
            Record::Origin(_) | Record::Segment(_) => CLASS_PROVENANCE,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        // class (1) + length (2) + value
        match self {
            Record::Hint(h) => {
                out.push(CLASS_HINT);
                out.extend_from_slice(&7u16.to_be_bytes());
                out.push(h.rank);
                out.extend_from_slice(&h.damp_fom.to_be_bytes());
                out.extend_from_slice(&h.igp_cost.to_be_bytes());
            }
            Record::Policy(p) => {
                out.push(CLASS_POLICY);
                out.extend_from_slice(&17u16.to_be_bytes());
                out.push(p.role);
                out.extend_from_slice(&p.import_digest);
                out.extend_from_slice(&p.export_digest);
            }
            Record::Origin(o) => {
                out.push(CLASS_PROVENANCE);
                out.extend_from_slice(&9u16.to_be_bytes());
                out.extend_from_slice(&o.origin_as.to_be_bytes());
                out.push(o.max_valid_len);
                out.extend_from_slice(&o.expiry.to_be_bytes());
            }
            Record::Segment(s) => {
                out.push(CLASS_PROVENANCE);
                out.extend_from_slice(&36u16.to_be_bytes());
                out.extend_from_slice(&s.asn.to_be_bytes());
                out.extend_from_slice(&s.digest);
            }
        }
    }
}

/// One exchange-plane record set: the attribute body of type
/// [`ATTRIBUTE_TYPE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRecord {
    pub version: u8,
    /// Remaining hops the record may traverse. Scope-1 records are
    /// consumed by the receiver; provenance records decrement and
    /// re-sign per lr hop (design §7).
    pub scope: u8,
    pub flags: u8,
    /// Signing/verification key id (the receiver looks it up in the
    /// negotiated intersection).
    pub key_id: u16,
    /// Per-sender monotonic sequence (design §6).
    pub sequence: u32,
    /// The receiver's OPEN nonce — a stale value means replay.
    pub nonce_echo: [u8; NONCE_LEN],
    pub records: Vec<Record>,
    pub tag: Option<[u8; TAG_LEN]>,
}

impl ExchangeRecord {
    /// An unsigned, link-local-scope record set.
    pub fn new(scope: u8, key_id: u16, nonce_echo: [u8; NONCE_LEN], sequence: u32) -> Self {
        Self {
            version: VERSION,
            scope,
            flags: 0,
            key_id,
            sequence,
            nonce_echo,
            records: Vec::new(),
            tag: None,
        }
    }

    /// The BGP path-attribute flags octet: optional transitive
    /// (design §4) so non-lr transit speakers forward the attribute
    /// with the Partial bit set (RFC 4271 §5.1.2 / §5.3).
    pub fn attribute_flags() -> u8 {
        0b1100_0000
    }

    fn encode_header_and_records(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.push(self.scope);
        out.push(self.flags);
        out.extend_from_slice(&self.key_id.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.nonce_echo);
        for record in &self.records {
            record.encode_into(&mut out);
        }
        out
    }

    /// Encode the body (what travels as the attribute value after the
    /// standard RFC 4271 attribute header the codec writes).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.encode_header_and_records();
        if let Some(tag) = &self.tag {
            out.push(CLASS_AUTH_TAG);
            out.extend_from_slice(&(tag.len() as u16).to_be_bytes());
            out.extend_from_slice(tag);
        }
        out
    }

    /// Decode a body. Unknown record classes are skipped (TLVs are
    /// self-describing; RFC 7606 §3 posture); a duplicate tag or a
    /// truncated body is an error.
    pub fn decode(body: &[u8]) -> Result<Self, ExchangePlaneError> {
        if body.len() < 3 + 6 + NONCE_LEN {
            return Err(ExchangePlaneError::Truncated);
        }
        let version = body[0];
        if version != VERSION {
            return Err(ExchangePlaneError::BadVersion);
        }
        let scope = body[1];
        let flags = body[2];
        let key_id = u16::from_be_bytes([body[3], body[4]]);
        let sequence = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
        let mut nonce_echo = [0u8; NONCE_LEN];
        nonce_echo.copy_from_slice(&body[9..9 + NONCE_LEN]);
        let mut rest = &body[9 + NONCE_LEN..];
        let mut records = Vec::new();
        let mut tag = None;
        while !rest.is_empty() {
            if rest.len() < 3 {
                return Err(ExchangePlaneError::Truncated);
            }
            let class = rest[0];
            let len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
            if rest.len() < 3 + len {
                return Err(ExchangePlaneError::Truncated);
            }
            let value = &rest[3..3 + len];
            match class {
                CLASS_HINT => {
                    if len != 7 {
                        return Err(ExchangePlaneError::BadLength);
                    }
                    records.push(Record::Hint(HintRecord {
                        rank: value[0],
                        damp_fom: u16::from_be_bytes([value[1], value[2]]),
                        igp_cost: u32::from_be_bytes([value[3], value[4], value[5], value[6]]),
                    }));
                }
                CLASS_POLICY => {
                    if len != 17 {
                        return Err(ExchangePlaneError::BadLength);
                    }
                    let mut import_digest = [0u8; 8];
                    import_digest.copy_from_slice(&value[1..9]);
                    let mut export_digest = [0u8; 8];
                    export_digest.copy_from_slice(&value[9..17]);
                    records.push(Record::Policy(PolicyIntent {
                        role: value[0],
                        import_digest,
                        export_digest,
                    }));
                }
                CLASS_PROVENANCE => match len {
                    9 => records.push(Record::Origin(OriginAttestation {
                        origin_as: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                        max_valid_len: value[4],
                        expiry: u32::from_be_bytes([value[5], value[6], value[7], value[8]]),
                    })),
                    36 => {
                        let mut digest = [0u8; 32];
                        digest.copy_from_slice(&value[4..36]);
                        records.push(Record::Segment(PathSegmentSig {
                            asn: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                            digest,
                        }));
                    }
                    _ => return Err(ExchangePlaneError::BadLength),
                },
                CLASS_AUTH_TAG => {
                    if len != TAG_LEN {
                        return Err(ExchangePlaneError::BadLength);
                    }
                    if tag.is_some() {
                        return Err(ExchangePlaneError::BadLength);
                    }
                    let mut t = [0u8; TAG_LEN];
                    t.copy_from_slice(value);
                    tag = Some(t);
                }
                // Unknown classes are skipped (design §4).
                _ => {}
            }
            rest = &rest[3 + len..];
        }
        Ok(Self {
            version,
            scope,
            flags,
            key_id,
            sequence,
            nonce_echo,
            records,
            tag,
        })
    }

    /// The bytes the authentication tag covers: everything up to (and
    /// excluding) the tag TLV.
    fn signed_bytes(&self) -> Vec<u8> {
        self.encode_header_and_records()
    }

    /// Append the HMAC tag with `key`. Re-signing replaces any
    /// previous tag (the per-hop re-sign rule, design §7).
    pub fn sign(&mut self, key: &ExchangeKey) {
        let tag = compute_tag(key, &self.signed_bytes());
        self.tag = Some(tag);
    }

    /// Verify the tag with `key`. `false` when the tag is absent —
    /// an unsigned record is never a verified one (design §8:
    /// fail-closed for trust assertions).
    pub fn verify(&self, key: &ExchangeKey) -> bool {
        let Some(tag) = &self.tag else {
            return false;
        };
        let expected = compute_tag(key, &self.signed_bytes());
        constant_time_eq(tag, &expected)
    }
}

fn compute_tag(key: &ExchangeKey, data: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = match key.alg {
        KeyAlg::HmacSha256 => {
            HmacSha256::new_from_slice(&key.secret).expect("HMAC accepts any key length")
        }
    };
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out[..TAG_LEN]);
    tag
}

fn constant_time_eq(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Replay tracker (design §6)
// ---------------------------------------------------------------------------

/// Accept/reject decision for a received record set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    Accept,
    /// The sequence is not strictly greater than the last accepted one
    /// for this key id.
    StaleSequence,
    /// The nonce echo does not match this session instance's OPEN
    /// nonce — the record was captured from another session.
    ForeignSession,
}

/// Per-session replay state: the highest accepted sequence per key id.
#[derive(Debug, Default, Clone)]
pub struct ReplayTracker {
    last_sequence: Vec<(u16, u32)>,
}

impl ReplayTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a session instance: clears the sequence window (a new
    /// OPEN nonce is a new sequence space).
    pub fn reset(&mut self) {
        self.last_sequence.clear();
    }

    pub fn accept(
        &mut self,
        key_id: u16,
        sequence: u32,
        nonce_echo: &[u8; NONCE_LEN],
        local_nonce: &[u8; NONCE_LEN],
    ) -> ReplayDecision {
        if nonce_echo != local_nonce {
            return ReplayDecision::ForeignSession;
        }
        match self.last_sequence.iter_mut().find(|(k, _)| *k == key_id) {
            Some((_, last)) => {
                if sequence > *last {
                    *last = sequence;
                    ReplayDecision::Accept
                } else {
                    ReplayDecision::StaleSequence
                }
            }
            None => {
                self.last_sequence.push((key_id, sequence));
                ReplayDecision::Accept
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn config_a() -> ExchangePlaneConfig {
        ExchangePlaneConfig {
            hints: true,
            provenance: true,
            nonce: [1, 2, 3, 4, 5, 6, 7, 8],
            keys: vec![
                ExchangeKey::hmac_sha256(1, "alpha"),
                ExchangeKey::hmac_sha256(2, "beta"),
            ],
        }
    }

    fn config_b() -> ExchangePlaneConfig {
        ExchangePlaneConfig {
            hints: true,
            provenance: false,
            nonce: [8, 7, 6, 5, 4, 3, 2, 1],
            keys: vec![
                ExchangeKey::hmac_sha256(2, "beta"),
                ExchangeKey::hmac_sha256(3, "gamma"),
            ],
        }
    }

    #[test]
    fn capability_roundtrip() {
        let cfg = config_a();
        let cap = cfg.capability();
        assert_eq!(cap.code.to_u8(), CAPABILITY_CODE);
        let open = parse_capability(&cap).expect("parses");
        assert_eq!(open.version, VERSION);
        assert_eq!(open.flags, cfg.flags());
        assert_eq!(open.nonce, cfg.nonce);
        assert_eq!(
            open.offered_keys,
            vec![(1, KeyAlg::HmacSha256), (2, KeyAlg::HmacSha256)]
        );
    }

    #[test]
    fn parse_ignores_other_capabilities() {
        let cap = Capability::route_refresh();
        assert!(parse_capability(&cap).is_none());
    }

    #[test]
    fn parse_rejects_truncated_value() {
        let mut cap = config_a().capability();
        cap.value.truncate(5);
        assert!(parse_capability(&cap).is_none());
    }

    #[test]
    fn negotiation_activates_on_intersection() {
        let session = negotiate(
            &config_a(),
            &parse_capability(&config_b().capability()).unwrap(),
        )
        .expect("key 2 is shared");
        assert_eq!(session.keys.len(), 1);
        assert_eq!(session.keys[0].id, 2);
        assert_eq!(session.peer_nonce, [8, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn negotiation_deactivates_without_shared_keys() {
        let mut peer = config_b();
        peer.keys = vec![ExchangeKey::hmac_sha256(9, "delta")];
        let open = parse_capability(&peer.capability()).unwrap();
        assert!(negotiate(&config_a(), &open).is_none());
    }

    #[test]
    fn negotiation_deactivates_on_version_mismatch() {
        let mut peer = config_b();
        let mut cap = peer.capability();
        cap.value[0] = VERSION + 1;
        peer.nonce = cap.value[2..10].try_into().unwrap();
        let open = parse_capability(&cap).unwrap();
        assert!(negotiate(&config_a(), &open).is_none());
    }

    #[test]
    fn record_roundtrip_all_classes() {
        let mut record = ExchangeRecord::new(SCOPE_LINK_LOCAL, 2, [0xAA; NONCE_LEN], 42);
        record.records.push(Record::Hint(HintRecord {
            rank: 1,
            damp_fom: 1500,
            igp_cost: 30,
        }));
        record.records.push(Record::Policy(PolicyIntent {
            role: ROLE_CUSTOMER,
            import_digest: [1; 8],
            export_digest: [2; 8],
        }));
        record.records.push(Record::Origin(OriginAttestation {
            origin_as: 64512,
            max_valid_len: 24,
            expiry: 1_800_000_000,
        }));
        record.records.push(Record::Segment(PathSegmentSig {
            asn: 64512,
            digest: [7; 32],
        }));
        // An unknown-class TLV the receiver of a newer version might
        // add — class 200, value 4 bytes. The decoder must skip it.
        let mut bytes = record.encode();
        bytes.extend_from_slice(&[200, 0, 4, 0xDE, 0xAD, 0xBE, 0xEF]);
        let decoded = ExchangeRecord::decode(&bytes).expect("decodes");
        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.scope, SCOPE_LINK_LOCAL);
        assert_eq!(decoded.key_id, 2);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.nonce_echo, [0xAA; NONCE_LEN]);
        assert_eq!(decoded.records, record.records);
        assert!(decoded.tag.is_none());
    }

    #[test]
    fn truncated_tlv_is_an_error() {
        let mut record = ExchangeRecord::new(1, 1, [0; NONCE_LEN], 1);
        record.records.push(Record::Hint(HintRecord {
            rank: 1,
            damp_fom: 0,
            igp_cost: 0,
        }));
        let mut bytes = record.encode();
        bytes.truncate(bytes.len() - 2);
        assert_eq!(
            ExchangeRecord::decode(&bytes),
            Err(ExchangePlaneError::Truncated)
        );
    }

    #[test]
    fn bad_version_is_an_error() {
        let mut record = ExchangeRecord::new(1, 1, [0; NONCE_LEN], 1);
        record.version = VERSION + 1;
        let bytes = record.encode();
        assert_eq!(
            ExchangeRecord::decode(&bytes),
            Err(ExchangePlaneError::BadVersion)
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = ExchangeKey::hmac_sha256(2, "beta");
        let mut record = ExchangeRecord::new(1, 2, [0; NONCE_LEN], 7);
        record.records.push(Record::Origin(OriginAttestation {
            origin_as: 64512,
            max_valid_len: 24,
            expiry: 1_800_000_000,
        }));
        record.sign(&key);
        assert!(record.verify(&key));
        assert!(!record.verify(&ExchangeKey::hmac_sha256(2, "wrong")));
        // Any tampering breaks the tag.
        let mut bytes = record.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let decoded = ExchangeRecord::decode(&bytes).unwrap();
        assert!(!decoded.verify(&key));
    }

    #[test]
    fn unsigned_record_never_verifies() {
        let key = ExchangeKey::hmac_sha256(1, "alpha");
        let record = ExchangeRecord::new(1, 1, [0; NONCE_LEN], 7);
        assert!(!record.verify(&key));
    }

    #[test]
    fn duplicate_tag_is_an_error() {
        let key = ExchangeKey::hmac_sha256(1, "alpha");
        let mut record = ExchangeRecord::new(1, 1, [0; NONCE_LEN], 7);
        record.sign(&key);
        let bytes = record.encode();
        // Append the tag TLV a second time.
        let mut twice = bytes.clone();
        let tag_start = bytes.len() - 3 - TAG_LEN;
        twice.extend_from_slice(&bytes[tag_start..]);
        assert_eq!(
            ExchangeRecord::decode(&twice),
            Err(ExchangePlaneError::BadLength)
        );
    }

    #[test]
    fn attribute_is_optional_transitive() {
        // O=1 T=1 (design §4): non-lr transit forwards with Partial set.
        assert_eq!(ExchangeRecord::attribute_flags(), 0b1100_0000);
    }

    #[test]
    fn replay_accepts_fresh_and_rejects_stale() {
        let local_nonce = [9; NONCE_LEN];
        let mut tracker = ReplayTracker::new();
        assert_eq!(
            tracker.accept(1, 10, &local_nonce, &local_nonce),
            ReplayDecision::Accept
        );
        assert_eq!(
            tracker.accept(1, 10, &local_nonce, &local_nonce),
            ReplayDecision::StaleSequence
        );
        assert_eq!(
            tracker.accept(1, 5, &local_nonce, &local_nonce),
            ReplayDecision::StaleSequence
        );
        assert_eq!(
            tracker.accept(1, 11, &local_nonce, &local_nonce),
            ReplayDecision::Accept
        );
        // Independent sequence spaces per key id.
        assert_eq!(
            tracker.accept(2, 1, &local_nonce, &local_nonce),
            ReplayDecision::Accept
        );
    }

    #[test]
    fn replay_rejects_foreign_session_nonce() {
        let local_nonce = [9; NONCE_LEN];
        let foreign = [8; NONCE_LEN];
        let mut tracker = ReplayTracker::new();
        assert_eq!(
            tracker.accept(1, 10, &foreign, &local_nonce),
            ReplayDecision::ForeignSession
        );
    }

    #[test]
    fn replay_resets_on_new_session_instance() {
        let mut tracker = ReplayTracker::new();
        let local_nonce = [9; NONCE_LEN];
        assert_eq!(
            tracker.accept(1, 100, &local_nonce, &local_nonce),
            ReplayDecision::Accept
        );
        tracker.reset();
        assert_eq!(
            tracker.accept(1, 1, &local_nonce, &local_nonce),
            ReplayDecision::Accept
        );
    }
}
