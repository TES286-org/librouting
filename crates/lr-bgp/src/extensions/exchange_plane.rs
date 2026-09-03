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
use sha2::{Digest, Sha256};

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
    /// RFC 9234 role claimed for this session in the policy-intent
    /// record (design §5.2). `None` = no policy record is attached.
    pub policy_role: Option<u8>,
    /// SipHash-2-4 digest over the sender's canonical import filter
    /// set (design §5.2; computed by the embedder — the FSM never
    /// sees policy). `None` = no policy record is attached.
    pub policy_import_digest: Option<[u8; 8]>,
    /// See `policy_import_digest`.
    pub policy_export_digest: Option<[u8; 8]>,
    /// Provenance hop budget (design §4 scope field): the scope value
    /// the ORIGINATOR puts on a fresh record set. Every forwarding lr
    /// hop decrements it; a set whose scope reaches 0 is stripped.
    pub provenance_scope: u8,
    /// Wall-clock seconds at configuration time (embedder-supplied;
    /// the library stays clock-free). Origin-attestation expiry is
    /// `origin_base_secs + origin_ttl_secs`.
    pub origin_base_secs: u64,
    /// Origin-attestation lifetime (design §5.3 expiry field,
    /// seconds). 86400 (24 h) is the prototype default.
    pub origin_ttl_secs: u32,
}

impl ExchangePlaneConfig {
    pub fn new(nonce: [u8; NONCE_LEN]) -> Self {
        Self {
            hints: true,
            provenance: true,
            nonce,
            keys: Vec::new(),
            policy_role: None,
            policy_import_digest: None,
            policy_export_digest: None,
            provenance_scope: 8,
            origin_base_secs: 0,
            origin_ttl_secs: 86_400,
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

// ---------------------------------------------------------------------------
// Egress record-set construction (design §5, §7 — the attach hook)
// ---------------------------------------------------------------------------

/// Provenance chain digest over an origin attestation (design §5.3):
/// `digest_0 = SHA-256(origin attestation TLV value)`. Every path
/// segment signature chains from it, so a receiver holding the key
/// block can recompute the whole chain from the record set alone.
pub fn origin_digest(origin: &OriginAttestation) -> [u8; 32] {
    let mut tlv = Vec::with_capacity(9);
    tlv.extend_from_slice(&origin.origin_as.to_be_bytes());
    tlv.push(origin.max_valid_len);
    tlv.extend_from_slice(&origin.expiry.to_be_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tlv);
    hasher.finalize().into()
}

/// One hop's path-segment digest (design §5.3): the hop signs
/// `(its own AS, the digest it received, the AS it learned from)` with
/// the negotiated key. The previous hop's AS is the previous segment's
/// `asn` (or the origin AS for the first signature) — the chain is
/// therefore fully recomputable from the record set.
pub fn hop_digest(
    key: &ExchangeKey,
    asn: u32,
    received_digest: &[u8; 32],
    learned_from: u32,
) -> [u8; TAG_LEN] {
    let mut data = Vec::with_capacity(4 + 32 + 4);
    data.extend_from_slice(&asn.to_be_bytes());
    data.extend_from_slice(received_digest);
    data.extend_from_slice(&learned_from.to_be_bytes());
    compute_tag(key, &data)
}

/// Walk a provenance chain the way a validating receiver does: recompute
/// `digest_0` from the origin attestation, then each hop's HMAC from the
/// previous hop's digest and AS. `keys` maps the signing hop's AS to its
/// verification key (distribution is configuration, design §8). Returns
/// the verified path as `(asn, learned_from)` pairs, or the prefix of the
/// chain that verified before the first failure — a chain crossing a
/// non-lr hop is verifiable up to that hop and detectably incomplete
/// past it (design §5.3).
pub fn verify_provenance_chain(
    records: &[Record],
    keys: &[(u32, ExchangeKey)],
) -> (Vec<(u32, u32)>, Option<usize>) {
    let mut origin = None;
    let mut segments: Vec<&PathSegmentSig> = Vec::new();
    for r in records {
        match r {
            Record::Origin(o) => origin = Some(*o),
            Record::Segment(s) => segments.push(s),
            _ => {}
        }
    }
    let Some(origin) = origin else {
        return (Vec::new(), None);
    };
    let mut digest = origin_digest(&origin);
    let mut learned_from = origin.origin_as;
    let mut verified = Vec::with_capacity(segments.len());
    for (i, seg) in segments.iter().enumerate() {
        let Some((_, key)) = keys.iter().find(|(asn, _)| *asn == seg.asn) else {
            return (verified, Some(i));
        };
        let expected = hop_digest(key, seg.asn, &digest, learned_from);
        if seg.digest != expected {
            return (verified, Some(i));
        }
        digest = seg.digest;
        verified.push((seg.asn, learned_from));
        learned_from = seg.asn;
    }
    (verified, None)
}

/// The egress inputs for one advertised route (design §5 + §7).
pub struct EgressInput<'a> {
    /// The local speaker's AS (origin attestation + hop signatures).
    pub local_as: u32,
    /// The route's locally-originated flag (`route.origin.proto == 2`):
    /// a locally originated route gets a fresh origin attestation.
    pub locally_originated: bool,
    /// The announced prefix (max-valid-len and chain digest inputs).
    pub prefix: &'a lr_core::addr::Prefix,
    /// The provenance records the route already carries (decoded from
    /// the private record store by the caller), if any.
    pub received: Option<&'a ExchangeRecord>,
    /// The peer AS this session talks to (the record set is addressed
    /// to this receiver; its OPEN nonce is echoed).
    pub peer_as: u32,
}

/// What the egress attach hook produced.
pub struct EgressOutput {
    /// The record set to encode as the wire attribute (already signed).
    pub record: ExchangeRecord,
    /// The key id the set is signed under.
    pub key_id: u16,
}

/// Build the wire record set for one advertised route, or `None` when
/// nothing should be attached (no enabled record class, or the
/// provenance budget ran out). Implements design §5 (record classes),
/// §6 (sequence + nonce echo) and §7 (scope decrement, per-hop re-sign):
///
/// * scope-1 records are rebuilt fresh from the local configuration —
///   received ones are never re-sent (§7: consumed by the receiver);
/// * received provenance records (origin attestation + upstream segment
///   signatures) ride along with the scope decremented by one;
/// * a locally originated route gets a fresh origin attestation at the
///   configured budget;
/// * this hop's segment signature chains onto the received set (or onto
///   the fresh attestation) and the whole set is re-signed with the
///   session key.
pub fn build_record_set(
    local: &ExchangePlaneConfig,
    session: &ExchangePlaneSession,
    input: &EgressInput<'_>,
    sequence: u32,
) -> Option<EgressOutput> {
    let key = session.keys.first()?;
    let mut records: Vec<Record> = Vec::new();

    // --- scope-1 classes (rebuilt fresh, never relayed) ---
    if local.hints && session.peer_flags & FLAG_HINTS_CAPABLE != 0 {
        // Prototype rank semantics: the decision process is untouched
        // and every route handed to egress is by definition the sender's
        // rank-1 path for this peer (design §5.1). Damping and IGP
        // integration are future work — 0 is the documented "off" value.
        records.push(Record::Hint(HintRecord {
            rank: 1,
            damp_fom: 0,
            igp_cost: 0,
        }));
        if let (Some(role), Some(import), Some(export)) = (
            local.policy_role,
            local.policy_import_digest,
            local.policy_export_digest,
        ) {
            records.push(Record::Policy(PolicyIntent {
                role,
                import_digest: import,
                export_digest: export,
            }));
        }
    }

    // --- provenance (scope N, re-signed per hop) ---
    let mut scope = 0u8;
    // The provenance records this hop forwards/originates, kept apart
    // from the scope-1 set so a headless chain (segments without an
    // origin anchor) is dropped as a whole instead of leaking.
    let mut provenance: Vec<Record> = Vec::new();
    let mut chain_from: Option<(u32, [u8; TAG_LEN])> = None; // (asn, digest)
    if local.provenance && session.peer_flags & FLAG_PROVENANCE_CAPABLE != 0 {
        match input.received {
            Some(received) if received.scope > 1 => {
                // Forward the upstream chain with the budget decremented
                // (design §7). Scope-1 records in the received set are
                // never re-sent.
                scope = received.scope - 1;
                let mut origin_seen = false;
                for r in &received.records {
                    match r {
                        Record::Origin(o) => {
                            origin_seen = true;
                            provenance.push(Record::Origin(*o));
                        }
                        Record::Segment(s) => {
                            chain_from = Some((s.asn, s.digest));
                            provenance.push(Record::Segment(*s));
                        }
                        Record::Hint(_) | Record::Policy(_) => {}
                    }
                }
                if !origin_seen {
                    // A chain without an anchor cannot be validated —
                    // strip instead of forwarding a headless tail.
                    provenance.clear();
                    chain_from = None;
                    scope = 0;
                }
            }
            Some(_) => {
                // Budget exhausted (§7: scope 0 strips the attribute).
            }
            None if input.locally_originated => {
                // New origin (design §5.3): attest the announcement set
                // for exactly this prefix length, expiring at
                // configuration time + TTL.
                scope = local.provenance_scope.max(1);
                let attestation = OriginAttestation {
                    origin_as: input.local_as,
                    max_valid_len: input.prefix.prefix_len,
                    expiry: (local.origin_base_secs + local.origin_ttl_secs as u64) as u32,
                };
                provenance.push(Record::Origin(attestation));
            }
            None => {}
        }
        if scope > 0 {
            // Our hop's signature: chain onto the last received segment
            // (or onto the fresh origin attestation) — design §5.3.
            let digest = match (&chain_from, input.received) {
                (Some((asn, d)), _) => hop_digest(key, input.local_as, d, *asn),
                (None, Some(_received)) => {
                    // Upstream set had provenance but no origin anchor:
                    // handled above (scope stripped) — unreachable here.
                    return None;
                }
                (None, _) => {
                    // Fresh origination: chain from digest_0 (the origin
                    // attestation we just built).
                    let Some(Record::Origin(o)) =
                        provenance.iter().find(|r| matches!(r, Record::Origin(_)))
                    else {
                        return None;
                    };
                    let d0 = origin_digest(o);
                    hop_digest(key, input.local_as, &d0, o.origin_as)
                }
            };
            provenance.push(Record::Segment(PathSegmentSig {
                asn: input.local_as,
                digest,
            }));
        }
        records.extend(provenance);
    }

    if records.is_empty() {
        return None;
    }
    let mut record = ExchangeRecord::new(scope.max(1), key.id, session.peer_nonce, sequence);
    record.records = records;
    record.sign(key);
    Some(EgressOutput {
        record,
        key_id: key.id,
    })
}

// ---------------------------------------------------------------------------
// Private record store (the Loc-RIB carrier between ingress and egress)
// ---------------------------------------------------------------------------

/// Store kind prefix: a verified (tag-checked, replay-checked) record
/// set follows, encoded with [`ExchangeRecord::encode`].
pub const STORE_VERIFIED: u8 = 0;
/// Store kind prefix: the raw wire body of an attribute that arrived
/// with the Partial bit set — forwarding material (design §7), never
/// consumed or re-signed, re-emitted byte-identically downstream.
pub const STORE_PARTIAL_RAW: u8 = 1;

/// Encode a verified record set for the private record store.
pub fn store_verified(record: &ExchangeRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 64);
    out.push(STORE_VERIFIED);
    out.extend_from_slice(&record.encode());
    out
}

/// Encode a partial-transit raw body for the private record store.
pub fn store_partial_raw(wire_body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + wire_body.len());
    out.push(STORE_PARTIAL_RAW);
    out.extend_from_slice(wire_body);
    out
}

/// Decode the private record store. Returns the kind prefix plus the
/// payload (`(STORE_VERIFIED, decoded record set)` or
/// `(STORE_PARTIAL_RAW, raw wire body)`), or `None` for a malformed
/// store (treated as absent — the route's standard content survives).
pub fn load_store(value: &[u8]) -> Option<(u8, &[u8])> {
    let (&kind, payload) = value.split_first()?;
    match kind {
        STORE_VERIFIED => {
            ExchangeRecord::decode(payload).ok()?;
            Some((kind, payload))
        }
        STORE_PARTIAL_RAW => Some((kind, payload)),
        _ => None,
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
            policy_role: None,
            policy_import_digest: None,
            policy_export_digest: None,
            provenance_scope: 8,
            origin_base_secs: 1_700_000_000,
            origin_ttl_secs: 86_400,
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
            policy_role: None,
            policy_import_digest: None,
            policy_export_digest: None,
            provenance_scope: 8,
            origin_base_secs: 1_700_000_000,
            origin_ttl_secs: 86_400,
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

    // ----- egress record-set construction (W6.3 follow-up) -----

    fn session_for(local: &ExchangePlaneConfig, peer_nonce: [u8; 8]) -> ExchangePlaneSession {
        ExchangePlaneSession {
            version: VERSION,
            peer_flags: FLAG_HINTS_CAPABLE | FLAG_PROVENANCE_CAPABLE,
            peer_nonce,
            local_nonce: local.nonce,
            keys: local.keys.clone(),
        }
    }

    fn egress_prefix() -> lr_core::addr::Prefix {
        lr_core::addr::Prefix::new_v4([203, 0, 113, 0], 24)
    }

    #[test]
    fn build_record_set_originates_full_set() {
        let local = config_a();
        let session = session_for(&local, [0xAA; NONCE_LEN]);
        let mut local = local;
        local.policy_role = Some(ROLE_CUSTOMER);
        local.policy_import_digest = Some([1; 8]);
        local.policy_export_digest = Some([2; 8]);
        let input = EgressInput {
            local_as: 64512,
            locally_originated: true,
            prefix: &egress_prefix(),
            received: None,
            peer_as: 64513,
        };
        let out = build_record_set(&local, &session, &input, 1).expect("records attached");
        // Hint + policy (scope 1) + origin attestation + our segment sig.
        assert!(matches!(out.record.records[0], Record::Hint(_)));
        assert!(matches!(out.record.records[1], Record::Policy(p) if p.role == ROLE_CUSTOMER));
        let origin = out
            .record
            .records
            .iter()
            .find_map(|r| match r {
                Record::Origin(o) => Some(*o),
                _ => None,
            })
            .expect("origin attestation");
        assert_eq!(origin.origin_as, 64512);
        assert_eq!(origin.max_valid_len, 24);
        assert_eq!(origin.expiry, 1_700_000_000 + 86_400);
        assert!(matches!(
            out.record.records.last(),
            Some(Record::Segment(s)) if s.asn == 64512
        ));
        // Scope carries the originator's budget.
        assert_eq!(out.record.scope, 8);
        // The tag verifies under the negotiated key and echoes the peer
        // nonce (design §6).
        assert_eq!(out.record.nonce_echo, [0xAA; NONCE_LEN]);
        assert!(out.record.verify(&session.keys[0]));
    }

    #[test]
    fn build_record_set_skips_unenabled_classes() {
        let mut local = config_a();
        local.hints = false;
        local.provenance = false;
        let session = session_for(&local, [0xAA; NONCE_LEN]);
        let input = EgressInput {
            local_as: 64512,
            locally_originated: true,
            prefix: &egress_prefix(),
            received: None,
            peer_as: 64513,
        };
        assert!(build_record_set(&local, &session, &input, 1).is_none());
    }

    #[test]
    fn build_record_set_gates_on_peer_flags() {
        // The peer did not advertise the provenance flag: no provenance
        // records even though the local side is willing (design §5 —
        // every class is only meaningful with the receiver's consent).
        let local = config_a();
        let mut session = session_for(&local, [0xAA; NONCE_LEN]);
        session.peer_flags = FLAG_HINTS_CAPABLE;
        let input = EgressInput {
            local_as: 64512,
            locally_originated: true,
            prefix: &egress_prefix(),
            received: None,
            peer_as: 64513,
        };
        let out = build_record_set(&local, &session, &input, 1).expect("hint still attached");
        assert_eq!(out.record.records.len(), 1);
        assert!(matches!(out.record.records[0], Record::Hint(_)));
        assert_eq!(out.record.scope, 1);
    }

    #[test]
    fn build_record_set_exhausted_scope_strips_provenance() {
        let local = config_a();
        let session = session_for(&local, [0xAA; NONCE_LEN]);
        // A received set at scope 1 has no budget left (§7: scope 0
        // strips the attribute entirely).
        let mut received = ExchangeRecord::new(1, 1, [0xAA; NONCE_LEN], 5);
        received.records.push(Record::Origin(OriginAttestation {
            origin_as: 65000,
            max_valid_len: 24,
            expiry: 999,
        }));
        let input = EgressInput {
            local_as: 64512,
            locally_originated: false,
            prefix: &egress_prefix(),
            received: Some(&received),
            peer_as: 64513,
        };
        // Hints are still rebuilt fresh (they are ours, not relayed).
        let out = build_record_set(&local, &session, &input, 1).expect("hint attached");
        assert!(out
            .record
            .records
            .iter()
            .all(|r| matches!(r, Record::Hint(_) | Record::Policy(_)),));
    }

    #[test]
    fn build_record_set_relays_and_re_signs_chain() {
        let upstream = config_a();
        let upstream_session = session_for(&upstream, [0xBB; NONCE_LEN]);
        let upstream_input = EgressInput {
            local_as: 65000,
            locally_originated: true,
            prefix: &egress_prefix(),
            received: None,
            peer_as: 64512,
        };
        let first =
            build_record_set(&upstream, &upstream_session, &upstream_input, 1).expect("origin");

        // The downstream hop forwards the received chain with the scope
        // decremented and its own signature appended.
        let down = config_b();
        let mut down = down;
        down.provenance = true;
        let down_session = session_for(&down, [0xCC; NONCE_LEN]);
        let down_input = EgressInput {
            local_as: 64512,
            locally_originated: false,
            prefix: &egress_prefix(),
            received: Some(&first.record),
            peer_as: 64513,
        };
        let second =
            build_record_set(&down, &down_session, &down_input, 1).expect("chain forwarded");
        assert_eq!(second.record.scope, first.record.scope - 1);
        // Origin attestation + upstream segment + own segment.
        let segments: Vec<&PathSegmentSig> = second
            .record
            .records
            .iter()
            .filter_map(|r| match r {
                Record::Segment(s) => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[1].asn, 64512);
        // The whole chain verifies with both hops' keys (the receiver's
        // validation walk, design §5.3).
        let keys = vec![
            (65000u32, upstream_session.keys[0].clone()),
            (64512u32, down_session.keys[0].clone()),
        ];
        let (path, broken) = verify_provenance_chain(&second.record.records, &keys);
        assert!(broken.is_none());
        assert_eq!(path, vec![(65000, 65000), (64512, 65000)]);
    }

    #[test]
    fn build_record_set_drops_headless_chain() {
        let local = config_a();
        let session = session_for(&local, [0xAA; NONCE_LEN]);
        // A received set whose origin attestation went missing (e.g. a
        // truncated hop) is not forwardable.
        let mut received = ExchangeRecord::new(4, 1, [0xAA; NONCE_LEN], 5);
        received.records.push(Record::Segment(PathSegmentSig {
            asn: 65000,
            digest: [7; 32],
        }));
        let input = EgressInput {
            local_as: 64512,
            locally_originated: false,
            prefix: &egress_prefix(),
            received: Some(&received),
            peer_as: 64513,
        };
        let out = build_record_set(&local, &session, &input, 1).expect("hint still attached");
        assert!(!out
            .record
            .records
            .iter()
            .any(|r| matches!(r, Record::Origin(_) | Record::Segment(_))));
    }

    #[test]
    fn store_roundtrips() {
        let local = config_a();
        let session = session_for(&local, [0xAA; NONCE_LEN]);
        let input = EgressInput {
            local_as: 64512,
            locally_originated: true,
            prefix: &egress_prefix(),
            received: None,
            peer_as: 64513,
        };
        let out = build_record_set(&local, &session, &input, 1).expect("records");
        let stored = store_verified(&out.record);
        let (kind, payload) = load_store(&stored).expect("verified store");
        assert_eq!(kind, STORE_VERIFIED);
        let decoded = ExchangeRecord::decode(payload).unwrap();
        assert_eq!(decoded, out.record);

        let raw_store = store_partial_raw(&[1, 2, 3]);
        let (kind, raw) = load_store(&raw_store).expect("raw store");
        assert_eq!(kind, STORE_PARTIAL_RAW);
        assert_eq!(raw, &[1, 2, 3]);

        assert!(load_store(&[9, 0]).is_none(), "unknown kind rejected");
    }

    #[test]
    fn chain_verification_detects_tampering() {
        let local = config_a();
        let session = session_for(&local, [0xAA; NONCE_LEN]);
        let input = EgressInput {
            local_as: 64512,
            locally_originated: true,
            prefix: &egress_prefix(),
            received: None,
            peer_as: 64513,
        };
        let out = build_record_set(&local, &session, &input, 1).expect("records");
        let keys = vec![(64512u32, session.keys[0].clone())];
        let (path, broken) = verify_provenance_chain(&out.record.records, &keys);
        assert!(broken.is_none() && path.len() == 1);

        // Flip one bit in the segment digest: the chain breaks there.
        let mut tampered = out.record.records.clone();
        if let Some(Record::Segment(s)) = tampered.last_mut() {
            s.digest[0] ^= 0x01;
        }
        let (_, broken) = verify_provenance_chain(&tampered, &keys);
        assert_eq!(broken, Some(0));
    }
}
