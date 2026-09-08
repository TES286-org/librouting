# The lr Exchange Plane — design notes (W6.2)

The Exchange Plane (LRXP hereafter) is a private, capability-negotiated
data plane that lr speakers run alongside standard BGP to exchange
state the base protocol cannot carry: feasibility hints, policy intent,
and provenance proofs. This document is the design review artifact for
roadmap item W6.2; the prototype (W6.3) lands in
`lr-bgp::extensions::exchange_plane` behind a feature flag once this
design converges. `STATUS.md` remains the implementation status.

Design ground rules, in priority order:

1. **Standards compliance by default.** The plane is off until both
   speakers advertise the capability. Off means *zero* wire difference
   from RFC 4271 — the fallback requirement in `ROADMAP.md` W6.2. No
   experimental code path may alter standard behavior for a
   non-participating peer, ever.
2. **Additive, never load-bearing.** The route data plane (NLRI,
   standard attributes, best path) must remain fully correct if every
   LRXP record is dropped, forged, or replayed. Records accelerate or
   annotate; they never decide.
3. **Bounded growth.** Every propagated record has an explicit scope;
   nothing accumulates unboundedly on the wire (the defect class
   RFC 3345 documents for MED and RFC 7606 for attributes applies here
   too — the plane must not become a new one).

## 1. What problem this solves

`BGP-DEFECTS.md` ends by naming the defects that remain unpatched in
practice because the base protocol has no place to carry the needed
state:

* **Policy opacity** (defect §3): nothing on the wire states the
  sender's intended policy, so receivers learn policy only by observing
  what gets announced and withdrawn — the churn-heavy way.
* **Origin/path forgery** (defect §4): the only content check BGP
  mandates is the local-AS loop check; authorization state (who may
  announce what) exists nowhere on the wire for speakers without
  deployed RPKI/BGPsec.
* **Exploration latency** (defect §1): a receiver's decision process
  explores alternate paths blind, one per UPDATE round, because the
  sender knows things about its own alternates it cannot express
  (their relative rank, their cost, their damping state).

The Exchange Plane gives these three a wire representation under
lr-only negotiation. It deliberately does **not** try to fix
convergence timers (defect §6) or MED comparability (defect §7) —
those are selection-rule properties, not information-model gaps.

## 2. Related work and precedents

* **RFC 5492 capabilities** (§3): "If a BGP speaker receives from its
  peer a capability that it does not itself support or recognize, it
  MUST ignore that capability" and MUST NOT send Unsupported
  Capability or terminate the session. This is the standard,
  interop-safe negotiation hook the plane hooks into.
* **RFC 4271 §5 (path attributes)**: an optional *transitive* attribute
  an implementation does not understand "is accepted and passed along
  to other BGP peers with the Partial bit" set. Carrying LRXP records
  in one such attribute makes them survive transit through
  non-lr speakers — the same trick BGPsec opted out of (it uses a
  non-transitive attribute and requires every hop to participate).
* **RFC 7311 (AIGP)**: precedent for an attribute whose payload is a
  TLV registry of auxiliary decision hints; also a cautionary tale —
  AIGP is non-transitive with strict scope rules because unbounded
  metric propagation misbehaves. LRXP copies the scope discipline.
* **RFC 8205 (BGPsec)**: the provenance-proof record is shaped like a
  simplified BGPsec update-signing chain, but signs whole-record
  digests with modern algorithms and requires no PKI roll-out; where
  BGPsec re-signs per AS on the path, LRXP re-signs per *lr* hop only.
* **RFC 7120 (early IANA allocation)**: the path to production code
  points once the prototype stabilizes.

## 3. Negotiation

A single capability (RFC 5492 §4, parameter type 2, capability
optional parameter):

* **Capability code 251.** The "Capability Codes" registry reserves
  239-254 for experimental use (verified against the IANA registry);
  251 is chosen for the prototype and must be replaced by an early
  allocation (RFC 7120) before anything ships beyond the lab. Because
  RFC 5492 §3 makes unknown capabilities inert for other speakers,
  the code is safe to advertise everywhere lr runs — including toward
  BIRD and FRR (this is exercised by the interop suite in W6.3's
  fallback test).
* **Value layout** (all multi-octet fields big-endian, RFC 1700
  network order, as the rest of BGP):

      +-------------------+-------------------+
      | version (1 octet) | flags (1 octet)   |
      +-------------------+-------------------+
      | sender nonce (8 octets)               |
      +-------------------+-------------------+
      | key block TLVs ...                    |
      +---------------------------------------+

  - `version`: 0 for the prototype; a mismatch deactivates the plane
    (never the session).
  - `flags`: bit 0 — "provenance capable" (the speaker can verify
    signatures); bit 1 — "hints capable". A speaker may advertise the
    capability and use only the record classes it cares about.
  - `sender nonce`: random per OPEN; binds every record sent on the
    session to this session instance (replay guard, §6).
  - `key block TLVs`: one per verification key the sender is willing
    to receive records under:

        +--------------+--------------+----------+
        | key-id (2)   | alg (1)      | reserved |
        +--------------+--------------+----------+

    `alg` 0 = HMAC-SHA256 (the prototype; the same primitive
    lr-babel's RFC 8967 auth already uses), 1 = Ed25519 (the target
    for provenance once the prototype settles).

**Session activation rule:** the plane is active on a session only
when *both* OPENs carry the capability with the same version, and the
intersection of the receiver's key-block with the sender's key ids is
non-empty. Otherwise the plane is off in both directions — one-sided
operation is deliberately not supported, because every record class
is only meaningful with the receiver's consent.

## 4. Wire representation of records

Records ride inside UPDATE messages as one optional-transitive path
attribute:

* **Type code 251** (unassigned range of the "BGP Path Attributes"
  registry; same early-allocation caveat as the capability code).
* **Flags: O=1, T=1** (`0xC0`), i.e. optional transitive, so that
  RFC 4271 §5.3 requires every non-lr speaker on the path to forward
  it unchanged with the Partial bit set. lr speakers that decode the
  attribute use the Partial bit as a transit signal (§7).
* **Body**: a common header followed by record TLVs:

      +---------------------------------------+
      | version (1) | scope (1) | flags (1)   |
      +---------------------------------------+
      | key-id (2)  | sequence (4)            |
      +---------------------------------------+
      | nonce-echo (8)                        |
      +---------------------------------------+
      | record TLVs ...                       |
      +---------------------------------------+

  - `scope`: remaining hops the record may traverse, 1-255. Records
    with scope 1 are consumed by the immediate receiver (stripped
    before re-advertisement). Records that propagate are re-signed by
    each lr hop and decremented (§7).
  - `key-id` + `sequence` + `nonce-echo`: integrity and replay fields
    (§6); the authentication tag is the last TLV.
  - Attribute size: bounded by the negotiated message size (4096
    octets, or the RFC 8654 extended length when negotiated). A record
    set that does not fit is split across multiple UPDATEs; a single
    record that does not fit is dropped, not truncated.

Record TLV layout (common to all classes):

    +--------------+--------------+-----------+
    | class (1)    | length (2)   | value ... |
    +--------------+--------------+-----------+

`class` 0 = feasibility hint, 1 = policy intent, 2 = provenance
proof, 3 = authentication tag. Unknown classes are skipped (TLVs are
self-describing; this is the RFC 7606 §3 "skip unknown TLV" posture).

## 5. Record classes

### 5.1 Feasibility hints (class 0, scope 1 — never propagated)

Attached to an UPDATE carrying NLRI; one sub-record per announced
prefix (or per Add-Path path-id, RFC 7911, when the session negotiates
Add-Path):

    +----------------+----------------+---------------+
    | rank (1)       | damp FoM (2)   | igp-cost (4)  |
    +----------------+----------------+---------------+

* `rank`: the sender's local best-path rank of this path among its
  alternates for the prefix (1 = the path the sender itself uses, 2 =
  its first alternate, ...). A receiver learning that its currently
  used path is the sender's rank-1, while a newly arrived path is
  rank-3, can short-circuit the exploration that defect §1 documents:
  the third-best path of a remote speaker is a poor repair candidate.
* `damp FoM`: the sender's current route-flap figure of merit for the
  prefix (0 when damping is off), so a receiver can deprioritize
  routes its peer itself considers unstable — damping information
  without the RFC 2439 penalty-sharing pathology (the receiver tunes
  its *own* damping; nothing is shared upstream).
* `igp-cost`: the sender's IGP cost from its decision-point to the
  next hop of this path — the quantity the RFC 4271 §9.1.2.2 tie-break
  rules assume "all the BGP speakers within an autonomous system can
  ascertain" and that inter-AS receivers otherwise cannot see at all.

### 5.2 Policy intent (class 1, scope 1 — never propagated)

One sub-record per address family per session, re-sent on change
(and on RFC 2918 route refresh):

    +----------------+----------------+----------------+
    | role (1)       | import-digest (8)               |
    +----------------+----------------+----------------+
    | export-digest (8)                               |
    +-------------------------------------------------+

* `role`: the RFC 9234 role vocabulary (0 = provider, 1 = customer,
  2 = RS, 3 = RS-client, 4 = peer, 255 = unspecified) as *claimed by
  the sender about this session*. The receiver may cross-check it
  against its own configured role for the session (RFC 9234 §5 makes
  a mismatch an error for OTC purposes; here a mismatch is merely a
  log + a downgrade of the record's trust level, because the plane is
  advisory).
* `import-digest` / `export-digest`: SipHash-2-4 (keyed per session
  from the capability nonce) over the sender's canonical sorted prefix
  list for the family — a fingerprint of the filter set, not the
  filter set itself. Two different sessions reporting the same digest
  announce the same effective filter; a *change* of digest between
  the same sender's consecutive records signals a policy edit that is
  about to manifest as churn, which the receiver can smooth (hold the
  previous best path longer, batch the resulting re-evaluation).

### 5.3 Provenance proofs (class 2, scope N — propagated, re-signed)

The heavyweight class, attached to the NLRI it proves. Two sub-records:

* **Origin attestation** (added by the originating lr speaker):

      +-----------------+-----------------+---------------+
      | origin as (4)   | max-valid (1)   | expiry (4)    |
      +-----------------+-----------------+---------------+

  `max-valid` bounds the prefix length the origin authorizes for this
  announcement set (the ROA maxLength idea, RFC 6811 §3, without the
  PKI); `expiry` is an absolute timestamp after which downstream
  speakers must stop trusting the record. The origin signs the digest
  of (prefix, origin as, max-valid, expiry) with its configured key.

* **Path segment signatures** (added by every lr speaker that forwards
  the UPDATE, including the originator): a digest chain in the BGPsec
  shape — each hop signs (its own AS, the received attribute's digest,
  the peer it learned from) and replaces the attribute digest. A
  receiver holding the key block (from the capability, §3) verifies
  the chain end-to-end exactly like BGPsec path validation, but only
  lr hops sign: a non-lr transit sets the Partial bit, and a chain
  crossing such a hop is verifiable up to that hop, detectably
  incomplete past it (the receiver's trust policy decides whether a
  partial chain is usable — fail-closed default).

This is the defect-§4 mitigation for deployments that have no RPKI:
a pre-shared, per-AS key pair gives origin authenticity and path
integrity for the lr subset of the Internet, with no infrastructure
beyond configuration. It is a *pragmatic* defense — the trust-on-first
use of key distribution is documented in §8 — and explicitly not a
BGPsec replacement where a PKI exists.

## 6. Session binding and replay protection

Every record carries `nonce-echo` — the receiver's own OPEN nonce —
and `sequence`, a per-sender monotonic counter. The receiver:

1. drops any record whose nonce-echo does not match its OPEN nonce
   (a record captured from a different session instance replays into
   a dead corner);
2. drops any record whose sequence is not strictly greater than the
   last accepted sequence for that (key-id, session);
3. verifies the authentication tag (class-3 TLV) over the common
   header plus all non-tag TLVs before acting on any record.

Transport authentication (RFC 2385/5925, already implemented in lr)
covers the session path; these fields cover the *records'* lifetime,
which is longer than the session's when provenance propagates.

## 7. Propagation and scope rules

* scope-1 records (hints, policy intent): consumed by the receiver;
  MUST be stripped before any re-advertisement. A receiver that also
  received the attribute transitively (Partial bit set by a middle
  speaker) does not consume it — a Partial-bit record is forwarding
  material only.
* provenance records: every lr speaker re-signs, decrements scope,
  and re-emits. scope = 0 strips the attribute entirely. Aggregation
  (RFC 4271 §9.2.2.1) strips provenance for the aggregated prefix:
  an aggregate is a new origin, and carrying the components' proofs
  through information reduction would silently widen their trust to
  prefixes the originators never signed.
* The Partial bit arriving on a negotiated session (a non-lr speaker
  between two lr speakers) is reported in the runtime API
  (`exchange_plane_partial_transit` counter) so operators can see how
  much of a path's provenance is real.

## 8. Trust model and security considerations

* **Prototype trust**: symmetric, pre-shared per key-id (HMAC-SHA256).
  Key distribution is configuration, exactly like the existing
  `[babel.key]` / TCP-AO keys. Rotation = new key-id advertised in the
  key block while the old one verifies; keys are removed only after
  the expiry of provenance records signed under them.
* **Target trust**: Ed25519 per speaker with a documented
  fingerprint exchange (the capability key block grows a
  fingerprint TLV). Trust-on-first-use is the honest default; the
  design does not pretend it is a PKI. Defect §4's full fix remains
  RPKI/BGPsec where deployable.
* **Failure direction**: for *route data* the plane fails open
  (drop the record, keep the route, log — RFC 7606 §3 posture). For
  *trust assertions* it fails closed (an unverifiable provenance
  record is treated as absent, never as valid).
* **Amplification**: scope limits + one attribute per UPDATE bound
  the cost; a sender that exceeds the receiver's per-session record
  budget (configurable) is rate-limited, not disconnected — a
  misbehaving plane must not take the session down with it.

## 9. Interaction with standard features

* **Route Refresh (RFC 2918)**: re-advertised routes re-carry their
  records; the receiver's sequence tracking resets with the session
  instance nonce.
* **Add-Path (RFC 7911)**: hints key on (prefix, path-id); provenance
  signs the per-path attribute set, so alternate paths carry
  independent proofs.
* **Graceful Restart (RFC 4724) / LLGR (RFC 9494)**: plane records are
  ephemeral and are not retained across a restart; a recovering
  speaker re-learns them with the routes. Stale (LLGR-retained)
  routes keep their last provenance state, which expiry timestamps
  already bound in time.
* **OTC (RFC 9234)**: the policy-intent role and the OTC attribute are
  complementary — OTC is enforced by every conforming speaker; the
  plane's role claim is advisory and cross-checked.
* **Extended messages (RFC 8654)**: adopted transparently via the
  negotiated MaxPDU; no LRXP-specific sizing beyond the record-split
  rule in §4.

## 10. Prototype plan (W6.3)

> **Status.** The prototype and the daemon integration are landed
> behind the `exchange-plane` feature (off by default): the codec +
> negotiation + replay tracker (first slice), the UPDATE attach/detach
> hooks with per-hop re-signing (second slice), and the daemon
> config/CLI/runtime-API wiring plus the interop gate (third slice).
> The exit criteria below are met: the W5.3 parity harness replays a
> captured lr→BIRD stream into an IDENTICAL Loc-RIB with the flag off,
> `tests/interop/exchange_plane.sh` proves the fallback against plain
> BIRD 2 with the flag on, and the loopback e2e
> (`crates/lr-cli/tests/daemon_exchange_plane.rs`) demonstrates all
> three record classes. Config keys: `[bgp] exchange_plane` +
> `exchange_plane_keys`, per-peer `[peer] exchange_plane`; see
> `templates/daemon.toml`.

* **Module layout**: `lr-bgp::extensions::exchange_plane` (capability
  codec in `capabilities.rs`, record codec in the new module; no-std,
  like the rest of lr-bgp). Router plumbing: records surface as
  `RouterEvent::Log` + a typed accessor; the decision process is
  untouched in the prototype (hints are observed, not acted on).
* **Feature flag**: `exchange-plane` (off by default; the codec is
  feature-gated so the release build carries none of it until
  enabled).
* **Daemon config**: `[peer] exchange_plane = true` +
  `[bgp] exchange_plane_key = "<key-id>:<secret>"` (mirroring the
  babel/TCP-AO key syntax), CLI `--exchange-plane` / `--no-exchange-plane`.
* **Test plan**:
  1. codec round-trips (capability + attribute + every record class,
     including truncation and unknown-TLV skip);
  2. negotiation: lr-lr activates, lr-BIRD stays plain (the fallback
     gate, run in the existing interop harness against BIRD 2);
  3. replay: a captured record re-injected on a fresh session is
     dropped by nonce mismatch;
  4. provenance: three-speaker loopback chain, middle-hop re-sign,
     partial-chain detection after a non-lr hop (a speaker with the
     plane off);
  5. scope: scope-1 records never leak past the first non-lr hop.
* **Exit criteria for the prototype**: the interop suite above stays
  green with the flag off (byte-identical UPDATE streams via the W5.3
  parity harness), and the loopback e2e demonstrates all three record
  classes with the flag on.

## 11. Open questions

1. Key distribution beyond TOFU for the Ed25519 stage — DNSSEC/DANE,
   or ride the existing RPKI repository when present?
2. Should policy-intent digests use a canonical prefix-list encoding
   shared with the daemon's policy engine (`lr-policy`), so digests
   are comparable across implementations? (Prototype: yes, SipHash-2-4
   over the sorted, normalized set.)
3. Route-server mode (RFC 7947): hints computed by a route server
   describe the server's view, which is not the client's next hop —
   do RS sessions suppress class-0 records by default? (Prototype:
   yes, pending review.)
4. Does the provenance chain interact with RFC 8212's
   require-policy mode as a *third* acceptance criterion (route
   acceptable only with a valid origin attestation)? Configurable,
   default no — keeping rule 1 of this document.
