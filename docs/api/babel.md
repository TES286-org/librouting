# Babel API (`lr-babel`, `lr-router`)

Read this page if you authenticate Babel datagrams (RFC 8967) or mirror
learned Babel routes into a kernel FIB.

No extra feature is needed; `lr-babel` enables `source_specific` by
default. The authentication code needs `std` at run time for its nonce
source.

## Example

The stateful interface runs the whole RFC 8967 reception algorithm: the
MAC test, packet-counter verification, Challenge Request/Reply
resynchronization and neighbour-state expiry. Drive it with the
datagram, its pseudo-header and a monotonic clock:

```rust
use lr_babel::{
    BabelAuthConfig, BabelAuthInterface, BabelCodec, BabelFrame,
    BabelMacAlgorithm, BabelMacKey, BabelPseudoHeader, NonceSource,
    SystemNonceSource,
};
use lr_core::addr::IpAddr;

// One interface. Every outgoing packet carries one MAC per key, which is
// what makes key rotation non-disruptive (RFC 8967 §5).
let mut cfg = BabelAuthConfig::new(BabelMacKey::new(b"interface-secret".to_vec()));
cfg.keys.push(BabelMacKey {
    algorithm: BabelMacAlgorithm::Blake2s128,
    secret: b"rotated-blake2s-key".to_vec(),
});
cfg.pc_window = Some(128); // RFC 9467 §3.2 window; optional

// The Index must be fresh — never reused with these keys (§3.1).
let mut nonce = SystemNonceSource::new();
let mut index = [0u8; 8];
nonce.fill(&mut index);
let mut iface = BabelAuthInterface::new(cfg, index.to_vec(), 0, Box::new(nonce))?;
```

Egress appends the PC TLV — generating a fresh index when the counter
overflows (§4.2) — and then one MAC TLV per key. Ingress returns the
plain body, ready for the ordinary codec, plus the challenge control
traffic to emit (`iface` and `raw` continue from above):

```rust
let pseudo_header = BabelPseudoHeader {
    source: IpAddr::V4([192, 0, 2, 1]),
    source_port: 6696,
    destination: IpAddr::V4([224, 0, 0, 111]),
    destination_port: 6696,
};

let raw = BabelCodec::new().encode_vec(&BabelFrame::empty())?;
let wire: Vec<u8> = iface.authenticate_packet(&raw, pseudo_header)?;

let outcome = iface.verify(&wire, pseudo_header, /* now_ms */ 42);
if let Some(plain) = outcome.accepted {
    // The PC, Challenge and MAC TLVs are already stripped.
    let frame = BabelCodec::new().decode_slice(&plain)?.unwrap();
    // ... feed `frame` to the Babel route table ...
}
for action in outcome.actions {
    // Build the Challenge Request/Reply TLV (challenge_request_tlv /
    // challenge_reply_tlv), authenticate it, and unicast it to the peer.
    let _ = action;
}
iface.gc(/* now_ms */ 42); // §4.4 neighbour-state expiry
```

The stateless primitives remain for single-key embedders that keep their
own replay state; they never rotate the index, so the counter reports
`BabelAuthError::CounterExhausted` at overflow instead:

```rust
use lr_babel::{
    authenticate_packet, verify_packet, BabelMacKey, BabelPacketCounter,
    BabelReplayProtection,
};

let key = BabelMacKey::new(b"single-key".to_vec());
let mut counter = BabelPacketCounter::new(b"fresh-interface-index".to_vec(), 0)?;
let signed = authenticate_packet(&raw, pseudo_header, &key, &mut counter)?;
let mut replay = BabelReplayProtection::default();
let plain = verify_packet(&signed, pseudo_header, &[key], &mut replay)?;
let _ = plain;
```

## Configuration

| Knob | Default | Effect |
| --- | --- | --- |
| `keys` | one HMAC-SHA-256 key | Every outbound packet carries one MAC per key |
| `accept_unauthenticated` | false | §5 incremental deployment: accept plain inbound |
| `split_unicast_multicast` | true | RFC 9467 §3.1 separate PC spaces |
| `pc_window` | `None` | RFC 9467 §3.2 verification window; 128 is the recommended size |
| `challenge_interval_ms` | 300 | §4.3.1.1 pacing of Challenge Requests |
| `reply_interval_ms` | 300 | §4.3.1.2 pacing of Challenge Replies |
| `challenge_expiry_ms` | 30 000 | §4.3.1.1 challenge lifetime |
| `neighbour_expiry_ms` | 300 000 | §4.4 state expiry without activity |
| `nonce_len` | 16 | §6.3 allows 0..=192 |
| `index_len` | 8 | §6.2 fresh-index length on PC overflow |

`BabelMacAlgorithm::HmacSha256` is mandatory to implement (RFC 8967
§4.1); `Blake2s128` is the 16-octet keyed-BLAKE2s alternative.

## Egress next hops

Every route learned on a Babel session egresses *that session's
interface*, not whatever interface the kernel's own next-hop resolution
prefers. An embedder that mirrors the Loc-RIB into a kernel FIB should
pin the egress interface for the addresses the peer advertises:

```rust
use lr_router::{DefaultRouter, RouterInstance};

let mut r = DefaultRouter::new();
// ... Babel session h established, Updates flowing ...
match r.babel_egress_nexthops(h) {
    // `None` means h is not a Babel session at all.
    None => {}
    Some((v4, v6)) => {
        // Each element is Some(address) once that family has been
        // learned: a NextHop TLV (RFC 8966 §4.6.4) or the peer's own
        // source address as the fallback (§3.5.3). A `None` element
        // means nothing has been learned for that family yet.
        let _ = (v4, v6);
    }
}
```

The v4-over-v6 case is why this exists: a v4 next hop carried over an
IPv6 session is on-link only on that session's interface, and
longest-prefix resolution can otherwise land the route on an unrelated
adapter.

## RFCs

- RFC 8967 — MAC authentication: the stateful interface, the
  pseudo-header (§3.1), the sending path (§4.2), the reception algorithm
  (§4.3), challenge pacing (§4.3.1.1/§4.3.1.2), neighbour expiry (§4.4),
  keys and rotation (§5), API and limits (§6).
- RFC 9467 — PC verification updates: the unicast/multicast split
  (§3.1), the optional window (§3.2), §5 incremental deployment.
- RFC 8966 — §3.5.3 (the sender as next hop), §4.6.4 (NextHop TLVs),
  §A.2.4 (RTT cost) and §3.2.6 (Route Requests) for the pieces the
  `lr-router` Babel runtime consumes.

## See also

- [`router.md`](router.md) — the session kind and the runtime methods.
- [`core.md`](core.md) — the codec traits `BabelCodec` implements.
- [`../RFC_MAP.md`](../RFC_MAP.md) — the Babel coverage rows.
