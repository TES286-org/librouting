# RFC 8362 E-LSA implementation design

This document is the implementation plan for the OSPFv3 Extended-LSA
machinery (RFC 8362) in `librouting`. It exists because the
`STATUS.md` "next planned work" list puts E-LSA + SRv6 End.X SIDs as
Phase 3 item 2 — the next protocol-correctness slice after the
OSPFv3 graceful-restart work (RFC 5187) landed. The slice is large
enough (the E-Router / E-Network / E-Link / E-Intra-Area-Prefix /
E-Inter-Area / E-AS-External LSA set with TLV bodies, the U-bit-2
flooding rules, and an E-LSA SPF path) that a design doc keeps the
implementation honest: the codec shapes, the database projection
rules, the SPF integration and the interop verification are all
enumerated here before any code lands.

Sources: RFC 8362 (text at rfc-editor.org), RFC 5340 §A (the OSPFv3
LSA base), FRR 10.3 `ospf6d` source (`ospf6_lsa.c`, `ospf6_asbr.c`,
`ospf6_abr.c` — the field-proven reference for the E-LSA codec
shapes and the SPF integration), BIRD 2 `ospf.c` (the v3 LSA handling
the E-LSAs replace). Every section number cited below was checked
against the published RFC text.

## 1. Why E-LSAs

RFC 5340's original LSA types (Router-LSA 0x2001, Network-LSA
0x2002, etc.) carry fixed-format bodies that cannot be extended
without a new LSA type. RFC 8362 replaces them with TLV-bodied
equivalents (E-Router-LSA 0xA020, E-Network-LSA 0xA021, …) so new
sub-TLVs can be added without breaking the base codec. The driving
use case is SRv6: the End.X and LAN End.X SID sub-TLVs (RFC 9513 §9)
ride the E-Router-LSA's Router-Link TLV, which has no home in the
fixed-format Router-LSA.

A speaker that supports E-LSAs advertises the E-bit (0x20) in its
OSPFv3 Router-LSA Options field (RFC 5340 §A.2). Receivers that do
not set the E-bit ignore E-LSAs from that speaker (forward-compat
rule). A mixed network can run side-by-side: the legacy LSAs carry
the topology, the E-LSAs carry the extensions.

## 2. LSA function codes and the U-bit

RFC 8362 §3 assigns function codes 32-38 to the E-LSAs. Combined with
the U-bit (0x8000) and the flooding-scope bits (S2=0x4000, S1=0x2000),
the on-wire LS Type values are:

| E-LSA                  | Function code | LS Type  | Scope  | Replaces                |
| ---------------------- | ------------- | -------- | ------ | ----------------------- |
| E-Router-LSA           | 32            | 0xA020   | area   | Router-LSA (0x2001)     |
| E-Network-LSA          | 33            | 0xA021   | area   | Network-LSA (0x2002)   |
| E-Inter-Area-Prefix    | 34            | 0xA022   | area   | Inter-Area-Prefix (0x2003) |
| E-Inter-Area-Router    | 35            | 0xA023   | area   | Inter-Area-Router (0x2004) |
| E-AS-External          | 36            | 0xA024   | AS     | AS-External (0x4005)   |
| E-Link-LSA            | 37            | 0xA025   | link   | Link-LSA (0x0008)      |
| E-Intra-Area-Prefix   | 38            | 0xA026   | area   | Intra-Area-Prefix (0x2009) |

The constants land in `crates/lr-ospf/src/lsa/e_v3.rs` (a new module,
mirroring the `v3.rs` layout):

```rust
/// E-Router-LSA (RFC 8362 §3): function code 32, U-bit set, area-scoped.
pub const LS_TYPE_E_ROUTER: u16 = 0xA020;
/// E-Network-LSA: function code 33, area-scoped.
pub const LS_TYPE_E_NETWORK: u16 = 0xA021;
/// E-Inter-Area-Prefix-LSA: function code 34, area-scoped.
pub const LS_TYPE_E_INTER_PREFIX: u16 = 0xA022;
/// E-Inter-Area-Router-LSA: function code 35, area-scoped.
pub const LS_TYPE_E_INTER_ROUTER: u16 = 0xA023;
/// E-AS-External-LSA: function code 36, AS-scoped.
pub const LS_TYPE_E_AS_EXTERNAL: u16 = 0xA024;
/// E-Link-LSA: function code 37, link-scoped.
pub const LS_TYPE_E_LINK: u16 = 0xA025;
/// E-Intra-Area-Prefix-LSA: function code 38, area-scoped.
pub const LS_TYPE_E_INTRA_PREFIX: u16 = 0xA026;
```

## 3. TLV framing

Every E-LSA body is a sequence of TLVs in the RFC 3630 convention
(already used by `lr-ospf::lsa::srv6`): `Type(2) | Length(2) |
Value(Length)`, padded to a 4-octet boundary with trailing zeroes
when the value length is not a multiple of 4. Unknown TLV types are
skipped on decode (forward-compat). Sub-TLVs use the same framing
inside their parent TLV's value.

The shared codec helper lands in the new `e_v3.rs` module:

```rust
/// Encode a TLV: type(2) + length(2) + value, padded to 4 octets.
pub fn encode_tlv(out: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    out.extend_from_slice(&tlv_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    out.extend(std::iter::repeat(0u8).take(pad));
}

/// Decode one TLV header. Returns (type, value_slice, total_bytes_consumed).
pub fn decode_tlv(b: &[u8], off: usize) -> Option<(u16, &[u8], usize)> {
    if off + 4 > b.len() { return None; }
    let t = u16::from_be_bytes([b[off], b[off+1]]);
    let l = u16::from_be_bytes([b[off+2], b[off+3]]) as usize;
    if off + 4 + l > b.len() { return None; }
    let padded = (l + 3) & !3;  // round up to 4
    Some((t, &b[off+4..off+4+l], 4 + padded))
}
```

This shape mirrors `srv6.rs`'s TLV handling so a reader who knows one
immediately knows the other.

## 4. The E-Router-LSA body

The E-Router-LSA (RFC 8362 §4.1) carries one or more **Router-Link
TLVs** (TLV type 1). Each Router-Link TLV describes one of the
router's interfaces and carries:

- Link Type (1 = point-to-point, 2 = transit, 4 = virtual — same
  values as the legacy Router-LSA)
- Link Metric (the output cost)
- Link Interface ID / Neighbor Interface ID / Neighbor Router ID
  (same 4-octet fields as the legacy Router-LSA link descriptor)
- Sub-TLVs (this is the extension point — the End.X SID sub-TLV
  rides here)

```rust
/// Router-Link TLV (RFC 8362 §4.1.1, TLV type 1 of the E-Router-LSA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ERouterLinkTlv {
    /// 1 = point-to-point, 2 = transit, 4 = virtual.
    pub link_type: u8,
    /// 16-bit metric (RFC 8362 §4.1.1 — a 0xFFFF metric means "link
    /// down" for traffic-engineering purposes, but the LSA is still
    /// flooded).
    pub metric: u16,
    pub interface_id: u32,
    pub neighbor_interface_id: u32,
    pub neighbor_router_id: u32,
    /// Raw sub-TLV bytes. The End.X SID sub-TLV (RFC 9513 §9.1) and
    /// the LAN End.X SID sub-TLV (RFC 9513 §9.2) live here in the
    /// slice that follows this scaffolding.
    pub sub_tlvs: Vec<u8>,
}
```

The `sub_tlvs` field is kept as raw bytes (not a typed list) so the
first slice can land the codec without committing to a specific sub-TLV
type set. The End.X SID slice adds typed accessors on top.

The E-Router-LSA body is a thin container:

```rust
/// E-Router-LSA body (RFC 8362 §4.1): a sequence of Router-Link TLVs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ERouterLsaBody {
    pub bits: u8,       // same B/E/V6 bits as the legacy Router-LSA
    pub options: u32,   // 24-bit Options (RFC 5340 §A.2), includes the E-bit
    pub links: Vec<ERouterLinkTlv>,
}
```

## 5. The other E-LSA bodies (same shape)

The remaining six E-LSAs follow the same TLV-container pattern. The
TLV types per RFC 8362 §B:

| TLV type | TLV name                  | Parent E-LSA              |
| -------- | ------------------------- | ------------------------- |
| 1        | Router-Link               | E-Router-LSA              |
| 2        | Attached-Routers          | E-Network-LSA             |
| 3        | Inter-Area-Prefix         | E-Inter-Area-Prefix-LSA   |
| 4        | Inter-Area-Router         | E-Inter-Area-Router-LSA   |
| 5        | AS-External               | E-AS-External-LSA          |
| 6        | Link-Local                | E-Link-LSA                |
| 7        | IPv6 Link-Local Address   | sub-TLV of Link-Local      |
| 8        | Intra-Area-Prefix         | E-Intra-Area-Prefix-LSA   |
| 9        | IPv6 Address              | sub-TLV of Intra-Area-Prefix |
| 10       | Link-Local Address       | sub-TLV of Router-Link     |

Each TLV's value shape mirrors the corresponding legacy LSA's
fixed-format body, so the `v3.rs` codec code is the reference. The
difference is framing: legacy = fixed-format, E-LSA = TLV + sub-TLVs.

## 6. The U-bit-2 flooding rules

RFC 8362 §3 defines the U-bit (forward-compat) behavior for E-LSAs:
a receiver that does not understand an E-LSA's function code MUST
store and re-flood it unchanged (the standard U-bit=1 behavior), so a
mixed-vendor network can carry E-LSAs through non-participating
routers. This is already what `lr-ospf::lsdb` does for any U-bit-set
LSA — verified by the `ospf6_frr_srv6.sh` interop lab where FRR
ospf6d (no SRv6) stores and re-floods lr's SRv6 LSAs unchanged.

The E-LSA-specific rule (RFC 8362 §3.1): when a receiver that does
not support E-LSAs receives one, it stores it but does NOT use it in
SPF. The legacy LSAs from the same speaker still carry the topology.
A speaker that supports E-LSAs MUST advertise the E-bit in its
Router-LSA Options (RFC 5340 §A.2 bit 0x20, "E-bit" — note: this is
the Options byte's bit 0x20, distinct from the LS Type field's
U-bit 0x8000).

## 7. SPF integration

The E-LSA SPF path is the largest piece of the slice. The existing
`run_spf_v3` in `crates/lr-ospf/src/spf.rs` consumes the legacy
Router-LSA / Network-LSA / Intra-Area-Prefix-LSA. The E-LSA path:

1. **Detect E-bit support.** The SPF root checks each neighbor's
   Router-LSA Options for the E-bit. If set, the SPF prefers the
   E-LSAs from that neighbor; if clear, it uses the legacy LSAs.
2. **E-Router-LSA → SPF links.** The E-Router-LSA's Router-Link TLVs
   map directly to the legacy `V3RouterLink` shape (link type, metric,
   interface IDs, neighbor router ID). The SPF function gets a new
   `spf_v3_links_from_e_router_lsa(&Lsa) -> Vec<V3RouterLink>` helper.
3. **E-Network-LSA → transit network.** The Attached-Routers TLV
   carries the list of attached routers (same shape as the legacy
   Network-LSA's body). The SPF gets a
   `attached_routers_from_e_network_lsa(&Lsa) -> Vec<u32>` helper.
4. **E-Intra-Area-Prefix-LSA → prefix attachment.** The
   Intra-Area-Prefix TLV carries the prefixes plus their referenced
   LSA (Router or Network). Same shape as the legacy body.
5. **E-Inter-Area + E-AS-External.** These map directly to the
   existing inter-area and external route calculation paths.

The SPF code stays the same shape — only the LSA-to-SPF-input
extractors gain an E-LSA branch. This keeps the regression risk
low: a deployment that does not configure E-LSAs sees byte-identical
SPF output.

## 8. The End.X SID sub-TLV (RFC 9513 §9)

The End.X SID sub-TLV is the payoff for the whole E-LSA slice: it
carries the per-adjacency SRv6 End.X SID that the kernel mirror
installs as a `seg6local` route. Its shape (RFC 9513 §9.1):

```text
sub-TLV type: 31 (OSPFv3 Extended-LSA Sub-TLV registry)
sub-TLV length: 4 + 16 + variable
flags: 1 octet (none defined; MUST be 0)
reserved: 1 octet
behavior: 2 octets (RFC 8986 End.X opcode = 5)
SID: 16 octets
sub-sub-TLVs: optional (e.g. SID Structure, RFC 9513 §10)
```

The LAN End.X SID sub-TLV (RFC 9513 §9.2, type 32) is the broadcast-
network variant (one per DR-adjacency instead of one per p2p
adjacency); same shape, different semantics.

The codec lands in `crates/lr-ospf/src/lsa/srv6.rs` next to the
existing End SID sub-TLV (§8), sharing the `Srv6SidStructure` type.
The sub-TLV is added to the `ERouterLinkTlv::sub_tlvs` bytes on
origination and extracted by the `srv6db` projection on reception.

## 9. Interop verification

The acceptance gate is the same shape as the existing SRv6 slice
(`tests/interop/ospf6_frr_srv6.sh`):

1. **lr x lr at the library level** — two `DefaultRouter` instances
   exchange E-LSAs over the existing OSPFv3 transport; both install
   each other's E-Router-LSA links in their SPF; the End.X SID
   sub-TLV projects into `srv6db` and installs as a `seg6local`
   route on the kernel mirror.
2. **FRR transparency** — FRR 10.3 ospf6d (no E-LSA support) stores
   and re-floods the U-bit-set E-LSAs unchanged. The lab extends
   `ospf6_frr_srv6.sh`'s 3-node topology with an E-LSA originator
   and an E-LSA receiver on either side of the FRR relay.
3. **BIRD compat** — BIRD 2 has no E-LSA support either; the lab
   verifies the same transparency.

No reference implementation produces E-LSAs yet (FRR's `ospf6d` E-LSA
support is incomplete as of 10.3), so the acceptance is RFC-figure-
pinned unit tests + router-level e2e + FRR/BIRD transparency. This
mirrors the SRv6 slice's acceptance posture.

## 10. Slice breakdown

The implementation is broken into three slices so each lands with
its own verification gate:

### Slice 1 — codecs (this design doc's scope)

- `crates/lr-ospf/src/lsa/e_v3.rs` — the function code constants,
  the TLV framing helpers, and the seven E-LSA body codecs with
  their TLV type constants.
- Comprehensive unit tests pinning every TLV shape byte-for-byte
  against the RFC figures.
- No SPF integration, no daemon origination — pure codec layer.

**Acceptance:** all existing tests stay green; the new codec tests
pin the wire shapes; the E-LSA bodies round-trip through
encode/decode.

### Slice 2 — SPF integration

- `crates/lr-ospf/src/spf.rs` gains the E-bit detection and the
  E-LSA → SPF-input extractors (§7).
- `crates/lr-ospf/src/lsdb.rs` gains the E-LSA reception path
  (store + re-flood the U-bit-set bodies; use in SPF only when the
  speaker's E-bit is set).
- Router-level e2e: two `DefaultRouter` instances exchange E-LSAs
  and produce byte-identical SPF output to the legacy-LSA path.

**Acceptance:** a deployment that does not configure E-LSAs sees
byte-identical SPF output to the current code; a deployment that
configures E-LSAs produces the same routes via the E-LSA path.

### Slice 3 — End.X SID origination + dataplane

- `crates/lr-ospf/src/lsa/srv6.rs` gains the End.X SID sub-TLV
  codec (§8).
- `crates/lr-ospf/src/srv6db.rs` projects the End.X SIDs from the
  E-Router-LSA's Router-Link TLV sub-TLVs.
- `crates/lr-cli/src/daemon_ospf3.rs` originates the E-Router-LSA
  with End.X SID sub-TLVs per interface on Full adjacency.
- `lr-osroute::seg6_route` installs the End.X SID as a `seg6local`
  route on the kernel mirror.
- Interop lab `tests/interop/ospf6_e_lsa.sh` — the 3-node topology
  with FRR transparency.

**Acceptance:** the End.X SIDs project into `srv6db` and install as
`seg6local` routes; FRR ospf6d stores and re-floods the E-LSAs
unchanged.

## 11. Risk and mitigation

| Risk | Mitigation |
| --- | --- |
| SPF regression on the legacy path | The E-LSA SPF branch is additive — `run_spf_v3` only takes the E-LSA branch when the speaker's E-bit is set. A deployment that does not configure E-LSAs sees byte-identical output. The existing interop suite (`ospf6_frr.sh`, `ospf6_broadcast.sh`, `ospf6_gr.sh`, `ospf6_gr_frr.sh`) stays green. |
| TLV padding bug | The TLV framing helper is unit-tested against RFC 3630's padding examples and the existing SRv6 TLV codec's test vectors. |
| E-bit detection race | The E-bit is in the Router-LSA Options (24-bit), not the LS Type field. The SPF root reads it from the neighbor's Router-LSA, not from the E-Router-LSA itself — so a speaker that originates E-LSAs but has not yet originated its Router-LSA is invisible to the E-LSA path. |
| End.X SID + dataplane | The kernel mirror's `seg6local` install path is already proven by the End SID (RFC 9513 §8) slice. The End.X SID reuses the same `Seg6LocalRoute` builder. |

## 12. What this design doc does NOT cover

- The actual codec code — that's slice 1 above. This doc is the plan
  the implementer follows.
- The OSPFv2 Extended-LSA equivalents (RFC 7684 / RFC 7684-bis) —
  those are the v2 Opaque-LSA shape, already implemented in
  `crates/lr-ospf/src/lsa/sr.rs`. The v3 E-LSA shape is a clean
  slate, not a port.
- The BGP-LS projection of E-LSA topology (RFC 7752 / RFC 9552) —
  that's Phase 3 item 3, a separate slice that consumes the E-LSA
  database this slice produces.

## 13. References

- RFC 8362 — OSPFv3 LSA Extendability
- RFC 5340 §A — OSPFv3 LSA formats (the base this extends)
- RFC 9513 §9 — SRv6 End.X / LAN End.X SID sub-TLVs (the driving
  use case)
- RFC 9352 §4 — the shared IGP MSD-Types registry (already
  implemented for the SRv6 Node MSD TLV)
- FRR 10.3 `ospf6d` source — the field-proven reference for the
  E-LSA codec shapes and the SPF integration
- BIRD 2 `ospf.c` — the v3 LSA handling the E-LSAs replace
- `crates/lr-ospf/src/lsa/srv6.rs` — the existing SRv6 LSA codec
  whose TLV framing pattern the E-LSAs mirror
- `crates/lr-ospf/src/lsa/v3.rs` — the existing v3 LSA codecs whose
  body shapes the E-LSAs carry in TLV form
- `crates/lr-ospf/src/spf.rs` — the SPF code that gains the E-LSA
  branch in slice 2
