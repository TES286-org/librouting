# Audit report — `crates/lr-ospf` (OSPFv2 / OSPFv3 routing-protocol library)

Scope: every source file of `crates/lr-ospf` (all of `src/`, including tests). No files were modified.
Baseline: `cargo test -p lr-ospf` → **119 passed, 0 failed** (all tests pass; several suites only round-trip through the crate's own (sometimes wrong) codecs, so they do not detect wire-format deviations).

Severity scale: **CRITICAL** = wire-interoperability break / remote panic / protocol violation; **MAJOR** = incorrect protocol behavior in realistic configurations; **MINOR** = robustness/performance/readability/test-quality.

References verified against RFC texts: RFC 2328 (A.3.3/A.3.4/A.4.1/A.4.2/D.3), RFC 5340 (§2.7, A.3.3/A.3.4/A.4.1, 4.4.3.4/4.4.3.6), RFC 3101, RFC 3623 (Appendix A), RFC 5709 (§3.1/§3.3), RFC 7166 (§4.1/§4.5), RFC 7684, plus FRR `ospfd/ospf_packet.{h,c}` and `ospf6d/ospf6_{message,proto}.{c,h}` for cross-implementation confirmation.

---

## 1. `codec.rs` — wire codec

### C1. CRITICAL — OSPFv3 Database-Description body uses the v2 layout (24-bit Options mangled)
`codec.rs:141-150` (encode) and `codec.rs:274-296` (decode) share one v2-shaped DBD codec: `mtu(2) | options(1) | flags(1) | dd_seq(4)`, fixed body = 8 bytes. RFC 5340 §2.7 and §A.3.3 expand the Options field to **24 bits** in Hello and DBD: the v3 DBD body is `mtu(2) | options(3) | flags(1) | dd_seq(4)` = 10 bytes, flags at offset 5. A v3 DBD decoded by this codec reads the second Options byte as `flags` and shifts the sequence number and every LSA header by 2 bytes; encoding is wrong in the mirror direction. `DbDescBody.options` (`packet/mod.rs:114`) is `u8`, too narrow for v3's 24-bit options. There is no version dispatch in `encode_dbdesc`/`decode_dbdesc`.

### C2. CRITICAL — OSPFv3 LS-Request decoding reads the LS type from the wrong byte
`codec.rs:298-317`: `decode_lsreq` is shared by v2 and v3 and reads `ls_type = b[i + 3]`. For v2 this is correct (RFC 2328 §A.3.4 entries are `LS type(4) | LS ID(4) | Adv Router(4)` — confirmed by FRR `OSPF_LSA_KEY_SIZE 12 /* type(4) + id(4) + ar(4) */` and `stream_getl(s)` in `ospf_ls_req()`). For v3, RFC 5340 §A.3.4 entries are `LS type(2) | Unused(2) | LS ID(4) | Adv Router(4)` (FRR `ospf6_make_lsreq` writes `stream_putw(0); stream_putw(ntohs(type)); ...`). `b[i+3]` is then the second **Unused** byte (always 0), so every v3 LS-Request decodes with `ls_type = 0` (the 0x20/0x40 high byte of 0x2001/0x4005 is lost). `LsRequestEntry.ls_type: u8` (`packet/mod.rs:124`) cannot represent v3 types at all.

### C3. MAJOR — Codec wedges permanently on the first malformed packet
`codec.rs:35-49` (`decode_slice`) and `codec.rs:83-99` (`Decoder::decode`): the carryover buffer is only drained on success (`self.carryover.drain(0..length)`). On any `ParseError` — bad version (`decode_packet` line 203), unknown packet type, truncated body, `length < 24` — the offending bytes stay in `carryover`, so every subsequent call re-parses the same buffer and fails again. A single corrupted/attacker-sent byte sequence permanently jams the session decoder (also for `lr-router` and `lr-ffi`, which use `decode_slice`). The decoder should advance past (or drop) the bad frame on error.

### C4. MAJOR — No checksum verification on receive; no v3 checksum support at all
`decode_packet` (`codec.rs:199-230`) never validates the packet checksum. For v2, `origination::v2_packet_checksum_ok` exists but is never called from the decode path (RFC 2328 §8.2 requires dropping packets with bad checksums). For v3 there is **no checksum code anywhere**: RFC 5340 §A.3.1 requires the IPv6 upper-layer checksum (one's-complement over the packet plus the IPv6 pseudo-header), which this crate can neither compute nor verify. This directly contradicts `lib.rs:6-7` ("The codec handles both v2 … and v3 (IPv6, pseudo-header checksum)") and the `OspfHeader.checksum` doc (`packet/mod.rs:31`). Encoded v3 packets leave the checksum field zero.

### C5. MAJOR — Authentication trailers cannot be used with the streaming codec
RFC 5709 §3.3 / RFC 7166 §4.1 implementation notes: the auth trailer is appended after the body and is **not** counted in the OSPF `length` field. `decode_slice`/`decode` frame solely on the length field, so with crypto auth the trailer bytes remain in `carryover` and are re-interpreted as the header of the next packet — decode either errors (wedging, see C3) or produces garbage packets. There is no codec hook for v2 crypto (AuType 2) or the v3 trailer (RFC 7166), and the `Auth` trait (`auth/mod.rs:39-46`) is never wired into encode/decode (no other crate uses it; it is dead library API).

### C6. MAJOR — `encode_vec` allocates a fresh 64 KiB buffer per packet
`codec.rs:51-57`: `vec![0u8; 65535]` on every encode, even for a 44-byte Hello; then `out.truncate(n)`. Hot-path allocation waste; packets larger than 65535 bytes are silently rejected (`WriteBuf::BufferFull`).

### C7. MINOR — LS-Update `# advertisements` count is not validated; trailing garbage tolerated
`codec.rs:319-344`: the loop stops at `lsas.len() < lsa_count` or buffer end, but the result keeps the **declared** `lsa_count` even when fewer LSAs were present; leftover bytes < 20 after the last LSA are silently dropped. FRR (`ospf_lsaseq_examin`) treats a declared/actual count mismatch as a malformed packet error.

### C8. MINOR — v3 Hello cannot carry a non-zero Interface ID
`codec.rs:120-126`: for v3, `encode_hello` always writes `0` for the Interface ID field (ignores `h.network_mask`, whose doc says "v2 only"). RFC 5340 §A.3.2: the Interface ID is how the DR's network-LSA LS ID is assigned; a real v3 Hello always needs it. Decode maps the field back into `network_mask` (`codec.rs:262`), so the round-trip is self-consistent but the wire value is always 0.

### C9. MINOR — `length`/`total` truncation and a vacuous length check
`codec.rs:74`: `(total as u16)` truncates silently for packets > 65535 bytes. `decode_packet`'s `length as usize != b.len()` check (`codec.rs:208`) is vacuous: `decode_slice` already slices `b` to exactly `length`.

### C10. MINOR — duplicated streaming logic, O(n) front-drain
`decode_slice` and `Decoder::decode` are near-identical copies (`codec.rs:35-49` vs `83-99`); `carryover.drain(0..length)` is O(remaining) per packet, O(n²) for a burst of queued packets.

---

## 2. `packet/mod.rs`

### P1. MINOR — header struct is v2-shaped; v3 semantics documented but not representable
`OspfHeader` (`packet/mod.rs:25-37`) is fine for both versions' 24-byte header. `DbDescBody.options: u8` (line 114) and `LsRequestEntry.ls_type: u8` (line 124) cannot represent v3 (24-bit options; 16-bit types) — see C1/C2.

---

## 3. `lsa/mod.rs` — LSA model

### L1. CRITICAL — v3 LSA header type encoding is structurally broken; originated v3 LSAs carry the wrong type on the wire
`LsaHeader` (`lsa/mod.rs:21-32`) stores `options: u8` + `ls_type: u8`. RFC 5340 §2.8/§A.4.2: the v3 LSA header has **no options field**; the 16-bit LS type occupies bytes 2-3. `encode_lsa_header` (`codec.rs:183-197`) writes `[age][options][ls_type]…`, so for v3 the type's high byte must be smuggled into `options`. `LsaTypeV3::function_code()` (`lsa/mod.rs:409-414`) returns only the low byte, and `abr::originate_v3_inter_area_prefix_lsa` sets `options: 0x00, ls_type: 0x03` (`abr.rs:141-142`) — the wire type is **0x0003** (U-bit 0, link-local scope, function 3), not 0x2003. Decode is equally lossy: a received 0x2003 LSA becomes `options=0x20, ls_type=0x03`, and any keying/matching on `ls_type` (e.g. `LsaKey`, `external_routes`, `nssa_routes`) then confuses v3 types with v2 types. The comments at `lsa/mod.rs:405-411` describe the hack but do not make it safe; `LsaKey.ls_type: u8` (`lsa/mod.rs:40-44`) cannot key v3 LSAs correctly.

### L2. CRITICAL — OSPFv3 inter-area-prefix-LSA body is not RFC 5340 conformant
`encode_v3_inter_area_prefix_body` (`lsa/mod.rs:233-251`) and `decode_v3_inter_area_prefix_body` (`lsa/mod.rs:266-284`) use the layout `Metric(3) | PrefixLength(1) | PrefixOptions(1) | Prefix(ceil(PL/8), unpadded)`. RFC 5340 §A.4.5 + §A.4.1 (confirmed by FRR `struct ospf6_prefix { prefix_length; prefix_options; union{prefix_metric, …} u; }` with `OSPF6_PREFIX_SPACE(x) = (((x)+31)/32)*4`): the body is `PrefixLength(1) | PrefixOptions(1) | Metric(2) | Prefix(padded to a 32-bit boundary)`. The implementation is wrong in three ways: field order, metric width (3 vs 2 bytes), and missing 32-bit padding (RFC 5340 §4.4.3.4: "The prefix is padded out to an even number of 32-bit words"). Metric semantics are also wrong: v3's 16-bit metric space has LSInfinity = 0xFFFF, not 0x00FF_FFFF (`lsa/mod.rs:234` caps at 0x00ff_fffe; `external.rs`/`nssa.rs` reuse the v2 constant). Any real OSPFv3 peer will misparse these LSAs; only the crate's own self-round-trip tests pass.

### L3. MAJOR — RFC 7684 prefix-link-local entries are encoded without 32-bit padding
`encode_v3_prefix_link_local_entry` (`lsa/mod.rs:572-583`) writes `ceil(PL/8)` prefix bytes with no padding; RFC 7684 §3.1 encodes prefixes per RFC 5340 §A.4.1 (32-bit aligned). Also `entry.prefix_bytes[..n.min(len)]` silently truncates an undersized prefix vector instead of erroring.

### L4. MAJOR — Router-LSA link decoding ignores TOS entries; the "12 bytes per TOS" comment is wrong
`decode_router_links` is in `spf.rs` but defines the shared `RouterLink` model (`lsa/mod.rs:476-484`, which also drops the `# TOS` count). RFC 2328 §A.4.2: each link is 12 bytes followed by `n` 4-byte TOS entries. `spf.rs:270-271` claims "Skip any TOS entries (12 bytes per TOS)" and skips nothing — a router-LSA with `TOS != 0` entries is misparsed (the next link's fields shift). TOS is deprecated (RFC 2328 requires TOS=0), so severity is capped at MAJOR for robustness.

### L5. MINOR — `Lsa::finalize` truncates the length field silently
`lsa/mod.rs:90`: `(LsaHeader::LEN + body.len()) as u16` wraps for bodies > 65515 bytes.

### L6. MINOR — `V3InterAreaPrefixBody::to_prefix` accepts `prefix_len > 128` without rejecting
`lsa/mod.rs:290-295`: a wire `PrefixLength` of 200 is stored into a `Prefix` as-is (clamping happens later in `Prefix` helpers); the decode bounds the *bytes* but not the length. Harmless today, but the invariant should be enforced at decode time.

### L7. MINOR — lenient non-contiguous-mask handling
`mask_to_prefix_len` (`lsa/mod.rs:124-126`) counts set bits, so a garbage mask like 0x8000_0001 yields /2. Lenient, documented, matches some implementations — but combined with `spf.rs`/`external.rs` it silently derives bogus prefix lengths from malformed LSAs instead of rejecting them.

---

## 4. `lsa/grace.rs` — RFC 3623 / RFC 5187 Grace-LSA

### G1. CRITICAL — Wrong LSA type: AS-scope opaque (11) instead of link-local opaque (9)
`originate_grace_lsa_v2` (`grace.rs:270`) sets `ls_type = LsaTypeV2::OpaqueAsLsa` (11). RFC 3623 Appendix A: "The grace-LSA is a **link-local** scoped Opaque-LSA … LS type = 9, Opaque Type 3, Opaque ID 0". The module doc (`grace.rs:2-4`) even says "AS-scope Opaque-LSA (RFC 5250)" — RFC 5250 defines opaque types 9/10/11; RFC 3623 mandates the link-local (type 9) one. Peers flood/scope the LSA wrongly (AS-scope instead of link-local), so the restart request never stays on the link and can even be suppressed by scoping rules.

### G2. CRITICAL — Grace TLV type numbers are wrong (shifted by one, plus a nonexistent TLV)
`GraceTlvType` (`grace.rs:56-79`): `AddressFamily=1, GracePeriod=2, Reason=3, Ipv4Address=4, Ipv6Address=5`. RFC 3623 Appendix A defines **Grace Period = 1, Graceful Restart Reason = 2, IP interface address = 3**; RFC 5187 (v3) likewise uses 1/2/3 (Grace Period, Reason, IPv6 Interface Address). There is no "Address Family" Grace TLV. Encoding emits `GracePeriod=2`/`Reason=3` on the wire and decoding reads `1` as an (unknown) Address-Family TLV, so no RFC 3623 helper can parse these bodies.

### G3. MAJOR — Grace TLV values are not padded to 4-octet alignment
`GraceLsaBody::encode` (`grace.rs:146-175`) writes the 1-byte Reason TLV with no padding. RFC 3623 Appendix A: "The TLV is padded to four-octet alignment; padding is not included in the length field (so a three octet value would have a length of three, but the total size of the TLV would be eight octets)."

### G4. MINOR — doc/scope confusion and missing v3 origination
Doc claims v2+v3 support but only `originate_grace_lsa_v2` exists; the v3 Grace-LSA type (0x000B, link-local, per RFC 5187) is never originated. `OPTIONS_O_BIT = 0x40` matches RFC 3623 §1 (v2 options bit 6); RFC 5187 reuses the same bit within the v3 options, so the constant is usable but the codec cannot set 24-bit v3 options anyway (C1).

---

## 5. `auth/` — RFC 5709 (v2 HMAC) and RFC 7166 (v3 trailer)

### A1. CRITICAL — RFC 5709 support is not wire-interoperable (Auth Data Len semantics + MAC input + HMAC variant)
`auth/crypto.rs`:
- **Auth Data Len**: `sign_trailer` writes `TRAILER_OVERHEAD + digest` (26 for SHA-1, 38 for SHA-256) into the trailer's second byte (`crypto.rs:184`) and `verify` demands `auth_data_len == trailer.len()` (`crypto.rs:234-240`). RFC 5709 §3.1: "set the Authentication Data Length field to the length … of the cryptographic hash … with NIST SHA-256, the Authentication Data Length is 32 bytes" — i.e., the **digest length only** (20/32), never the total trailer. Conformant senders are rejected; this library's own trailers are rejected by conformant receivers.
- **MAC input**: `compute_mac` (`crypto.rs:192-218`) hashes `header + body` with checksum/auth zeroed. RFC 5709 §3.3 requires `First-Hash = H(Ko XOR Ipad || OSPFv2 Packet)` where "(OSPFv2 Packet) … includes the Authentication Trailer containing the Apad value" (trailer = key-id | auth-data-len | crypto-seq | Apad), with `Ko` derived from the key padded/truncated to **L octets**, not the RFC 2104 block-size padding the `hmac` crate applies. The digest computation is completely different.
- **Phantom pseudo-header**: the optional `source` pseudo-header (`crypto.rs:127-130, 207-216`: src + 0 + 89) exists in neither RFC 2328 §D.3 nor RFC 5709 §3.3 (RFC 5709's input is the OSPF packet + trailer only). The doc comment's claim "RFC 2328 §D.3 specifies an IPv4 pseudo-header" is incorrect. Enabling `with_source` makes the digest even less interoperable.

### A2. CRITICAL — RFC 7166 v3 auth implements the obsolete RFC 6506 trailer and a non-standard MAC
`auth/v3_auth.rs`:
- **Trailer layout**: RFC 7166 §4.1 (Figure 3) is `Authentication Type(2) | Auth Data Len(2) | Reserved(2) | SA ID(2) | Crypto Seq(8) | Auth Data` — 16-octet fixed header, with `Auth Data Len` = length of the **entire trailer** including the 16-octet header, and a 16-bit SA ID. `V3Auth::sign_trailer` (`v3_auth.rs:113-121`) emits `SA ID(4) | Auth Data Len(2) | Crypto Seq(8) | Digest` — exactly the **RFC 6506** (obsoleted March 2014) format: no Authentication Type, no Reserved, 32-bit SA ID, wrong length semantics.
- **MAC input**: `compute_mac` (`v3_auth.rs:125-149`) hashes `packet` plus a standard IPv6 pseudo-header (src, dst, len, 0,0,0, 89). RFC 7166 §4.5 requires the First-Hash over "(OSPFv3 Packet) + LLS data block + Authentication Trailer filled with **Apad**", where `Apad` = IPv6 **source address** (16 octets) followed by 0x878FE1F3 repeated (L−16)/4 times, and `Ks = K || OSPFv3 Cryptographic Protocol ID (2 octets, value 1)`, with `Ko` prepared to L octets. The pseudo-header here is invented; the digest will never match a peer implementation.
- **No AT-bit handling**: RFC 7166 §2.1 requires the AT-bit (0x000400 in the 24-bit options) in Hello/DBD and per-packet-type sequence-number tracking (§4.6) — both absent.

### A3. MAJOR — Anti-replay bootstrap hole in both auth implementations
`crypto.rs:245` and `v3_auth.rs:185`: `if peer_seq <= self.last_peer_seq && self.last_peer_seq != 0 { return false; }`. A first packet with seq 0 is accepted and `last_peer_seq` stays 0, so **any** later packet with seq 0 is also accepted — seq-0 packets can be replayed forever. The "first packet" exemption should track "has seen any packet", not "last seen != 0".

### A4. MINOR — no tests against RFC 5709/7166 test vectors; header/trailer consistency not enforced
The unit tests only round-trip the crate's own (wrong) conventions; there is no cross-check of the header `auth_data`/crypto-seq against the trailer, and no validation that the header's crypt auth_data_len (RFC 2328 D.3) matches the trailer.

---

## 6. `lsdb.rs` — link-state database

### D1. MAJOR — `install` accepts out-of-range sequence numbers, corrupting the sequence space
`lsdb.rs:79-82`: the comparison `(lsa.seq as i32) <= (prev_seq as i32)` accepts any signed-newer value. An instance with seq `0x00000001` compares **greater** than a stored `0x80000001` (1 > −2147483647), so a malformed/buggy peer can replace a valid initial-sequence LSA; afterwards the watermark (1) blocks every legitimate `0x80000001+` instance until a flush. RFC 2328 §12.1.2 restricts the sequence space to `0x80000001..=0x7fffffff` (0x80000000 reserved); out-of-range values should be rejected, not compared.

### D2. MAJOR — No checksum validation; same-seq-different-checksum instances silently dropped
RFC 2328 §13.1: an incoming LSA is a duplicate only when seq **and checksum** match (with the MaxAgeDiff age tolerance); same seq + different checksum must be compared by age. `install` keys only on the sequence number (`lsdb.rs:79-84`) and never calls `Lsa::checksum_ok`, so corrupted instances with a new seq replace good ones, and distinct instances sharing a seq are dropped. (RFC 2328 §13 step (1): discard only after checksum validation; step (5) install logic.)

### D3. MAJOR — A MaxAge instance purges unconditionally, even when older than the stored copy
`lsdb.rs:68-77`: any `ls_age >= MAX_AGE` instance removes the entry regardless of sequence number. RFC 2328 §13 step (5)/(6): an older MaxAge instance must be discarded and the database copy sent back; only a *newer-or-absent* MaxAge instance triggers removal. A stale MaxAge with an old seq can evict a valid newer LSA.

### D4. MINOR — `refresh_due` does not cap the sequence at `MAX_SEQUENCE_NUMBER`
`lsdb.rs:136-141`: `checked_add(1)` only guards overflow; refreshing at seq `0x7fffffff` produces the reserved `0x80000000` (unlike `Lsa::maxage_flush`, `lsa/mod.rs:108-119`, which checks it).

### D5. MINOR — stored LS age is never advanced
`age_out` (`lsdb.rs:156-175`) computes "now − installed + received age" for expiry but never updates the stored `ls_age`; every consumer (`headers()`, SPF, exchange) sees the stale received age. RFC 2328 §14 requires aging the stored LSA.

### D6. MINOR — redundant watermark map and O(n) `headers()` per DBD page
`seq_watermark` (`lsdb.rs:47`) duplicates the sequence already present in `entries`; `headers()` (`lsdb.rs:178-180`) allocates a fresh Vec on every call, which `exchange::next_our_chunk` invokes once per DBD page (`exchange.rs:496`) — O(n²) work + allocations for a large LSDB exchange (see E6).

---

## 7. `spf.rs` — RFC 2328 §16.1/§16.2

### S1. MAJOR — No equal-cost multipath support at all
`run_spf` (`spf.rs:85-175`) keeps a single best distance per vertex (`result.vertices: BTreeMap<VertexId, u64>`), and relaxes edges only on strict improvement (`if new_dist < prev`, lines 115/129/164). RFC 2328 §16.1 (2) explicitly adds equal-cost parents ("If the new distance is the same as the old … the vertex is added to the list of equal-cost parents"; §16.8 covers the multipath routing table). No parent lists exist anywhere in `SpfResult`, so ECMP is impossible even at the caller.

### S2. MAJOR — O(V·L) SPF: full LSDB scan per vertex
For every popped vertex, `run_spf` iterates the **entire** LSDB to find that vertex's Router-LSA/Network-LSA (`spf.rs:95-98` and `spf.rs:156-159`). With V vertices and L LSAs this is O(V·L) plus L heap relaxations; RFC 2328 §16.1 with adjacency indexing is O(E log V). For area sizes where SPF cost matters (hundreds of routers), this is the dominant hot-path cost.

### S3. MAJOR — Transit (broadcast) networks never produce routes; `transit_routes` is dead output
Network-LSA vertices are used only for graph traversal (`spf.rs:154-173`); the intra-area routes for transit networks (RFC 2328 §16.1(2)(c) + §16.1.1) are never emitted — `SpfResult.transit_routes` is never pushed to (doc at `spf.rs:35-36` promises "Best next-hop IP for each transit network"). Consequence in `external.rs:319-327`: the §16.4(c) forwarding-address "covering" table is built from `stub_routes + transit_routes + summaries`, so a forwarding address on a transit network is never covered and the external route is dropped (same gap in `nssa.rs:211-216`).

### S4. MAJOR — No next-hop computation anywhere; `SpfRoute.next_hop` is always `None`
RFC 2328 §16.1.1 computes next hops during the tree walk; `run_spf` never does (all `next_hop: None`, `spf.rs:142-147`), and the docs at `spf.rs:33-36` claim next-hop output that the code never produces. `summary_routes`/`external_routes` pass `None` through, so a caller of this crate cannot obtain usable routes (intra-area or inter-area) without re-implementing §16.1.1.

### S5. MAJOR — `summary_routes` does not implement §16.2 (b) intra-area preference (and the fixture masks it)
The doc (`spf.rs:191-194`) admits the intra-area-wins rule is left to the caller; fine as a contract, but see T2: the crate's own test fixture never actually builds two reachable border routers, so the tie-break behavior is untested.

### S6. MINOR — Stub links with LSInfinity metric are installed
`spf.rs:137-148` adds every stub link unconditionally; RFC 2328 §16.1 (3) requires the resulting distance to be below LSInfinity to enter the table.

### S7. MINOR — Virtual links are treated as plain point-to-point links without endpoint reachability
`spf.rs:102-122` relaxes type-4 links directly. RFC 2328 §15: a virtual link is usable only when its endpoints are mutually reachable through the transit area, and the metric in the LSA is the maintained transit cost — this is a reasonable shortcut for the backbone SPF but is not validated, and the comment's justification is an approximation.

### S8. MINOR — `decode_network_attached_routers` ignores the network mask; network-LSA path untested
The network vertex handling (the only place `VertexId::Network` is exercised) has **no unit test** — `dijkstra_basic` covers p2p + stub only. See M2.

---

## 8. `external.rs` — §16.4

### X1. MAJOR — Forwarding-address cover is incomplete (transit networks missing)
`external.rs:319-327`: the covering table omits transit-network routes because `transit_routes` is never populated (S3). RFC 2328 §16.4 (c): the forwarding address may be covered by *any* intra-area route, including transit networks. This silently drops valid external routes whose FA is a broadcast/NBMA network address.

### X2. MINOR — §16.4 checks not enforced
`external.rs`: no verification that the type-5's advertising router is an ASBR (E-bit in its router-LSA, RFC 2328 §16.4), and self-originated type-5s are not skipped (documented deviation, `nssa.rs:193-197`). Candidate selection `beats` (`external.rs:235-249`) otherwise matches §16.4 (6) (type-1 over type-2; metric; internal cost for type-2 ties).

### X3. MINOR — `ExternalDestination`/`SummaryDestination` caps are bypassable
The structs' fields are public; `ExternalDestination::new` caps the metric (`external.rs:93`) but direct construction (`ExternalDestination { metric: LS_INFINITY, .. }`) lets `originate_external_lsa` (`external.rs:127-131`) emit an LSInfinity type-5 that receivers treat as unreachable — should be rejected at origination.

---

## 9. `abr.rs` — type-3 origination

### B1. CRITICAL — v3 inter-area-prefix-LSA carries type 0x0003 on the wire (see L1)
`abr.rs:141-142`: `options: 0x00, ls_type: function_code()` — the 16-bit v3 type high byte (0x20) is dropped; wire type = 0x0003. The v3 tests (`abr.rs:252-277`) assert only the struct field (`function_code()`), never the wire bytes, so they pass while the emitted LSA is invalid.

### B2. MAJOR — v3 metric space / LSInfinity wrong (see L2)
`abr.rs:137` → `lsa/mod.rs:234` caps at 0x00ff_fffe; v3 metrics are 16-bit (LSInfinity 0xFFFF).

### B3. MINOR — link-state-ID collisions documented but not handled
`abr.rs:18-26` documents that overlapping prefixes (`10.0.0.0/8` vs `10.0.0.0/16`) collide on one LS ID and "the last originated LSA wins" — an acknowledged limitation, worth surfacing to embedders.

---

## 10. `nssa.rs` — RFC 3101

### N1. MAJOR — Translator election ignores the caller's own Nt-bit
`is_elected_translator` (`nssa.rs:296-314`) skips `key.advertising_router == router_id`, so a router whose *own* router-LSA sets the Nt-bit (unconditional translator, RFC 3101 Appendix B) is treated as a normal candidate: any other B-bit router with a higher router ID "wins" against it. Per RFC 3101 §3.1, Nt beats router ID regardless.

### N2. MAJOR — NSSA default handling deviates from §2.5 for non-border internal ASBR defaults
`originate_nssa_lsa` (`nssa.rs:103-105`) rejects any P-bit type-7 with a zero forwarding address (RFC 3101 §2.3 — correct), but `originate_nssa_default_lsa` (`nssa.rs:149-161`) is the only way to originate a default; there is no way to originate a P-bit *set* default from an internal ASBR with a zero FA, which §2.4 permits only with an FA — the code is actually stricter than the RFC here for the P-bit case (matches §2.3), so this is a documented behavior, not a bug. Keep as informational.

### N3. MINOR — same transit-network cover gap as X1
`nssa.rs:211-216` builds the intra-area covering table from `stub_routes + transit_routes`; transit_routes is never populated (S3), so FA coverage for transit networks is missing in NSSA too.

---

## 11. `origination.rs`

### O1. MAJOR — Router-LSA flags (B/E/V) and options are hard-coded and cannot be set
`originate_router_lsa` (`origination.rs:101`) always writes flags `0u16` and `options: 0x02` (E-bit) (`origination.rs:114`). RFC 2328 §12.4.1 requires setting B (ABR), E (ASBR), V (virtual-link endpoint); §12.4.1.5 and stub/NSSA rules require options without the E-bit (stub: E=0; NSSA: N-bit; graceful restart: O-bit). An ABR/ASBR using this helper is invisible as such to its peers, breaking type-3/type-4/type-5 processing elsewhere (and the crate's own `is_elected_translator` B-bit scan, `nssa.rs:304`).

### O2. MINOR — v2 packet checksum is correct but only available as an explicit post-step
`finalize_v2_packet`/`v2_packet_checksum_ok` (`origination.rs:140-212`) implement RFC 2328 §A.1 correctly (header minus 8 auth bytes, checksum included as zero, one's-complement; odd-byte high-order padding consistent with RFC 1071). The risk is purely that the codec never does this itself (C4) and the embedder must remember to call it.

---

## 12. `exchange.rs` — RFC 2328 §10.3–§10.8

The master/slave negotiation, I/M/MS handling, sequence echo, and the two `exchange_tests.rs` scripted conversations are otherwise coherent and match §10.3/§10.6/§10.7 closely. Findings:

### E1. MAJOR — Integer underflow (panic / giant allocation) for `iface_mtu < 52`
`exchange.rs:339` (`on_ls_request`: `let max_bytes = self.iface_mtu as usize - DD_OVERHEAD;`) and `exchange.rs:494` (`next_our_chunk`: `((self.iface_mtu as usize - DD_OVERHEAD) / LSA_HEADER_LEN).max(1)`). With a configured MTU below 52, debug builds panic on underflow; release builds wrap to a huge `per_page`/`max_bytes` and attempt absurd allocations. `DbExchange::new` accepts any `u16` MTU with no lower bound.

### E2. MAJOR — LS-Request packets are never paged to the MTU
`take_ls_request`/`lsr_body_from_queue` (`exchange.rs:428-436, 550-554`) serialize the **entire** request queue into one packet. RFC 2328 §10.7/§10.9 and FRR (`ospf6_make_lsreq` / `ospf_ls_req_send`) bound LS-Request size by the MTU; with a large request list this emits an oversized packet (or an LSU request exceeding the peer's MTU).

### E3. MAJOR — Hard-coded v2, E-bit options, and no options/MTU-equality validation
`base_header` (`exchange.rs:558-569`) hard-codes `version: 2` and `db_desc_packet` hard-codes `options: 0x02` (`exchange.rs:576`) — wrong for stub (E=0)/NSSA (N-bit)/grace (O-bit) areas, and the module is v2-only despite the crate claiming v3. Received DBD options are never validated (RFC 2328 §10.6 requires the E/N bits to match the area). The MTU check (`exchange.rs:204-206`) rejects only `d.mtu > ours` (lenient; BIRD enforces equality — documented, acceptable per RFC wording).

### E4. MAJOR — LS-Request satisfaction drops requests regardless of the received instance's recency
`on_ls_update` (`exchange.rs:374-391`) removes any queued request whose (type, id, adv) matches a received LSA, even if the received instance is *older* than the instance we asked for (and even if the caller's `install` then ignores it). RFC 2328 §10.8/§13: a request is satisfied only by an equally-new or newer instance. An older instance can empty the queue early, declaring the adjacency Full while our copy is stale.

### E5. MINOR — No retransmission of the ExStart initial DBD
`poll` (`exchange.rs:397-411`) retransmits only in `Phase::Exchange`; if the initial DBD (`initial_db_desc`, `exchange.rs:178-187`) is lost, the master sits in ExStart until something else happens (there is no inactivity timer in the neighbor FSM either, `neighbor.rs`).

### E6. MINOR — O(n²) header paging: `lsdb.headers()` allocates and copies the whole DB per page
`next_our_chunk` (`exchange.rs:493-505`) calls `lsdb.headers()` (full Vec, `lsdb.rs:178`) then `skip(cursor)` on every page. For n LSAs and page size p this is O(n²/p) copies; a cursor-based iterator over the BTreeMap would be O(n).

### E7. MINOR — header comparison ignores checksum/age for equal-sequence headers
`process_their_headers` (`exchange.rs:463-470`) compares only sequence numbers; RFC 2328 §10.5's "same seq, different checksum" case (compare ages, request the newer) is not handled. Also the Loading/Full duplicate check (`exchange.rs:292-300`) matches flags+seq only, ignoring header content.

### E8. MINOR — `their_more` initialization and dead code
`their_more: true` at construction (`exchange.rs:136`) is a placeholder that is never read before negotiation; `next_our_chunk`'s `let _ = iter;` (`exchange.rs:503`) is dead.

---

## 13. `interface.rs` — DR/BDR election and interface FSM

### I1. MAJOR — DR/BDR election deviates from RFC 2328 §9.4.1 in four ways
`elect` (`interface.rs:63-106`):
1. **No priority-0 exclusion**: RFC 2328 §9.4.1 restricts candidates to routers with priority > 0; a priority-0 router that claims DR in its Hello is elected here (lines 80-89).
2. **Self is never a candidate**: the caller passes `our_id = 0` (`interface.rs:149`), and the RFC's fallback "if we are eligible, we can be DR/BDR" never applies; the `unwrap_or(our_id)` (line 103) can never fire with a real ID.
3. **No re-run excluding self**: RFC 2328 §9.4.1 step (3) repeats the calculation with the calculating router itself excluded when *it* wins; not implemented (the final `if bdr == 0 { bdr_final } else { bdr }` at line 105 is a different, wrong rule).
4. **Step-3 "BDR recompute" is mis-scoped**: it selects among all electors except the DR without the priority>0 rule, and is only used when no router declared itself BDR — the RFC fallback BDR is chosen among *eligible* routers excluding the DR.

### I2. MAJOR — The interface FSM never reaches DR/Backup; the election result is discarded
`step` (`interface.rs:139-167`): the `NeighborChange` arm runs `elect` and then maps **every** outcome to `IfState::DrOther` (`interface.rs:152-156`) — the match arms `(_, 0)` / `(0, _)` / `_` are all `DrOther`, so `self.dr`/`self.bdr` are stored but the state machine can never become `Dr` or `Backup`. The `Waiting` arm even *constructs and discards* a `NeighborChange` event (`interface.rs:143-145`, dead code) instead of running the election. RFC 2328 §9.4/§9.3: Waiting+WaitTimer/BackupSeen → elect and enter DR/Backup/DrOther.

### I3. MINOR — misleading test comment
`interface.rs:225-227` (`elect_with_higher_priority_no_declared`): the comment claims "dr would be our_id" but per RFC step (2) DR falls back to the elected BDR, and the code returns `bdr` — the comment contradicts both.

---

## 14. `neighbor.rs` — neighbor FSM

### N4. MINOR — FSM is a skeleton missing RFC 2328 §10.3 events
No `InactivityTimer`/`KillNbr`, no `Attempt` state events, no `AdjOk`-re-evaluation on Hello in 2-Way, and `BadLsa`/`SeqMismatch` from any state including `Down`/`Init` jump to ExStart (`neighbor.rs:138-144`) — acceptable as a minimal library FSM (documented), but the missing inactivity timer interacts with E5.

---

## 15. Missing / weak tests (coverage)

### M1. No OSPFv3 codec tests at all
There is not a single v3 encode/decode test in `codec.rs` (or anywhere): Hello-v3, DBD-v3, LSR-v3, LSU-v3, v3 LSA headers are untested. This is why C1, C2, L1, L2, B1 shipped: every v3 path is only self-round-tripped. **This is the single most consequential test gap.**

### M2. SPF: transit-network (network-LSA) path untested; no ECMP, no LSInfinity-stub, no next-hop tests
`spf.rs` tests cover p2p, stub, and virtual links only. The `VertexId::Network` branch (`spf.rs:154-173`) has zero coverage.

### M3. `spf.rs` test fixture `two_border_routers()` does not build what its name/comment claims
`spf.rs:454-488`: the root's second router-LSA (link to BR-b) has the *same key and sequence number* as the first (link to BR-a), so `install` returns `Ignored` (`lsdb.rs:80-82`) and the database contains only the BR-a link — **BR-b is unreachable**. The "equal-cost tie-break" test (`summary_prefers_lower_total_metric_then_lower_border`, `spf.rs:517-548`) therefore never exercises two competing candidates; its comment "both 20 — deterministic winner" is vacuous.

### M4. Exchange: missing tests for MTU-mismatch drop, master-side multi-page exchange, empty-LSDB fast path, LSR retransmission (`poll`), sequence wrap, options validation, and any failure-recovery path
`exchange_tests.rs` covers the happy-path slave and master scripts, mismatch restart, duplicate handling, one MTU-paging case, and DBD retransmission — but none of the above, and nothing that would trip E1/E2/E4.

### M5. LSDB: no tests for checksum-aware duplicate handling, out-of-range sequences, older-MaxAge purges (D1-D3).

### M6. Auth: no RFC 5709/7166 conformance vectors; no test for the seq-0 replay hole (A3).

### M7. No tests for `Lsa::finalize` length overflow, `encode_vec` > 64 KiB, or codec recovery after a malformed packet (C3/C6).

---

## Top 10 most important findings (ranked)

1. **CRITICAL — v3 inter-area-prefix-LSA body is not RFC 5340 conformant** (`lsa/mod.rs:233-284`, `abr.rs:126-153`): wrong field order/width (`Metric(3) | PL | PO` vs `PL | PO | Metric(2)`), no 32-bit prefix padding, v2 LSInfinity semantics. Every OSPFv3 peer will misparse these LSAs; no v3 codec test exists to catch it.
2. **CRITICAL — v3 LSA type handling is structurally broken; originated LSAs carry type 0x0003 instead of 0x2003** (`lsa/mod.rs:21-32,409-414`, `abr.rs:141-142`, `codec.rs:183-197`): the 16-bit v3 type is mangled through a v2-shaped `options`+`ls_type` pair; `LsaKey`/LSDB keying cannot represent v3 types.
3. **CRITICAL — Grace-LSA is wrong on three axes** (`lsa/grace.rs`): link-local opaque (type 9) vs emitted type 11; TLV numbers shifted (RFC 3623: 1=Grace Period, 2=Reason, 3=IP address vs the code's 1=AddressFamily, 2=GracePeriod, 3=Reason, 4=IPv4, 5=IPv6); TLV values not 4-octet padded.
4. **CRITICAL — RFC 5709 HMAC auth is non-interoperable** (`auth/crypto.rs`): `Auth Data Len` = full trailer instead of the digest length (RFC 5709 §3.1); MAC input lacks the trailer-with-Apad and uses plain RFC 2104 HMAC instead of the RFC 5709 Ko/Apad procedure; a nonexistent "IPv4 pseudo-header" is offered as a feature.
5. **CRITICAL — RFC 7166 v3 auth implements the obsolete RFC 6506 trailer and a non-standard MAC** (`auth/v3_auth.rs`): missing Authentication-Type/Reserved fields, 32-bit SA ID vs 16-bit, standard IPv6 pseudo-header instead of the RFC 7166 Apad (source-address-embedded) computation.
6. **MAJOR — OSPFv3 DBD and LS-Request codecs use v2 layouts** (`codec.rs:141-150,274-317`): v3 DBD Options is 24 bits (flags at offset 5, 10-byte fixed body); v3 LS-Request LS type is 2 bytes at entry offset 2 (the code reads the padding byte). No v3 packet tests exist.
7. **MAJOR — Codec robustness: permanent wedge on malformed input + no checksum validation + auth trailers break framing** (`codec.rs:35-49,83-99,199-230`; `lib.rs:6-7`): the carryover is never drained on error; received checksums are never verified (v3 checksum is unimplemented despite the lib.rs claim); with crypto auth the trailer bytes are misparsed as the next packet.
8. **MAJOR — DR/BDR election and interface FSM deviate from RFC 2328 §9.4.1** (`interface.rs:63-106,139-167`): no priority>0 eligibility, self excluded, no re-run-on-self-win, and the FSM can never transition to DR/Backup (every election outcome maps to DrOther).
9. **MAJOR — SPF is not RFC 2328 §16.1 complete**: no equal-cost multipath (single best distance, `spf.rs:115/129/164`), O(V·L) full-LSDB scans per vertex (`spf.rs:95-98,156-159`), no transit-network routes and no next-hop computation (`SpfRoute.next_hop` always `None`), which also breaks §16.4(c) forwarding-address cover for transit networks (`external.rs:319-327`).
10. **MAJOR — LSDB/install + exchange edge cases**: out-of-range sequence numbers accepted and corrupting the sequence space, no LSA checksum validation, older MaxAge instances purging newer entries (`lsdb.rs:66-98`), and `DbExchange` integer underflow panics for MTU < 52 plus unpaged LS-Requests and unvalidated DBD options (`exchange.rs:339,494,550-554,576`).

---

*Sources consulted: [RFC 2328](https://datatracker.ietf.org/doc/html/rfc2328), [RFC 5340](https://www.rfc-editor.org/rfc/rfc5340.txt), [RFC 5709](https://datatracker.ietf.org/doc/html/rfc5709), [RFC 7166](https://datatracker.ietf.org/doc/html/rfc7166), [RFC 3623](https://datatracker.ietf.org/doc/html/rfc3623), [FRR ospfd/ospf_packet.c](https://raw.githubusercontent.com/FRRouting/frr/master/ospfd/ospf_packet.c), [FRR ospf6d/ospf6_message.c](https://raw.githubusercontent.com/FRRouting/frr/master/ospf6d/ospf6_message.c), [FRR ospf6d/ospf6_proto.h](https://raw.githubusercontent.com/FRRouting/frr/master/ospf6d/ospf6_proto.h).*
