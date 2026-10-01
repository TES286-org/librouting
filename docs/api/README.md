# librouting API guide

Read this page to find the page that covers the API you are calling.
The pages are written for embedders who use the library from Rust;
operators running the daemon should start at
[`../lr-cli.md`](../lr-cli.md) instead.

## The pages

| Page | Read it for |
| --- | --- |
| [`core.md`](core.md) | Addresses, codec traits, generic FSM, routes, timers |
| [`bgp.md`](bgp.md) | BGP codec, FSM, roles, best-path, extensions, BMP, MRT |
| [`ospf.md`](ospf.md) | OSPFv2/v3 LSAs, exchange, origination, areas, SR |
| [`babel.md`](babel.md) | Babel MAC authentication, egress next hops |
| [`policy.md`](policy.md) | Hook chain, safety net, `PolicySet`, damping |
| [`bfd.md`](bfd.md) | BFD session FSM, socket wiring |
| [`ldp-mpls.md`](ldp-mpls.md) | LDP engine, MPLS label codec, kernel LSP install |
| [`router.md`](router.md) | `RouterInstance`, `DefaultRouter`, pipes, introspection |
| [`compat-matrix.md`](compat-matrix.md) | One daemon knob per row, across every surface |

Each page opens with a signature-level example, then the knobs and
configuration surface, then its RFC citations. `cargo doc --workspace
--open` documents every other item.

## Error handling

Every wire codec implements the traits in `lr_core::codec`:

```rust
pub trait Encoder<M> {
    fn encode(&self, msg: &M, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError>;
}
pub trait Decoder<M> {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<M>, ParseError>;
}
pub trait Codec<M>: Encoder<M> + Decoder<M> {}
```

- `Ok(None)` from `decode` means the buffer does not hold a whole frame
  yet. Append more bytes and call again; nothing was consumed.
- `ParseError` carries `kind: ErrorKind`, a byte `offset`, a `context`
  label such as `"bgp.open.capability[3].value"`, and an optional
  `detail`. Match on `kind`: `Truncated`, `InvalidValue`, `BadLength`,
  `UnknownType`, `ChecksumMismatch` and so on.
- `EncodeError` is `BufferFull`, `InvalidValue(&'static str)` or
  `MissingContext(&'static str)`. `BufferFull` means the caller's slice
  was too small, not that the message is malformed.
- `lr_core::error` also defines `FsmError`, `ConfigError`, `PolicyError`
  and the FFI-facing `FfiError`.

The router's management surface is deliberately different.
`RouterInstance` and `DefaultRouter` return `Result<T, String>` from
`add_session`, `start_session`, `set_mrai`, `set_session_policy` and the
other setters. The `String` is an operator-readable message
(`"BGP session 7 not found"`), not a typed error, because the callers
are config parsers and management front ends; match on it only in tests.
Nothing on that surface carries a wire-level failure — a malformed
message travels to the peer as a NOTIFICATION.

Individual crates add their own error enums next to the API that raises
them: `lr_bgp::error::BgpError`, `lr_babel::BabelAuthError`,
`lr_ospf::gr` outcomes, `lr_osroute::gtsm::GtsmError`,
`lr_osroute::mpls_route::MplsRouteError`.

## Thread safety

- The hook traits `lr_policy::ImportHook`, `SelectionHook` and
  `ExportHook` are declared `Send + Sync`, and the router stores them as
  boxed trait objects. `DefaultRouter` owns nothing else that is not
  `Send + Sync`, so a router can be moved to another thread.
- Every mutating call takes `&mut self`, so one thread drives a router
  at a time. The daemon's ticker thread is that thread. Wrapping the
  router in an `Arc<Mutex<_>>` also works; the router does no locking of
  its own.
- `DefaultRouter::set_bmp_sink` takes
  `impl Fn(&[u8]) + Send + Sync + 'static` and runs the closure inline
  from `feed_input` and `tick`: it must not block.
- A session's protocol runtime (BGP peer FSM, OSPF neighbor FSM, Babel
  route table) is owned by the router and never shared between sessions.

## One codec per session

A decoder is stateful. It buffers the partial frame of the connection it
is decoding, so an instance belongs to exactly one session or transport:

- Keep one decoder per peer and feed it only that peer's bytes. Feeding
  one decoder interleaved bytes from two peers can complete a frame from
  one with bytes from the other.
- Encoders are stateless and may be shared. A codec used to decode a
  single self-contained stream (a pcap, a file) needs no sharing rule.
- `DefaultRouter` keeps one codec per session already. The rule matters
  when you drive a codec or an FSM yourself.

## Feature flags

Cargo features are additive. The table lists the ones that are off in a
default build, because those are what a snippet can silently miss.

| Crate | Feature | Enables |
| --- | --- | --- |
| `lr-bgp` | `long_lived` | RFC 9494 long-lived graceful restart |
| `lr-bgp` | `exchange-plane` | private exchange plane (experimental) |
| `lr-router` | `exchange-plane` | forwards to `lr-bgp/exchange-plane` |
| `lr-policy` | `damping` | RFC 2439 `DampingImportHook` |

Defaults worth knowing: `lr-bgp` enables `asn4`, `mp_bgp`, `addpath`,
`graceful_restart`, `enhanced_rr`, `extended_communities` and
`labeled_unicast`; `lr-router` enables `labeled_unicast`; `lr-policy`
and `lr-mrt` enable `bgp`; `lr-ospf` enables `v2`, `v3`, `nssa`, `te`,
`hmac_sha` and `graceful_restart`; `lr-babel` enables
`source_specific`. Each API page names the feature its snippets need.

## `no_std`

Four crates build without `std`: `lr-core`, `lr-mpls`, `lr-ldp` and
`lr-srv6`. Each gates `std` behind a default feature, so turn it off:

```toml
lr-core = { version = "<version>", default-features = false }
lr-mpls = { version = "<version>", default-features = false }
```

They still need `alloc`: the codec buffers are `Vec`-backed and the
timer queue is heap-based. `lr-core` says so itself — some helpers, the
timer queue among them, require `alloc`.

The other crates require `std`: `lr-bgp`, `lr-ospf`, `lr-babel`,
`lr-router`, `lr-policy`, `lr-rib`, `lr-bfd`, `lr-bmp`, `lr-mrt`,
`lr-damping` and `lr-osroute`.

## `RouterInstance` and `DefaultRouter`

`RouterInstance`, in `lr-router`, is the trait that owns the session
lifecycle: `add_session`, `start_session`, `feed_input`, `drain_output`,
`tick`, `poll_events`, `rib_snapshot`. The methods a host may not be
able to implement carry defaults — `babel_egress_nexthops` returns
`None`, `flush_rib_for_shutdown` and the `babel_*` setters do nothing —
so a mock or a host without a Babel runtime implements only what it
needs and the trait still works as `Box<dyn RouterInstance>`.

`DefaultRouter` is the concrete implementation. It owns the sessions,
Adj-RIB-In and Adj-RIB-Out, the Loc-RIB, the timer queue, the hook chain
and the policy state, and it is what the daemon, the FFI layer and the
examples construct.

Reach for the trait when you inject your own host; reach for
`DefaultRouter` when you want the whole pipeline.

## See also

- [`../tutorial.md`](../tutorial.md) — a first working program.
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — how the pieces fit.
- [`../examples/`](../examples/) — per-scenario walkthroughs.
- [`../RFC_MAP.md`](../RFC_MAP.md) — RFC-by-RFC coverage, by crate.
