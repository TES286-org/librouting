# Policy API (`lr-policy`)

Read this page if you are injecting route policy into the router: custom
hooks, the protocol-invariant safety net, named route-maps, or RFC 2439
damping.

The `damping` snippet needs the `damping` feature on `lr-policy`. The
rest works in a default build (`std` and `bgp` are on by default).

## Example

Three hook traits sit at fixed points in the pipeline. All three are
`Send + Sync` and all three take `&self`, so a hook keeps its own
interior mutability if it needs state:

```rust
use lr_core::rib::Route;
use lr_policy::{
    ExportHook, HookChain, HookVerdict, ImportHook, SelectionHook,
};

struct FilterOnAsPath {
    my_as: u32,
}

impl ImportHook for FilterOnAsPath {
    fn on_import(&self, route: &mut Route) -> HookVerdict {
        if route.origin.peer == 0 {
            HookVerdict::Drop
        } else {
            HookVerdict::Keep // or HookVerdict::Replace(modified)
        }
    }
}

let mut chain = HookChain::new();
chain.import.push(Box::new(FilterOnAsPath { my_as: 64512 }));
let _ = &chain.selection;
let _ = &chain.export;
```

`HookChain` holds three `Vec<Box<dyn ...>>` slots — `import`,
`selection`, `export` — and the router runs them with `run_import`,
`run_selection`, `run_export` and `run_export_to(route, session_id)`.
`on_export_to` is the destination-aware export variant; its default
delegates to `on_export`, so a hook that does not care about the egress
session needs one method. The `run_*` helpers apply the verdicts: the
first `Drop` stops the chain, a `Replace` swaps the route in place.

The safety net checks protocol invariants before any hook runs. Each
check is a `SafetyConfig` toggle and all of them default to on:

```rust
use lr_core::addr::Asn;
use lr_policy::{SafetyConfig, SafetyNet};

let mut safety = SafetyNet::new(Asn(64512));
safety.cfg = SafetyConfig { reject_as_loop: true, ..Default::default() };
safety.check(&route, /* is_ebgp */ true)?; // Err(SafetyViolation)
```

`SafetyNet::new(local_as)` also takes `with_local_addr(addr)` for the
NEXT_HOP check. A violation carries the rule that fired; the router
applies it to decide whether to drop the route or count it.

Named policy objects and per-session route-maps go through `PolicySet`,
which binds user-facing names to prefix-lists, AS-path filters,
community lists and route-maps and implements `MatchResolver`, so a
route-map's `match` clauses resolve through the same set:

```rust
use lr_core::addr::Prefix;
use lr_policy::prefix_list::{PrefixList, PrefixListEntry};
use lr_policy::route_map::RouteMapEntry;
use lr_policy::{ListKind, PolicySet, SetAction};

let mut set = PolicySet::new();
let mut space = PrefixList::new();
space.push(PrefixListEntry {
    prefix: Prefix::new_v4([203, 0, 113, 0], 24),
    ge: 24,
    le: 32,
    permit: true,
});
set.add_prefix_list("customer-space", space);
set.push_route_map_entry(
    "to-customer",
    RouteMapEntry {
        matches: vec![set.match_condition(ListKind::Prefix, "customer-space").unwrap()],
        sets: vec![SetAction::SetLocalPref(200)],
        verdict: Some(true),
    },
);

// Attach to session 3, then take the hook pair.
set.bind_export(3, "to-customer");
set.validate()?; // catches a dangling name before the session comes up
let hooks = set.hooks();
// `router` is the DefaultRouter that owns this hook chain.
router.hooks_mut().import.push(Box::new(hooks.clone()));
router.hooks_mut().export.push(Box::new(hooks));
```

Evaluation follows FRR route-map semantics: entries are tried in order,
the first matching entry applies its `sets` and its verdict, and no match
means deny. A session with no binding passes through untouched, so a
peer without a route-map keeps its previous behaviour. `hooks()` consumes
the set and returns a `PolicyHooks` that implements both `ImportHook` and
`ExportHook`; it is cheap to clone because it shares one `Arc` internally.

Damping is an import hook over a shared table:

```rust
use lr_damping::{DampingConfig, DampingTable};
use lr_policy::hooks::DampingImportHook;
use std::sync::{Arc, Mutex};

let table = Arc::new(Mutex::new(DampingTable::new(DampingConfig::default())));
let hook = DampingImportHook::new(Arc::clone(&table));
router.hooks_mut().import.push(Box::new(hook));

// The router never decays on its own: drive it from your ticker.
let penalised: Vec<lr_core::addr::Prefix> = table.lock().unwrap().decay_all(0);
let _ = penalised;
```

`DampingImportHook::shared_table()` hands the same `Arc` back, which is
how a ticker thread reaches the table without taking ownership.
`DampingTable::on_withdraw` and `on_announce` update the figure of merit
and return whether the prefix is now suppressed; `decay_all` decays every
entry and returns the prefixes that left the suppressed state.

## Configuration

| Item | Default | Effect |
| --- | --- | --- |
| `SafetyConfig::reject_as_loop` | true | RFC 4271 §9.1.2.15 local-AS check |
| `SafetyConfig::reject_invalid_next_hop` | true | RFC 4271 §6.7 NEXT_HOP sanity |
| `SafetyConfig::reject_empty_as_path_ebgp` | false | Requires a prepend from eBGP peers |
| `SafetyConfig::reject_invalid_origin` | true | ORIGIN must be present and valid |
| `SafetyConfig::reject_excessive_as_loop` | true | Caps local-AS repeats (`max_as_path_loops`, 3) |
| `SafetyConfig::reject_oversized_as_path` | true | Caps AS_PATH length (`max_as_path_length`, 64) |
| `SafetyConfig::reject_martian_prefix` | true | Rejects the martian list |
| `SafetyConfig::reject_oversized_local_pref` | true | Caps LOCAL_PREF (`max_local_pref`) |
| `HookChain::import` / `selection` / `export` | empty | The hook slots, in pipeline order |
| `PolicySet::bind_import/_export(session, name)` | none | Per-session route-map |
| `HookVerdict::Replace(route)` | — | Swaps the route, does not stop the chain |

`lr-policy` also ships the two RFC 8326 graceful-shutdown hooks,
`GracefulShutdownExportHook` (sender side) and
`GracefulShutdownImportHook` (receiver side, rewriting LOCAL_PREF), for
embedders that want the RFC 8326 procedure without the daemon's
configuration layer.

`HookVerdict::Drop` stops the import chain immediately; `Keep` and
`Replace` let it continue. The filter DSL compiles to bytecode that runs
on the same route representation — see
[`../filter_dsl_grammar.md`](../filter_dsl_grammar.md) for the syntax and
[`../examples/filter_dsl_roa.md`](../examples/filter_dsl_roa.md) for a
worked ROA filter. The DSL exposes the RFC 6811 validation outcome as
`roa.state`, the RFC 1997, RFC 4360 and RFC 8092 community sets, the
RFC 4271 §5.1.6 / RFC 4456 §8 route-reflector loop-detection attributes
(`bgp.atomic_aggregate`, `bgp.originator_id`, `bgp.cluster_list`), the
RFC 9234 §3.1 OTC leak-detection attribute (`bgp.otc`), the RFC 7311
AIGP accumulated-metric attribute (`bgp.aigp`), the RFC 4271 §5.1.7
AGGREGATOR attribute (`bgp.aggregator.asn`, `bgp.aggregator.speaker`),
the RFC 6514 §5 PMSI Tunnel attribute (`bgp.pmsi_tunnel`), the RFC 2328
§16 / RFC 5340 §4.1 primary OSPF metric (`ospf.metric1`), the RFC 2328
§16.4 / RFC 5340 §4.8.5 type-2 external OSPF metric (`ospf.metric2`,
carried through the Loc-RIB on the private `LrOspfMetric2`
path-attribute tag the OSPF route computation attaches to type-2
external routes), the RFC 2328 §A.4.5 bullet h / RFC 3101 §2.3 /
RFC 5340 §A.4.7 T bit / RFC 8362 §3.6 External-Prefix sub-TLV 3
external route tag (`ospf.tag`, carried through the Loc-RIB on the
existing `Route::tag` field the OSPF route computation populates
from the LSA's tag for type-5 / type-7 externals), and —
behind the `exchange-plane` feature — the LRXP exchange-plane records
the route carries (`bgp.lrxp.*`, issue #81).

## RFCs

- RFC 4271 §9.1.2.15 — AS_PATH loop detection, the `reject_as_loop`
  check; §6.7 for NEXT_HOP validity; §4.2/§5.1.5 for the attributes the
  set actions write; §5.1.6 for the ATOMIC_AGGREGATE marker the filter
  DSL exposes as `bgp.atomic_aggregate`; §5.1.7 for the AGGREGATOR
  attribute the filter DSL exposes as `bgp.aggregator.asn` and
  `bgp.aggregator.speaker` (the `(AS, IP)` pair a speaker stamps onto a
  summarised route; the typed accessor
  `lr-bgp::path::PathAttributes::aggregator` decodes both the 2-byte and
  4-byte-AS wire forms, and ingress reconciles AS4_AGGREGATOR into the
  canonical type-7 tag).
- RFC 2439 — route flap damping: the figure of merit, the suppress and
  reuse thresholds, and decay. RFC 7196 documents why the RFC 2439
  defaults are harmful in the default-free zone; damping is off unless
  an operator enables it.
- RFC 1997 communities, RFC 4360 extended communities, RFC 8092 large
  communities — what the community lists match.
- RFC 4456 — ORIGINATOR_ID and CLUSTER_LIST loop-detection attributes
  the filter DSL exposes as `bgp.originator_id` and `bgp.cluster_list`.
- RFC 6811 — the ROA validation state the filter DSL reads.
- RFC 8326 — graceful-shutdown signalling, both directions.
- RFC 9234 — the OTC ("Only To Customer") attribute the filter DSL
  exposes as `bgp.otc`; the daemon's role logic (`lr-bgp::role::otc`)
  sets the attribute on ingress and gates it on egress, and the filter
  DSL surfaces the resulting value for leak-detection policies.
- RFC 7311 — the AIGP ("Accumulated IGP Metric") attribute the filter
  DSL exposes as `bgp.aigp`; the typed accessor
  (`lr-bgp::path::PathAttributes::aigp`) decodes the attribute's TLV
  stream (type-1 TLV = 8-byte accumulated metric, unknown TLVs
  preserved) and surfaces the accumulated metric for metric-comparison
  policies (`if bgp.aigp < 100 then accept;`). The daemon's best-path
  decision process (RFC 7311 §4) is a future follow-up.
- RFC 6514 §5 — the PMSI Tunnel attribute the filter DSL exposes as
  `bgp.pmsi_tunnel`; the typed accessor
  (`lr-bgp::path::PathAttributes::pmsi_tunnel`) decodes the
  attribute's value field (Flags + Tunnel Type + 3-octet MPLS Label
  + variable-length Tunnel Identifier; Tunnel Type 0 hard rule
  enforced, Tunnel Type 6 endpoint-width hard rule enforced, unknown
  types preserved verbatim, mirroring BIRD's
  `bgp_decode_pmsi_tunnel` default arm). The attribute surfaces as a
  read-only `bool` — `true` when the attribute is present, `false`
  when absent — mirroring BIRD's `EAF_TYPE_OPAQUE` +
  `T_ENUM_EMPTY` exposure so the canonical presence-probe idiom
  `if defined(bgp.pmsi_tunnel) then reject;` translates faithfully.
- RFC 2328 §16 / RFC 5340 §4.1 — the primary OSPF metric the filter
  DSL exposes as `ospf.metric1`; the typed accessor
  (`lr-policy::ospf::metric1`) reads `route.preference.metric` for
  OSPFv2 / OSPFv3 routes and returns `None` for non-OSPF routes
  (mirroring BIRD's eattr default for an unattached `ospf_metric1`
  reference, so the canonical idiom `if defined(ospf.metric1) &&
  ospf.metric1 > 100 then reject;` short-circuits on the `defined()`
  arm for a non-OSPF route). The attribute surfaces as a read-only
  `int` — `0` when the route is not OSPF — and the read pays one
  `match` on `route.protocol` plus one field read, cheaper than any
  `bgp.*` accessor that decodes a path attribute.
- RFC 2328 §16.4 / RFC 5340 §4.8.5 — the type-2 external OSPF metric
  the filter DSL exposes as `ospf.metric2`; the typed accessor
  (`lr-policy::ospf::metric2`) reads the private `LrOspfMetric2`
  path-attribute tag the OSPF route computation
  (`lr-router::instance::ospf_ops::ospf_recompute`) attaches to
  type-2 external routes and returns `None` for everything else
  (non-OSPF routes, OSPF intra-area / inter-area routes, and OSPF
  type-1 external routes — mirroring BIRD's eattr default for an
  unattached `ospf_metric2` reference, so the canonical idiom `if
  defined(ospf.metric2) && ospf.metric2 > 100 then reject;`
  short-circuits on the `defined()` arm for a non-type-2-external
  route). The attribute surfaces as a read-only `int` — `0` when
  the route is not a type-2 external — and the read pays one
  protocol-kind `match` plus one BTreeMap lookup plus one 4-byte
  read on `route.attributes`, cheaper than any `bgp.*` accessor
  that decodes a multi-byte TLV stream, more expensive than
  `ospf.metric1` (which reads a struct field, no lookup).
- RFC 2328 §A.4.5 bullet h / RFC 3101 §2.3 / RFC 5340 §A.4.7 T bit /
  RFC 8362 §3.6 External-Prefix sub-TLV 3 — the 32-bit external
  route tag the filter DSL exposes as `ospf.tag`; the typed
  accessor (`lr-policy::ospf::tag`) reads the existing
  `Route::tag` field the OSPF route computation
  (`lr-router::instance::ospf_ops::ospf_recompute`) populates
  from the LSA's tag for type-5 / type-7 externals and returns
  `None` for everything else (non-OSPF routes, OSPF intra-area /
  inter-area routes, and v3 externals without the T bit set —
  mirroring BIRD's eattr default for an unattached `ospf_tag`
  reference, so the canonical idiom `if defined(ospf.tag) &&
  ospf.tag == 3735928559 then accept;` short-circuits on the
  `defined()` arm for a route without a tag). The attribute
  surfaces as a read-only `int` — `0` when the route carries no
  tag — and the read pays one `match` on `route.protocol` plus
  one `Option<u32>` field read off `route.tag`, cheaper than
  `ospf.metric2` (which pays a BTreeMap lookup plus a 4-byte
  read) and the same shape as `ospf.metric1` (which reads a
  struct field, no lookup). The `defined(ospf.tag)` predicate
  consults `has_tag`: the v2 LSA body always carries a 4-byte
  tag (zero being well-formed), so a v2 external surfaces
  `Some(t)` even when the tag is zero; the v3 form's T bit
  distinguishes "no tag" from "tag of zero".
- RFC 2328 §A.4 `Advertising Router` field / RFC 5340 §A.4 the
  same field on every v3 LSA — the 32-bit OSPF Router-ID of the
  router that originated the LSA the route was computed from
  (the Router-LSA's advertising router for intra-area stub
  routes; the Network-LSA's advertising router — the DR — for
  intra-area transit routes; the summary-LSA's advertising
  router — the ABR — for inter-area routes; the AS-external-LSA's
  advertising router — the ASBR — for external routes) the filter
  DSL exposes as `ospf.router_id`; the typed accessor
  (`lr-policy::ospf::router_id`) reads the private
  `LrOspfRouterId` path-attribute tag the OSPF route computation
  (`lr-router::instance::ospf_ops::ospf_recompute`) attaches to
  every OSPFv2 / OSPFv3 route with a known originating LSA and
  returns `None` for everything else (non-OSPF routes, and OSPF
  routes whose computation could not identify the originating
  LSA's advertising router — a defensive fallback; the LSA
  header always carries the field per RFC 2328 §A.4 — mirroring
  BIRD's eattr default for an unattached `ospf_router_id`
  reference, so the canonical idiom `if defined(ospf.router_id) &&
  ospf.router_id == 3221225985 then accept;` (3221225985 =
  0xc000_0201 = 192.0.2.1) short-circuits on the `defined()` arm
  for a route without the attribute). The attribute surfaces as
  a read-only `int` — `0` when the route carries no OSPF
  router-id attribute — and the read pays one `match` on
  `route.protocol` plus one BTreeMap lookup plus one 4-byte read
  on `route.attributes`, the same shape as `ospf.metric2` (which
  reads a different private tag), more expensive than
  `ospf.metric1` / `ospf.tag` (which read struct fields, no
  lookup). The `defined(ospf.router_id)` predicate consults
  `has_router_id`: RFC 2328 §3.1.b recommends a non-zero
  Router-ID but does not forbid 0.0.0.0, so an OSPF route with
  Router-ID 0.0.0.0 surfaces `Some(0)` and `defined(ospf.router_id)`
  is true even when the Router-ID is zero. This closes the OSPF
  filter-attribute surface — every `ospf_*` filter attribute
  BIRD's 2 grammar declares now has a faithful lr-DSL spelling;
  the remaining unmappable per-route attributes are the Babel
  triplet `babel_metric` / `babel_router_id` / `babel_seqno`.
- Route-map evaluation order and implicit deny are FRR behaviour, not an
  RFC.

### Babel per-route attributes — `babel.metric` / `babel.seqno` / `babel.router_id`

The Babel per-route attribute surface mirrors BIRD's `babel_metric`,
`babel_router_id` and `babel_seqno` eattrs (RFC 8966 §3.2 — the
route's `(prefix, source-prefix, router-id, seqno)` four-tuple key
and the metric the decision process ranks against). The three
attributes surface through the filter DSL:

- `babel.metric` (RFC 8966 §3.2 + §3.4.3) — the value the Update
  TLV advertised, folded into `route.preference.metric` by the
  Babel route computation after applying the receiver-side link
  cost. Read-only `int`, `0` when the route is not Babel,
  mirroring BIRD's eattr default for an unattached `babel_metric`
  reference. `defined(babel.metric)` distinguishes "non-Babel
  route" from "Babel route with metric 0" via
  `lr-policy::babel::has_metric`. The read is one branch on
  `route.protocol` plus one field read (no allocation), so the
  peephole pass's `BranchFieldIntCmp` fast path fuses
  `babel.metric == N` / `> N` / etc. comparisons the same way it
  fuses `ospf.metric1` / `bgp.local_pref` / `bgp.med` /
  `bgp.otc`.
- `babel.seqno` (RFC 8966 §3.2 + §4.6.9) — the source's sequence
  number the feasibility machinery ranks against. Read-only `int`,
  `0` when the route is not Babel, mirroring BIRD's eattr default
  for an unattached `babel_seqno` reference. `defined(babel.seqno)`
  distinguishes "non-Babel route" from "Babel route with seqno 0"
  via `lr-policy::babel::has_seqno` (RFC 8966 §3.1 treats 0 as a
  valid sequence number). The seqno rides the private
  `LrBabelSeqno` path-attribute tag (code point 249 — stripped at
  BGP encode, the same shape `LrOspfMetric2` at 253 uses), and
  the Babel route computation
  (`lr-router::instance::babel::BabelRuntime::best_routes`)
  attaches the attribute for every published Babel route,
  populated from the Update TLV's seqno. The peephole pass's
  `BranchFieldIntCmp` fast path fuses `babel.seqno == N` / `> N` /
  etc. comparisons the same way it fuses `ospf.metric2` /
  `ospf.tag` / `ospf.router_id`.
- `babel.router_id` (RFC 8966 §3.2 + §4.6.8) — the 64-bit
  EUI-64-style value the route's source claims, carried in every
  Update TLV's Router-Id TLV. Read-only `int`, `0` when the route
  is not Babel, mirroring BIRD's eattr default for an unattached
  `babel_router_id` reference — though BIRD stores the value as
  an opaque 8-byte bytestring under `EAF_TYPE_OPAQUE`, lr's DSL
  exposes it as a 64-bit `Int` for the canonical
  `defined(babel.router_id)` idiom and for direct equality
  against the route's i64-form literal; a value with the high
  bit set (>= `0x8000_0000_0000_0000`) reads as a negative i64
  but round-trips losslessly for the comparison operator (the
  lexer parses i64 literals). `defined(babel.router_id)`
  distinguishes "no attribute" from "attribute present but zero"
  via `lr-policy::babel::has_router_id` (RFC 8966 §3.1 does not
  forbid Router-ID 0; the EUI-64 form discourages it but the
  protocol accepts any 64-bit value). The Router-ID rides the
  private `LrBabelRouterId` path-attribute tag (code point 250 —
  stripped at BGP encode, the same shape `LrOspfRouterId` at 252
  uses), and the Babel route computation
  (`lr-router::instance::babel::BabelRuntime::best_routes`)
  attaches the attribute for every published Babel route,
  populated from the Router-Id TLV's 64-bit value. The peephole
  pass's `BranchFieldIntCmp` fast path fuses
  `babel.router_id == N` / `> N` / etc. comparisons the same way
  it fuses `ospf.router_id` / `ospf.metric2` / `ospf.tag`.

The BIRD translator renames `babel_metric` to `babel.metric`,
`babel_seqno` to `babel.seqno` and `babel_router_id` to
`babel.router_id` (and removes the `babel_` prefix from
`UNMAPPABLE_PREFIXES`); with this release every BIRD per-route
filter attribute the BIRD 2 grammar declares under the
`ospf_*` / `babel_*` prefixes has a faithful lr-DSL spelling.

## See also

- [`bgp.md`](bgp.md) — the sessions these hooks run in front of.
- [`router.md`](router.md) — `hooks_mut`, `set_safety_net` and events.
- [`core.md`](core.md) — `Route`, the value every hook receives.
