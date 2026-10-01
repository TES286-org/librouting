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
`roa.state`, alongside the RFC 1997, RFC 4360 and RFC 8097 community
sets.

## RFCs

- RFC 4271 §9.1.2.15 — AS_PATH loop detection, the `reject_as_loop`
  check; §6.7 for NEXT_HOP validity; §4.2/§5.1.5 for the attributes the
  set actions write.
- RFC 2439 — route flap damping: the figure of merit, the suppress and
  reuse thresholds, and decay. RFC 7196 documents why the RFC 2439
  defaults are harmful in the default-free zone; damping is off unless
  an operator enables it.
- RFC 1997 communities, RFC 4360 extended communities, RFC 8097 large
  communities — what the community lists match.
- RFC 6811 — the ROA validation state the filter DSL reads.
- RFC 8326 — graceful-shutdown signalling, both directions.
- Route-map evaluation order and implicit deny are FRR behaviour, not an
  RFC.

## See also

- [`bgp.md`](bgp.md) — the sessions these hooks run in front of.
- [`router.md`](router.md) — `hooks_mut`, `set_safety_net` and events.
- [`core.md`](core.md) — `Route`, the value every hook receives.
