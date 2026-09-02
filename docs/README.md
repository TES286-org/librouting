# librouting documentation index

Start here. The documentation set is organized by audience: embedders
writing Rust, operators running the daemon, and contributors extending
the protocol crates.

## Orientation

| Document                             | Audience                | Contents                                                         |
| ------------------------------------ | ----------------------- | ---------------------------------------------------------------- |
| [`../README.md`](../README.md)       | everyone                | Project overview, crate map, quick-start daemon example          |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | contributors, embedders | Layering, RIB pipeline diagram, extension points, testing layout |
| [`STATUS.md`](STATUS.md)             | everyone                | Implemented-vs-missing gap analysis + the active roadmap         |
| [`RFC_MAP.md`](RFC_MAP.md)           | contributors            | RFC-by-RFC coverage table with crate paths                       |

## Embedding the library

| Document                                         | Contents                                                                                     |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| [`API.md`](API.md)                               | Public API tour, layer by layer, with code snippets                                          |
| [`scaffolding/README.md`](scaffolding/README.md) | Generating starter projects from `templates/` (analyzer, RR, BFD, OS integration)            |
| [`examples/`](examples/)                         | Per-scenario walkthroughs: route reflector, confederation, route server, BFD, OS integration |

## Running the daemon

| Document                   | Contents                                                             |
| -------------------------- | -------------------------------------------------------------------- |
| `templates/daemon.toml`    | Fully commented reference configuration (every key explained)        |
| [`PARITY.md`](PARITY.md)   | Behaviour knobs vs. BIRD 2 / FRR 10: RFC latitude, defaults, mapping |
| [`INTEROP.md`](INTEROP.md) | Interop lab against BIRD / FRR: what is verified, how to run locally |

## Platform porting

| Document                                 | Contents                                                                                                        |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| [`OS-INTEGRATION.md`](OS-INTEGRATION.md) | Kernel route-table backends (Linux rtnetlink, BSD route(4), Windows IP Helper), layout tables, porting a new OS |

## Research

| Document                                          | Contents                                                                                      |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| [`research/BGP-DEFECTS.md`](research/BGP-DEFECTS.md) | BGP's protocol-inherent defects: mechanisms, primary evidence, standard mitigations, lr status |
| [`research/EXCHANGE-PLANE.md`](research/EXCHANGE-PLANE.md) | Capability-negotiated private exchange plane design: feasibility hints, policy intent, provenance proofs |

## Standing rules

1. Every landed feature updates `STATUS.md` and `RFC_MAP.md` in the same
   series of commits (enforced at review).
2. `API.md` gains a section whenever a new public API surface appears.
3. Documents are English-only; keep lines under ~80 characters.
