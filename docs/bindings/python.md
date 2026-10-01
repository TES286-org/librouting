# Python binding guide

`bindings/lr-python` uses cffi against the C ABI. `librouting.Router` is a
context manager that owns a router instance, sessions are integer
handles, and bytes flow through `feed_input` / `drain_output`. Read this
if you are embedding the library in a Python program.

The ABI underneath is documented in [`c.md`](c.md), and the design
rationale in [`../ffi_design.md`](../ffi_design.md).

Build the shared library once, then install the binding (editable mode is
enough for local work):

```sh
cargo build --release -p lr-ffi
pip install -e bindings/lr-python
```

## How the library is found

[`_ffi.py`](../../bindings/lr-python/src/librouting/_ffi.py) resolves the
shared library, then `dlopen`s that absolute path. It tries, in order:

1. **The `LIBROUTING_LIB` environment variable**, taken as the path to the
   library file itself, not to a directory:

   ```sh
   export LIBROUTING_LIB=/opt/librouting/liblr_ffi.so
   ```

2. **A parent-directory search.** Starting from the directory that holds
   `_ffi.py`, it walks up and looks for
   `<dir>/target/release/liblr_ffi.so`, `.dylib` then `.a`, and then the
   same names under `target/debug`. From an editable install inside this
   repository that walk reaches the workspace root, so a plain
   `cargo build --release -p lr-ffi` is enough.

If neither finds a file, importing raises `RuntimeError("librouting
shared library not found. Set LIBROUTING_LIB.")`. No `LD_LIBRARY_PATH`
is consulted — the loader is handed an absolute path, so the dynamic
linker's search path is irrelevant.

## A first program

```python
#!/usr/bin/env python3
"""librouting quickstart: originate a prefix and show the RIB."""

import librouting

with librouting.Router() as router:
    session = router.add_bgp_session(
        local_as=64512,
        peer_as=64513,
        local_bgp_id=0x0A000001,  # 10.0.0.1
    )
    router.set_local_address(session, "192.0.2.1")
    router.start_session(session)

    # Originate 203.0.113.0/24 with next-hop-self.
    router.originate_v4("203.0.113.0/24", next_hop="192.0.2.1")

    # The OPEN the session wants on the wire (send it to the peer).
    wire = router.drain_output(session)
    print("wire bytes:", wire.hex())

    # Timers are embedder-driven: pump tick() with a monotonic clock.
    router.tick(0)

    print(router.rib_dump())
```

Run it with `python3 quickstart.py`, with `LIBROUTING_LIB` set only if
the parent-directory search cannot find the library.

## Error handling

The C ABI returns `int32_t` and stores the reason in a thread-local
string. The binding translates both: it raises `librouting.LrError`,
whose message names the failing C function, the return code and the C
message:

```python
from librouting import LrError, last_error

try:
    router.originate_v4("203.0.113.0/24", next_hop="192.0.2.1")
except LrError as exc:
    # e.g. "lr_router_originate_v4 failed (rc=-3): ..."
    print(f"originate failed: {exc}")
    print(f"raw last error: {last_error()}")
```

`LrError` derives from `Exception` and adds nothing to it — there is no
error-code attribute, so parse the message or call `last_error()`
directly. `librouting.last_error()` returns the C-side string for the
current thread.

Two silent-success shapes to watch for, because they are not exceptions:

- **`Router.start_session`, `Router.feed_input` and `Router.tick` return
  `None`.** A non-zero C code raises, so there is nothing to check.
- **`originate_labeled_v4` / `_v6` and `withdraw_v4` / `_v6` return
  `None`**; `withdraw` treats "the prefix was not locally originated" as
  a no-op rather than an error. `Router.soft_reconfig_inbound` returns a
  route count. `RoaStore.validate` returns one of `ROA_VALID`,
  `ROA_NOT_FOUND` or `ROA_INVALID` and raises only on a genuine failure.

## Resource management

`Router` is a context manager: `__enter__` returns the router and
`__exit__` calls `lr_router_destroy`. It also defines `__del__`, so an
unreferenced router is destroyed at collection time. Use `with` so the
native state goes away at a known point.

`RoaStore` follows the same pattern and adds `__len__` and `validate`.
The policy objects in
[`policy.py`](../../bindings/lr-python/src/librouting/policy.py) —
`Route`, `PrefixList`, `RouteMap`, `Resolver`, `CompiledFilter` — hold
their own handles and are freed the same way.

The FFI destroy contract forbids destroying a handle while another call
is in flight ([`../ffi_design.md`](../ffi_design.md) §5), so keep the
router referenced while any session handle is live and let the `with`
block, not the collector, close it.

## Running the tests

`bindings/lr-python/tests/test_librouting.py` exercises the same surface
against the real library and doubles as a runnable script:

```sh
python3 -m pytest bindings/lr-python/tests -v
python3 bindings/lr-python/tests/test_librouting.py
```

The `ffi-bindings` job of
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs both,
after `cargo build --release -p lr-ffi`.

## API map

| Area | Names |
| --- | --- |
| Lifecycle | `Router`, `abi_version`, `last_error`, `LrError` |
| BGP sessions | `add_bgp_session`, `start_session`, `set_session_policy` |
| OSPF / Babel | `add_ospf_session`, `add_ospfv3_session`, `add_babel_session` |
| Data plane | `feed_input`, `drain_output`, `tick`, `poll_events` |
| Session knobs | `set_mp_families`, `set_extended_next_hop`, `set_add_path`, `set_add_path_max_paths`, `set_mrai`, `set_local_address` |
| RFC 8212 posture | `set_ebgp_requires_policy`, `set_enforce_first_as`, `set_default_ipv4_unicast`, `set_local_as_tolerance` |
| Soft reconfiguration | `set_soft_reconfig_inbound`, `soft_reconfig_inbound` |
| Local routes | `originate_v4`/`_v6`, `originate_labeled_v4`/`_v6`, `withdraw_v4`/`_v6`, `install_static_v4`/`_v6`, `uninstall_static_v4`/`_v6` |
| Redistribution | `add_redistribution_pipe`, `add_aggregate`, `remove_aggregate`, `PROTO_*`, `METRIC_*` |
| ROA | `RoaStore`, `add_roa_entry`, `set_roa_validate`, `ROA_*` |
| Damping | `set_damping`, `Damping` |
| Policy objects | `Route`, `PrefixList`, `RouteMap`, `Resolver`, `Match`, `Set`, `AsPathFilter`, `CommunityEntry` |
| Filter DSL | `compile_filter`, `CompiledFilter`, `FILTER_*` |
| Codecs | `codec.encode_keepalive`, `encode_open`, `encode_notification`, `encode_update_withdraw_v4`, `encode_update_announce_v4`, `decode_bgp`, `decode_ospf_v2`, `decode_babel`, `encode_srv6_srh`, `decode_srv6_srh` |
| Diagnostics | `rib_len`, `rib_dump`, `sessions_dump`, `mpls_platform_labels` |

`add_bgp_session` takes the full graceful-restart knob set:
`hold_time`, `keepalive`, `asn4`, `graceful_restart`, `gr_restart_time`
(RFC 4724), `long_lived_gr` and `llgr_stale_time` (RFC 9494), and
`llgr_max_stale_time`, the local cap on the peer's advertised stale time
(RFC 9494 §4.2). LLGR requires GR, so `long_lived_gr` with
`graceful_restart` off advertises nothing.
