# Python binding guide

The Python binding (`bindings/lr-python`) uses cffi against the C
ABI. `librouting.Router` is a context manager that owns a native
router instance; sessions are integer handles; bytes flow through
`feed_input`/`drain_output` per session.

Build the shared library once, then install the binding (editable
mode is enough for local work):

```sh
cargo build --release -p lr-ffi
pip install -e bindings/lr-python
```

The loader looks for `liblr_ffi.so` under `target/release` (set
`LD_LIBRARY_PATH` if it is somewhere else).

A complete program — create a router, add an eBGP session, originate
a prefix, and print the Loc-RIB and the wire bytes:

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

Run it:

```sh
export LD_LIBRARY_PATH="$PWD/target/release"
python3 quickstart.py
```

The binding's test suite (`bindings/lr-python/tests/`) exercises the
same surface against the real library; `pytest bindings/lr-python/tests`
validates an installation.

API map: `add_bgp_session(...)` takes the full RFC 4724/9494 knob set
(`graceful_restart`, `gr_restart_time`, `long_lived_gr`,
`llgr_stale_time`); `set_ebgp_requires_policy`,
`set_enforce_first_as`, `set_session_policy` shape the RFC 8212
posture; `set_local_as_tolerance` is FRR `allowas-in`; `set_mp_families`
and `set_extended_next_hop` (RFC 5549) gate the multi-protocol
families; `originate_labeled_v4/v6` speak RFC 8277; `rib_dump` and
`sessions_dump` render the Loc-RIB and the session table.
