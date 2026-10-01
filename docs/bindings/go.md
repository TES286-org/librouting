# Go binding guide

`bindings/lr-go` is a cgo wrapper over the C ABI. One `librouting.Router`
owns a router instance; sessions are `uint64` handles; the embedder feeds
and drains bytes per session. Read this if you are embedding the library
in a Go program and want the C handles managed for you.

The ABI underneath is documented in [`c.md`](c.md), and the design
rationale in [`../ffi_design.md`](../ffi_design.md).

Build the shared library once:

```sh
cargo build --release -p lr-ffi
```

## How the library is found

The package compiles against the header and links against the shared
library, both declared in its cgo preamble
([`librouting.go`](../../bindings/lr-go/librouting.go)):

```go
/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -llr_ffi

#include <stdlib.h>
#include "lr_ffi.h"
*/
import "C"
```

`CFLAGS` resolves the header relative to the package, so no include path
is needed. `LDFLAGS` says `-llr_ffi` without a directory, so the linker
and the loader need that directory supplied from outside. Set both:

```sh
export CGO_LDFLAGS="-L$PWD/target/release -llr_ffi"
export LD_LIBRARY_PATH="$PWD/target/release"   # macOS: DYLD_LIBRARY_PATH
```

There is no environment variable that makes the binding locate the
library by itself — unlike the Python binding, which has
`LIBROUTING_LIB`.

## A first program

Marked illustrative: it is a `package main` for a module that imports
the binding, so it does not live in this repository.

```go
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	lr "github.com/TES286-org/librouting/bindings/lr-go"
)

func main() {
	r, err := lr.NewRouter()
	if err != nil {
		panic(err)
	}
	// The native router is freed by a runtime finalizer.

	session, err := r.AddBGPSession(64512, 64513, 0x0A000001, 90, 0, true)
	if err != nil {
		panic(err)
	}
	if err := r.StartSession(session); err != nil {
		panic(err)
	}

	// Originate 203.0.113.0/24 with next-hop 192.0.2.1 (next-hop-self).
	var prefix = [4]byte{203, 0, 113, 0}
	var nextHop = [4]byte{192, 0, 2, 1}
	if err := r.OriginateV4(prefix, 24, &nextHop); err != nil {
		panic(err)
	}

	// Drain whatever the session wants on the wire and print it.
	out, err := r.DrainOutput(session)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, hex.EncodeToString(out))
}
```

## Error handling

Every fallible method returns an `error` as its last result. The binding
builds it from the C return code and the C-side last error, so the
message names the failing entry point:

```go
session, err := r.AddBGPSession(64512, 64513, 0x0A000001, 90, 0, true)
if err != nil {
    // e.g. "lr_router_add_bgp_session_ext: ... (rc=-3)"
    return fmt.Errorf("add bgp session: %w", err)
}
```

- **`librouting.LastError()` exposes the raw C string** if you need it
  outside an error value. It reads the thread-local last-error string and
  returns `"no error"` when the C side set none.
- **A `bool` result is not a failure.** `WithdrawV4`, `WithdrawV6`,
  `UninstallStaticV4`, `UninstallStaticV6` and `RequestRouteRefresh`
  return `(bool, error)`, where `false` with a nil error means the prefix
  was not locally originated (or the peer did not negotiate route
  refresh) — an idempotent no-op.
- **A count is not a failure.** `SoftReconfigInbound` returns
  `(int64, error)`, `RibLen` returns `(int64, error)` and
  `(*Damping).Decay` returns `(int, error)`. Test the `error`, not the
  number.
- **`ABIVersion()` returns the packed ABI version** of the linked
  library, for the startup check described in
  [`../ffi_design.md`](../ffi_design.md) §10.

## Resource management

Handles are freed by `runtime.SetFinalizer`, so a value that goes out of
scope eventually releases its native state. Two consequences:

- **`*Router` has no explicit release.** `NewRouter` installs the
  finalizer that calls `lr_router_destroy`; there is no `Close` method.
  A router therefore lives until the garbage collector runs, which is
  fine for a long-lived process and awkward for a test that creates many.
- **The other handles offer an explicit release** in addition to the
  finalizer: `(*RoaStore).Close`, `(*Route).Free`,
  `(*PrefixList).Free`, `(*RouteMap).Free`, `(*Resolver).Free`,
  `(*CompiledFilter).Free` and `(*Damping).Destroy`. Each is idempotent
  and cancels the finalizer.

Because the FFI destroy contract forbids destroying a handle while
another call is in flight
([`../ffi_design.md`](../ffi_design.md) §5), a finalizer that fires while
you are still using the router through another reference is a
use-after-free. Keep the `*Router` reachable for as long as any session
handle is in use.

## Running the tests

`bindings/lr-go/librouting_test.go` exercises the lifecycle — router,
sessions, the RFC 8212 posture, Add-Path, labelled origination, the ROA
store, damping, policy objects and the filter DSL — against the real
library. It is the fastest way to check an installation:

```sh
export CGO_LDFLAGS="-L$PWD/target/release -llr_ffi"
export LD_LIBRARY_PATH="$PWD/target/release"
cd bindings/lr-go && go test -v ./...
```

The `ffi-bindings` job of
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs exactly
that, after `cargo build --release -p lr-ffi`.

## API map

The exported surface mirrors the C ABI group by group.

| Area | Names |
| --- | --- |
| Router + sessions | `NewRouter`, `AddBGPSession`, `AddBGPSessionExt`, `StartSession` |
| OSPF / Babel | `AddOSPFSession`, `AddOSPFv3Session`, `AddOSPFSessionExt`, `AddBabelSession` |
| Data plane | `FeedInput`, `DrainOutput`, `Tick`, `PollEvents`, `Event` |
| Session knobs | `SetMPFamilies`, `SetExtendedNextHop`, `SetAddPath`, `SetAddPathMaxPaths`, `SetMRAI`, `SetLocalAddress` |
| RFC 8212 posture | `SetEbgpRequiresPolicy`, `SetEnforceFirstAs`, `SetSessionPolicy`, `SetDefaultIPv4Unicast` |
| Soft reconfiguration | `SetSoftReconfigInbound`, `SoftReconfigInbound` |
| Local routes | `OriginateV4`/`V6`, `OriginateLabeledV4`/`V6`, `WithdrawV4`/`V6`, `InstallStaticV4`/`V6`, `UninstallStaticV4`/`V6` |
| Redistribution | `AddRedistributionPipe`, `AddAggregate`, `RemoveAggregate`, `Protocol`, `MetricPolicy` |
| ROA | `NewRoaStore`, `RoaStore`, `AddROAEntry`, `SetROAValidate` |
| Damping | `SetDamping`, `DampingConfig`, `(*Damping).Decay` |
| Policy objects | `NewRouteV4`/`V6`, `NewPrefixList`, `NewRouteMap`, `NewResolver`, `Compile` |
| Codecs | `EncodeKeepalive`, `EncodeOpen`, `EncodeNotification`, `EncodeUpdateWithdrawV4`, `EncodeUpdateAnnounceV4`, `DecodeBGP`, `EncodeSRv6SRH`, `DecodeSRv6SRH` |
| Diagnostics | `LastError`, `ABIVersion`, `MplsPlatformLabels`, `RibLen`, `RibDump`, `SessionsDump` |
