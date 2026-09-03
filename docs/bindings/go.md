# Go binding guide

The Go binding (`bindings/lr-go`) wraps the C ABI with cgo. One
`Router` owns a librouting router instance; sessions are handles
(`uint64`); the embedder feeds and drains bytes per session — the
same contract the Rust `DefaultRouter` exposes. Cleanup rides on
`runtime.SetFinalizer`, so a `Router` that goes out of scope frees
its native state; no explicit close call is needed.

Build the shared library once:

```sh
cargo build --release -p lr-ffi
```

A complete program — create a router, add an eBGP session, originate
a prefix, and dump the wire bytes (here to stderr as hex; point the
reader at your TCP peer instead):

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

Build and run (the linker must find the shared library at build and
run time):

```sh
export CGO_LDFLAGS="-L$PWD/target/release -llr_ffi"
export LD_LIBRARY_PATH="$PWD/target/release"
go run ./cmd/example
```

The binding test suite (`bindings/lr-go/librouting_test.go`) runs the
same lifecycle — router, session, policy knobs, labelled origination —
against the real library; `go test ./...` is the fastest way to check
an installation.

API map: `AddBGPSessionExt` (graceful restart knobs),
`SetMPFamilies` / `SetExtendedNextHop` / `SetAddPath` (per-session
families and RFC 7911), `SetEbgpRequiresPolicy` /
`SetEnforceFirstAs` / `SetSessionPolicy` (RFC 8212 posture),
`SetLocalAsTolerance` (FRR `allowas-in`), `SetSoftReconfigInbound` /
`SoftReconfigInbound` (FRR `soft-reconfiguration inbound`),
`OriginateLabeledV4`/`V6` (RFC 8277), `Tick` (drive timers with a
monotonic millisecond clock — call it from a loop or `time.Ticker`).
