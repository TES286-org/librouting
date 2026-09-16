# FFI design — `lr-ffi`

This document is the canonical reference for the librouting C ABI
design: the panic-barrier contract, the `lr_bytes_t` ownership model,
the cbindgen pipeline, the opaque-handle pattern, and why
OSPF/Babel/LDP sessions are not exposed at the FFI layer today.

It is the contributor-facing companion to
[`docs/bindings/c.md`](bindings/c.md) (the embedder-facing C guide),
[`docs/bindings/cpp.md`](bindings/cpp.md) (the C++ RAII wrapper) and
the generated header [`include/lr_ffi.h`](../include/lr_ffi.h). The
source of truth is [`crates/lr-ffi/src/`](../crates/lr-ffi/src/) —
this document explains *why* the source is shaped the way it is.

---

## 1. Layering

`lr-ffi` is a thin `extern "C"` wrapper over the Rust library
crates. It owns no protocol state itself — every entry point locks
the underlying `DefaultRouter` (or a dedicated handle) and delegates
to the library. The layering is:

```
+-------------------+
|  C / C++ / Go /   |
|  Python embedder  |
+---------+---------+
          | extern "C"
+---------v---------+
|     lr-ffi        |  <- this crate
| (panic barrier,   |
|  handle types,    |
|  cbindgen header) |
+---------+---------+
          | normal Rust calls
+---------v---------+
|  lr-router        |
|  lr-bgp / -ospf / |
|  -babel / -ldp    |
|  lr-policy        |
|  lr-core          |
+-------------------+
```

The crate is a `cdylib` + `staticlib` + `rlib` (see `Cargo.toml`):
the `cdylib` produces `liblr_ffi.so` / `lr_ffi.dll` / `liblr_ffi.dylib`
for dynamic linking; the `staticlib` produces `liblr_ffi.a` for static
linking; the `rlib` lets other Rust crates depend on the FFI types
without going through the C ABI.

---

## 2. The panic barrier

**Contract:** a Rust panic must never unwind across the C ABI.

C does not understand Rust's unwinding semantics. A panic that
unwinds into C frames is undefined behaviour in every calling
convention Rust supports today (`extern "C"`, `extern "C-unwind"`)
and has historically crashed embedders in production (the Go cgo
bridge in particular aborts the process on an unexpected unwind).

Every `extern "C"` entry point in `lr-ffi` wraps its body in
[`guarded`](../crates/lr-ffi/src/lib.rs) (`catch_unwind` +
`AssertUnwindSafe`). On a caught panic:

1. The thread-local last-error string is set to
   `"panic caught in FFI"` (see [`set_last_error`](../crates/lr-ffi/src/error.rs)).
2. The entry point returns its documented panic value:
   - `LR_ERR_PANIC` (`-4`, `LrError::Panic`) for integer returns.
   - `NULL` for pointer returns (e.g. `lr_router_new`).
   - `0` for `usize` / `u32` returns.
   - `()` for `void` returns.

The `guarded` helper is the single funnel: every entry point calls
`guarded(|| { ... }, fallback)`. The fallback is the panic value
documented on the entry point. A panic that originates *outside*
Rust (a C `longjmp`, a `SIGABRT`, a `pthread_cancel`) is not caught
by `catch_unwind` and leaves the handle unusable — treat the handle
as poisoned after any such event.

### What the barrier does NOT catch

- **Logic errors.** A `Result::Err` from the library is a normal
  return value, not a panic; the entry point maps it to the
  documented error code (typically `LR_ERR_OTHER` = `-6`) and sets
  the last-error string to the `Display` form of the error.
- **Deadlocks.** `std::sync::Mutex::lock` does not panic on
  contention; it blocks. A deadlock is a hang, not a panic, and the
  barrier does not interrupt it.
- **`abort` / `SIGFPE` / stack overflow.** `catch_unwind` catches
  unwinding panics only. An aborting panic (`panic = "abort"` in the
  release profile — see `Cargo.toml`) terminates the process; the
  barrier is irrelevant. The dev profile uses `panic = "unwind"` so
  the barrier is exercised by `cargo test`.

### The release-profile caveat

`Cargo.toml` sets `panic = "abort"` in the release profile. This
means **`catch_unwind` in release builds does not catch panics** —
they abort the process. The barrier is still present (so dev builds
and `cargo test` exercise it), but a release embedder should treat
any panic as a process crash, not a recoverable error.

This is the project's deliberate stance: a routing daemon that
panicked is in an unknown state, and silently continuing (the
dev-build behaviour) is more dangerous than crashing. The barrier
exists so `cargo test` can exercise the FFI surface without aborting
the test runner.

---

## 3. The `lr_bytes_t` ownership model

**Contract:** every `lr_bytes_t` returned from an `lr_*` function is
owned by the caller and must be freed via `lr_bytes_free`.

`lr_bytes_t` is a `#[repr(C)]` struct mirroring Rust's `Vec<u8>`
layout:

```c
typedef struct {
    uint8_t *ptr;
    size_t len;
    size_t cap;
} lr_bytes_t;
```

The FFI layer constructs it via
[`lr_bytes_t::from_vec`](../crates/lr-ffi/src/handle.rs), which
`std::mem::forget`s the `Vec` and hands the embedder the raw pointer,
length and capacity. The embedder owns the allocation until it calls
`lr_bytes_free`, which
[`reclaim_into_vec`](../crates/lr-ffi/src/handle.rs)s the bytes
(reconstructs the `Vec` from the raw parts) and drops it.

### Rules for the embedder

1. **Never `free` the `ptr` directly.** Always call `lr_bytes_free` on
   the `lr_bytes_t *` — it needs the `cap` field to release the
   allocation correctly. A bare `free(ptr)` leaks the `cap` slack and
   is a use-after-free on the next `lr_*` call.
2. **Never hold an `lr_bytes_t` across a `lr_router_destroy`.** The
   bytes are standalone (they do not reference the router), but the
   pattern is error-prone — free bytes as soon as you have copied
   their contents.
3. **NULL is a valid `lr_bytes_t *`.** `lr_bytes_free(NULL)`,
   `lr_bytes_len(NULL)` and `lr_bytes_ptr(NULL)` are all safe
   no-ops / zero returns. Every `lr_*` function that returns an
   `lr_bytes_t *` returns `NULL` on error — check before
   dereferencing.
4. **The pointer is valid until freed.** There is no borrow-checker
   across the FFI boundary; the embedder must not use the bytes
   after `lr_bytes_free`. Double-free is a use-after-free.

### The C++ RAII wrapper

`include/librouting.hpp` wraps `lr_bytes_t` in a `unique_ptr`-style
deleter so the bytes are freed automatically when the wrapper goes
out of scope. Go uses `runtime.SetFinalizer` for the same effect;
Python's `cffi` uses a `__del__` method. See the per-language guides.

---

## 4. The cbindgen pipeline

**Contract:** `include/lr_ffi.h` is generated from the Rust source by
`cbindgen` in `crates/lr-ffi/build.rs`. Never edit the header by
hand — the next `cargo build -p lr-ffi` overwrites it.

The pipeline:

1. `cargo build -p lr-ffi` runs `crates/lr-ffi/build.rs`.
2. `build.rs` constructs a `cbindgen::Config` with:
   - `language: C` (C++ consumers use the same header; the C++
     wrapper `include/librouting.hpp` includes it).
   - `include_guard: "LR_FFI_H"`.
   - `export.exclude: ["LrError", "lr_error_t"]` — cbindgen 0.29
     picks `LrError` up from the `lib.rs` re-export and emits a
     C23 fixed-width enum whose pre-C23 fallback (`typedef int32_t
     LrError`) conflicts with the enum definition. No exported entry
     point uses the enum (they return plain `int32_t`), so excluding
     it keeps the header portable.
   - `after_includes`: a block of `#define`s for protocol / metric /
     event-kind constants that cbindgen cannot derive from the Rust
     source (they are `pub const` values, not enum variants).
3. `cbindgen::generate_with_config(&crate_dir, cfg)` parses the Rust
   AST and emits the header to `include/lr_ffi.h`.
4. On `docs.rs` (`DOCS_RS` env var set), the header is not written —
   docs.rs builds do not need it and the write would fail (read-only
   filesystem).

### Why cbindgen and not hand-written headers?

- **Drift.** A hand-written header drifts from the Rust source the
  moment a signature changes. cbindgen regenerates the header on
  every build, so the header is always in sync with the source.
- **`#[repr(C)]` enforcement.** cbindgen refuses to emit types that
  are not `#[repr(C)]`, so the build fails if a new type is added
  without the right representation.
- **Documentation.** cbindgen copies Rust doc-comments into the
  header as `/** … */` blocks, so the C header is self-documenting.

### Why the `LrError` exclusion?

cbindgen 0.29 emits `LrError` as a C23 fixed-width enum
(`enum LrError : int32_t { … };`). Pre-C23 compilers (GCC < 13,
MSVC < 19.32) do not understand the `: int32_t` part and fall back
to `typedef int32_t LrError;` — which then conflicts with the enum
definition. Since no entry point uses the enum (they return plain
`int32_t`), excluding it from the header avoids the conflict. The
`LR_ERR_*` `#define`s in `after_includes` provide the values for C
consumers that want to name them.

---

## 5. The opaque-handle pattern

Every Rust object exposed to C is wrapped in an opaque handle — a
`#[repr(C)]` struct with a `_private: [u8; 0]` field. The C side
sees only `typedef struct OpaqueRouter OpaqueRouter;` (a forward
declaration); it can hold the pointer but never dereference it.

The pattern:

```rust
#[repr(C)]
pub struct OpaqueRouter {
    _private: [u8; 0],
}
pub type lr_router_t = *mut OpaqueRouter;

pub fn box_router(r: DefaultRouter) -> lr_router_t {
    let boxed: Box<Mutex<DefaultRouter>> = Box::new(Mutex::new(r));
    Box::into_raw(boxed) as lr_router_t
}

pub unsafe fn unbox_router(r: lr_router_t) {
    if r.is_null() { return; }
    let boxed: Box<Mutex<DefaultRouter>> = Box::from_raw(r as *mut _);
    drop(boxed);
}
```

### Why opaque?

1. **ABI stability.** The C side never sees the struct layout, so
   changing the Rust side (e.g. adding a field to `DefaultRouter`)
   does not break the C ABI. The handle is a pointer — its size and
   alignment never change.
2. **Encapsulation.** The C side cannot poke at the internals. Every
   mutation goes through an `lr_*` function that runs the panic
   barrier and the lock.

### The handle zoo

| Handle               | Rust type                          | Wrapper       |
| -------------------- | ---------------------------------- | ------------- |
| `lr_router_t`        | `Box<Mutex<DefaultRouter>>`        | `Mutex`       |
| `lr_roa_store_t`     | `Box<RoaStore>`                    | none (lock-free) |
| `lr_damping_t`       | `Box<Arc<Mutex<DampingTable>>>`    | `Arc<Mutex>`  |
| `lr_route_t`         | `Box<Route>`                       | none          |
| `lr_prefix_list_t`   | `Box<PrefixList>`                  | none          |
| `lr_route_map_t`     | `Box<RouteMap>`                    | none          |
| `lr_resolver_t`      | `Box<PolicySet>`                   | none          |
| `lr_filter_t`        | `Box<CompiledFilter>`              | none          |

The `lr_router_t` handle wraps a `Mutex<DefaultRouter>` because the
router is the shared state every entry point touches. The other
handles have no `Mutex` wrapper — `RoaStore` is already `Send + Sync`
(its readers are read-locked `Arc` clones), and the policy objects are
single-threaded by construction (the embedder builds them, hands
them to the router, and never touches them again).

### The destroy contract

`lr_router_destroy` (and every `lr_*_free` / `lr_*_destroy`) must:

1. **Not run concurrently with any other `lr_*` call on the same
   handle.** The `Mutex` is not reentrant; destroying while another
   thread is inside a call is a use-after-free.
2. **Not be called from a thread that currently holds the handle's
   lock.** A hook, sink or callback that calls `lr_router_destroy`
   from inside the lock deadlocks.
3. **Not be called twice.** Double-destroy is a double-free.

The contract is documented on
[`unbox_router`](../crates/lr-ffi/src/handle.rs); nothing in the FFI
layer enforces it. A future `lr_router_destroy_safe` that checks a
generation counter could relax this, but the current design trusts
the embedder to follow the rules (same as `free(3)`).

---

## 6. The non-reentrant lock hazard

Every `lr_router_*` entry point holds the `Mutex<DefaultRouter>` lock
for the entire call, including while running import/export hooks and
the BMP sink. `std::sync::Mutex` is **not reentrant**: a hook that
calls *any* `lr_router_*` function for the same router on the same
thread will deadlock on the second acquisition.

This is documented on
[`lock_router`](../crates/lr-ffi/src/handle.rs). The rule for
embedders writing hooks:

> Never call back into the FFI from code that runs under the router
> lock. Collect the work you need and call back only after the entry
> point returns.

The daemon's own hooks (the `GracefulShutdownExportHook`, the
`RoaValidateImportHook`, the damping hook) follow this rule — they
read the route's attributes through the `FilterContext` trait, never
through the FFI. The C-callback `lr_filter_context_t` (D5.2) lets an
embedder override individual fields without re-entering the FFI.

---

## 7. What is NOT exposed — and why

### OSPF / Babel sessions

`lr_router_add_ospf_session` / `lr_router_add_ospfv3_session` /
`lr_router_add_babel_session` ARE exposed (ROADMAP-v3 D5.1). They
construct a `SessionConfig` and hand it to the router — the same
path the daemon takes. The OSPF and Babel *engines* (the raw-socket
I/O loops) are NOT exposed: they are daemon-driven (the daemon owns
the sockets, the timers, the thread), and exposing them at the FFI
layer would advertise a capability the library does not have (an
embedder cannot run an OSPF engine without the daemon's I/O loop).

### LDP sessions

`lr_router_add_ldp_session` is deliberately absent (documented in
the D5.1 audit trail). `lr-router` has no LDP session kind — the
`LdpEngine` is daemon-driven (UDP/TCP 646 discovery + transport),
so an `lr_router_add_ldp_session` would advertise a capability the
library does not have. If the engine ever grows a router-level LDP
session model, the entry lands then.

### BMP / MRT / BFD

BMP (RFC 7854), MRT (RFC 6396) and BFD (RFC 5880) are codec/polling
crates — they parse and emit wire bytes, they do not run sessions.
The FFI exposes their codecs (`lr_bgp_decode_*`, `lr_bmp_decode_*`,
`lr_bfd_decode_*`) but not session lifecycle, because there is no
session lifecycle to expose.

### The exchange-plane prototype

The `--features exchange-plane` prototype (W6.3,
[`docs/research/EXCHANGE-PLANE.md`](research/EXCHANGE-PLANE.md)) is
explicitly experimental. Its wire format rides IANA experimental
code points pending an RFC 7120 early allocation. A 1.0 cut **does
not** freeze the exchange-plane surface, and the FFI does not expose
it — the prototype is daemon-only.

---

## 8. The error model

Every entry point returns a documented error code on failure:

| Code                  | Value | Meaning                                    |
| --------------------- | ----- | ------------------------------------------ |
| `LR_ERR_OK`           | `0`   | Success                                    |
| `LR_ERR_NULL`         | `-1`  | A required pointer argument was NULL       |
| `LR_ERR_INVALID_HANDLE` | `-2` | The handle did not unwrap to a valid Rust object |
| `LR_ERR_BAD_UTF8`     | `-3`  | A string argument was not valid UTF-8      |
| `LR_ERR_PANIC`        | `-4`  | The entry point's body panicked and the barrier caught it |
| `LR_ERR_ABI_MISMATCH` | `-5`  | The `lr_abi_version()` of the loaded library does not match the header the embedder compiled against |
| `LR_ERR_OTHER`        | `-6`  | A library error (mapped from `Result::Err`) |

The thread-local last-error string (set by `set_last_error`, read by
`lr_last_error`) carries the human-readable detail. The string is
valid until the next `lr_*` call on the same thread — copy it before
calling another entry point.

### The `LR_ERR_ABI_MISMATCH` check

`lr_abi_version()` returns `lr_core::ABI_VERSION` (a `u32` packed
from the major / minor / patch version). Embedders should call it
once at startup and compare against the `LR_ABI_VERSION` `#define`
in `include/lr_ffi.h`; a mismatch means the loaded `liblr_ffi.so`
was built from a different source than the header the embedder
compiled against. The 1.0 cut will assign the final value (see
[`docs/RELEASE-PLAN.md`](RELEASE-PLAN.md) §2.5).

---

## 9. Testing the FFI

The FFI surface is tested at three levels:

1. **Rust unit tests** (`crates/lr-ffi/src/*.rs` `#[cfg(test)]`
   modules) — exercise the Rust side of every entry point,
   including the panic barrier and the handle unwrap / lock
   paths. These run under `cargo test --workspace --all-features`
   on every platform.
2. **The C harness** (`tests/ffi/harness.c`) — a minimal C program
   that exercises the C ABI surface. Built and run in CI by
   `cc -Iinclude tests/ffi/harness.c -Ltarget/release -llr_ffi`.
   Sources MUST come before `-l` on the link line: Ubuntu's default
   `ld --as-needed` drops a shared library that appears before the
   objects that reference its symbols.
3. **The C++ harness** (`tests/ffi/harness.cpp`) — the same surface
   through the RAII wrapper (`include/librouting.hpp`). Verifies the
   `unique_ptr`-style deleter and the throwing-API path.
4. **The Go bindings test** (`bindings/lr-go/librouting_test.go`) —
   `go test -v ./...` with `CGO_LDFLAGS` pointing at the built
   `liblr_ffi.so`. Exercises the Go finalizer path.
5. **The Python bindings test** (`bindings/lr-python/tests/`) —
   `pytest` with `cffi` loading the shared library. Exercises the
   `__del__` path.

All four harnesses run in the `rust-tests` CI job (Linux) and the
`cross-platform` CI job (Linux + macOS + Windows). The interop
harnesses (BIRD / FRR) do NOT exercise the FFI — they run the daemon
binary, which is the daemon's own consumer of the library.

---

## 10. References

- Source of truth: [`crates/lr-ffi/src/`](../crates/lr-ffi/src/) —
  `lib.rs` (panic barrier), `handle.rs` (opaque types), `error.rs`
  (error model), `bytes.rs` (`lr_bytes_t`), `router.rs` /
  `sessions.rs` / `policy_objects.rs` / `filters.rs` / `roa_store.rs`
  / `srv6.rs` (entry points).
- Header generator: [`crates/lr-ffi/build.rs`](../crates/lr-ffi/build.rs)
  (cbindgen config).
- Generated header: [`include/lr_ffi.h`](../include/lr_ffi.h).
- C++ wrapper: [`include/librouting.hpp`](../include/librouting.hpp).
- Embedder guides: [`docs/bindings/c.md`](bindings/c.md),
  [`docs/bindings/cpp.md`](bindings/cpp.md),
  [`docs/bindings/go.md`](bindings/go.md),
  [`docs/bindings/python.md`](bindings/python.md).
- Release-plan ABI freeze: [`docs/RELEASE-PLAN.md`](RELEASE-PLAN.md) §1 / §2.5.
- cbindgen: <https://github.com/mozilla/cbindgen> (v0.29.4 per
  `Cargo.lock`).
