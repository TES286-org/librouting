module github.com/TES286-org/librouting/bindings/lr-go

go 1.21

// The lr-go package is a cgo wrapper around the librouting C ABI (lr_ffi.h).
// It expects liblr_ffi.so/.a/.dylib to be available on the linker path,
// typically installed by the parent Rust workspace's `cargo build --release -p lr-ffi`.
