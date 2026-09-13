//! Fuzz target: `BgpCodec::decode_slice` (ROADMAP-v3 D6.4).
//!
//! BGP is a TCP-streaming protocol; the codec receives arbitrary
//! bytes from a possibly-hostile peer and must either return
//! `Ok(Some(message))`, `Ok(None)` (incomplete frame) or
//! `Err(BgpError::Notification(...))` (a protocol error to be
//! surfaced to the peer as a NOTIFICATION). The contract is
//! that **the codec must never panic on arbitrary input** — a
//! panic here is a remote denial-of-service vulnerability.
//!
//! This fuzz target feeds arbitrary bytes to the codec and
//! asserts the codec contract holds: no panics, no aborts, no
//! undefined behaviour. A successful `cargo +nightly fuzz run
//! bgp_decode` over a corpus of millions of inputs is the
//! baseline for the protocol-correctness claim RFC 4271 §6
//! makes about error handling.
//!
//! Run locally:
//!
//! ```bash
//! cargo +nightly fuzz run bgp_decode -- -max_total_time=60
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use lr_bgp::codec::BgpCodec;

fuzz_target!(|data: &[u8]| {
    let mut codec = BgpCodec::new().with_asn4(true);
    // Result is intentionally discarded — the contract is that the
    // codec returns *some* Result, never panics. Whatever the
    // outcome (Ok / Err), it must be safe.
    let _ = codec.decode_slice(data);
});
