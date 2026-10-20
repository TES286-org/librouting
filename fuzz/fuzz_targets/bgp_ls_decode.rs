//! Fuzz target: BGP-LS NLRI codec (`lr_bgp::path::bgp_ls::BgpLsNlri`).
//!
//! BGP-LS shares the BGP transport: any input bytes may arrive on a
//! session that negotiates the BGP-LS AFI/SAFI pair. The codec must
//! either return `Some((nlri, consumed))`, `None` (framing error), or
//! never panic — a panic here is a remote denial-of-service. The
//! contract mirrors [`bgp_decode`]: no panics, no aborts, no undefined
//! behaviour on arbitrary input.
//!
//! The fuzz target also covers both the plain (SAFI=71) and VPN
//! (SAFI=72) decode paths by toggling the `is_vpn` flag from the
//! first byte of the corpus input — this doubles the corpus coverage
//! on a single target rather than running two near-identical targets.
//!
//! Run locally:
//!
//! ```bash
//! cargo +nightly fuzz run bgp_ls_decode -- -max_total_time=60
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use lr_bgp::path::bgp_ls::BgpLsNlri;

fuzz_target!(|data: &[u8]| {
    // Need at least one byte for the VPN toggle plus four bytes for
    // the NLRI header. Anything shorter is a trivial reject path.
    if data.len() < 5 {
        let _ = BgpLsNlri::decode(false, data);
        return;
    }
    let is_vpn = (data[0] & 1) == 1;
    let body = &data[1..];
    if let Some((nlri, _consumed)) = BgpLsNlri::decode(is_vpn, body) {
        // Round-trip: the re-encoded bytes must match the input slice
        // for the portion the decoder consumed. This catches
        // byte-encoding drift on any sub-TLV the codec models.
        let mut out = vec![0u8; nlri.wire_len()];
        let mut w = lr_core::buf::WriteBuf::new(&mut out);
        if let Ok(n) = nlri.encode(&mut w) {
            if n <= body.len() {
                assert_eq!(&out[..n], &body[..n], "round-trip mismatch");
            }
        }
    }
});
