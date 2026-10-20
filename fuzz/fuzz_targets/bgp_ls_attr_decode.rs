//! Fuzz target: BGP-LS Attribute TLV codec
//! (`lr_bgp::path::bgp_ls_attr::BgpLsAttr`).
//!
//! The BGP-LS Attribute (RFC 7752 §3.3, BGP path attribute type 29)
//! carries a TLV stream alongside a BGP-LS NLRI. Any bytes may
//! arrive on a session that negotiated the BGP-LS AFI/SAFI pair, so
//! the codec must either return `Ok`, return `Err(ParseError)`, or
//! never panic — a panic here is a remote denial-of-service. The
//! contract mirrors [`bgp_ls_decode`]: no panics, no aborts, no
//! undefined behaviour on arbitrary input.
//!
//! The target round-trips every successfully-decoded attribute: the
//! re-encoded bytes must match the input slice for the portion the
//! decoder consumed. This catches byte-encoding drift on any TLV
//! the codec models — the same contract the NLRI codec enforces.
//!
//! Run locally:
//!
//! ```bash
//! cargo +nightly fuzz run bgp_ls_attr_decode -- -max_total_time=60
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use lr_bgp::path::bgp_ls_attr::BgpLsAttr;

fuzz_target!(|data: &[u8]| {
    if let Ok(attr) = BgpLsAttr::decode(data) {
        // Round-trip: the re-encoded bytes must match the input
        // slice. This catches byte-encoding drift on any TLV the
        // codec models (well-known or Unknown-passthrough).
        if let Ok(out) = attr.encode() {
            // The decoded attribute's encode produces exactly the
            // value bytes (no header). The decoder consumed the
            // whole input (it walks TLVs until the buffer is
            // exhausted and returns ParseError on truncation), so
            // the re-encoded bytes must equal the input.
            assert_eq!(out, data, "round-trip mismatch");
        }
    }
});
