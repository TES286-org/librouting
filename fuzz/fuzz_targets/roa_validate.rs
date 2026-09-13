//! Fuzz target: `RoaTable::validate` (ROADMAP-v3 D6.4).
//!
//! RPKI-RTR (RFC 8210) is the future source of ROA data — the
//! daemon will receive arbitrary prefix / max_length / ASN
//! triples from the RPKI cache and feed them into the
//! `RoaTableBuilder`. A panic here is a cache-reconnect
//! denial-of-service.
//!
//! The contract is: `RoaTableBuilder::add` accepts arbitrary
//! `(prefix_str, max_length, asn)` triples and returns
//! `Ok(RoaEntry)` or `Err(RoaBuildError)` — never panics.
//! `RoaTable::validate` then accepts any `(Prefix, Option<Asn>)`
//! and returns a `RoaState` — never panics.
//!
//! The fuzzer exercises both paths: it synthesizes random
//! `(prefix_str, max_length, asn)` tuples, builds a small table,
//! and then queries `validate` with arbitrary probe prefixes.
//!
//! Run locally:
//!
//! ```bash
//! cargo +nightly fuzz run roa_validate -- -max_total_time=60
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use lr_bgp::roa::{RoaState, RoaTableBuilder};
use lr_core::addr::{Asn, Prefix};

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    // Build a small ROA table from the first half of the input:
    // each ROA needs 5 bytes (4 for the IPv4 address + 1 for the
    // max_length) plus 4 bytes for the ASN.
    let mut builder = RoaTableBuilder::new();
    let mut i = 0;
    while i + 9 <= data.len() / 2 {
        let addr = [data[i], data[i + 1], data[i + 2], data[i + 3]];
        let max_len = data[i + 4] % 33; // 0..=32 — valid IPv4 prefix length
        let asn = u32::from_be_bytes([
            data[i + 5],
            data[i + 6],
            data[i + 7],
            data[i + 8],
        ]);
        let prefix_str = format!("{}.{}.{}.{}/{}", addr[0], addr[1], addr[2], addr[3], max_len);
        // Builder enforces the RFC 6482 invariants — errors are
        // expected and ignored; the contract is "never panic".
        let _ = builder.add(&prefix_str, Some(max_len), asn);
        i += 9;
    }
    let table = builder.build();

    // Probe with a route prefix derived from the second half of
    // the input. The probe prefix length is forced into a valid
    // IPv4 range (0..=32) so the parse succeeds.
    if data.len() >= 10 {
        let p_addr = [data[data.len() - 4], data[data.len() - 3], data[data.len() - 2], data[data.len() - 1]];
        let p_len = (p_addr[0] & 0x1f) % 33;
        let prefix = Prefix::new_v4(p_addr, p_len);
        let asn = Asn(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
        let state = table.validate(&prefix, Some(asn));
        debug_assert!(matches!(
            state,
            RoaState::Valid | RoaState::Invalid | RoaState::NotFound
        ));
    }
});
