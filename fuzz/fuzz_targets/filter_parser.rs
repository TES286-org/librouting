//! Fuzz target: filter DSL parser (ROADMAP-v3 D6.4).
//!
//! The filter DSL is fed operator-authored configuration strings
//! — both the `[[filter]]` TOML table body and the `lrctl filter
//! compile <body>` API surface. A panic in the parser is a
//! config-reload denial-of-service: the operator saves a typo
//! in the config, the daemon reloads, and the panic kills the
//! routing process.
//!
//! The contract is: `compile(name, body)` returns `Ok(Filter)`
//! or `Err(ParseError)` for **any** input — never panics, never
//! aborts. The lexer is hand-rolled (no regex dependency), so
//! this target is the regression catch for off-by-one errors in
//! the lexer / Pratt parser state machines.
//!
//! Run locally:
//!
//! ```bash
//! cargo +nightly fuzz run filter_parser -- -max_total_time=60
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use lr_policy::filter::compile;

fuzz_target!(|data: &[u8]| {
    // The parser takes &str — convert from arbitrary bytes via
    // the lossy UTF-8 path so the fuzzer can exercise every byte
    // pattern including invalid UTF-8 (which must not panic the
    // parser either).
    let body = String::from_utf8_lossy(data);
    let _ = compile("fuzz", &body);
});
