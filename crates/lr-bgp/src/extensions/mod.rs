//! BGP extensions (RFC 4724 graceful restart, RFC 7911 AddPath, RFC 7313
//! enhanced route refresh, RFC 4893 4-byte AS, RFC 8277 long-lived).
//!
//! Most of the wire encoding for these features lives in the main
//! `path`/`capabilities` modules; this module groups doc-style type aliases
//! and small helpers.

pub mod addpath;
pub mod asn4;
pub mod enhanced_rr;
pub mod graceful_restart;
pub mod long_lived;
