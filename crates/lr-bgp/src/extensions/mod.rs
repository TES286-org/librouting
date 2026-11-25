//! BGP extensions (RFC 4724 graceful restart, RFC 7911 AddPath, RFC 7313
//! enhanced route refresh, RFC 4893 4-byte AS, RFC 5549 extended next-hop,
//! RFC 9494 long-lived, RFC 5291 ORF, RFC 8654 Extended Message, RFC 9234
//! BGP Role, draft-walton-bgp-hostname-capability-02 FQDN,
//! draft-ietf-idr-bgp-bfd-strict-mode-19 BFD Strict-Mode,
//! draft-abraitis-bgp-version-capability-18 Software Version,
//! draft-ietf-idr-addpath-paths-limit-00 PATHS-LIMIT,
//! draft-ietf-idr-linklocal-capability-06 Link-Local Next Hop, and the
//! Exchange plane behind the `exchange-plane` feature).
//!
//! Most of the wire encoding for these features lives in the main
//! `path`/`capabilities` modules; this module groups doc-style type aliases
//! and small helpers.

pub mod addpath;
pub mod asn4;
pub mod bfd_strict_mode;
pub mod bgp_role;
pub mod enhanced_rr;
#[cfg(feature = "exchange-plane")]
pub mod exchange_plane;
pub mod extended_message;
pub mod extended_next_hop;
pub mod fqdn;
pub mod graceful_restart;
pub mod link_local_next_hop;
pub mod long_lived;
pub mod orf;
pub mod paths_limit;
pub mod software_version;
