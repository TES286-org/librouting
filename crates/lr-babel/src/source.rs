//! Source-specific routing prefix (RFC 9079). The `source` prefix is a
//! separate destination attribute used by source-specific routing.

use lr_core::addr::Prefix;

/// A source-specific route. The route is reachable only for traffic whose
/// source address is contained in `source`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourcePrefix {
    pub prefix: Prefix,
}

impl SourcePrefix {
    pub fn new(prefix: Prefix) -> Self {
        Self { prefix }
    }
}
