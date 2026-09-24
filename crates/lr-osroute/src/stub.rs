//! Stub implementation of [`OsRouteTable`] for platforms without a kernel
//! routing table API. All operations return an error.

use crate::{OsRouteError, OsRouteTable};
use lr_core::addr::IpAddr;
use lr_core::addr::Prefix;

/// A no-op route table that rejects all operations. Useful for testing or
/// when the host platform doesn't support kernel route manipulation.
#[derive(Debug, Default, Clone)]
pub struct StubRouteTable;

impl StubRouteTable {
    pub fn new() -> Self {
        Self
    }

    /// Mirror of [`crate::linux::RtNetlink::connect`] so callers written
    /// against the Linux backend compile unchanged on other platforms (they
    /// get a runtime error instead).
    pub fn connect() -> Result<Self, OsRouteError> {
        Err(OsRouteError(
            "OS route table backend not available on this platform".to_string(),
        ))
    }
}

impl OsRouteTable for StubRouteTable {
    type Error = OsRouteError;
    fn add_route(
        &mut self,
        _prefix: Prefix,
        _next_hop: IpAddr,
        _if_index: u32,
    ) -> Result<(), Self::Error> {
        Err(OsRouteError(
            "stub: OS route table not available".to_string(),
        ))
    }
    fn add_blackhole_route(&mut self, _prefix: Prefix) -> Result<(), Self::Error> {
        Err(OsRouteError(
            "stub: OS route table not available".to_string(),
        ))
    }
    fn delete_route(&mut self, _prefix: Prefix) -> Result<(), Self::Error> {
        Err(OsRouteError(
            "stub: OS route table not available".to_string(),
        ))
    }
    fn list_routes(&mut self) -> Result<Vec<crate::KernelRoute>, Self::Error> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_rejects_add() {
        let mut s = StubRouteTable::new();
        let p: Prefix = "10.0.0.0/8".parse().unwrap();
        let gw: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(s.add_route(p, gw, 1).is_err());
    }

    #[test]
    fn stub_rejects_blackhole_add() {
        let mut s = StubRouteTable::new();
        let p: Prefix = "10.0.0.0/8".parse().unwrap();
        assert!(s.add_blackhole_route(p).is_err());
    }

    #[test]
    fn stub_returns_empty_list() {
        let mut s = StubRouteTable::new();
        assert!(s.list_routes().unwrap().is_empty());
    }
}
