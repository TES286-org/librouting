//! Non-Linux placeholder — the raw-socket transport exists only on
//! Linux in librouting. The configuration model stays portable;
//! embedders on other systems provide their own transport and feed
//! bytes through the router's session API (see docs/OS-INTEGRATION.md).

use super::{InterfaceV4Addr, InterfaceV6Addr, OspfTransportError};

pub fn interface_v4_addrs(_interface: &str) -> Result<Vec<InterfaceV4Addr>, OspfTransportError> {
    Err(OspfTransportError::Unsupported(
        "OSPF raw sockets exist only on Linux in librouting",
    ))
}

pub fn interface_v6_addrs(_interface: &str) -> Result<Vec<InterfaceV6Addr>, OspfTransportError> {
    Err(OspfTransportError::Unsupported(
        "OSPF raw sockets exist only on Linux in librouting",
    ))
}

pub fn ifindex_of(_interface: &str) -> Option<u32> {
    None
}

pub struct OspfV2Transport {
    _private: (),
}

impl OspfV2Transport {
    pub fn bind(_interface: &str, _multicast_loop: bool) -> Result<Self, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn set_nonblocking(&self, _on: bool) -> Result<(), OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn recv_from(
        &self,
        _buf: &mut [u8],
    ) -> Result<Option<(usize, std::net::Ipv4Addr)>, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn send_multicast(&self, _bytes: &[u8]) -> Result<usize, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn send_unicast(
        &self,
        _dst: core::net::Ipv4Addr,
        _bytes: &[u8],
    ) -> Result<usize, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn ifindex(&self) -> u32 {
        0
    }

    pub fn mtu(&self) -> Result<u16, super::OspfTransportError> {
        Err(super::OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }
}

/// Non-Linux placeholder for the OSPFv3 transport (see `imp_linux.rs`).
pub struct OspfV6Transport {
    _private: (),
}

impl OspfV6Transport {
    pub fn bind(_interface: &str, _multicast_loop: bool) -> Result<Self, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn set_nonblocking(&self, _on: bool) -> Result<(), OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn recv_from(
        &self,
        _buf: &mut [u8],
    ) -> Result<Option<(usize, std::net::Ipv6Addr)>, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn send_multicast(&self, _bytes: &[u8]) -> Result<usize, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn send_unicast(
        &self,
        _dst: core::net::Ipv6Addr,
        _bytes: &[u8],
    ) -> Result<usize, OspfTransportError> {
        Err(OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }

    pub fn ifindex(&self) -> u32 {
        0
    }

    pub fn mtu(&self) -> Result<u16, super::OspfTransportError> {
        Err(super::OspfTransportError::Unsupported(
            "OSPF raw sockets exist only on Linux in librouting",
        ))
    }
}
