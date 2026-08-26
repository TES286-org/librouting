//! Connection abstraction — the embedder owns the transport. The router
//! talks to its sessions through a [`Connection`] that the embedder provides.

pub trait Connection {
    /// Push bytes from the peer to the session.
    fn push_input(&mut self, bytes: &[u8]);
    /// Drain bytes the session prepared for the peer.
    fn drain_output(&mut self) -> Vec<u8>;
}

#[derive(Default)]
pub struct MemoryConn {
    inbound: Vec<u8>,
    outbound: Vec<u8>,
}

impl MemoryConn {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make a paired pair of MemoryConns. Bytes drained from one are pushed
    /// into the other.
    pub fn pair() -> (Self, Self) {
        (Self::new(), Self::new())
    }
}

impl Connection for MemoryConn {
    fn push_input(&mut self, bytes: &[u8]) {
        self.inbound.extend_from_slice(bytes);
    }

    fn drain_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbound)
    }
}

impl MemoryConn {
    pub fn take_input(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.inbound)
    }

    pub fn put_output(&mut self, bytes: &[u8]) {
        self.outbound.extend_from_slice(bytes);
    }
}
