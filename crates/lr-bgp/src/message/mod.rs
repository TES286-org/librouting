//! BGP message types.
//!
//! All five message types (RFC 4271 §4): OPEN, UPDATE, NOTIFICATION,
//! KEEPALIVE, ROUTE-REFRESH (RFC 2918).

pub mod keepalive;
pub mod notification;
pub mod open;
pub mod route_refresh;
pub mod update;

pub use keepalive::Keepalive;
pub use notification::Notification;
pub use open::{Open, OpenParam};
pub use route_refresh::RouteRefresh;
pub use update::Update;

/// BGP message header (RFC 4271 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgpHeader {
    /// Total message length (header + body), in [19, 4096].
    pub length: u16,
    /// Message type.
    pub kind: BgpMessageType,
}

impl BgpHeader {
    pub const LEN: usize = 19;
}

/// BGP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BgpMessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
}

impl BgpMessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Open,
            2 => Self::Update,
            3 => Self::Notification,
            4 => Self::Keepalive,
            5 => Self::RouteRefresh,
            _ => return None,
        })
    }
}

/// BGP message envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpMessage {
    Open(Open),
    Update(Update),
    Notification(Notification),
    Keepalive(Keepalive),
    RouteRefresh(RouteRefresh),
}

impl BgpMessage {
    pub fn kind(&self) -> BgpMessageType {
        match self {
            Self::Open(_) => BgpMessageType::Open,
            Self::Update(_) => BgpMessageType::Update,
            Self::Notification(_) => BgpMessageType::Notification,
            Self::Keepalive(_) => BgpMessageType::Keepalive,
            Self::RouteRefresh(_) => BgpMessageType::RouteRefresh,
        }
    }
}
