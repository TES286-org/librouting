//! BGP error codes per RFC 4271 §4.5 and RFC 4486 (Cease subcodes).
//!
//! These map directly to the wire values carried in NOTIFICATION messages.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BgpErrorCode {
    /// RFC 4271 §6.1 — Message Header Error
    Header = 1,
    /// RFC 4271 §6.2 — OPEN Message Error
    Open = 2,
    /// RFC 4271 §6.3 — UPDATE Message Error
    Update = 3,
    /// RFC 4271 §6.4 — Hold Timer Expired
    HoldTimerExpired = 4,
    /// RFC 4271 §6.5 — Finite State Machine Error
    FsmError = 5,
    /// RFC 4271 §6.6 — Cease / RFC 4486 subcodes
    Cease = 6,
    /// RFC 2918 — Route Refresh
    RouteRefresh = 7,
}

impl BgpErrorCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Header,
            2 => Self::Open,
            3 => Self::Update,
            4 => Self::HoldTimerExpired,
            5 => Self::FsmError,
            6 => Self::Cease,
            7 => Self::RouteRefresh,
            _ => return None,
        })
    }
}

impl fmt::Display for BgpErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Header => "Message Header Error",
            Self::Open => "OPEN Message Error",
            Self::Update => "UPDATE Message Error",
            Self::HoldTimerExpired => "Hold Timer Expired",
            Self::FsmError => "Finite State Machine Error",
            Self::Cease => "Cease",
            Self::RouteRefresh => "Route Refresh",
        })
    }
}

/// OPEN subcodes (RFC 4271 §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BgpOpenErrorSubcode {
    UnsupportedVersion = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParam = 4,
    AuthenticationFailure = 5,
    UnacceptableHoldTime = 6,
    UnsupportedCapability = 7,
    /// RFC 9205 — Bad OPEN message length.
    BadOpenLength = 8,
}

impl BgpOpenErrorSubcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::UnsupportedVersion,
            2 => Self::BadPeerAs,
            3 => Self::BadBgpIdentifier,
            4 => Self::UnsupportedOptionalParam,
            5 => Self::AuthenticationFailure,
            6 => Self::UnacceptableHoldTime,
            7 => Self::UnsupportedCapability,
            8 => Self::BadOpenLength,
            _ => return None,
        })
    }
}

/// UPDATE subcodes (RFC 4271 §6.3 + RFC 7606 revised handling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BgpUpdateErrorSubcode {
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    /// Deprecated by RFC 7606 §6.
    AttributeDiscontinuedDeprecated = 7,
    InvalidAsPath = 8,
    InvalidNextHop = 9,
    OptionalAttributeError = 10,
    InvalidNetworkField = 11,
    MalformedAsPath = 12,
}

impl BgpUpdateErrorSubcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::MalformedAttributeList,
            2 => Self::UnrecognizedWellKnownAttribute,
            3 => Self::MissingWellKnownAttribute,
            4 => Self::AttributeFlagsError,
            5 => Self::AttributeLengthError,
            6 => Self::InvalidOriginAttribute,
            7 => Self::AttributeDiscontinuedDeprecated,
            8 => Self::InvalidAsPath,
            9 => Self::InvalidNextHop,
            10 => Self::OptionalAttributeError,
            11 => Self::InvalidNetworkField,
            12 => Self::MalformedAsPath,
            _ => return None,
        })
    }
}

/// Header subcodes (RFC 4271 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BgpHeaderErrorSubcode {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
}

impl BgpHeaderErrorSubcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::ConnectionNotSynchronized,
            2 => Self::BadMessageLength,
            3 => Self::BadMessageType,
            _ => return None,
        })
    }
}

/// Cease subcodes (RFC 4486).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BgpCeaseSubcode {
    MaximumPrefixes = 1,
    AdministrativeShutdown = 2,
    PeerDeconfigured = 3,
    AdministrativeReset = 4,
    ConnectionRejected = 5,
    OtherConfigurationChange = 6,
    ConnectionCollision = 7,
    OutOfResources = 8,
    /// RFC 8533 — Long-Lived Graceful Restart, peer rejected LLGR.
    HardReset = 9,
}

impl BgpCeaseSubcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::MaximumPrefixes,
            2 => Self::AdministrativeShutdown,
            3 => Self::PeerDeconfigured,
            4 => Self::AdministrativeReset,
            5 => Self::ConnectionRejected,
            6 => Self::OtherConfigurationChange,
            7 => Self::ConnectionCollision,
            8 => Self::OutOfResources,
            9 => Self::HardReset,
            _ => return None,
        })
    }
}

/// A parsed NOTIFICATION message (RFC 4271 §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpNotification {
    pub error_code: u8,
    pub error_subcode: u8,
    /// Optional data (variable-length, often NULL for compactness).
    pub data: Vec<u8>,
}

impl BgpNotification {
    pub fn new(error_code: u8, error_subcode: u8, data: Vec<u8>) -> Self {
        Self {
            error_code,
            error_subcode,
            data,
        }
    }

    pub fn from_code(code: BgpErrorCode, subcode: u8, data: Vec<u8>) -> Self {
        Self::new(code as u8, subcode, data)
    }

    pub fn decode_error(&self) -> Option<(BgpErrorCode, &'static str)> {
        let code = BgpErrorCode::from_u8(self.error_code)?;
        let sub = match code {
            BgpErrorCode::Header => {
                BgpHeaderErrorSubcode::from_u8(self.error_subcode).map(|_| "header subcode")
            }
            BgpErrorCode::Open => {
                BgpOpenErrorSubcode::from_u8(self.error_subcode).map(|_| "open subcode")
            }
            BgpErrorCode::Update => {
                BgpUpdateErrorSubcode::from_u8(self.error_subcode).map(|_| "update subcode")
            }
            BgpErrorCode::Cease => {
                BgpCeaseSubcode::from_u8(self.error_subcode).map(|_| "cease subcode")
            }
            _ => None,
        };
        sub.map(|s| (code, s))
    }
}

/// BGP error kind used by codec/FSM internal results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpError {
    /// Wire parse failed; raise the contained NOTIFICATION to the peer.
    Notification(BgpNotification),
    /// Wire parse failed due to truncation; wait for more bytes.
    Truncated,
    /// Wire parse failed for a non-protocol reason (codec bug).
    Codec(String),
}
