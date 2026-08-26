//! Error model for librouting.
//!
//! All wire codecs return [`ParseError`]. Encoders return [`EncodeError`].
//! Library-level operations return [`Error`].
//!
//! The error carries enough context to map back to protocol-specific failures:
//! byte offset where parsing stopped, a string label of the field, and an
//! error kind.

use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Top-level library error.
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Parse(ParseError),
    Encode(EncodeError),
    Fsm(FsmError),
    Config(ConfigError),
    Policy(PolicyError),
    Ffi(FfiError),
    #[cfg(feature = "std")]
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "parse error: {}", e),
            Self::Encode(e) => write!(f, "encode error: {}", e),
            Self::Fsm(e) => write!(f, "fsm error: {}", e),
            Self::Config(e) => write!(f, "config error: {}", e),
            Self::Policy(e) => write!(f, "policy error: {}", e),
            Self::Ffi(e) => write!(f, "ffi error: {}", e),
            #[cfg(feature = "std")]
            Self::Other(s) => f.write_str(s),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::Encode(e) => Some(e),
            Self::Fsm(e) => Some(e),
            Self::Config(e) => Some(e),
            Self::Policy(e) => Some(e),
            Self::Ffi(e) => Some(e),
            Self::Other(_) => None,
        }
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<EncodeError> for Error {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl From<FsmError> for Error {
    fn from(e: FsmError) -> Self {
        Self::Fsm(e)
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<PolicyError> for Error {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

impl From<FfiError> for Error {
    fn from(e: FfiError) -> Self {
        Self::Ffi(e)
    }
}

/// Error kind for wire parsing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Buffer doesn't yet contain a complete frame; more bytes are needed.
    Truncated,
    /// A field carried an out-of-range or invalid value.
    InvalidValue,
    /// An unknown message type, attribute type, capability code, TLV type.
    UnknownType,
    /// A length field is inconsistent (e.g. declares a body shorter than the
    /// minimum required for the message type).
    BadLength,
    /// Checksum, MD5, or auth verification failed.
    ChecksumMismatch,
    /// A duplicate or conflicting attribute was found.
    Duplicate,
    /// An attribute is recognized but is not supported in this configuration.
    Unsupported,
    /// The message is well-formed but is not valid in the current FSM state.
    OutOfOrder,
    /// UTF-8 / string decoding failed.
    InvalidUtf8,
    /// Other.
    Other,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::InvalidValue => "invalid_value",
            Self::UnknownType => "unknown_type",
            Self::BadLength => "bad_length",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::Duplicate => "duplicate",
            Self::Unsupported => "unsupported",
            Self::OutOfOrder => "out_of_order",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A wire parsing error with byte offset and field label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub kind: ErrorKind,
    /// Offset in bytes from the start of the parsed frame.
    pub offset: usize,
    /// Short label, e.g. `"bgp.open.capability[3].value"`.
    pub context: &'static str,
    /// Optional human-readable detail.
    pub detail: Option<String>,
}

impl ParseError {
    pub const fn new(kind: ErrorKind, offset: usize, context: &'static str) -> Self {
        Self {
            kind,
            offset,
            context,
            detail: None,
        }
    }

    pub fn with_detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }

    pub const fn truncated(ctx: &'static str) -> Self {
        Self::new(ErrorKind::Truncated, 0, ctx)
    }

    pub const fn invalid(offset: usize, ctx: &'static str) -> Self {
        Self::new(ErrorKind::InvalidValue, offset, ctx)
    }

    pub const fn unknown_type(offset: usize, ctx: &'static str) -> Self {
        Self::new(ErrorKind::UnknownType, offset, ctx)
    }

    pub const fn bad_length(offset: usize, ctx: &'static str) -> Self {
        Self::new(ErrorKind::BadLength, offset, ctx)
    }

    pub const fn checksum(offset: usize, ctx: &'static str) -> Self {
        Self::new(ErrorKind::ChecksumMismatch, offset, ctx)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at offset {} in {}",
            self.kind, self.offset, self.context
        )?;
        if let Some(d) = &self.detail {
            write!(f, ": {}", d)?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Encoder error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Output buffer is too small.
    BufferFull,
    /// The value cannot be encoded (e.g. invalid combination).
    InvalidValue(&'static str),
    /// The value references a missing context (e.g. AS4 attribute but codec
    /// is in AS2 mode).
    MissingContext(&'static str),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferFull => f.write_str("output buffer is full"),
            Self::InvalidValue(s) => write!(f, "invalid value: {}", s),
            Self::MissingContext(s) => write!(f, "missing context: {}", s),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

/// Finite-state machine error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmError {
    /// Event received in a state that doesn't accept it.
    InvalidTransition {
        from: &'static str,
        event: &'static str,
    },
    /// Missing required state to dispatch.
    NotInitialized,
}

impl fmt::Display for FsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, event } => {
                write!(f, "invalid FSM transition from {} on {}", from, event)
            }
            Self::NotInitialized => f.write_str("FSM not initialized"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FsmError {}

/// Configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidValue(&'static str),
    Missing(String),
    Conflict(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(s) => write!(f, "invalid config value: {}", s),
            Self::Missing(s) => write!(f, "missing config: {}", s),
            Self::Conflict(s) => write!(f, "config conflict: {}", s),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConfigError {}

/// Policy evaluation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    NoSuchEntry(String),
    InvalidRegex(String),
    BadReference(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchEntry(s) => write!(f, "no such policy entry: {}", s),
            Self::InvalidRegex(s) => write!(f, "invalid regex: {}", s),
            Self::BadReference(s) => write!(f, "bad reference: {}", s),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PolicyError {}

/// FFI error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiError {
    NullPointer,
    InvalidHandle,
    BadUtf8,
    PanicCaught,
    AbiMismatch,
}

impl fmt::Display for FfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NullPointer => "null pointer",
            Self::InvalidHandle => "invalid handle",
            Self::BadUtf8 => "bad UTF-8",
            Self::PanicCaught => "panic caught in FFI",
            Self::AbiMismatch => "ABI version mismatch",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FfiError {}
