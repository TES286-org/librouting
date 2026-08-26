//! Wire codec traits.
//!
//! Every protocol codec implements [`Encoder`] + [`Decoder`] (and hence
//! [`Codec`]). The decoder is stateful (per-session framing carryover); the
//! encoder is stateless. The decoder returns `Ok(None)` when the buffer does
//! not yet contain a complete frame — the embedder must accumulate more bytes
//! and call again.
//!
//! Codecs never perform I/O. They consume [`crate::buf::ReadBuf`] /
//! [`crate::buf::WriteBuf`] which are slice-backed.

use crate::buf::{ReadBuf, WriteBuf};
use crate::error::{EncodeError, ParseError};

/// Encode a message into the output buffer. Returns the number of bytes
/// written on success.
pub trait Encoder<M> {
    fn encode(&self, msg: &M, out: &mut WriteBuf<'_>) -> Result<usize, EncodeError>;
}

/// Decode a single message from the input buffer. The buffer is advanced by
/// the bytes consumed (only on success). On [`ParseError`] of kind
/// [`crate::error::ErrorKind::Truncated`] the buffer is left untouched and
/// the caller should retry with more data.
pub trait Decoder<M> {
    fn decode(&mut self, src: &mut ReadBuf<'_>) -> Result<Option<M>, ParseError>;
}

/// Convenience trait combining encode + decode.
pub trait Codec<M>: Encoder<M> + Decoder<M> {}

impl<M, T> Codec<M> for T where T: Encoder<M> + Decoder<M> {}

/// A framed message with the number of bytes consumed from the input.
#[derive(Debug, Clone, Copy)]
pub struct Framed<M> {
    pub consumed: usize,
    pub message: M,
}
