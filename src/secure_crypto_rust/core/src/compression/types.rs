//! compression/constants.rs
//! Stable codec IDs and defaults, plus FFI-safe enum mapping.
use std::fmt;
use num_enum::TryFromPrimitive;

use crate::compression::constants::{codec_ids};
/// FFI-safe enum for compression codec identifiers.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum CompressionCodec {
    Auto    = codec_ids::AUTO,
    Zstd    = codec_ids::ZSTD,
    Lz4     = codec_ids::LZ4,
    Deflate = codec_ids::DEFLATE,
}

impl CompressionCodec {
    pub fn verify(raw: u16) -> Result<(), CodecError> {
        match raw {
            x if x == CompressionCodec::Auto as u16    => Ok(()),
            x if x == CompressionCodec::Zstd as u16    => Ok(()),
            x if x == CompressionCodec::Lz4 as u16     => Ok(()),
            x if x == CompressionCodec::Deflate as u16 => Ok(()),
            _ => Err(CodecError::UnknownCompression { raw }),
        }
    }
}

pub fn enum_name_or_hex<T>(raw: T::Primitive) -> String
where
    T: TryFromPrimitive + fmt::Debug,
    T::Primitive: fmt::LowerHex,
{
    match T::try_from_primitive(raw) {
        Ok(variant) => format!("{:?}", variant),
        Err(_) => format!("0x{:x}", raw),
    }
}

#[derive(Debug)]
pub enum CodecError {
    UnknownCompression { raw: u16 },
}

#[derive(Debug)]
pub enum CompressionError {
    UnsupportedCodec { codec_id: u16 },
    InvalidDictionary { dict_id: u32 },
    CodecInitFailed { codec: String, msg: String },
    CodecProcessFailed { codec: String, msg: String },
    ChunkTooLarge { have: usize, max: usize },
    StateError(String),
}

impl From<std::io::Error> for CompressionError {
    fn from(e: std::io::Error) -> Self {
        CompressionError::StateError(e.to_string())
    }
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CompressionError::*;
        match self {
            UnsupportedCodec { codec_id } =>
                write!(f, "unsupported compression codec: {}",
                       enum_name_or_hex::<CompressionCodec>(*codec_id)),
            InvalidDictionary { dict_id } =>
                write!(f, "invalid dictionary id: {}", dict_id),
            CodecInitFailed { codec, msg } =>
                write!(f, "codec {} init failed: {}", codec, msg),
            CodecProcessFailed { codec, msg } =>
                write!(f, "codec {} process failed: {}", codec, msg),
            ChunkTooLarge { have, max } =>
                write!(f, "chunk too large: {} > {}", have, max),
            StateError(msg) =>
                write!(f, "compression state error: {}", msg),
        }
    }
}

impl std::error::Error for CompressionError {}


// Require Send so trait objects can cross thread boundaries.
pub trait Compressor: Send {
    /// Compress a single chunk into out buffer.
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError>;
    /// Flush any pending state.
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), CompressionError>;
}

pub trait Decompressor: Send {
    /// Decompress a single chunk into out buffer.
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError>;
}
