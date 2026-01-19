// ## src/compression/codecs/mod.rs

//! compression/codes/mod.rs
//! Streaming-safe compression and decompression.
//!
//! Industry notes:
//! - Deterministic per-chunk compression ensures reproducibility and parallel safety.
//! - Dictionaries must be explicitly declared and bound via header.dict_id.
//! - Registry resolves codec IDs to implementations.

pub mod auto;
pub mod deflate;
pub mod lz4;
pub mod zstd;

pub use auto::*;
pub use deflate::*;
pub use lz4::*;
pub use zstd::*;

// Convert enum ID → compressor struct.
// pub fn codec_struct_from_id_compressor(
//     id: CompressionCodec,
//     level: Option<i32>,
//     dict: Option<&[u8]>,
// ) -> Result<Box<dyn Compressor + Send>, CompressionError> {
//     match id {
//         CompressionCodec::Auto    => Ok(Box::new(AutoCompressor::new())),
//         CompressionCodec::Zstd    => ZstdCompressor::new(level.unwrap_or(DEFAULT_LEVEL_ZSTD), dict),
//         CompressionCodec::Lz4     => Lz4Compressor::new(level.unwrap_or(DEFAULT_LEVEL_LZ4), dict),
//         CompressionCodec::Deflate => DeflateCompressor::new(level.unwrap_or(DEFAULT_LEVEL_DEFLATE)),
//     }
// }

// Convert enum ID → decompressor struct.
// pub fn codec_struct_from_id_decompressor(
//     id: CompressionCodec,
//     dict: Option<&[u8]>,
// ) -> Result<Box<dyn Decompressor + Send>, CompressionError> {
//     match id {
//         CompressionCodec::Auto    => Ok(Box::new(AutoDecompressor::new())),
//         CompressionCodec::Zstd    => ZstdDecompressor::new(dict),
//         CompressionCodec::Lz4     => Lz4Decompressor::new(dict),
//         CompressionCodec::Deflate => DeflateDecompressor::new(),
//     }
// }
