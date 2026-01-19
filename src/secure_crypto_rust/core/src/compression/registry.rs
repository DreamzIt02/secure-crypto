// ## src/compression/registry.rs

//! compression/registry.rs
//! Codec registry and factory functions.

use crate::compression::constants::{codec_ids};
use crate::compression::types::{Compressor, Decompressor, CompressionError};
use crate::compression::codecs::{auto, zstd, lz4, deflate};

pub struct CodecInfo {
    pub name: &'static str,
    pub supports_dict: bool,
    pub default_level: i32,
}

pub fn resolve(codec_id: u16) -> Result<CodecInfo, CompressionError> {
    match codec_id {
        x if x == codec_ids::AUTO =>
            Ok(CodecInfo { name: "auto", supports_dict: false, default_level: 0 }),
        x if x == codec_ids::ZSTD =>
            Ok(CodecInfo { name: "zstd", supports_dict: true, default_level: 6 }),
        x if x == codec_ids::LZ4 =>
            Ok(CodecInfo { name: "lz4", supports_dict: true, default_level: 0 }),
        x if x == codec_ids::DEFLATE =>
            Ok(CodecInfo { name: "deflate", supports_dict: false, default_level: 6 }),
        other => Err(CompressionError::UnsupportedCodec { codec_id: other }),
    }
}

pub fn create_compressor(codec_id: u16, level: Option<i32>, dict: Option<&[u8]>)
    -> Result<Box<dyn Compressor + Send>, CompressionError>
{
    match codec_id {
        x if x == codec_ids::AUTO => Ok(Box::new(auto::AutoCompressor::new())),
        x if x == codec_ids::ZSTD => zstd::ZstdCompressor::new(level.unwrap_or(6), dict),
        x if x == codec_ids::LZ4 => lz4::Lz4Compressor::new(level.unwrap_or(0), dict),
        x if x == codec_ids::DEFLATE => deflate::DeflateCompressor::new(level.unwrap_or(6)),
        other => Err(CompressionError::UnsupportedCodec { codec_id: other }),
    }
}

pub fn create_decompressor(codec_id: u16, dict: Option<&[u8]>)
    -> Result<Box<dyn Decompressor + Send>, CompressionError>
{
    match codec_id {
        x if x == codec_ids::AUTO => Ok(Box::new(auto::AutoDecompressor::new())),
        x if x == codec_ids::ZSTD => zstd::ZstdDecompressor::new(dict),
        x if x == codec_ids::LZ4 => lz4::Lz4Decompressor::new(dict),
        x if x == codec_ids::DEFLATE => deflate::DeflateDecompressor::new(),
        other => Err(CompressionError::UnsupportedCodec { codec_id: other }),
    }
}
