// ## src/compression/registry.rs

//! compression/registry.rs
//! Codec registry and factory functions.

use crate::compression::{CodecOptions};
use crate::compression::types::{codec_ids, Compressor, Decompressor, CompressionError};
use crate::compression::codecs::{auto, deflate, lz4, zstd};

pub fn create_compressor(codec_id: u16, options: Option<CodecOptions>) 
    -> Result<Box<dyn Compressor + Send>, CompressionError>
{
    let opts: CodecOptions<'_> = options.unwrap_or(CodecOptions::default(None));
    match codec_id {
        x if x == codec_ids::AUTO => Ok(Box::new(auto::AutoCompressor::new())),
        x if x == codec_ids::DEFLATE => deflate::DeflateCompressor::new(opts.level.unwrap_or(6)),
        x if x == codec_ids::LZ4 => lz4::Lz4Compressor::new(opts.level.unwrap_or(0), opts.dict),
        x if x == codec_ids::ZSTD => zstd::ZstdCompressor::new(opts.level.unwrap_or(6), opts.dict),
        other => Err(CompressionError::UnsupportedCodec { codec_id: other }),
    }
}

pub fn create_decompressor(codec_id: u16, options: Option<CodecOptions>) 
    -> Result<Box<dyn Decompressor + Send>, CompressionError>
{
    let opts: CodecOptions<'_> = options.unwrap_or(CodecOptions::default(None));
    match codec_id {
        x if x == codec_ids::AUTO => Ok(Box::new(auto::AutoDecompressor::new())),
        x if x == codec_ids::DEFLATE => deflate::DeflateDecompressor::new(),
        x if x == codec_ids::LZ4 => lz4::Lz4Decompressor::new(opts.dict),
        x if x == codec_ids::ZSTD => zstd::ZstdDecompressor::new(opts.dict),
        other => Err(CompressionError::UnsupportedCodec { codec_id: other }),
    }
}
