//! codecs/lz4.rs
//! LZ4 block streaming compressor/decompressor (deterministic, dictionary optional).
use lz4_flex::block::{compress_prepend_size, decompress_size_prepended};

use crate::compression::types::{Compressor, Decompressor, CompressionError};

/// LZ4 compressor using lz4 block API.
/// Note: lz4 does not expose streaming encoder with dictionary/level,
/// so we emulate streaming by compressing each chunk independently.
pub struct Lz4Compressor;

pub struct Lz4Decompressor;

impl Lz4Compressor {
    pub fn new(_level: i32, _dict: Option<&[u8]>) -> Result<Box<dyn Compressor + Send>, CompressionError> {
        // lz4 does not support level/dict in block mode.
        Ok(Box::new(Self))
    }
}

impl Compressor for Lz4Compressor {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        let compressed = compress_prepend_size(input);
        out.extend_from_slice(&compressed);
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CompressionError> {
        Ok(())
    }
}


impl Lz4Decompressor {
    pub fn new(_dict: Option<&[u8]>) -> Result<Box<dyn Decompressor + Send>, CompressionError> {
        Ok(Box::new(Self))
    }
}

impl Decompressor for Lz4Decompressor {
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        let decompressed = decompress_size_prepended(input)
            .map_err(|e| CompressionError::CodecProcessFailed {
                codec: "lz4".into(),
                msg: e.to_string(),
            })?;
        out.extend_from_slice(&decompressed);
        Ok(())
    }
}
