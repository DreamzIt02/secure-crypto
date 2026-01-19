// ## src/compression/codecs/auto.rs

//! codecs/auto.rs
//! Pass-through codec.

use crate::compression::types::{Compressor, Decompressor, CompressionError};

pub struct AutoCompressor;
pub struct AutoDecompressor;

impl AutoCompressor {
    pub fn new() -> Self { Self }
}
impl AutoDecompressor {
    pub fn new() -> Self { Self }
}

impl Compressor for AutoCompressor {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        out.extend_from_slice(input);
        Ok(())
    }
    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CompressionError> {
        Ok(())
    }
}

impl Decompressor for AutoDecompressor {
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        out.extend_from_slice(input);
        Ok(())
    }
}
