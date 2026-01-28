//! codecs/lz4.rs
//! LZ4 block streaming compressor/decompressor (deterministic, dictionary optional).
use lz4_flex::block::{compress_prepend_size, decompress_size_prepended};

use crate::compression::{compute_checksum, types::{CompressionError, Compressor, Decompressor}, verify_checksum};

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

        // Append CRC32 of original input
        let checksum = compute_checksum(&input, None);
        out.extend_from_slice(&checksum.to_le_bytes());

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
        if input.len() < 4 {
            return Err(CompressionError::CodecProcessFailed {
                codec: "lz4".into(),
                msg: "missing checksum".into(),
            });
        }
        
        // Split compressed data and checksum
        let (compressed, checksum_bytes) = input.split_at(input.len() - 4);
        let expected_crc = u32::from_le_bytes(checksum_bytes.try_into().unwrap());

        let decompressed = decompress_size_prepended(compressed)
            .map_err(|e| CompressionError::CodecProcessFailed {
                codec: "lz4".into(),
                msg: e.to_string(),
            })?;
        
        // Verify checksum
        let actual_crc = compute_checksum(&decompressed, None);
        verify_checksum(expected_crc, actual_crc, "lz4".into())?;
        
        out.extend_from_slice(&decompressed);
        Ok(())
    }
}
