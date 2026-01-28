// ## src/compression/codecs/auto.rs

//! codecs/auto.rs
//! Pass-through codec.

use crate::compression::{compute_checksum, types::{CompressionError, Compressor, Decompressor}, verify_checksum};

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
        let compressed = input;

        // Prefix with original plaintext length (u32, LE) — matches Zstd/LZ4-flex policy
        let orig_len = input.len() as u32;
        out.extend_from_slice(&orig_len.to_le_bytes());
        out.extend_from_slice(&compressed);

        // Append CRC32 of original plaintext
        let checksum = compute_checksum(&input, None);
        out.extend_from_slice(&checksum.to_le_bytes());

        Ok(())
    }
    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CompressionError> {
        Ok(())
    }
}

impl Decompressor for AutoDecompressor {
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        if input.len() < 8 {
            return Err(CompressionError::CodecProcessFailed {
                codec: "auto".into(),
                msg: "input too short for length+checksum prefix".into(),
            });
        }

        // Read original length prefix
        let orig_len = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;

        // compressed data is everything except the last 4 bytes
        let compressed = &input[4..input.len() - 4];
        let checksum_bytes = &input[input.len() - 4..];
        let expected_crc = u32::from_le_bytes(checksum_bytes.try_into().unwrap());

        let decompressed = compressed;

        // Optional sanity check: verify decoded size matches prefix
        if decompressed.len() != orig_len {
            return Err(CompressionError::CodecProcessFailed {
                codec: "auto".into(),
                msg: format!("decoded size {} != prefix {}", decompressed.len(), orig_len),
            });
        }

        // Verify checksum
        let actual_crc = compute_checksum(&decompressed, None);
        verify_checksum(expected_crc, actual_crc, "auto".into())?;
        
        out.extend_from_slice(&decompressed);
        Ok(())
    }
}
