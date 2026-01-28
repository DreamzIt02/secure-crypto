//! src/compression/codecs/zstd.rs
//!
//! Zstd streaming compressor/decompressor.
//!
//! Design notes:
//! - Wraps zstd streaming encoder/decoder with trait objects for uniform pipeline use.
//! - Errors are mapped into `CompressionError` variants with codec context.
//! - Compressor accumulates into an internal Vec; finish consumes encoder safely.
//! - Decompressor buffers input and reconstructs decoder per chunk for simplicity.

// #### Option 1: Use Zstd block API
// Zstd has a block compression API (`zstd::bulk::compress` / `decompress`) that produces standalone compressed blocks. Each block can be decompressed independently.
use std::io::{Cursor, BufReader};

use crate::compression::{compute_checksum, types::{CompressionError, Compressor, Decompressor}, verify_checksum};

/// Zstd streaming compressor.
/// - Holds an encoder writing into an internal Vec.
/// - Implements `Compressor` trait for chunked compression.
pub struct ZstdCompressor {
    _encoder: Option<zstd::stream::Encoder<'static, Vec<u8>>>, // wrapped in Option to allow finish()
}

/// Zstd streaming decompressor.
/// - Buffers compressed input.
/// - Reconstructs decoder per chunk for simplicity.
/// - Implements `Decompressor` trait.
pub struct ZstdDecompressor {
    _buffer: Vec<u8>,
    _decoder: Option<zstd::stream::Decoder<'static, BufReader<Cursor<Vec<u8>>>>>,
}

impl ZstdCompressor {
    /// Create a new Zstd compressor with given level and optional dictionary.
    ///
    /// # Errors
    /// - Returns `CompressionError::CodecInitFailed` if encoder initialization fails.
    pub fn new(level: i32, dict: Option<&[u8]>) -> Result<Box<dyn Compressor + Send>, CompressionError> {
        let encoder = if let Some(d) = dict {
            zstd::stream::Encoder::with_dictionary(Vec::new(), level, d)
                .map_err(|e| CompressionError::CodecInitFailed {
                    codec: "zstd".into(),
                    msg: e.to_string(),
                })?
        } else {
            zstd::stream::Encoder::new(Vec::new(), level)
                .map_err(|e| CompressionError::CodecInitFailed {
                    codec: "zstd".into(),
                    msg: e.to_string(),
                })?
        };
        Ok(Box::new(Self { _encoder: Some(encoder) }))
    }
}

impl Compressor for ZstdCompressor {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        // Compress the input
        let compressed = zstd::bulk::compress(input, 0)
            .map_err(|e| CompressionError::CodecProcessFailed { codec: "zstd".into(), msg: e.to_string() })?;

        // Prefix with original plaintext length (like lz4_flex does)
        let orig_len = input.len() as u32;
        out.extend_from_slice(&orig_len.to_le_bytes());
        out.extend_from_slice(&compressed);

        // Append CRC32 of original plaintext
        let checksum = compute_checksum(input, None);
        out.extend_from_slice(&checksum.to_le_bytes());
        
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CompressionError> {
        Ok(())
    }
}

impl ZstdDecompressor {
    pub fn new(dict: Option<&[u8]>) -> Result<Box<dyn Decompressor + Send>, CompressionError> {
        let cursor = Cursor::new(Vec::new());
        let result: Result<zstd::stream::Decoder<'_, BufReader<Cursor<Vec<u8>>>>, std::io::Error> =
            if let Some(d) = dict {
                zstd::stream::Decoder::with_dictionary(BufReader::new(cursor), d)
            } else {
                zstd::stream::Decoder::new(cursor)
            };

        let decoder = match result {
            Ok(dec) => Some(dec),
            Err(e) => {
                return Err(CompressionError::CodecInitFailed {
                    codec: "zstd".into(),
                    msg: e.to_string(),
                });
            }
        };

        Ok(Box::new(Self {
            _buffer: Vec::new(),
            _decoder: decoder,
        }))
    }
}

impl Decompressor for ZstdDecompressor {
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        if input.len() < 8 {
            return Err(CompressionError::CodecProcessFailed {
                codec: "zstd".into(),
                msg: "input too short for length+checksum".into(),
            });
        }

        // Read original length prefix
        let orig_len = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;

        // compressed data is everything except the last 4 bytes
        let compressed = &input[4..input.len() - 4];
        let checksum_bytes = &input[input.len() - 4..];
        let expected_crc = u32::from_le_bytes(checksum_bytes.try_into().unwrap());

        // Decompress with known output size
        let decompressed = zstd::bulk::decompress(compressed, orig_len)
            .map_err(|e| CompressionError::CodecProcessFailed { codec: "zstd".into(), msg: e.to_string() })?;

        // Optional sanity check: verify decoded size matches prefix
        if decompressed.len() != orig_len {
            return Err(CompressionError::CodecProcessFailed {
                codec: "zstd".into(),
                msg: format!("decoded size {} != prefix {}", decompressed.len(), orig_len),
            });
        }

        // Verify checksum
        let actual_crc = compute_checksum(&decompressed, None);
        verify_checksum(expected_crc, actual_crc, "zstd".into())?;

        out.extend_from_slice(&decompressed);
        Ok(())
    }
}
