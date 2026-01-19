//! Deflate (zlib wrapper) via flate2 with streaming enc/dec.

use std::io::Read;
use std::io::Write;
use flate2::{Compression, write::ZlibEncoder, read::ZlibDecoder};

use crate::compression::types::{Compressor, Decompressor, CompressionError};

pub struct DeflateCompressor {
    level: Compression,
}

impl DeflateCompressor {
    pub fn new(level: i32) -> Result<Box<dyn Compressor + Send>, CompressionError> {
        let lvl = match level {
            0..=9 => Compression::new(level as u32),
            _ => Compression::default(),
        };
        Ok(Box::new(Self { level: lvl }))
    }
}

impl Compressor for DeflateCompressor {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        // Encode this chunk as its own zlib stream
        let mut enc = ZlibEncoder::new(Vec::new(), self.level);
        enc.write_all(input)
            .map_err(|e| CompressionError::CodecProcessFailed { codec: "deflate".into(), msg: e.to_string() })?;
        let compressed = enc.finish()
            .map_err(|e| CompressionError::CodecProcessFailed { codec: "deflate".into(), msg: e.to_string() })?;

        // Prefix with original plaintext length (u32, LE) — matches Zstd/LZ4-flex policy
        let orig_len = input.len() as u32;
        out.extend_from_slice(&orig_len.to_le_bytes());
        out.extend_from_slice(&compressed);
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CompressionError> {
        // No-op: every frame is finalized independently
        Ok(())
    }
}

pub struct DeflateDecompressor;

impl DeflateDecompressor {
    pub fn new() -> Result<Box<dyn Decompressor + Send>, CompressionError> {
        Ok(Box::new(Self))
    }
}

impl Decompressor for DeflateDecompressor {
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        if input.len() < 4 {
            return Err(CompressionError::CodecProcessFailed {
                codec: "deflate".into(),
                msg: "input too short for length prefix".into(),
            });
        }

        // Read original length prefix
        let orig_len = u32::from_le_bytes(input[0..4].try_into().unwrap()) as usize;
        let compressed = &input[4..];

        // Decode an entire zlib stream for this frame
        let mut dec = ZlibDecoder::new(compressed);
        let mut buf = Vec::new();
        dec.read_to_end(&mut buf)
            .map_err(|e| CompressionError::CodecProcessFailed { codec: "deflate".into(), msg: e.to_string() })?;

        // Optional sanity check: verify decoded size matches prefix
        if buf.len() != orig_len {
            return Err(CompressionError::CodecProcessFailed {
                codec: "deflate".into(),
                msg: format!("decoded size {} != prefix {}", buf.len(), orig_len),
            });
        }

        out.extend_from_slice(&buf);
        Ok(())
    }
}
