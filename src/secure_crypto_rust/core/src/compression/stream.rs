// compression/stream.rs
//! compression/stream.rs
//! Streaming helpers that respect chunk_size discipline.
use std::io::Read;

use crate::compression::constants::*;
use crate::compression::types::{Compressor, Decompressor, CompressionError};

#[inline]
/// Summary: Compress data read from R in chunk_size blocks, yielding compressed chunks.
/// - Respects MAX_CHUNK_SIZE sanity.
/// - Calls compressor.finish() after EOF to flush pending state.
pub fn compress_stream<R: Read>(
    mut r: R,
    chunk_size: usize,
    mut compressor: Box<dyn Compressor>
) -> impl Iterator<Item = Result<Vec<u8>, CompressionError>> {
    assert!(chunk_size > 0 && chunk_size <= MAX_CHUNK_SIZE);
    let mut buf = vec![0u8; chunk_size];
    let mut eof = false;

    std::iter::from_fn(move || {
        if eof {
            // Flush and end stream (once).
            let mut out = Vec::new();
            if let Err(e) = compressor.finish(&mut out) {
                return Some(Err(e));
            }
            if out.is_empty() {
                return None;
            } else {
                return Some(Ok(out));
            }
        }

        match r.read(&mut buf) {
            Ok(0) => {
                eof = true;
                // Next iteration will flush.
                return None;
            }
            Ok(n) => {
                let mut out = Vec::new();
                if let Err(e) = compressor.compress_chunk(&buf[..n], &mut out) {
                    return Some(Err(e));
                }
                Some(Ok(out))
            }
            Err(_) => Some(Err(CompressionError::StateError("read error".into()))),
        }
    })
}

#[inline]
/// Summary: Decompress data read from R in chunk_size blocks, yielding decompressed chunks.
/// - Respects MAX_CHUNK_SIZE sanity.
/// - Stateless with respect to frame boundaries (caller controls boundaries).
pub fn decompress_stream<R: Read>(
    mut r: R,
    chunk_size: usize,
    mut decompressor: Box<dyn Decompressor>
) -> impl Iterator<Item = Result<Vec<u8>, CompressionError>> {
    assert!(chunk_size > 0 && chunk_size <= MAX_CHUNK_SIZE);
    let mut buf = vec![0u8; chunk_size];

    std::iter::from_fn(move || {
        match r.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                let mut out = Vec::new();
                if let Err(e) = decompressor.decompress_chunk(&buf[..n], &mut out) {
                    return Some(Err(e));
                }
                Some(Ok(out))
            }
            Err(_) => Some(Err(CompressionError::StateError("read error".into()))),
        }
    })
}
