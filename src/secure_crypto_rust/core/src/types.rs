use std::io;
use crate::{
    compression::CompressionError, 
    crypto::{AadError, CryptoError, NonceError}, 
    headers::HeaderError, 
    stream_v2::{framing::FrameError, segment_worker::SegmentWorkerError, segmenting::types::SegmentError}
};


/// Unified stream error covering I/O, frame, crypto, compression, nonce, and generic validation.
/// - Ergonomic `From<T>` impls enable `?` across the pipeline.
/// - Messages aim to be stable and contextual for telemetry and logs.
#[derive(Debug)]
pub enum StreamError {
    /// I/O error (wrapped as string to avoid OS-specific types at FFI boundary).
    Io(io::Error),

    /// Aad-level error (validation or parse).
    Aad(AadError),

    /// Frame-level error (validation or parse).
    Header(HeaderError),

    /// Segment-level error (validation or parse).
    SegmentWorker(SegmentWorkerError),

    /// Segment-level error (validation or parse).
    Segment(SegmentError),

    /// Frame-level error (validation or parse).
    Frame(FrameError),

    /// Cryptographic error (AEAD, key/nonce policy).
    Crypto(CryptoError),

    /// Compression/decompression error.
    Compression(CompressionError),

    /// Nonce derivation error (policy or calculation failure).
    Nonce(NonceError),


    /// Pipeline error for pipelining Segment
    PipelineError(&'static str),

    /// Generic high-level validation with a descriptive message.
    Validation(String),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Io(e) => write!(f, "I/O error: {}", e),
            StreamError::PipelineError(msg) => write!(f, "pipeline error: {}", msg),
            
            StreamError::Aad(e) => write!(f, "aad error: {}", e),
            StreamError::Header(e) => write!(f, "header error: {}", e),
            StreamError::SegmentWorker(e) => write!(f, "segment worker error: {}", e),
            StreamError::Segment(e) => write!(f, "segment error: {}", e),
            StreamError::Frame(e) => write!(f, "frame error: {}", e),
            StreamError::Crypto(e) => write!(f, "crypto error: {}", e),
            StreamError::Compression(e) => write!(f, "compression error: {}", e),
            StreamError::Nonce(e) => write!(f, "nonce error: {}", e),

            StreamError::Validation(msg) => write!(f, "validation error: {}", msg),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<io::Error> for StreamError {
    fn from(e: io::Error) -> Self {
        // Treat I/O during parse as validation of external input
        StreamError::Io(e)
    }
}
