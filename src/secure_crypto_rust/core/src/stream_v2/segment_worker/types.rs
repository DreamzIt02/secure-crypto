use std::fmt;
use std::convert::{From};
use bytes::Bytes;

use crate::crypto::{CryptoError, DigestAlg, DigestError, KEY_LEN_32};
use crate::headers::types::HeaderV1;
use crate::stream_v2::framing::{FrameError};
use crate::stream_v2::segmenting::SegmentHeader;
use crate::stream_v2::segmenting::types::SegmentFlags;
use crate::telemetry::counters::TelemetryCounters;
use crate::stream_v2::frame_worker::{FrameWorkerError};

/// Industry-standard frame sizes for parallel processing
pub const ALLOWED_FRAME_SIZES: &[usize] = &[
    4 * 1024,    // 4 KiB   - Maximum parallelization
    8 * 1024,    // 8 KiB   - Good balance
    16 * 1024,   // 16 KiB  - TLS record size (common) ✅ RECOMMENDED
    32 * 1024,   // 32 KiB  - Network packet friendly
    64 * 1024,   // 64 KiB  - Larger frames, less overhead
];

pub const DEFAULT_FRAME_SIZE: Option<usize> = None; // Auto-calculate
pub const MIN_FRAME_SIZE: usize = 4 * 1024;      // 4 KiB
pub const MAX_FRAME_SIZE: usize = 64 * 1024;     // 64 KiB

/// Frame size mapping table (precomputed for common segment sizes)
pub const FRAME_SIZE_TABLE: &[(usize, usize)] = &[
    // (segment_size, optimal_frame_size)
    (16 * 1024,    4 * 1024),   // 16 KiB segment → 4 KiB frames (4 frames)
    (32 * 1024,    8 * 1024),   // 32 KiB segment → 8 KiB frames (4 frames)
    (64 * 1024,    16 * 1024),  // 64 KiB segment → 16 KiB frames (4 frames)
    (128 * 1024,   16 * 1024),  // 128 KiB segment → 16 KiB frames (8 frames)
    (256 * 1024,   16 * 1024),  // 256 KiB segment → 16 KiB frames (16 frames)
    (1024 * 1024,  32 * 1024),  // 1 MiB segment → 32 KiB frames (32 frames)
    (2048 * 1024,  64 * 1024),  // 2 MiB segment → 64 KiB frames (32 frames)
    (4096 * 1024,  64 * 1024),  // 4 MiB segment → 64 KiB frames (64 frames)
];

/// `SegmentInput` is the “raw” form: just plaintext frames.
/// Input from reader stage (plaintext)
#[derive(Debug, Clone)]
pub struct EncryptSegmentInput {
    pub segment_index: u64,  // u64 matches our frame header type
    pub plaintext: Bytes, // 🔥 zero-copy shared
    pub flags: SegmentFlags, // 🔥 final segment, or other flags bit input from pipeline
    pub compressed_len: u32, // Calculate in caller after compress, before sending to the worker
}

/// Output of encryption
#[derive(Debug)]
pub struct EncryptedSegment {
    pub header: SegmentHeader,
    pub wire: Bytes, // 🔥 contiguous encoded frames
    pub telemetry: TelemetryCounters,
}

#[derive(Debug)]
pub struct DecryptSegmentInput {
    pub header: SegmentHeader,
    pub wire: Bytes, // 🔥 shared, sliceable
}

// Convert EncryptedSegment → DecryptSegmentInput
impl From<EncryptedSegment> for DecryptSegmentInput {
    fn from(seg: EncryptedSegment) -> Self {
        DecryptSegmentInput {
            header: seg.header,
            wire: seg.wire,
        }
    }
}

/// Output of decryption
#[derive(Debug)]
pub struct DecryptedSegment {
    pub header: SegmentHeader,
    pub frames: Vec<Bytes>, // plaintext frames
    pub telemetry: TelemetryCounters,
}

/// Immutable crypto context shared across workers
#[derive(Debug, Clone)]
pub struct SegmentCryptoContext {
    pub header: HeaderV1,
    pub session_key: [u8; KEY_LEN_32],
    pub digest_alg: DigestAlg,
    pub worker_count: usize,
    pub segment_size: usize,  // Our "chunk_size" from header: HeaderV1,
    pub frame_size: usize,    // Calculated
}

impl SegmentCryptoContext {
    pub fn new(
        header: HeaderV1,
        session_key: &[u8],
        digest_alg: DigestAlg,
        worker_count: usize,
        // segment_size: usize,  // Our "chunk_size" from header: HeaderV1,
        // frame_size: Option<usize>, // None = auto-calculate
    ) -> Result<Self, SegmentWorkerError> {
        //
        // Validate segment size in HeaderV1
        let segment_size = header.chunk_size as usize;

        if worker_count < 1 {
            return Err(SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerMissing));
        }

        if session_key.len() != KEY_LEN_32 {
            return Err(SegmentWorkerError::CryptoError(CryptoError::InvalidKeyLen { expected: KEY_LEN_32, actual: session_key.len() }));
        }

        let mut arr = [0u8; KEY_LEN_32];
        arr.copy_from_slice(session_key);

        // Auto-calculate optimal frame size
        // Calculate or validate frame size
        let frame_size = get_frame_size(segment_size);
        
        Ok(Self {
            header,
            session_key: arr,
            digest_alg,
            worker_count,
            segment_size,
            frame_size,
        })
    }
}

#[derive(Debug)]
pub enum SegmentWorkerError {
    InvalidSegment(String),
    CheckpointError(String),
    CheckpointRestoreFailed(String),
    MissingDigestFrame,
    MissingTerminatorFrame,

    FrameWorkerError(FrameWorkerError),
    DigestError(DigestError),
    FramingError(FrameError),
    CryptoError(CryptoError),
}
// #[derive(Debug, Error)]
// pub enum SegmentWorkerError {
    // #[error("Frame worker disconnected unexpectedly")]
    // FrameWorkerDisconnected,
    
    // #[error("Frame encryption failed: {0}")]
    // FrameEncryptionFailed(#[from] FrameWorkerError),
    
    // #[error("Frame decryption failed: {0}")]
    // FrameDecryptionFailed(FrameWorkerError),
    
    // #[error("Segment digest mismatch - data corruption or tampering detected")]
    // DigestMismatch(#[from] DigestError),
    
    // #[error("Segment framing error: {0}")]
    // FramingError(#[from] FrameError),
    
    // #[error("Invalid segment structure: {0}")]
    // InvalidSegment(String),
    
    // #[error("Checkpoint persistence failed: {0}")]
    // CheckpointError(String),
    
    // #[error("Digest frame decode failed")]
    // DigestFrameInvalid,
    
    // #[error("Missing mandatory digest frame")]
    // MissingDigestFrame,
    
    // #[error("Failed to restore checkpoint state")]
    // CheckpointRestoreFailed,
// }

impl fmt::Display for SegmentWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SegmentWorkerError::InvalidSegment(msg) =>
                write!(f, "invalid segment: {}", msg),
            SegmentWorkerError::CheckpointError(msg) =>
                write!(f, "checkpoint persistence failed: {}", msg),
            SegmentWorkerError::CheckpointRestoreFailed(msg) =>
                write!(f, "checkpoint restore failed: {}", msg),
            SegmentWorkerError::MissingDigestFrame =>
                write!(f, "invalid segment: {}", "Missing mandatory digest frame"),
            SegmentWorkerError::MissingTerminatorFrame =>
                write!(f, "invalid segment: {}", "Missing mandatory terminator frame"),

            SegmentWorkerError::FrameWorkerError(e) =>
                write!(f, "frame worker error: {}", e),
            SegmentWorkerError::DigestError(e) =>
                write!(f, "digest error: {}", e),
            SegmentWorkerError::FramingError(e) =>
                write!(f, "framing error: {}", e),
            SegmentWorkerError::CryptoError(e) =>
                write!(f, "crypto error: {}", e),
        }
    }
}

impl std::error::Error for SegmentWorkerError {}

impl From<DigestError> for SegmentWorkerError {
    fn from(e: DigestError) -> Self {
        SegmentWorkerError::DigestError(e)
    }
}
impl From<FrameWorkerError> for SegmentWorkerError {
    fn from(e: FrameWorkerError) -> Self {
        SegmentWorkerError::FrameWorkerError(e)
    }
}
impl From<FrameError> for SegmentWorkerError {
    fn from(e: FrameError) -> Self {
        SegmentWorkerError::FramingError(e)
    }
}
impl From<CryptoError> for SegmentWorkerError {
    fn from(e: CryptoError) -> Self {
        SegmentWorkerError::CryptoError(e)
    }
}


/// Calculate optimal frame size for a given segment size
pub fn optimal_frame_size(segment_size: usize) -> usize {

    const MIN_FRAMES_PER_SEGMENT: usize = 4;  // Minimum parallelization
    const MAX_FRAMES_PER_SEGMENT: usize = 64; // Don't over-fragment
    
    // Calculate frame size to get reasonable frame count
    let ideal_frame_size = segment_size / 16; // Target ~16 frames
    
    // Clamp to allowed range
    let frame_size = ideal_frame_size
        .max(MIN_FRAME_SIZE)
        .min(MAX_FRAME_SIZE);
    
    // Ensure we get at least MIN_FRAMES_PER_SEGMENT
    let frames_per_segment = segment_size / frame_size;
    if frames_per_segment < MIN_FRAMES_PER_SEGMENT {
        return segment_size / MIN_FRAMES_PER_SEGMENT;
    }
    
    frame_size
}

/// Get optimal frame size from lookup table
pub fn get_frame_size(segment_size: usize) -> usize {
    FRAME_SIZE_TABLE
        .iter()
        .find(|(seg_size, _)| *seg_size == segment_size)
        .map(|(_, frame_size)| *frame_size)
        .unwrap_or_else(|| optimal_frame_size(segment_size))
}