use std::fmt;
use std::convert::{From};

use crate::crypto::{CryptoError, KEY_LEN_32};
use crate::headers::types::HeaderV1;
use crate::stream_v2::framing::FrameType;
use crate::telemetry::counters::TelemetryCounters;
use crate::stream_v2::frame_worker::{FrameInput, FrameWorkerError};

#[derive(Debug, Clone, Copy)]
pub struct DigestResumePoint {
    /// First frame index that has NOT yet been authenticated
    pub next_frame_index: u32,
}

/// `SegmentInput` is the “raw” form: just plaintext frames.
/// Input from reader stage (plaintext)
#[derive(Debug, Clone)]
pub struct SegmentInput {
    pub segment_index: u64,
    pub frames: Vec<Vec<u8>>, // plaintext frames
}

/// `SegmentInput1` is the “typed” form: each frame is a `FrameInput` with metadata.
#[derive(Debug, Clone)]
pub struct SegmentInput1 {
    pub segment_index: u64,
    pub frames: Vec<FrameInput>, // typed frames
}

/// ### From `SegmentInput` → `SegmentInput1`
/// Here we wrap each raw plaintext frame into a `FrameInput`.  
/// We assume they are all **Data frames** by default, with ascending indices.
impl From<SegmentInput> for SegmentInput1 {
    fn from(raw: SegmentInput) -> Self {
        let frames = raw.frames
            .into_iter()
            .enumerate()
            .map(|(i, plaintext)| FrameInput {
                frame_type: FrameType::Data, // default assumption
                segment_index: raw.segment_index,
                frame_index: i as u32,
                plaintext,
            })
            .collect();

        SegmentInput1 {
            segment_index: raw.segment_index,
            frames,
        }
    }
}

/// ### From `SegmentInput1` → `SegmentInput`
/// Here we strip away metadata and keep only plaintexts.
impl From<SegmentInput1> for SegmentInput {
    fn from(typed: SegmentInput1) -> Self {
        let frames = typed.frames
            .into_iter()
            .map(|f| f.plaintext)
            .collect();

        SegmentInput {
            segment_index: typed.segment_index,
            frames,
        }
    }
}

// ### Example Usage

// ```rust
// fn main() {
//     // Raw segment
//     let raw = SegmentInput {
//         segment_index: 42,
//         frames: vec![b"hello".to_vec(), b"world".to_vec()],
//     };

//     // Convert to typed
//     let typed: SegmentInput1 = raw.clone().into();
//     assert_eq!(typed.frames[0].frame_type, FrameType::Data);
//     assert_eq!(typed.frames[0].plaintext, b"hello");

//     // Convert back to raw
//     let raw2: SegmentInput = typed.into();
//     assert_eq!(raw2.frames[1], b"world");
// }
// ```

/// Output of encryption
#[derive(Debug)]
pub struct EncryptedSegment {
    pub segment_index: u64,
    pub wire: Vec<u8>,              // contiguous encoded frames
    pub telemetry: TelemetryCounters,
}

/// Output of decryption
#[derive(Debug)]
pub struct DecryptedSegment {
    pub segment_index: u64,
    pub frames: Vec<Vec<u8>>,       // plaintext frames
    pub telemetry: TelemetryCounters,
}

/// Immutable crypto context shared across workers
#[derive(Debug, Clone)]
pub struct SegmentCryptoContext {
    pub header: HeaderV1,
    pub session_key: [u8; KEY_LEN_32],
}
impl SegmentCryptoContext {
    pub fn new(header: HeaderV1, session_key: &[u8]) -> Result<Self, CryptoError> {
        if session_key.len() != KEY_LEN_32 {
            return Err(CryptoError::InvalidKeyLen {
                expected: KEY_LEN_32,
                actual: session_key.len(),
            });
        }
        let mut arr = [0u8; KEY_LEN_32];
        arr.copy_from_slice(session_key);
        Ok(Self { header, session_key: arr })
    }
}


#[derive(Debug)]
pub enum SegmentWorkerError {
    Frame(FrameWorkerError),
    InvalidSegment(String),
}

impl fmt::Display for SegmentWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SegmentWorkerError::Frame(e) =>
                write!(f, "frame error: {}", e),
            SegmentWorkerError::InvalidSegment(msg) =>
                write!(f, "invalid segment: {}", msg),
        }
    }
}

impl std::error::Error for SegmentWorkerError {}

impl From<FrameWorkerError> for SegmentWorkerError {
    fn from(e: FrameWorkerError) -> Self {
        SegmentWorkerError::Frame(e)
    }
}
