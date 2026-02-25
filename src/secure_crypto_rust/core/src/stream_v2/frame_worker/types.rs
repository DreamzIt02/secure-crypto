use std::fmt;
use std::ops::Range;
use bytes::Bytes;

use crate::stream_v2::framing::FrameHeader;
use crate::stream_v2::framing::types::{FrameError, FrameType};
use crate::crypto::types::{TAG_LEN, CryptoError, NonceError, AadError};
use crate::telemetry::StageTimes;

#[derive(Debug, Clone)]
pub enum FrameWorkerError {
    StateError(String),
    InvalidInput(String),
    CryptoFailure(String),
    InvalidHeader,
    WorkerDisconnected,
    WorkerMissing,
    Cancelled,
    
    Crypto(CryptoError),
    Nonce(NonceError),
    Aad(AadError),
    Framing(FrameError),
}
// #[derive(Debug, Error)]
// pub enum FrameWorkerError {
    // #[error("AEAD encryption failed: {0}")]
    // EncryptionFailed(#[from] CryptoError),
    
    // #[error("AEAD decryption failed: {0}")]
    // DecryptionFailed(CryptoError),
    
    // #[error("Frame parsing error: {0}")]
    // FrameParsing(#[from] FrameError),
    
    // #[error("Invalid frame header")]
    // InvalidHeader,
    
    // #[error("Frame type conversion error")]
    // InvalidFrameType,
// }

impl fmt::Display for FrameWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FrameWorkerError::*;
        match self {
            StateError(msg) => write!(f, "state error: {}", msg),
            InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            CryptoFailure(msg) => write!(f, "crypto failure: {}", msg),
            WorkerDisconnected => write!(f, "fatal error: {}", "Frame worker disconnected unexpectedly"),
            Cancelled => write!(f, "fatal error: {}", "Frame worker cancelled"),
            WorkerMissing => write!(f, "fatal error: {}", "Frame worker is not allocated"),
            InvalidHeader => write!(f, "invalid header: {}", "Invalid frame header"),

            Crypto(e) => write!(f, "crypto error: {}", e),
            Nonce(e) => write!(f, "nonce error: {}", e),
            Aad(e) => write!(f, "aad error: {}", e),
            Framing(e) => write!(f, "framing error: {}", e),
        }
    }
}

impl std::error::Error for FrameWorkerError {}

impl From<CryptoError> for FrameWorkerError {
    fn from(e: CryptoError) -> Self {
        FrameWorkerError::Crypto(e)
    }
}
impl From<NonceError> for FrameWorkerError {
    fn from(e: NonceError) -> Self {
        FrameWorkerError::Nonce(e)
    }
}
impl From<AadError> for FrameWorkerError {
    fn from(e: AadError) -> Self {
        FrameWorkerError::Aad(e)
    }
}
impl From<FrameError> for FrameWorkerError {
    fn from(e: FrameError) -> Self {
        FrameWorkerError::Framing(e)
    }
}

/// This makes frame semantics: Plaintext frame input
/// * explicit
///* validated
///* protocol-native
#[derive(Debug, Clone)]
pub struct FrameInput {
    pub segment_index: u32,
    pub frame_index: u32,
    pub frame_type: FrameType,
    pub payload: Bytes, // 🔥 instead of Arc<[u8]>
}

// ## ✅ Policy for `FrameType::Digest`

// Digest frames are special: they don’t carry arbitrary plaintext, but instead must contain a well‑formed digest structure (algorithm ID + length + digest bytes).

// 1. **Non‑empty plaintext required** (a digest frame must contain at least 4 bytes: alg_id + digest_len).
// 2. **Parsable by `DigestFrame::decode`** (if decode fails, reject).
// 3. **Digest length must match actual bytes** (already enforced by `DigestFrame::decode`).
// 4. **Algorithm must be known** (already enforced by `DigestAlg::try_from`).

impl FrameInput {
    pub fn validate(&self) -> Result<(), FrameWorkerError> {
        match self.frame_type {
            FrameType::Data => {
                if self.payload.is_empty() {
                    return Err(FrameWorkerError::InvalidInput(
                        "DATA frame cannot be empty".into(),
                    ));
                }
            }
            FrameType::Terminator => {
                if !self.payload.is_empty() {
                    return Err(FrameWorkerError::InvalidInput(
                        "TERMINATOR frame must be empty".into(),
                    ));
                }
            }
            FrameType::Digest => {
                if self.payload.len() < 4 {
                    return Err(FrameWorkerError::InvalidInput(
                        "DIGEST frame too short".into(),
                    ));
                }
                // Try decoding the digest frame
                // match DigestFrame::decode(&self.payload) {
                //     Ok(_) => {}
                //     Err(e) => {
                //         return Err(FrameWorkerError::InvalidInput(format!(
                //             "DIGEST frame invalid: {:?}",
                //             e
                //         )));
                //     }
                // }
            }
        }
        Ok(())
    }
}

/// Output of encryption
#[derive(Debug, Clone)]
pub struct EncryptedFrame {
    pub segment_index: u32,
    pub frame_index: u32,
    pub frame_type: FrameType,
    
    /// Shared ownership of the full wire frame
    pub wire: Bytes,
    /// Ciphertext view inside `wire`
    pub ct_range: Range<usize>,
    pub stage_times: StageTimes,
}

impl EncryptedFrame {
    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &self.wire[self.ct_range.clone()]
    }
    
    #[inline]
    pub fn frame_overhead() -> usize {
        return FrameHeader::LEN + TAG_LEN
    }
}

impl Default for EncryptedFrame {
    fn default() -> Self {
        Self {
            segment_index: 0,
            frame_index: 0,
            frame_type: FrameType::Data, // choose a neutral variant
            wire: Bytes::new(),          // empty buffer
            ct_range: 0..0,              // empty range
            stage_times: StageTimes::default(),
        }
    }
}

/// Output of decryption
#[derive(Debug, Clone)]
pub struct DecryptedFrame {
    pub segment_index: u32,
    pub frame_index: u32,
    pub frame_type: FrameType,

    /// Encrypted ciphertext hold zero-copy for using in digest verification of segment
    #[deprecated]
    pub wire: Bytes,
    /// Ciphertext view inside `wire`
    pub ct_range: Range<usize>,

    /// Decrypted plaintext
    pub plaintext: Bytes,
    pub stage_times: StageTimes,
}

impl DecryptedFrame {
    #[deprecated]
    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &self.wire[self.ct_range.clone()]
    }
    // ✔ digest-safe
    // ✔ zero-copy ciphertext
    // ✔ reorderable
    // ✔ lifetime-safe
}

impl Default for DecryptedFrame {
    fn default() -> Self {
        Self {
            segment_index: 0,
            frame_index: 0,
            frame_type: FrameType::Data, // neutral default variant
            wire: Bytes::new(),          // empty buffer
            ct_range: 0..0,              // empty range
            plaintext: Bytes::new(),     // empty plaintext
            stage_times: StageTimes::default(),
        }
    }
}
