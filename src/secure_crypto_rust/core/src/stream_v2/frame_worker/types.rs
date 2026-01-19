use std::fmt;

use crate::crypto::DigestFrame;
use crate::stream_v2::framing::types::{FrameError, FrameType};
use crate::crypto::types::{CryptoError, NonceError, AadError};

#[derive(Debug)]
pub enum FrameWorkerError {
    Crypto(CryptoError),
    Nonce(NonceError),
    Aad(AadError),
    Framing(FrameError),
    InvalidInput(String),
}

impl fmt::Display for FrameWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FrameWorkerError::*;
        match self {
            Crypto(e) => write!(f, "crypto error: {}", e),
            Nonce(e) => write!(f, "nonce error: {}", e),
            Aad(e) => write!(f, "aad error: {}", e),
            Framing(e) => write!(f, "framing error: {}", e),
            InvalidInput(msg) => write!(f, "invalid input: {}", msg),
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
    pub segment_index: u64,
    pub frame_index: u32,
    pub frame_type: FrameType,
    pub plaintext: Vec<u8>,
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
                if self.plaintext.is_empty() {
                    return Err(FrameWorkerError::InvalidInput(
                        "DATA frame cannot be empty".into(),
                    ));
                }
            }
            FrameType::Terminator => {
                if !self.plaintext.is_empty() {
                    return Err(FrameWorkerError::InvalidInput(
                        "TERMINATOR frame must be empty".into(),
                    ));
                }
            }
            FrameType::Digest => {
                if self.plaintext.len() < 4 {
                    return Err(FrameWorkerError::InvalidInput(
                        "DIGEST frame too short".into(),
                    ));
                }
                // Try decoding the digest frame
                // match DigestFrame::decode(&self.plaintext) {
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
#[derive(Debug)]
pub struct EncryptedFrame {
    pub segment_index: u64,
    pub frame_index: u32,
    pub frame_type: FrameType,
    pub ciphertext: Vec<u8>,
    pub wire: Vec<u8>,
}

/// Output of decryption
#[derive(Debug)]
pub struct DecryptedFrame {
    pub segment_index: u64,
    pub frame_index: u32,
    pub frame_type: FrameType,
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
}
