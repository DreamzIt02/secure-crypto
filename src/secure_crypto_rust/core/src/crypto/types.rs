
// ## 📂 File: `src/crypto/types.rs`

use std::fmt;
use crate::headers::{HeaderV1, enum_name_or_hex};
use crate::headers::{AadDomain, CipherSuite, HeaderError, HkdfPrf};

/// Stable key and nonce sizes.
pub const KEY_LEN_32: usize = 32;

/// Standard 12-byte nonce length for AES-GCM and ChaCha20-Poly1305.
pub const NONCE_LEN_12: usize = 12;

/// Fixed AEAD tag length (bytes).
pub const TAG_LEN: usize = 16;

/// Canonical frame header (fixed size)
///
/// All fields are little-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AadHeader {
    pub frame_type: u8,
    pub segment_index: u32,
    pub frame_index: u32,
    /// Plaintext length in this frame (DATA only; last frame may be < chunk_size).
    pub plaintext_len: u32,
}

impl AadHeader {
    pub const FRAME_LEN: usize = 1 // frame_type  
        + 4                  // segment_index
        + 4                  // frame_index 
        + 4;                 // plaintext_len
        
    pub const LEN_V1: usize = AadHeader::FRAME_LEN  // FRAME_LEN
        + HeaderV1::LEN;                  // HeaderV1 len
}
#[derive(Debug)]
pub enum AadError {
    /// Unknown or unsupported AAD domain.
    UnknownDomain { raw: u16 },

    /// Validation failure with context.
    Validation(String),
}

impl fmt::Display for AadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AadError::UnknownDomain { raw } =>
                write!(f, "unknown or unsupported AAD domain: {}",
                       enum_name_or_hex::<AadDomain>(*raw)),
            AadError::Validation(msg) =>
                write!(f, "AAD validation error: {}", msg),
        }
    }
}

impl std::error::Error for AadError {}

impl From<HeaderError> for AadError {
    fn from(e: HeaderError) -> Self {
        AadError::Validation(e.to_string())
    }
}

#[derive(Debug)]
pub enum NonceError {
    /// Salt is invalid (e.g., all zeros).
    InvalidSalt,

    /// Requested nonce length is unsupported.
    InvalidNonceLen { requested: usize, supported: usize },

    /// Generic validation or derivation error with context.
    Validation(String),
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonceError::InvalidSalt => write!(f, "invalid salt: all zeros"),
            NonceError::InvalidNonceLen { requested, supported } =>
                write!(f, "invalid nonce length: requested={}, supported={}", requested, supported),
            NonceError::Validation(msg) => write!(f, "nonce validation error: {}", msg),
        }
    }
}

impl std::error::Error for NonceError {}


#[derive(Debug)]
pub enum CryptoError {
    /// Unsupported cipher suite ID from header.
    UnsupportedCipher { cipher_id: u16 },

    /// Unsupported HKDF PRF selection from header.
    UnsupportedPrf { prf_id: u16 },

    /// Invalid key length provided to cipher.
    InvalidKeyLen { expected: usize, actual: usize },

    /// Nonce length mismatch (must be 12 bytes for supported ciphers).
    InvalidNonceLen { expected: usize, actual: usize },

    /// AEAD tag mismatch (authentication failure).
    TagMismatch,

    /// General derivation or runtime error with context.
    Failure(String),
    /// Formatted runtime error with context.
    Format(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CryptoError::*;
        match self {
            UnsupportedCipher { cipher_id } =>
                write!(f, "unsupported cipher suite: {}",
                       enum_name_or_hex::<CipherSuite>(*cipher_id)),
            UnsupportedPrf { prf_id } =>
                write!(f, "unsupported HKDF PRF: {}",
                       enum_name_or_hex::<HkdfPrf>(*prf_id)),
            InvalidKeyLen { expected, actual } =>
                write!(f, "invalid key length: expected={}, actual={}", expected, actual),
            InvalidNonceLen { expected, actual } =>
                write!(f, "invalid nonce length: expected={}, actual={}", expected, actual),
            TagMismatch =>
                write!(f, "AEAD tag mismatch"),
            Failure(msg) =>
                write!(f, "crypto failure: {}", msg),
            Format(msg) =>
                write!(f, "{}", msg),
        }
    }
}

// ### ✅ Improvements
// - `UnsupportedCipher` now prints `unsupported cipher suite: Aes256Gcm` or `Chacha20Poly1305` instead of `0x0001`.
// - `UnsupportedPrf` now prints `unsupported HKDF PRF: Sha256`, `Sha512`, or `Blake3K` instead of `0x0002`.
// - If the raw ID doesn’t map to a known variant, `enum_name_or_hex` falls back to hex (`0x0004`).

impl std::error::Error for CryptoError {}

impl From<NonceError> for CryptoError {
    fn from(e: NonceError) -> Self {
        CryptoError::Failure(e.to_string())
    }
}

impl From<AadError> for CryptoError {
    fn from(e: AadError) -> Self {
        CryptoError::Failure(e.to_string())
    }
}
