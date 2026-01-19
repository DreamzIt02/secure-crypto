// ## 📂 File: `src/crypto/aead.rs`

//! src/crypto/aead.rs
//! AEAD interface for AES-256-GCM and ChaCha20-Poly1305.
//!
//! Design notes:
//! - Both ciphers use 32-byte keys and 12-byte nonces.
//! - Tag verification is constant-time and must fail closed (no partial plaintext).
//! - Caller provides nonce and AAD (built by aad module) per frame.
//! - Cipher selection is driven by header.cipher (u16 registry).

use crate::constants::{cipher_ids};
use crate::headers::types::{HeaderV1};
use crate::crypto::types::{KEY_LEN_32, NONCE_LEN_12, TAG_LEN};
use crate::crypto::types::{CryptoError};

// Import AEAD traits from aes_gcm's re-export to avoid unresolved `aead` path and duplicates.
use aes_gcm::aead::{Aead, KeyInit, Payload};

// Concrete AEAD types
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};                // 32-byte key, 12-byte nonce
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce}; // 32-byte key, 12-byte nonce

/// Unified AEAD cipher implementation selected by header.cipher.
#[derive(Clone)]
pub enum AeadImpl {
    AesGcm(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl AeadImpl {
    /// Construct AEAD implementation from header.cipher and derived session key.
    pub fn from_header_and_key(header: &HeaderV1, session_key: &[u8]) -> Result<Self, CryptoError> {
        if session_key.len() != KEY_LEN_32 {
            return Err(CryptoError::InvalidKeyLen {
                expected: KEY_LEN_32,
                actual: session_key.len(),
            });
        }

        match header.cipher {
            x if x == cipher_ids::AES256_GCM => {
                let cipher = Aes256Gcm::new_from_slice(session_key)
                    .map_err(|_| CryptoError::InvalidKeyLen {
                        expected: KEY_LEN_32,
                        actual: session_key.len(),
                    })?;
                Ok(Self::AesGcm(cipher))
            }
            x if x == cipher_ids::CHACHA20_POLY1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(session_key)
                    .map_err(|_| CryptoError::InvalidKeyLen {
                        expected: KEY_LEN_32,
                        actual: session_key.len(),
                    })?;
                Ok(Self::ChaCha(cipher))
            }
            other => Err(CryptoError::UnsupportedCipher { cipher_id: other }),
        }
    }

    /// AEAD seal (encrypt) plaintext with nonce and AAD.
    pub fn seal(
        &self,
        nonce_12: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce_12.len() != NONCE_LEN_12 {
            return Err(CryptoError::InvalidNonceLen {
                expected: NONCE_LEN_12,
                actual: nonce_12.len(),
            });
        }

        if plaintext.is_empty() {
            return Err(CryptoError::Failure("plaintext must not be empty".into()));
        }

        match self {
            AeadImpl::AesGcm(cipher) => {
                cipher
                    .encrypt(AesNonce::from_slice(nonce_12), Payload { msg: plaintext, aad })
                    .map_err(|_| CryptoError::Failure("AES-GCM seal failed".into()))
            }
            AeadImpl::ChaCha(cipher) => {
                cipher
                    .encrypt(ChaNonce::from_slice(nonce_12), Payload { msg: plaintext, aad })
                    .map_err(|_| CryptoError::Failure("ChaCha20-Poly1305 seal failed".into()))
            }
        }
    }


    /// AEAD open (decrypt) ciphertext with nonce and AAD.
    pub fn open(
        &self,
        nonce_12: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce_12.len() != NONCE_LEN_12 {
            return Err(CryptoError::InvalidNonceLen {
                expected: NONCE_LEN_12,
                actual: nonce_12.len(),
            });
        }

        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(CryptoError::Failure("ciphertext too short".into()));
        }

        match self {
            AeadImpl::AesGcm(cipher) => {
                cipher
                    .decrypt(AesNonce::from_slice(nonce_12), Payload { msg: ciphertext_and_tag, aad })
                    .map_err(|_| CryptoError::TagMismatch)
            }
            AeadImpl::ChaCha(cipher) => {
                cipher
                    .decrypt(ChaNonce::from_slice(nonce_12), Payload { msg: ciphertext_and_tag, aad })
                    .map_err(|_| CryptoError::TagMismatch)
            }
        }
    }

}
