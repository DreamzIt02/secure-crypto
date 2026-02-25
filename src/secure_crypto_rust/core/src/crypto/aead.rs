// ## 📂 File: `src/crypto/aead.rs`

//! src/crypto/aead.rs
//! AEAD interface for AES-256-GCM and ChaCha20-Poly1305.
//!
//! Design notes:
//! - Both ciphers use 32-byte keys and 12-byte nonces.
//! - Tag verification is constant-time and must fail closed (no partial plaintext).
//! - Caller provides nonce and AAD (built by aad module) per frame.
//! - Cipher selection is driven by header.cipher (u16 registry).

use crate::constants::{MASTER_KEY_LENGTHS, cipher_ids};
use crate::headers::types::{HeaderV1};
use crate::crypto::types::{KEY_LEN_32, NONCE_LEN_12, TAG_LEN};
use crate::crypto::types::{CryptoError};

// Import AEAD traits from aes_gcm's re-export to avoid unresolved `aead` path and duplicates.
use aes_gcm::aead::{Aead, Buffer, KeyInit, Payload};
use aes_gcm::aead::AeadInOut;
use hybrid_array::{Array, sizes::U12};

// Concrete AEAD types
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};                // 32-byte key, 12-byte nonce
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use tracing::debug; // 32-byte key, 12-byte nonce

/// Custom nonce wrapper for Blake3
// pub struct Blake3Nonce<'a>(&'a [u8]);

// impl<'a> Blake3Nonce<'a> {
//     pub fn from_slice(nonce: &'a [u8]) -> Self {
//         Self(nonce)
//     }
// }

/// Custom Blake3Cipher wrapper
// #[derive(Clone)]
// pub struct Blake3Cipher {
//     key: [u8; 32],
// }

// impl Blake3Cipher {
//     pub fn new_from_slice(key_bytes: &[u8]) -> Result<Self, InvalidLength> {
//         if key_bytes.len() != 32 {
//             return Err(InvalidLength); // we’ll map this to CryptoError later
//         }

//         let mut key = [0u8; 32];
//         key.copy_from_slice(key_bytes);
//         Ok(Self { key })
//     }

//     pub fn encrypt(&self, nonce: Blake3Nonce<'_>, payload: Payload<'_, '_>) -> Result<Vec<u8>, aes_gcm::Error> {
//         // blake3_aead::encrypt returns Vec<u8>
//         let ct = blake3_aead::encrypt(&self.key, nonce.0, payload.aad, payload.msg);

//         // Wrap into Result<Vec<u8>, aes_gcm::Error>
//         if ct.is_empty() {
//             // Example invariant: ciphertext must not be empty
//             Err(aes_gcm::Error) // wrap into aes_gcm::Error for symmetry
//         } else {
//             Ok(ct)
//         }
//     }

//     pub fn decrypt(&self, nonce: Blake3Nonce<'_>, payload: Payload<'_, '_>) -> Result<Vec<u8>, aes_gcm::Error> {
//         // blake3_aead::decrypt returns Result<Vec<u8>, ()>
//         match blake3_aead::decrypt(&self.key, nonce.0, payload.aad, payload.msg) {
//             Ok(pt) => {
//                 if pt.is_empty() {
//                     // Example invariant: plaintext must not be empty
//                     Err(aes_gcm::Error)
//                 } else {
//                     Ok(pt)
//                 }
//             }
//             Err(_) => Err(aes_gcm::Error), // wrap () into aes_gcm::Error
//         }
//     }

//     /// Encrypt in place: buffer contains plaintext, will be replaced with ciphertext+tag.
//     pub fn encrypt_in_place(&self, nonce: Blake3Nonce<'_>, aad: &[u8], buf: &mut (dyn Buffer + 'static),) 
//         -> Result<(), aes_gcm::Error> {
//         // Convert trait object to slice
//         let slice: &mut [u8] = buf.as_mut();

//         // Delegate to blake3_aead, which mutates the slice directly
//         blake3_aead::encrypt_in_place(&self.key, nonce.0, aad, slice);

//         Ok(())
//     }
//     /// Decrypt in place: buffer contains ciphertext+tag, will be replaced with plaintext.
//     pub fn decrypt_in_place(&self, nonce: Blake3Nonce<'_>, aad: &[u8], buf: &mut (dyn Buffer + 'static),)
//         -> Result<(), aes_gcm::Error> {
//         // Convert trait object to slice
//         let slice: &mut [u8] = buf.as_mut();

//         // Delegate to blake3_aead, which mutates the slice directly
//         blake3_aead::decrypt_in_place(&self.key, nonce.0, aad, slice)
//             .map_err(|_| aes_gcm::Error);

//         Ok(())
//     }

// }

/// Unified AEAD cipher implementation selected by header.cipher.
#[derive(Clone)]
pub enum AeadImpl {
    AesGcm(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
    // Blake3(Blake3Cipher),
}

impl AeadImpl {
    /// Construct AEAD implementation from header.cipher and derived session key.
    pub fn from_header_and_key(header: &HeaderV1, session_key: &[u8]) -> Result<Self, CryptoError> {
        if session_key.len() != KEY_LEN_32 {
            return Err(CryptoError::InvalidKeyLen {
                expected: &MASTER_KEY_LENGTHS,
                actual: session_key.len(),
            });
        }

        match header.cipher {
            x if x == cipher_ids::AES256_GCM => {
                let cipher = Aes256Gcm::new_from_slice(session_key)
                    .map_err(|_| CryptoError::InvalidKeyLen {
                        expected: &MASTER_KEY_LENGTHS,
                        actual: session_key.len(),
                    })?;
                Ok(Self::AesGcm(cipher))
            }
            x if x == cipher_ids::CHACHA20_POLY1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(session_key)
                    .map_err(|_| CryptoError::InvalidKeyLen {
                        expected: &MASTER_KEY_LENGTHS,
                        actual: session_key.len(),
                    })?;
                Ok(Self::ChaCha(cipher))
            }
            // x if x == cipher_ids::BLAKE3K => {
            //     // Blake3Aead expects a 32-byte key
            //     let cipher = Blake3Cipher::new_from_slice(session_key)
            //         .map_err(|_| CryptoError::InvalidKeyLen {
            //             expected: &MASTER_KEY_LENGTHS,
            //             actual: session_key.len(),
            //         })?;
            //     Ok(Self::Blake3(cipher))
            // }

            other => Err(CryptoError::UnsupportedCipher { cipher_id: other }),
        }
    }
        

    fn extract_nonce(
        &self,
        nonce_12: &[u8],
    ) -> Result<Array<u8, U12>, CryptoError> {
        
        if nonce_12.len() != NONCE_LEN_12 {
            return Err(CryptoError::InvalidNonceLen {
                expected: NONCE_LEN_12,
                actual: nonce_12.len(),
            });
        }

        match self {
            AeadImpl::AesGcm(_) => {
                let nonce = AesNonce::try_from(nonce_12).map_err(|e|CryptoError::Failure(e.to_string()))?;
                Ok(nonce)
            }
            AeadImpl::ChaCha(_) => {
                let nonce = ChaNonce::try_from(nonce_12).map_err(|e|CryptoError::Failure(e.to_string()))?;
                Ok(nonce)
            }
        }
    }

    /// AEAD seal (encrypt) plaintext with nonce and AAD.
    pub fn seal(
        &self,
        nonce_12: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if plaintext.is_empty() {
            return Err(CryptoError::Failure("plaintext must not be empty".into()));
        }
        let nonce = self.extract_nonce(nonce_12)?;

        // Debug information
        debug!(
            "[AEAD::seal] cipher={:?}, plaintext_len={}, aad_len={}, nonce={:02x?}",
            match self {
                AeadImpl::AesGcm(_) => "AES-GCM",
                AeadImpl::ChaCha(_) => "ChaCha20-Poly1305",
                // AeadImpl::Blake3(_) => "Blake3-AEAD",
            },
            plaintext.len(),
            aad.len(),
            nonce_12
        );

        match self {
            AeadImpl::AesGcm(cipher) => {
                debug!(
                    "[AEAD::seal] AES-GCM sealing frame with {} bytes payload",
                    plaintext.len()
                );
                cipher
                    .encrypt(&nonce, Payload { msg: plaintext, aad })
                    .map_err(|e| CryptoError::Failure(format!("AES-GCM seal failed: {e}")))
            }
            AeadImpl::ChaCha(cipher) => {
                debug!(
                    "[AEAD::seal] ChaCha20-Poly1305 sealing frame with {} bytes payload",
                    plaintext.len()
                );
                cipher
                    .encrypt(&nonce, Payload { msg: plaintext, aad })
                    .map_err(|e| CryptoError::Failure(format!("ChaCha20-Poly1305 seal failed: {e}")))
            }
            // AeadImpl::Blake3(cipher) => {
            //     debug!(
            //         "[AEAD::seal] Blake3-AEAD sealing frame with {} bytes payload",
            //         plaintext.len()
            //     );
            //     cipher
            //         .encrypt(Blake3Nonce::from_slice(nonce_12), Payload { msg: plaintext, aad })
            //         .map_err(|_| CryptoError::Failure("Blake3-AEAD seal failed".into()))
            // }
        }
    }

    /// AEAD open (decrypt) ciphertext with nonce and AAD.
    pub fn open(
        &self,
        nonce_12: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_and_tag.len() < TAG_LEN {
            return Err(CryptoError::Failure("ciphertext too short".into()));
        }
        let nonce = self.extract_nonce(nonce_12)?;

        match self {
            AeadImpl::AesGcm(cipher) => {
                cipher
                    .decrypt(&nonce, Payload { msg: ciphertext_and_tag, aad })
                    .map_err(|e| CryptoError::Failure(format!("AES-GCM open failed: {e}")))
            }
            AeadImpl::ChaCha(cipher) => {
                cipher
                    .decrypt(&nonce, Payload { msg: ciphertext_and_tag, aad })
                    .map_err(|e| CryptoError::Failure(format!("ChaCha20-Poly1305 open failed: {e}")))
            }
            // AeadImpl::Blake3(cipher) => {
            //     cipher.decrypt(Blake3Nonce::from_slice(nonce_12), Payload { msg: ciphertext_and_tag, aad })
            //         .map_err(|_| CryptoError::TagMismatch)
            // }
        }

    }

    // ### In‑Place AEAD Implementation

    /// AEAD seal (encrypt) plaintext in place with nonce and AAD.
    /// The buffer must have enough capacity for plaintext + tag.
    pub fn seal_in_place(
        &self,
        nonce_12: &[u8],
        aad: &[u8],
        buf: &mut (dyn Buffer + 'static), // contains plaintext, will be replaced with ciphertext+tag
    ) -> Result<(), CryptoError> {
        if buf.is_empty() {
            return Err(CryptoError::Failure("plaintext must not be empty".into()));
        }

        let nonce = self.extract_nonce(nonce_12)?;

        match self {
            AeadImpl::AesGcm(cipher) => cipher
                .encrypt_in_place(&nonce, aad, buf)
                .map_err(|e| CryptoError::Failure(format!("AES-GCM seal_in_place failed: {e}"))),

            AeadImpl::ChaCha(cipher) => cipher
                .encrypt_in_place(&nonce, aad, buf)
                .map_err(|e| CryptoError::Failure(format!("ChaCha20-Poly1305 seal_in_place failed: {e}"))),

            // AeadImpl::Blake3(cipher) => {
            //     cipher
            //         .encrypt_in_place(Blake3Nonce::from_slice(nonce_12), aad, buf)
            //         .map_err(|_| CryptoError::Failure("Blake3-AEAD seal_in_place failed".into()))
            // }
        }
    }

    /// AEAD open (decrypt) ciphertext in place with nonce and AAD.
    /// The buffer must contain ciphertext+tag, will be replaced with plaintext.
    pub fn open_in_place(
        &self,
        nonce_12: &[u8],
        aad: &[u8],
        buf: &mut (dyn Buffer + 'static), // contains ciphertext+tag, will be replaced with plaintext
    ) -> Result<(), CryptoError> {
        if buf.len() < TAG_LEN {
            return Err(CryptoError::Failure("ciphertext too short".into()));
        }

        let nonce = self.extract_nonce(nonce_12)?;
        
        match self {
            AeadImpl::AesGcm(cipher) => cipher
                .decrypt_in_place(&nonce, aad, buf)
                .map_err(|e| CryptoError::Failure(format!("AES-GCM open_in_place failed: {e}"))),

            AeadImpl::ChaCha(cipher) => cipher
                .decrypt_in_place(&nonce, aad, buf)
                .map_err(|e| CryptoError::Failure(format!("ChaCha20-Poly1305 open_in_place failed: {e}"))),
            
            // AeadImpl::Blake3(cipher) => {
            //     cipher
            //         .decrypt_in_place(Blake3Nonce::from_slice(nonce_12), aad, buf)
            //         .map_err(|_| CryptoError::TagMismatch)
            // }
        }
    }

    // ### Key Differences
    // - **`encrypt_in_place` / `decrypt_in_place`**: These are the in‑place APIs provided by `aes-gcm`, `chacha20poly1305`, and similar crates. They mutate the buffer directly.
    // - **Buffer ownership**: Instead of returning a new `Vec<u8>`, the caller provides a mutable buffer (`Vec<u8>` or `BytesMut`) that already contains plaintext (for seal) or ciphertext+tag (for open).
    // - **No extra copies**: Encryption/decryption happens inside the buffer, then we can freeze into `Bytes` if needed.
    // ### Usage Example
    // ```rust
    // let mut buf = BytesMut::from(&plaintext[..]);
    // buf.reserve(TAG_LEN); // ensure space for tag

    // aead.seal_in_place(&nonce, &aad, &mut buf)?;
    // let ciphertext_and_tag = buf.freeze();

    // let mut ct_buf = ciphertext_and_tag.to_vec();
    // aead.open_in_place(&nonce, &aad, &mut ct_buf)?;
    // let plaintext = Bytes::from(ct_buf);
    // ```
}
    // This pattern ensures **true zero‑copy** across our encrypt/decrypt pipeline: one buffer, mutated in place, no redundant allocations.  

