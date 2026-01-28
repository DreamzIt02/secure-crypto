// ## 📂 File: `src/crypto/nonce.rs`

//! nonce/builder.rs
//! Deterministic nonce derivation from stream salt and frame index.
//!
//! Design:
//! - TLS-like scheme: take a 12-byte base IV from the stream salt, then XOR the
//!   low 8 bytes with the little-endian frame_index.
//!
//! Why:
//! - Deterministic, stateless derivation enables parallel workers to compute nonces
//!   independently from (salt, frame_index).
//! - Salt uniqueness per stream prevents nonce reuse across streams.
//!
//! Security notes:
//! - Never reuse the same (salt, frame_index) pair. The salt must be random per stream.
//! - Do not use all-zero salts. Validate before deriving.

use crate::crypto::types::{NONCE_LEN_12};
use crate::crypto::types::{NonceError};

/// Derive a 12-byte AEAD nonce in a TLS-style pattern from a 16-byte salt and frame index.
///
/// Design:
/// - Base IV: the first 12 bytes of `salt` become the starting nonce.
/// - Counter: XOR the low 8 bytes (positions 4..12) with `frame_index` in little-endian.
///   This maintains a fixed 4-byte static prefix (nonce[0..4]) and a varying 8-byte tail,
///   giving up to 2^64 unique nonces per session.
/// - This schedule must be identical for encrypt and decrypt. Do not change endianness
///   or the XOR region without updating both sides and test vectors.
///
/// Contract and invariants:
/// - `salt` must pass `validate_salt` (length and optional domain constraints).
/// - Output length is exactly `NONCE_LEN_12`.
/// - Deterministic mapping: same `(salt, frame_index)` → same nonce.
/// - Monotonic frame_index produces distinct nonces across frames.
///
/// Notes:
/// - Works for AES-GCM and ChaCha20-Poly1305 (12-byte nonce).
/// - If we introduce non-12-byte AEADs, do not call this helper; add a dedicated
///   derivation that matches the required nonce length and update `derive_nonce`.
#[inline]
pub fn derive_nonce_12_tls_style(
    salt: &[u8; 16],
    frame_index: u64,
) -> Result<[u8; NONCE_LEN_12], NonceError> {
    validate_salt(salt)?;

    let mut nonce = [0u8; NONCE_LEN_12];
    nonce.copy_from_slice(&salt[..NONCE_LEN_12]);

    let ctr: [u8; 8] = frame_index.to_le_bytes(); // always 8 bytes
    for j in 0..8 {
        nonce[4 + j] ^= ctr[j];
    }

    Ok(nonce)
}

/// Derive an AEAD nonce of the requested length.
/// Currently supports only 12-byte nonces (AES-GCM, ChaCha20-Poly1305).
///
/// Contract:
/// - `nonce_len` must be supported (12).
/// - Returns a nonce as `Vec<u8>` of exact `nonce_len`.
///
/// Notes:
/// - This function dispatches to `derive_nonce_12_tls_style` for 12-byte nonces.
/// - If future cipher suites require different nonce lengths (e.g., 8 or 24),
///   extend this function with a dedicated branch that matches the suite’s
///   standard derivation and update the AEAD selection to request the right length.
#[inline]
pub fn derive_nonce(
    salt: &[u8; 16],
    frame_index: u64,
    nonce_len: usize,
) -> Result<Vec<u8>, NonceError> {
    validate_nonce_len(nonce_len)?;
    match nonce_len {
        NONCE_LEN_12 => {
            let n12 = derive_nonce_12_tls_style(salt, frame_index)?;
            Ok(n12.to_vec())
        }
        // If we add other nonce lengths, implement their derivation and branch here.
        _ => Err(NonceError::InvalidNonceLen { requested: nonce_len, supported: NONCE_LEN_12 }),
    }
}

/// Summary: Validate that salt is not all zeros.
/// Returns Ok(()) if valid; Err(NonceError) otherwise.
///
/// Industry note: Salt must be random per stream; all-zero is forbidden.
#[inline]
pub fn validate_salt(salt: &[u8; 16]) -> Result<(), NonceError> {
    if salt.iter().all(|&b| b == 0) {
        return Err(NonceError::InvalidSalt);
    }
    Ok(())
}

/// Summary: Validate requested nonce length.
/// Currently only 12-byte nonces are supported.
///
/// Returns Ok(()) if nonce_len == 12; Err otherwise.
#[inline]
pub fn validate_nonce_len(nonce_len: usize) -> Result<(), NonceError> {
    if nonce_len != NONCE_LEN_12 {
        return Err(NonceError::InvalidNonceLen { requested: nonce_len, supported: NONCE_LEN_12 });
    }
    Ok(())
}
