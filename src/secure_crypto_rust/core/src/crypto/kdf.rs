// ## src/crypto/kdf.rs

//! crypto/kdf.rs
//! HKDF-based session key derivation from master key and header salt.
//!
//! Design:
//! - HKDF-Extract(master_key, salt) -> PRK
//! - HKDF-Expand(PRK, info) -> session key (32 bytes)
//!
//! Industry notes:
//! - Mirrors TLS 1.3/QUIC key schedules: derive traffic keys via HKDF.
//! - Salt must be random per stream. Info binds protocol identity.

use crate::constants::{prf_ids};
use crate::headers::types::HeaderV1;
use crate::crypto::types::{KEY_LEN_32};
use crate::crypto::types::{CryptoError};

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

#[inline]
/// Summary: Build HKDF 'info' from header fields to bind protocol identity.
/// Included fields: magic, version, alg_profile, cipher, hkdf_prf, compression,
/// strategy, flags, aad_domain, chunk_size, key_id.
/// Excludes reserved/telemetry.
fn build_info_from_header(header: &HeaderV1) -> Vec<u8> {
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(&header.magic);
    info.extend_from_slice(&header.version.to_le_bytes());
    info.extend_from_slice(&header.alg_profile.to_le_bytes());
    info.extend_from_slice(&header.cipher.to_le_bytes());
    info.extend_from_slice(&header.hkdf_prf.to_le_bytes());
    info.extend_from_slice(&header.compression.to_le_bytes());
    info.extend_from_slice(&header.strategy.to_le_bytes());
    info.extend_from_slice(&header.flags.to_le_bytes());
    info.extend_from_slice(&header.aad_domain.to_le_bytes());
    info.extend_from_slice(&header.chunk_size.to_le_bytes());
    info.extend_from_slice(&header.key_id.to_le_bytes());
    info
}

/// Summary: Derive a 32-byte per-stream session key via HKDF from master_key + header.salt.
/// - PRF chosen from header.hkdf_prf (SHA-256, SHA-512, optionally keyed BLAKE3).
/// - 'info' binds protocol identity and configuration.
/// Returns [u8;32] session key.
///
/// Errors:
/// - Unsupported PRF selection returns CryptoError::UnsupportedPrf.
///
/// Security notes:
/// - Never use master_key directly for AEAD; always derive.
/// - Ensure header.salt is random per stream (validated in headers).
#[inline]
pub fn derive_session_key_32(
    master_key: &[u8],
    header: &HeaderV1,
) -> Result<[u8; KEY_LEN_32], CryptoError> {
    if header.salt.iter().all(|&b| b == 0) {
        return Err(CryptoError::Failure("salt must not be all-zero".into()));
    }

    let info = build_info_from_header(header);

    match header.hkdf_prf {
        x if x == prf_ids::SHA256 => {
            let hk = Hkdf::<Sha256>::new(Some(&header.salt), master_key);
            let mut key = [0u8; KEY_LEN_32];
            hk.expand(&info, &mut key)
                .map_err(|_| CryptoError::Failure("HKDF expand failed (SHA-256)".into()))?;
            Ok(key)
        }

        x if x == prf_ids::SHA512 => {
            let hk = Hkdf::<Sha512>::new(Some(&header.salt), master_key);
            let mut key = [0u8; KEY_LEN_32];
            hk.expand(&info, &mut key)
                .map_err(|_| CryptoError::Failure("HKDF expand failed (SHA-512)".into()))?;
            Ok(key)
        }

        x if x == prf_ids::BLAKE3K => {
            use blake3::Hasher;

            let mut extract = Hasher::new();
            extract.update(b"RSE1|HKDF|EXTRACT");
            extract.update(master_key);
            extract.update(&header.salt);
            let prk = extract.finalize();

            let mut expand = Hasher::new();
            expand.update(b"RSE1|HKDF|EXPAND");
            expand.update(prk.as_bytes());
            expand.update(&info);

            let out = expand.finalize();
            let mut key = [0u8; KEY_LEN_32];
            key.copy_from_slice(&out.as_bytes()[..KEY_LEN_32]);
            Ok(key)
        }

        other => Err(CryptoError::UnsupportedPrf { prf_id: other }),
    }
}

