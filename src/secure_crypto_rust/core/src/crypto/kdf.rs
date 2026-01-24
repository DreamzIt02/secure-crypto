// ## src/crypto/kdf.rs

//! crypto/kdf.rs
//! HKDF-based session key derivation from master key and header salt.
//!
//! Supported PRFs: SHA-256, SHA-512, SHA3-256, SHA3-512, Blake3 derive_key.
//!
//! Design:
//! - HKDF-Extract(master_key, salt) -> PRK
//! - HKDF-Expand(PRK, info) -> session key (32 bytes)
//! - HKDF-based session key derivation from master key and header salt.
//! - Supports SHA-256, SHA-512, SHA3-256, SHA3-512, and Blake3 derive_key.
//!
//! Security notes:
//! - Salt must be random per stream.
//! - Info binds protocol identity and configuration.
//! - Never use master_key directly for AEAD; always derive.
//!
//! Industry notes:
//! - Mirrors TLS 1.3/QUIC key schedules: derive traffic keys via HKDF.
//! - Salt must be random per stream. Info binds protocol identity.

use crate::constants::prf_ids;
use crate::headers::types::HeaderV1;
use crate::crypto::types::{KEY_LEN_32, CryptoError};

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use blake3::derive_key;

/// Summary: Build HKDF 'info' from header fields to bind protocol identity.
/// Included fields: magic, version, alg_profile, cipher, hkdf_prf, compression,
/// strategy, aad_domain, flags, chunk_size, key_id.
/// Excludes reserved/telemetry.
#[inline]
fn build_info_from_header(header: &HeaderV1) -> Vec<u8> {
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(&header.magic);
    info.extend_from_slice(&header.version.to_le_bytes());
    info.extend_from_slice(&header.alg_profile.to_le_bytes());
    info.extend_from_slice(&header.cipher.to_le_bytes());
    info.extend_from_slice(&header.hkdf_prf.to_le_bytes());
    info.extend_from_slice(&header.compression.to_le_bytes());
    info.extend_from_slice(&header.strategy.to_le_bytes());
    info.extend_from_slice(&header.aad_domain.to_le_bytes());
    info.extend_from_slice(&header.flags.to_le_bytes());
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

        x if x == prf_ids::SHA3_256 => {
            let hk = Hkdf::<Sha3_256>::new(Some(&header.salt), master_key);
            let mut key = [0u8; KEY_LEN_32];
            hk.expand(&info, &mut key)
                .map_err(|_| CryptoError::Failure("HKDF expand failed (SHA3-256)".into()))?;
            Ok(key)
        }

        x if x == prf_ids::SHA3_512 => {
            let hk = Hkdf::<Sha3_512>::new(Some(&header.salt), master_key);
            let mut key = [0u8; KEY_LEN_32];
            hk.expand(&info, &mut key)
                .map_err(|_| CryptoError::Failure("HKDF expand failed (SHA3-512)".into()))?;
            Ok(key)
        }

        x if x == prf_ids::BLAKE3K => {
            let material = [master_key, &header.salt, &info].concat();
            let key = derive_key("RSE1|HKDF|SESSION", &material);
            Ok(key)
        }

        other => Err(CryptoError::UnsupportedPrf { prf_id: other }),
    }
}

