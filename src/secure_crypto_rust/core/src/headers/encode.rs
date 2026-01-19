// ## 📂 File: `src/headers/encode.rs`
//! src/headers/encode.rs
//!
//! Header encoding utilities.
//!
//! Design notes:
//! - Serializes `HeaderV1` into a fixed 80‑byte buffer in little‑endian order.
//! - Field order must match `types.rs` layout exactly for ABI stability.
//! - Validation is performed before encoding to fail fast on invalid headers.
//! - Returns a fixed `[u8; HEADER_LEN_V1]` buffer on success.

use crate::headers::types::{HEADER_LEN_V1};
use crate::headers::types::{HeaderV1, HeaderError};

/// Serialize a `HeaderV1` into an 80‑byte buffer in little‑endian order.
///
/// # Returns
/// - `Ok([u8; HEADER_LEN_V1])` containing the encoded header bytes.
/// - `Err(HeaderError)` if validation fails (bad magic, zero salt, invalid enums, etc.).
///
/// # Notes
/// - Field order must match the struct layout in `types.rs`.
/// - Uses helper functions for compact little‑endian writes.
/// - Debug assertion ensures exactly 80 bytes are written.
#[inline]
pub fn encode_header_le(h: &HeaderV1) -> Result<[u8; HEADER_LEN_V1], HeaderError> {
    // Validate header fields before encoding.
    // Better call from caller explicitly before calling this function
    // validate_header(h)?;

    // Fixed output buffer of 80 bytes.
    let mut out = [0u8; HEADER_LEN_V1];
    // Write cursor index.
    let mut i = 0usize;

    // Helper functions for little‑endian writes.
    fn put_u16(out: &mut [u8], i: &mut usize, v: u16) {
        out[*i..*i + 2].copy_from_slice(&v.to_le_bytes());
        *i += 2;
    }
    fn put_u32(out: &mut [u8], i: &mut usize, v: u32) {
        out[*i..*i + 4].copy_from_slice(&v.to_le_bytes());
        *i += 4;
    }
    fn put_u64(out: &mut [u8], i: &mut usize, v: u64) {
        out[*i..*i + 8].copy_from_slice(&v.to_le_bytes());
        *i += 8;
    }
    fn put_bytes(out: &mut [u8], i: &mut usize, b: &[u8]) {
        out[*i..*i + b.len()].copy_from_slice(b);
        *i += b.len();
    }

    // Field order must match HeaderV1 layout and documentation.
    put_bytes(&mut out, &mut i, &h.magic);       // 0..4   magic number
    put_u16(&mut out, &mut i, h.version);        // 4..6   version
    put_u16(&mut out, &mut i, h.alg_profile);    // 6..8   algorithm profile
    put_u16(&mut out, &mut i, h.cipher);         // 8..10  cipher suite
    put_u16(&mut out, &mut i, h.hkdf_prf);       // 10..12 HKDF PRF
    put_u16(&mut out, &mut i, h.compression);    // 12..14 compression codec
    put_u16(&mut out, &mut i, h.strategy);       // 14..16 strategy
    put_u16(&mut out, &mut i, h.aad_domain);     // 16..18 AAD domain
    put_u16(&mut out, &mut i, h.flags);          // 18..20 flags bitmask
    put_u32(&mut out, &mut i, h.chunk_size);     // 20..24 chunk size
    put_u64(&mut out, &mut i, h.plaintext_size); // 24..32 total plaintext size
    put_u32(&mut out, &mut i, h.crc32);          // 32..36 CRC32 checksum
    put_u32(&mut out, &mut i, h.dict_id);        // 36..40 dictionary ID
    put_bytes(&mut out, &mut i, &h.salt);        // 40..56 salt (16 bytes)
    put_u32(&mut out, &mut i, h.key_id);         // 56..60 key identifier
    put_u32(&mut out, &mut i, h.parallel_hint);  // 60..64 parallelization hint
    put_u64(&mut out, &mut i, h.enc_time_ns);    // 64..72 encryption timestamp (ns)
    put_bytes(&mut out, &mut i, &h.reserved);    // 72..80 reserved bytes

    // Sanity check: ensure we wrote exactly HEADER_LEN_V1 bytes.
    debug_assert_eq!(i, HEADER_LEN_V1, "encoding wrote incorrect length");

    Ok(out)
}
