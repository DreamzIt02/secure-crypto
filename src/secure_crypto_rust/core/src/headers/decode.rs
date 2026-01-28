// ## 📂 File: `src/headers/decode.rs`
//! src/headers/decode.rs
//!
//! Header decoding utilities.
//!
//! Design notes:
//! - Deserializes a fixed 80‑byte buffer into a `HeaderV1` struct.
//! - Field order must match `encode.rs` exactly for ABI stability.
//! - Validation is performed after decoding to reject malformed or incompatible streams.
//! - Treat header as authoritative source for strategy and chunk sizing.

use crate::headers::types::{HeaderV1, HeaderError};

/// Deserialize an 80‑byte little‑endian header into `HeaderV1`.
///
/// # Returns
/// - `Ok(HeaderV1)` if decoding and validation succeed.
/// - `Err(HeaderError)` if buffer length mismatches or validation fails.
///
/// # Notes
/// - Field order must match the struct layout in `encode.rs`.
/// - Uses helper functions for compact little‑endian reads.
/// - Debug assertion ensures exactly 80 bytes are consumed.
#[inline]
pub fn decode_header_le(buf: &[u8]) -> Result<HeaderV1, HeaderError> {
    // Ensure buffer has at least HEADER_LEN_V1 bytes.
    if buf.len() < HeaderV1::LEN {
        return Err(HeaderError::BufferTooShort { have: buf.len(), need: HeaderV1::LEN });
    }

    // Cursor helpers
    let mut i = 0usize;
    #[inline] fn get_u16(buf: &[u8], i: &mut usize) -> u16 { let v = u16::from_le_bytes(buf[*i..*i+2].try_into().unwrap()); *i += 2; v }
    #[inline] fn get_u32(buf: &[u8], i: &mut usize) -> u32 { let v = u32::from_le_bytes(buf[*i..*i+4].try_into().unwrap()); *i += 4; v }
    #[inline] fn get_u64(buf: &[u8], i: &mut usize) -> u64 { let v = u64::from_le_bytes(buf[*i..*i+8].try_into().unwrap()); *i += 8; v }
    #[inline] fn get_bytes<const N: usize>(buf: &[u8], i: &mut usize) -> [u8; N] {
        let mut dst = [0u8; N]; dst.copy_from_slice(&buf[*i..*i+N]); *i += N; dst
    }

    // Initialize header with defaults.
    let mut h = HeaderV1::default();

    // Field order must match encode.rs layout.
    h.magic          = get_bytes::<4>(buf, &mut i);   // 0..4   magic number
    h.version        = get_u16(buf, &mut i);            // 4..6   version
    h.alg_profile    = get_u16(buf, &mut i);            // 6..8   algorithm profile
    h.cipher         = get_u16(buf, &mut i);            // 8..10  cipher suite
    h.hkdf_prf       = get_u16(buf, &mut i);            // 10..12 HKDF PRF
    h.compression    = get_u16(buf, &mut i);            // 12..14 compression codec
    h.strategy       = get_u16(buf, &mut i);            // 14..16 strategy
    h.aad_domain     = get_u16(buf, &mut i);            // 16..18 AAD domain
    h.flags          = get_u16(buf, &mut i);            // 18..20 flags bitmask
    h.chunk_size     = get_u32(buf, &mut i);            // 20..24 chunk size
    h.plaintext_size = get_u64(buf, &mut i);            // 24..32 total plaintext size
    h.crc32          = get_u32(buf, &mut i);            // 32..36 CRC32 checksum
    h.dict_id        = get_u32(buf, &mut i);            // 36..40 dictionary ID
    h.salt           = get_bytes::<16>(buf, &mut i); // 40..56 salt (16 bytes)
    h.key_id         = get_u32(buf, &mut i);            // 56..60 key identifier
    h.parallel_hint  = get_u32(buf, &mut i);            // 60..64 parallelization hint
    h.enc_time_ns    = get_u64(buf, &mut i);            // 64..72 encryption timestamp (ns)
    h.reserved       = get_bytes::<8>(buf, &mut i);  // 72..80 reserved bytes

    // Sanity check: ensure we consumed exactly HEADER_LEN_V1 bytes.
    if i != HeaderV1::LEN {
        return Err(HeaderError::BufferTooShort { have: i, need: HeaderV1::LEN });
    }

    // ✅ CRC32 validation: compute over first 32 bytes (0..32)
    let computed_crc = crc32fast::hash(&buf[0..32]);
    if h.crc32 != computed_crc {
        return Err(HeaderError::InvalidCrc32 { have: h.crc32 as usize, need: computed_crc as usize });
    }

    // Validate decoded header fields.
    h.validate()?;

    Ok(h)
}
