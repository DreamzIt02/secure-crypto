use crate::stream_v2::framing::types::FrameView;
use crate::stream_v2::framing::types::{FrameHeader, FrameError};

// ✅ **This is framing-only**
// ✅ **No duplicate decode logic**
// ✅ **Zero-copy slicing works perfectly**
#[inline]
pub fn decode_frame_header(buf: &[u8]) -> Result<FrameHeader, FrameError> {
    FrameHeader::from_bytes(buf)
}

/// Decode a single frame from bytes.
///
/// Caller guarantees:
/// - Full frame bytes are provided
/// - Ordering is handled externally
pub fn decode_frame(wire: &[u8]) -> Result<FrameView<'_>, FrameError> {
    let header = FrameHeader::from_bytes(wire)?;

    let expected_len = FrameHeader::LEN + header.ciphertext_len() as usize;
    if wire.len() != expected_len {
        return Err(FrameError::LengthMismatch {
            expected: expected_len,
            actual: wire.len(),
        });
    }

    let ciphertext = &wire[FrameHeader::LEN..expected_len];

    Ok(FrameView { header, ciphertext })

    // 🚫 no `Vec`
    // 🚫 no allocation
    // 🚫 no copy
    // ✔ constant time
    // ✔ cache-friendly
}

// ### In‑Place Decode

#[inline]
pub fn decode_header_in_place(buf: &[u8]) -> Result<FrameHeader, FrameError> {
    FrameHeader::from_bytes(buf)
}

pub fn decode_in_place<'a>(wire: &'a [u8]) -> Result<FrameView<'a>, FrameError> {
    let header = FrameHeader::from_bytes(wire)?;

    let expected_len = FrameHeader::LEN + header.ciphertext_len() as usize;
    if wire.len() != expected_len {
        return Err(FrameError::LengthMismatch {
            expected: expected_len,
            actual: wire.len(),
        });
    }

    let ciphertext = &wire[FrameHeader::LEN..expected_len];

    Ok(FrameView { header, ciphertext })
}

// ### Key Differences
// - **Caller provides buffer**: `encode_frame_in_place` writes directly into a `BytesMut` supplied by the caller, instead of returning a new `Vec<u8>`.
// - **No extra allocations**: We control buffer reuse (e.g., via a slab allocator), so repeated calls don’t churn the allocator.
// - **Decode stays zero‑copy**: It just slices into the provided wire buffer, no new allocations.

// ### Usage Example
// ```rust
// let mut buf = BytesMut::with_capacity(FrameHeader::LEN + ciphertext.len());
// encode_frame_in_place(&header, &ciphertext, &mut buf)?;
// let wire = buf.freeze();

// let view = decode_frame_in_place(&wire)?;
// ```