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
