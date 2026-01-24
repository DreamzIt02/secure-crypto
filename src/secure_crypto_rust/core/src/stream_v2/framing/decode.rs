use byteorder::{LittleEndian, ByteOrder};

use crate::stream_v2::framing::types::{FRAME_MAGIC, FRAME_VERSION, FrameView};
use crate::stream_v2::framing::types::{FrameType, FrameHeader, FrameError};

#[inline]
pub fn parse_frame_header(wire: &[u8]) -> Result<FrameHeader, FrameError> {
    if wire.len() < FrameHeader::LEN {
        return Err(FrameError::Truncated);
    }

    // --- fixed offsets ---
    let mut off = 0;

    let magic = &wire[off..off + 4];
    off += 4;
    if magic != FRAME_MAGIC {
        let mut m = [0u8; 4];
        m.copy_from_slice(magic);
        return Err(FrameError::InvalidMagic(m));
    }

    let version = wire[off];
    off += 1;
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }

    let frame_type = FrameType::try_from_u8(wire[off])?;
    off += 1;

    let segment_index = LittleEndian::read_u64(&wire[off..off + 8]);
    off += 8;

    let frame_index = LittleEndian::read_u32(&wire[off..off + 4]);
    off += 4;

    let plaintext_len = LittleEndian::read_u32(&wire[off..off + 4]);
    off += 4;

    // let compressed_len = LittleEndian::read_u32(&wire[off..off + 4]);
    // off += 4;

    let ciphertext_len = LittleEndian::read_u32(&wire[off..off + 4]);

    Ok(FrameHeader {
        frame_type,
        segment_index,
        frame_index,
        plaintext_len,
        ciphertext_len,
    })
}

// ✅ **This is framing-only**
// ✅ **No duplicate decode logic**
// ✅ **Zero-copy slicing works perfectly**
#[inline]
pub fn decode_frame_header(buf: &[u8]) -> Result<FrameHeader, FrameError> {
    parse_frame_header(buf)
}
/// Decode a single frame from bytes.
///
/// Caller guarantees:
/// - Full frame bytes are provided
/// - Ordering is handled externally
pub fn decode_frame(wire: &[u8]) -> Result<FrameView<'_>, FrameError> {
    let header = parse_frame_header(wire)?;

    let expected_len = FrameHeader::LEN + header.ciphertext_len as usize;
    if wire.len() != expected_len {
        return Err(FrameError::LengthMismatch {
            expected: expected_len,
            actual: wire.len(),
        });
    }

    let ciphertext = &wire[FrameHeader::LEN..expected_len];

    Ok(FrameView {
        header,
        ciphertext,
    })

    // 🚫 no `Vec`
    // 🚫 no allocation
    // 🚫 no copy
    // ✔ constant time
    // ✔ cache-friendly
}
