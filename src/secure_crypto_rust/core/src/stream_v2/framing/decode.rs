use byteorder::{LittleEndian, ReadBytesExt, ByteOrder};
use std::io::{Cursor, Read};

use crate::stream_v2::framing::types::{FRAME_VERSION, FRAME_MAGIC};
use crate::stream_v2::framing::types::{FrameType, FrameHeader, FrameRecord, FrameError};

#[inline]
pub fn parse_frame_header(buf: &[u8]) -> Result<FrameHeader, FrameError> {
    if buf.len() < FrameHeader::LEN {
        return Err(FrameError::Truncated);
    }

    // --- fixed offsets ---
    let mut off = 0;

    let magic = &buf[off..off + 4];
    off += 4;
    if magic != FRAME_MAGIC {
        let mut m = [0u8; 4];
        m.copy_from_slice(magic);
        return Err(FrameError::InvalidMagic(m));
    }

    let version = buf[off];
    off += 1;
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }

    let frame_type = FrameType::try_from_u8(buf[off])?;
    off += 1;

    let segment_index = LittleEndian::read_u64(&buf[off..off + 8]);
    off += 8;

    let frame_index = LittleEndian::read_u32(&buf[off..off + 4]);
    off += 4;

    let plaintext_len = LittleEndian::read_u32(&buf[off..off + 4]);
    off += 4;

    let compressed_len = LittleEndian::read_u32(&buf[off..off + 4]);
    off += 4;

    let ciphertext_len = LittleEndian::read_u32(&buf[off..off + 4]);

    Ok(FrameHeader {
        frame_type,
        segment_index,
        frame_index,
        plaintext_len,
        compressed_len,
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
pub fn decode_frame(buf: &[u8]) -> Result<FrameRecord, FrameError> {
    let header = parse_frame_header(buf)?;

    let expected_len = FrameHeader::LEN + header.ciphertext_len as usize;
    if buf.len() != expected_len {
        return Err(FrameError::LengthMismatch {
            expected: expected_len,
            actual: buf.len(),
        });
    }

    let ciphertext = buf[FrameHeader::LEN..expected_len].to_vec();

    Ok(FrameRecord {
        header,
        ciphertext,
    })
}
/// Decode a single frame from bytes.
///
/// Caller guarantees:
/// - Full frame bytes are provided
/// - Ordering is handled externally
pub fn decode_frame_explicit(buf: &[u8]) -> Result<FrameRecord, FrameError> {
    if buf.len() < FrameHeader::LEN {
        return Err(FrameError::Truncated);
    }

    let mut cur = Cursor::new(buf);

    let mut magic = [0u8; 4];
    cur.read_exact(&mut magic).map_err(|_| FrameError::Truncated)?;
    if magic != FRAME_MAGIC {
        return Err(FrameError::InvalidMagic(magic));
    }

    let version = cur.read_u8().map_err(|_| FrameError::Truncated)?;
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }

    let frame_type =
        FrameType::try_from_u8(cur.read_u8().map_err(|_| FrameError::Truncated)?)?;

    let segment_index = cur.read_u64::<LittleEndian>().map_err(|_| FrameError::Truncated)?;
    let frame_index = cur.read_u32::<LittleEndian>().map_err(|_| FrameError::Truncated)?;
    let plaintext_len = cur.read_u32::<LittleEndian>().map_err(|_| FrameError::Truncated)?;
    let compressed_len = cur.read_u32::<LittleEndian>().map_err(|_| FrameError::Truncated)?;
    let ciphertext_len = cur.read_u32::<LittleEndian>().map_err(|_| FrameError::Truncated)?;

    let header = FrameHeader {
        frame_type,
        segment_index,
        frame_index,
        plaintext_len,
        compressed_len,
        ciphertext_len,
    };

    let expected_len = FrameHeader::LEN + ciphertext_len as usize;
    if buf.len() != expected_len {
        return Err(FrameError::LengthMismatch {
            expected: expected_len,
            actual: buf.len(),
        });
    }

    let mut ciphertext = vec![0u8; ciphertext_len as usize];
    cur.read_exact(&mut ciphertext).map_err(|_| FrameError::Truncated)?;

    Ok(FrameRecord {
        header,
        ciphertext,
    })
}
