use byteorder::{LittleEndian, ByteOrder};

use crate::stream_v2::segmenting::{SegmentHeader, types::{SegmentError, SegmentFlags, SegmentView}};


#[inline]
pub fn parse_segment_header(wire: &[u8]) -> Result<SegmentHeader, SegmentError> {
    if wire.len() < SegmentHeader::LEN {
        return Err(SegmentError::Truncated);
    }

    // --- fixed offsets ---
    let mut off = 0;

    let segment_index = LittleEndian::read_u32(&wire[off..off + 4]);
    off += 4;

    let bytes_len = LittleEndian::read_u32(&wire[off..off + 4]);
    off += 4;

    let wire_len = LittleEndian::read_u32(&wire[off..off + 4]);
    off += 4;

    let wire_crc32 = LittleEndian::read_u32(&wire[off..off + 4]);
    off += 4;

    let frame_count = LittleEndian::read_u32(&wire[off..off + 4]);
    off += 4;

    let digest_alg = LittleEndian::read_u16(&wire[off..off + 2]);
    off += 2;

    let flags_raw = LittleEndian::read_u16(&wire[off..off + 2]);
    off += 2;

    let reserved = LittleEndian::read_u16(&wire[off..off + 2]);

    let flags = SegmentFlags::from_bits(flags_raw)
        .ok_or(SegmentError::InvalidFlags{raw: flags_raw})?;

    Ok(SegmentHeader {
        segment_index,
        bytes_len,
        wire_len,
        wire_crc32,
        frame_count,
        digest_alg,
        flags,
        reserved,
    })
}

// ✅ **This is segmenting-only**
// ✅ **No duplicate decode logic**
// ✅ **Zero-copy slicing works perfectly**
#[inline]
pub fn decode_segment_header(buf: &[u8]) -> Result<SegmentHeader, SegmentError> {
    parse_segment_header(buf)
}

/// Decode a single segment from bytes.
///
/// Caller guarantees:
/// - Full segment bytes are provided
/// - Ordering is handled externally
pub fn decode_segment(wire: &[u8]) -> Result<SegmentView<'_>, SegmentError> {
    let header = parse_segment_header(wire)?;

    let expected_len = SegmentHeader::LEN + header.wire_len as usize;
    if wire.len() != expected_len {
        return Err(SegmentError::LengthMismatch {
            expected: expected_len,
            actual: wire.len(),
        });
    }

    let segment_sire = &wire[SegmentHeader::LEN..expected_len];

    Ok(SegmentView {
        header,
        wire: segment_sire,
    })

    // 🚫 no `Vec`
    // 🚫 no allocation
    // 🚫 no copy
    // ✔ constant time
    // ✔ cache-friendly
}
