use crate::stream_v2::segmenting::{SegmentHeader, types::{SegmentError, SegmentView}};

// ✅ **This is segmenting-only**
// ✅ **No duplicate decode logic**
// ✅ **Zero-copy slicing works perfectly**
#[inline]
pub fn decode_segment_header(wire: &[u8]) -> Result<SegmentHeader, SegmentError> {
    SegmentHeader::from_bytes(wire)
}

/// Decode a single segment from bytes.
///
/// Caller guarantees:
/// - Full segment bytes are provided
/// - Ordering is handled externally
pub fn decode_segment(wire: &[u8]) -> Result<SegmentView<'_>, SegmentError> {
    let header = SegmentHeader::from_bytes(wire)?;

    let expected_len = SegmentHeader::LEN + header.wire_len() as usize;
    if wire.len() != expected_len {
        return Err(SegmentError::LengthMismatch {
            expected: expected_len,
            actual: wire.len(),
        });
    }

    let segment_wire = &wire[SegmentHeader::LEN..expected_len];

    Ok(SegmentView {
        header,
        wire: segment_wire,
    })

    // 🚫 no `Vec`
    // 🚫 no allocation
    // 🚫 no copy
    // ✔ constant time
    // ✔ cache-friendly
}
