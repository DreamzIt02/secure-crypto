use byteorder::{LittleEndian, WriteBytesExt};
use bytes::Bytes;

use crate::stream_v2::segmenting::{SegmentHeader, types::SegmentError};

/// Encode a segment record into canonical wire format.
///
/// Layout:
///
/// ```text
/// [ segment_index (4) ]
/// [ bytes_len     (4) ]
/// [ wire_len      (4) ]
/// [ wire_crc32    (4) ]
/// [ frame_count   (2) ]
/// [ digest_alg    (2) ]
/// [ flags         (2) ]
/// [ reserved      (2) ]
/// ```
pub fn encode_segment(
    header: &SegmentHeader,
    segment_wire: &Bytes,
) -> Result<Vec<u8>, SegmentError> {
    let expected = SegmentHeader::LEN + header.wire_len as usize;

    if segment_wire.len() != header.wire_len as usize {
        return Err(SegmentError::LengthMismatch {
            expected,
            actual: segment_wire.len(),
        });
    }

    let mut wire = Vec::with_capacity(expected);

    // --- Header ---
    wire.write_u32::<LittleEndian>(header.segment_index).unwrap();
    wire.write_u32::<LittleEndian>(header.bytes_len).unwrap();
    wire.write_u32::<LittleEndian>(header.wire_len).unwrap();
    wire.write_u32::<LittleEndian>(header.wire_crc32).unwrap();
    wire.write_u32::<LittleEndian>(header.frame_count).unwrap();
    wire.write_u16::<LittleEndian>(header.digest_alg).unwrap();
    wire.write_u16::<LittleEndian>(header.flags.bits()).unwrap();
    wire.write_u16::<LittleEndian>(header.reserved).unwrap();

    // --- Body ---
    wire.extend_from_slice(segment_wire);

    // --- Validation ---
    debug_assert_eq!(wire.len(), expected);

    Ok(wire)

    // ### 🔥 Why this is better

    // * Encoding no longer **requires ownership**
    // * Segment_wire can be:

    // * `Vec<u8>`
    // * `Bytes`
    // * slice from another buffer
    // * Header + body are **logically separated**
}
