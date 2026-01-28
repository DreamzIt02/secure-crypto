use byteorder::{LittleEndian, WriteBytesExt};

use crate::stream_v2::framing::types::{FRAME_VERSION, FRAME_MAGIC};
use crate::stream_v2::framing::types::{FrameHeader, FrameError};
/// Encode a frame record into canonical wire format.
///
/// Layout:
///
/// ```text
/// [ magic (4) ]
/// [ version (1) ]
/// [ frame_type (1) ]
/// [ segment_index (4) ]
/// [ frame_index (4) ]
/// [ plaintext_len (4) ]
/// [ ciphertext_len (4) ]
/// [ ciphertext (M) ]
/// ```
pub fn encode_frame(
    header: &FrameHeader,
    ciphertext: &[u8],
) -> Result<Vec<u8>, FrameError> {
    let expected = FrameHeader::LEN + header.ciphertext_len as usize;

    if ciphertext.len() != header.ciphertext_len as usize {
        return Err(FrameError::LengthMismatch {
            expected,
            actual: ciphertext.len(),
        });
    }

    let mut wire = Vec::with_capacity(expected);

    // --- Header ---
    wire.extend_from_slice(&FRAME_MAGIC);
    wire.push(FRAME_VERSION);
    wire.push(header.frame_type.try_to_u8()?);

    wire.write_u32::<LittleEndian>(header.segment_index).unwrap();
    wire.write_u32::<LittleEndian>(header.frame_index).unwrap();
    wire.write_u32::<LittleEndian>(header.plaintext_len).unwrap();
    // wire.write_u32::<LittleEndian>(header.compressed_len).unwrap();
    wire.write_u32::<LittleEndian>(header.ciphertext_len).unwrap();

    // --- Body ---
    wire.extend_from_slice(ciphertext);

    // --- Validation ---
    debug_assert_eq!(wire.len(), expected);

    Ok(wire)

    // ### 🔥 Why this is better

    // * Encoding no longer **requires ownership**
    // * Ciphertext can be:

    // * `Vec<u8>`
    // * `Bytes`
    // * slice from another buffer
    // * Header + body are **logically separated**
}
