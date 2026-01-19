use byteorder::{LittleEndian, WriteBytesExt};

use crate::stream_v2::framing::types::{FRAME_VERSION, FRAME_MAGIC};
use crate::stream_v2::framing::types::{FrameHeader, FrameRecord, FrameError};
/// Encode a frame record into canonical wire format.
///
/// Layout:
///
/// ```text
/// [ magic (4) ]
/// [ version (1) ]
/// [ frame_type (1) ]
/// [ segment_index (8) ]
/// [ frame_index (4) ]
/// [ plaintext_len (4) ]
/// [ compressed_len (4) ]
/// [ ciphertext_len (4) ]
/// [ ciphertext (M) ]
/// ```
pub fn encode_frame(record: &FrameRecord) -> Result<Vec<u8>, FrameError> {
    let expected = FrameHeader::LEN + record.header.ciphertext_len as usize;
    let mut out = Vec::with_capacity(expected);

    // --- Header ---
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.push(record.header.frame_type.try_to_u8()?);
    
    out.write_u64::<LittleEndian>(record.header.segment_index).unwrap();
    out.write_u32::<LittleEndian>(record.header.frame_index).unwrap();
    out.write_u32::<LittleEndian>(record.header.plaintext_len).unwrap();
    out.write_u32::<LittleEndian>(record.header.compressed_len).unwrap();
    out.write_u32::<LittleEndian>(record.header.ciphertext_len).unwrap();

    // --- Body ---
    out.extend_from_slice(&record.ciphertext);

    // --- Validation ---
    if out.len() != expected {
        return Err(FrameError::LengthMismatch {
            expected,
            actual: out.len(),
        });
    }

    Ok(out)
}
