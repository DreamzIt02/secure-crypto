use std::fmt;
use byteorder::{LittleEndian, ByteOrder};
use bytes::Bytes;
use crc32fast::Hasher;

use crate::utils::{ChecksumAlg, compute_checksum};

bitflags::bitflags! {
    /// ## 🚩 Segment flags (explicit, extensible)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SegmentFlags: u16 {
        /// Final segment of the stream
        const FINAL_SEGMENT = 0b0000_0001;

        /// Segment contains compressed frames
        const COMPRESSED = 0b0000_0010;

        /// Segment written after resume
        const RESUMED = 0b0000_0100;

        /// Reserved for future use
        const RESERVED = 0b1000_0000;
    }

    // > Using `bitflags` here is **intentional**:
    // > it prevents accidental semantic drift and gives us cheap validation.
}

/// Segment type identifiers for the envelope.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    /// Monotonic segment number starting at 0
    segment_index: u32,

    /// Total plaintext (or maybe compressed) bytes represented by this segment before encrypt, and after decrypt
    bytes_len: u32,

    /// Total encrypted+encoded bytes following this header (frames only), and before decrypt
    wire_len: u32,

    /// Optional integrity check of the segment wire (0 if unused)
    wire_crc32: u32,

    /// Number of frames in this segment (data + digest + terminator)
    frame_count: u32,

    /// Digest algorithm used (binds verifier)
    digest_alg: u16,

    /// Segment-level flags (LAST, CHECKPOINT, etc.)
    flags: SegmentFlags, // ✅ NOT u16

    /// CRC32 of the entire SegmentHeader (all fields above, including wire_len and wire_crc32) 
    header_crc32: u32,
}

impl SegmentHeader {
    /// Total serialized length of the header in bytes (28)
    pub const LEN: usize = 4  // segment_index
        + 4                  // bytes_len
        + 4                  // wire_len
        + 4                  // wire_crc32
        + 4                  // frame_count
        + 2                  // digest_alg
        + 2                  // flags
        + 4;                 // header_crc32

    /// Construct a fully-validated SegmentHeader.
    ///
    /// This function:
    /// - computes wire_len
    /// - computes wire_crc32
    /// - computes header_crc32 over all fields except header_crc32 itself
    /// - freezes segment metadata
    pub fn new(
        wire: &Bytes,
        segment_index: u32,
        bytes_len: u32,
        frame_count: u32,
        digest_alg: u16,
        flags: SegmentFlags,
    ) -> Self {
        // --- length ---
        let wire_len = wire.len();
        assert!(wire_len <= u32::MAX as usize, "segment wire too large");

        // --- CRC32 of wire ---
        let wire_crc32 = compute_checksum(wire, Some(ChecksumAlg::Crc32));

        // Build header without header_crc32
        let mut header = SegmentHeader {
            segment_index,
            bytes_len,
            wire_len: wire_len as u32,
            wire_crc32,
            frame_count,
            digest_alg,
            flags,
            header_crc32: 0, // placeholder
        };

        // Compute header CRC32
        let header_crc32 = header.compute_header_crc32();
        header.header_crc32 = header_crc32;

        header
    }

    /// Parse a SegmentHeader from raw bytes, including CRC validation.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, SegmentError> {
        if buf.len() < SegmentHeader::LEN {
            return Err(SegmentError::Truncated);
        }

        // Split into header fields and CRC
        let (header_bytes, crc_bytes) = buf.split_at(SegmentHeader::LEN - 4);
        let stored_crc = u32::from_le_bytes(crc_bytes.try_into().unwrap());

        // Compute CRC over header_bytes
        let computed_crc = crc32fast::hash(header_bytes);
        if stored_crc != computed_crc {
            return Err(SegmentError::Malformed("SegmentHeader CRC mismatch".into()));
        }

        // Fixed offsets
        let mut off = 0;
        let segment_index = LittleEndian::read_u32(&buf[off..off + 4]); off += 4;
        let bytes_len     = LittleEndian::read_u32(&buf[off..off + 4]); off += 4;
        let wire_len      = LittleEndian::read_u32(&buf[off..off + 4]); off += 4;
        let wire_crc32    = LittleEndian::read_u32(&buf[off..off + 4]); off += 4;
        let frame_count   = LittleEndian::read_u32(&buf[off..off + 4]); off += 4;
        let digest_alg    = LittleEndian::read_u16(&buf[off..off + 2]); off += 2;
        let flags_raw     = LittleEndian::read_u16(&buf[off..off + 2]); off += 2;
        let header_crc32  = LittleEndian::read_u32(&buf[off..off + 4]);

        let flags = SegmentFlags::from_bits(flags_raw)
            .ok_or(SegmentError::InvalidFlags { raw: flags_raw })?;

        Ok(SegmentHeader {
            segment_index,
            bytes_len,
            wire_len,
            wire_crc32,
            frame_count,
            digest_alg,
            flags,
            header_crc32,
        })
    }

    /// Compute CRC32 over all header fields except header_crc32 itself
    fn compute_header_crc32(&self) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(&self.segment_index.to_le_bytes());
        hasher.update(&self.bytes_len.to_le_bytes());
        hasher.update(&self.wire_len.to_le_bytes());
        hasher.update(&self.wire_crc32.to_le_bytes());
        hasher.update(&self.frame_count.to_le_bytes());
        hasher.update(&self.digest_alg.to_le_bytes());
        hasher.update(&(self.flags.bits()).to_le_bytes()); // assuming SegmentFlags is bitflags
        hasher.finalize()
    }

    /// Validate both wire CRC32 and header CRC32
    pub fn validate(&self, wire: &Bytes) -> Result<(), SegmentError> {
        // --- wire CRC32 ---
        let wire_crc32 = compute_checksum(wire, Some(ChecksumAlg::Crc32));
        if self.wire_crc32 != wire_crc32 {
            return Err(SegmentError::Malformed("Wire checksum failed".into()));
        }

        // --- header CRC32 ---
        let expected = self.compute_header_crc32();
        if self.header_crc32 != expected {
            return Err(SegmentError::Malformed("Header checksum failed".into()));
        }

        Ok(())
    }

    /// Accessors (read-only)
    pub fn segment_index(&self) -> u32 { self.segment_index }
    pub fn bytes_len(&self) -> u32 { self.bytes_len }
    pub fn wire_len(&self) -> u32 { self.wire_len }
    pub fn wire_crc32(&self) -> u32 { self.wire_crc32 }
    pub fn frame_count(&self) -> u32 { self.frame_count }
    pub fn digest_alg(&self) -> u16 { self.digest_alg }
    pub fn flags(&self) -> SegmentFlags { self.flags }
    pub fn header_crc32(&self) -> u32 { self.header_crc32 }

    /// Produce a concise debug summary of the segment header
    pub fn summary(&self) -> String {
        format!(
            "SegmentHeader {{ index: {}, bytes_len: {}, wire_len: {}, wire_crc32: {}, \
             frame_count: {}, digest_alg: {}, flags: {:?}, header_crc32: {} }}",
            self.segment_index,
            self.bytes_len,
            self.wire_len,
            self.wire_crc32,
            self.frame_count,
            self.digest_alg,
            self.flags,
            self.header_crc32,
        )
    }
    // ### ✅ Key Improvements
    // - **Private fields**: All fields are private, with read‑only accessors.
    // - **Header CRC32**: Computed over all fields except itself, stored in `header_crc32`.
    // - **Validation**: `validate()` checks both wire CRC32 and header CRC32.
    // - **Safety**: If `header_crc32` is corrupted, validation fails immediately before parsing other fields.
}


#[derive(Debug, Clone, Copy)]
pub struct SegmentView<'a> {
    pub header: SegmentHeader,
    pub wire: &'a [u8],
}
// ✔ decode-safe
// ✔ digest-safe
// ✔ no allocation
// ✔ lifetime-bound
// ✔ zero-copy

#[derive(Debug, Clone)]
pub enum SegmentError {
    LengthMismatch {
        expected: usize,
        actual: usize,
    },
    Truncated,
    Malformed(String),
    InvalidFlags { raw: u16 },

}

impl fmt::Display for SegmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SegmentError::*;
        match self {
            LengthMismatch { expected, actual } => write!(f, "length mismatch: expected {}, got {}", expected, actual),
            Truncated => write!(f, "truncated segment"),
            InvalidFlags { raw } => write!(f, "unknown cipher suite: {}", *raw),
            Malformed(msg) => write!(f, "malformed segment: {}", msg),
        }
    }
}

impl std::error::Error for SegmentError {}
