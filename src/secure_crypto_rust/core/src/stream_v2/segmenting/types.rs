use std::fmt;
use bytes::Bytes;

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

/// Segmetn type identifiers for the envelope.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    /// Monotonic segment number starting at 0
    pub segment_index: u32,

    /// Total plaintext (or maybe compressed) bytes represented by this segment before encrypt, and after decrypt
    pub bytes_len: u32,

    /// Total encrypted+encoded bytes following this header (frames only), and before decrypt
    pub wire_len: u32,

    /// Optional integrity check of the segment wire (0 if unused)
    pub wire_crc32: u32,

    /// Number of frames in this segment (data + digest + terminator)
    pub frame_count: u32,

    /// Digest algorithm used (binds verifier)
    pub digest_alg: u16,

    /// Segment-level flags (LAST, CHECKPOINT, etc.)
    pub flags: SegmentFlags, // ✅ NOT u16

    /// Reserved for future use; must be zero
    pub reserved: u16,
}

impl SegmentHeader {
    pub const LEN: usize = 4  // segment_index
        + 4                  // bytes_len
        + 4                  // wire_len
        + 4                  // wire_crc32
        + 4                  // frame_count
        + 2                  // digest_alg
        + 2                  // flags
        + 2;                 // reserved

    /// Construct a fully-validated SegmentHeader.
    ///
    /// This function:
    /// - computes wire_len
    /// - computes CRC32
    /// - freezes segment metadata
    ///
    /// Callers must NOT mutate fields afterward.
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
        assert!(
            wire_len <= u32::MAX as usize,
            "segment wire too large"
        );

        // --- CRC32 ---
        let wire_crc32 = compute_checksum(wire, Some(ChecksumAlg::Crc32));
        
        SegmentHeader {
            segment_index,
            wire_len: wire_len as u32,
            bytes_len: bytes_len as u32,
            wire_crc32: wire_crc32,
            frame_count,
            digest_alg,
            flags: flags,
            reserved: 0u16,
        }
    }

    pub fn validate(&self, wire: &Bytes) -> Result<(), SegmentError> {
        // --- CRC32 ---
        let wire_crc32 = compute_checksum(wire, Some(ChecksumAlg::Crc32));

        if self.wire_crc32 != wire_crc32 {
            return Err(SegmentError::Malformed("Wire checksum failed".into()));
        }
        Ok(())
    }
    /// Produce a concise debug summary of the segment header
    pub fn summary(&self) -> String {
        format!(
            "SegmentHeader {{ index: {}, bytes_len: {}, wire_len: {}, crc32: {}, \
             frame_count: {}, digest_alg: {}, flags: {:?}, reserved: {} }}",
            self.segment_index,
            self.bytes_len,
            self.wire_len,
            self.wire_crc32,
            self.frame_count,
            self.digest_alg,
            self.flags,
            self.reserved,
        )
    }
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

#[derive(Debug)]
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
