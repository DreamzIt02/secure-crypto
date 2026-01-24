use std::fmt;
use num_enum::TryFromPrimitive;

pub const FRAME_MAGIC: [u8; 4] = *b"SV2F";
pub const FRAME_VERSION: u8 = 1;

/// Frame type identifiers for the envelope.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
pub enum FrameType {
    Data       = 0x0001,
    Terminator = 0x0002,
    Digest     = 0x0003,
}

impl FrameType {
    #[inline(always)]
    pub const fn to_le_bytes(self) -> [u8; 2] {
        (self as u16).to_le_bytes()
    }

    #[inline(always)]
    pub const fn from_u16_le(v: u16) -> Result<Self, FrameError> {
        let lo = (v & 0x00FF) as u8;
        let hi = (v >> 8) as u8;

        // Reject non-canonical encodings (future-proof & strict)
        if hi != 0 {
            return Err(FrameError::InvalidFrameType(lo));
        }

        match lo {
            0x01 => Ok(FrameType::Data),
            0x02 => Ok(FrameType::Terminator),
            0x03 => Ok(FrameType::Digest),
            _ => Err(FrameError::InvalidFrameType(lo)),
        }
    }

    #[inline(always)]
    pub const fn try_from_u8(v: u8) -> Result<Self, FrameError> {
        match v {
            0x01 => Ok(FrameType::Data),
            0x02 => Ok(FrameType::Terminator),
            0x03 => Ok(FrameType::Digest),
            _ => Err(FrameError::InvalidFrameType(v)),
        }
    }
    
    /// Canonical wire encoding (1 byte).
    #[inline(always)]
    pub const fn try_to_u8(self) -> Result<u8, FrameError> {
        let v = self as u16;
        let lo = (v & 0x00FF) as u8;
        let hi = (v >> 8) as u8;

        // Enforce canonical single-byte encoding
        if hi != 0 {
            return Err(FrameError::InvalidFrameType(lo));
        }

        Ok(lo)
    }
}

/// Canonical frame header (fixed size)
///
/// All fields are little-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub segment_index: u64,
    pub frame_index: u32,
    pub frame_type: FrameType,
    /// Plaintext length in this frame (DATA only; last frame may be < chunk_size).
    pub plaintext_len: u32,
    /// Ciphertext bytes in this frame (DATA only).
    pub ciphertext_len: u32,
}

impl FrameHeader {
    pub const LEN: usize = 4  // magic
        + 1                  // version
        + 1                  // frame_type
        + 8                  // segment_index
        + 4                  // frame_index
        + 4                  // plaintext_len
        + 4;                 // ciphertext_len

    /// Summary: Construct a zeroed header (not valid until fields are set).
    /// Industry note: callers must populate lengths and tag, then validate.
    pub fn zero() -> Self {
        Self {
            frame_type: FrameType::Terminator,
            segment_index: 0,
            frame_index: 0,
            plaintext_len: 0,
            ciphertext_len: 0,
        }
    }

    /// Canonical header for tests.
    /// Guaranteed to pass `validate()` unless a regression is introduced.
    pub fn test_header(frame_type: FrameType, segment_index: u64) -> Self {
        Self {
            frame_type: frame_type,
            segment_index: segment_index,
            frame_index: 0,
            plaintext_len: 0,
            ciphertext_len: 0,
        }
    }

    // ### 1. Add helpers to `FrameHeader`

    /// Convert raw u16 → FrameType enum
    pub fn frame_type_enum(&self) -> Option<FrameType> {
        FrameType::try_from(self.frame_type).ok()
    }

    /// Set raw u16 from FrameType enum
    pub fn set_frame_type(&mut self, ft: FrameType) {
        self.frame_type = ft;
    }

    /// Convenience: return human‑readable string
    pub fn frame_type_str(&self) -> &'static str {
        match self.frame_type_enum() {
            Some(FrameType::Data) => "data",
            Some(FrameType::Terminator) => "terminator",
            Some(FrameType::Digest) => "digest",
            None => "unknown",
        }
    }

}

// ## 1️⃣ Replace `FrameRecord` with a *borrowed* view
#[derive(Debug, Clone, Copy)]
pub struct FrameView<'a> {
    pub header: FrameHeader,
    pub ciphertext: &'a [u8],
}
// ✔ decode-safe
// ✔ digest-safe
// ✔ no allocation
// ✔ lifetime-bound
// ✔ zero-copy


#[derive(Debug)]
pub enum FrameError {
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u8),
    InvalidFrameType(u8),
    LengthMismatch {
        expected: usize,
        actual: usize,
    },
    Truncated,
    Malformed(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FrameError::*;
        match self {
            InvalidMagic(m) =>
                write!(f, "invalid frame magic: {:?}", m),
            UnsupportedVersion(v) =>
                write!(f, "unsupported frame version: {}", v),
            InvalidFrameType(v) =>
                write!(f, "invalid frame type: {}", v),
            LengthMismatch { expected, actual } =>
                write!(f, "length mismatch: expected {}, got {}", expected, actual),
            Truncated =>
                write!(f, "truncated frame"),
            Malformed(msg) =>
                write!(f, "malformed frame: {}", msg),
        }
    }
}

impl std::error::Error for FrameError {}
