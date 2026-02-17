use std::fmt;
use byteorder::{LittleEndian, ByteOrder};

pub const FRAME_MAGIC: [u8; 4] = *b"SV2F";
pub const FRAME_VERSION: u8 = 1;

/// Frame type identifiers for the envelope.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, num_enum::TryFromPrimitive)]
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
    segment_index: u32,
    frame_index: u32,
    frame_type: FrameType,
    /// Plaintext length in this frame (DATA only; last frame may be < frame_size).
    plaintext_len: u32,
    /// Ciphertext bytes in this frame (DATA only).
    ciphertext_len: u32,
}

impl FrameHeader {
    /// Fixed header wire length (22 bytes)
    pub const LEN: usize = 4  // magic
        + 1                  // version
        + 1                  // frame_type
        + 4                  // segment_index
        + 4                  // frame_index
        + 4                  // plaintext_len
        + 4;                 // ciphertext_len

    /// Construct a new header
    pub fn new(
        segment_index: u32,
        frame_index: u32,
        frame_type: FrameType,
        plaintext_len: u32,
        ciphertext_len: u32,
    ) -> Self {
        Self {
            segment_index,
            frame_index,
            frame_type,
            plaintext_len,
            ciphertext_len,
        }
    }

    /// Accessors
    pub fn segment_index(&self) -> u32 { self.segment_index }
    pub fn frame_index(&self) -> u32 { self.frame_index }
    pub fn frame_type(&self) -> FrameType { self.frame_type }
    pub fn plaintext_len(&self) -> u32 { self.plaintext_len }
    pub fn ciphertext_len(&self) -> u32 { self.ciphertext_len }

    /// Encode to wire
    pub fn to_bytes(&self) -> [u8; FrameHeader::LEN] {
        let mut buf = [0u8; FrameHeader::LEN];
        buf[0..4].copy_from_slice(&FRAME_MAGIC);
        buf[4] = FRAME_VERSION;
        buf[5] = self.frame_type.try_to_u8().unwrap();
        LittleEndian::write_u32(&mut buf[6..10], self.segment_index);
        LittleEndian::write_u32(&mut buf[10..14], self.frame_index);
        LittleEndian::write_u32(&mut buf[14..18], self.plaintext_len);
        LittleEndian::write_u32(&mut buf[18..22], self.ciphertext_len);
        buf
    }
    
    /// Decode from wire
    pub fn from_bytes(buf: &[u8]) -> Result<Self, FrameError> {
        if buf.len() < FrameHeader::LEN {
            return Err(FrameError::Truncated);
        }

        // magic
        if &buf[0..4] != FRAME_MAGIC {
            let mut m = [0u8; 4];
            m.copy_from_slice(&buf[0..4]);
            return Err(FrameError::InvalidMagic(m));
        }

        // version
        let version = buf[4];
        if version != FRAME_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }

        // frame type
        let frame_type = FrameType::try_from_u8(buf[5])?;

        // fields
        let segment_index = LittleEndian::read_u32(&buf[6..10]);
        let frame_index   = LittleEndian::read_u32(&buf[10..14]);
        let plaintext_len = LittleEndian::read_u32(&buf[14..18]);
        let ciphertext_len= LittleEndian::read_u32(&buf[18..22]);

        Ok(FrameHeader::new(
            segment_index,
            frame_index,
            frame_type,
            plaintext_len,
            ciphertext_len,
        ))
    }

    /// Validate structural sanity
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.ciphertext_len == 0 && self.frame_type == FrameType::Data {
            return Err(FrameError::Malformed("data frame with zero ciphertext".into()));
        }
        Ok(())
    }

    pub fn summary(&self) -> String {
        format!(
            "FrameHeader {{ seg: {}, frame: {}, type: {:?}, plaintext_len: {}, ciphertext_len: {} }}",
            self.segment_index,
            self.frame_index,
            self.frame_type,
            self.plaintext_len,
            self.ciphertext_len,
        )
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

// ## `FrameView`
#[derive(Debug, Clone, Copy)]
pub struct FrameView<'a> {
    pub header: FrameHeader,
    pub ciphertext: &'a [u8],

    // ✔ decode-safe
    // ✔ digest-safe
    // ✔ no allocation
    // ✔ lifetime-bound
    // ✔ zero-copy
}

impl<'a> FrameView<'a> {
    pub fn from_wire(buf: &'a [u8]) -> Result<Self, FrameError> {
        let header = FrameHeader::from_bytes(buf)?;
        let expected_len = FrameHeader::LEN + header.ciphertext_len() as usize;
        if buf.len() != expected_len {
            return Err(FrameError::LengthMismatch {
                expected: expected_len,
                actual: buf.len(),
            });
        }
        let ciphertext = &buf[FrameHeader::LEN..expected_len];
        Ok(FrameView { header, ciphertext })
    }
}


#[derive(Debug, Clone)]
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
