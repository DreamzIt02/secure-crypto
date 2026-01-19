// ## 📂 File: `src/headers/types.rs`

//! headers/types.rs
//! Core header struct and typed views.
//!
//! Industry notes:
//! - #[repr(C)] + fixed field sizes ensures binary stability across Rust and FFI.
//! - Use little-endian when writing/reading multi-byte integers for cross-language parity.
//! - Reserved bytes allow future fields without changing size; always zero them.
//! - This header is 80 bytes, fixed length, designed for reproducibility and forward compatibility.

use std::fmt;
use num_enum::TryFromPrimitive;

use crate::compression::CodecError;
use crate::compression::CompressionCodec;
use crate::constants::HEADER_V1;
use crate::constants::{MAGIC_RSE1, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE};
use crate::constants::{cipher_ids, prf_ids, flags};

/// Fixed header size in bytes.
pub const HEADER_LEN_V1: usize = 80;

/// Strategy choices for encoder metadata (decoder may still parallelize).
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum Strategy {
    Sequential = 0x0000,
    Parallel   = 0x0001,
    Auto       = 0x0002,
}
impl Strategy {
    pub fn verify(raw: u16) -> Result<(), HeaderError> {
        match raw {
            x if x == Strategy::Sequential as u16 => Ok(()),
            x if x == Strategy::Parallel as u16   => Ok(()),
            x if x == Strategy::Auto as u16       => Ok(()),
            _ => Err(HeaderError::UnknownStrategy { raw }),
        }
    }
}

/// Cipher suites (header registry).
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum CipherSuite {
    Aes256Gcm        = cipher_ids::AES256_GCM,
    Chacha20Poly1305 = cipher_ids::CHACHA20_POLY1305,
}
impl CipherSuite {
    pub fn verify(raw: u16) -> Result<(), HeaderError> {
        match raw {
            x if x == CipherSuite::Aes256Gcm as u16        => Ok(()),
            x if x == CipherSuite::Chacha20Poly1305 as u16 => Ok(()),
            _ => Err(HeaderError::UnknownCipherSuite { raw }),
        }
    }
}

/// HKDF PRF choices (header registry).
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum HkdfPrf {
    Sha256  = prf_ids::SHA256,
    Sha512  = prf_ids::SHA512,
    Blake3K = prf_ids::BLAKE3K,
}
impl HkdfPrf {
    pub fn verify(raw: u16) -> Result<(), HeaderError> {
        match raw {
            x if x == HkdfPrf::Sha256 as u16  => Ok(()),
            x if x == HkdfPrf::Sha512 as u16  => Ok(()),
            x if x == HkdfPrf::Blake3K as u16 => Ok(()),
            _ => Err(HeaderError::UnknownHkdfPrf { raw }),
        }
    }
}

/// Algorithm profile bundles cipher + PRF combinations.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum AlgProfile {
    Aes256GcmHkdfSha256         = 0x0101,
    Aes256GcmHkdfSha512         = 0x0102,
    Chacha20Poly1305HkdfSha256  = 0x0201,
    Chacha20Poly1305HkdfSha512  = 0x0202,
    Chacha20Poly1305HkdfBlake3K = 0x0203,
}
impl AlgProfile {
    pub fn verify(raw: u16) -> Result<(), HeaderError> {
        match raw {
            x if x == AlgProfile::Aes256GcmHkdfSha256 as u16         => Ok(()),
            x if x == AlgProfile::Aes256GcmHkdfSha512 as u16         => Ok(()),
            x if x == AlgProfile::Chacha20Poly1305HkdfSha256 as u16  => Ok(()),
            x if x == AlgProfile::Chacha20Poly1305HkdfSha512 as u16  => Ok(()),
            x if x == AlgProfile::Chacha20Poly1305HkdfBlake3K as u16 => Ok(()),
            _ => Err(HeaderError::UnknownAlgProfile { raw }),
        }
    }
}

/// AAD domain identifiers.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum AadDomain {
    Generic      = 0x0001,
    FileEnvelope = 0x0002,
    PipeEnvelope = 0x0003,
}
impl AadDomain {
    pub fn verify(raw: u16) -> Result<(), HeaderError> {
        match raw {
            x if x == AadDomain::Generic as u16      => Ok(()),
            x if x == AadDomain::FileEnvelope as u16 => Ok(()),
            x if x == AadDomain::PipeEnvelope as u16 => Ok(()),
            _ => Err(HeaderError::UnknownAadDomain { raw }),
        }
    }
}

/// Core Rust header type used internally by pipelines.
/// - Fixed-size fields ensure deterministic wire format.
/// - Salt provides per-stream nonce uniqueness.
/// - Reserved bytes allow safe extension without breaking ABI.
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct HeaderV1 {
    pub magic: [u8; 4],        // "RSE1" magic marker
    pub version: u16,          // protocol version
    pub alg_profile: u16,      // bundle id (cipher + PRF choice)
    pub cipher: u16,           // cipher enum
    pub hkdf_prf: u16,         // PRF enum
    pub compression: u16,      // compression enum (codec_ids)
    pub strategy: u16,         // sequential / parallel / auto
    pub aad_domain: u16,       // binds header semantics in AAD
    pub flags: u16,            // presence and behavior bits
    pub chunk_size: u32,       // frame plaintext target size
    pub plaintext_size: u64,   // optional; 0 if unknown
    pub crc32: u32,            // optional; 0 if not provided
    pub dict_id: u32,          // optional compression dictionary id
    pub salt: [u8; 16],        // nonce base (random per stream)
    pub key_id: u32,           // master key registry reference
    pub parallel_hint: u32,    // optional suggested worker count
    pub enc_time_ns: u64,      // optional monotonic encoding timestamp
    pub reserved: [u8; 8],     // future fields; must be zero
}

impl Default for HeaderV1 {
    /// Provides a default header with sane values:
    /// - Magic set to "RSE1"
    /// - Default cipher: Chacha20-Poly1305
    /// - Default PRF: HKDF-SHA256
    /// - Default compression: Auto
    /// - Default strategy: Sequential
    /// - Default chunk size: 64 KiB
    /// - Optional fields zeroed
    fn default() -> Self {
        Self {
            magic: MAGIC_RSE1,
            version: HEADER_V1,
            alg_profile: AlgProfile::Chacha20Poly1305HkdfSha256 as u16,
            cipher: CipherSuite::Chacha20Poly1305 as u16,
            hkdf_prf: HkdfPrf::Sha256 as u16,
            compression: CompressionCodec::Auto as u16,
            strategy: Strategy::Sequential as u16,
            aad_domain: AadDomain::Generic as u16,
            flags: 0,
            chunk_size: DEFAULT_CHUNK_SIZE as u32,        // 64 KiB default
            plaintext_size: 0,
            crc32: 0,
            dict_id: 0,
            salt: [1u8; 16],
            key_id: 0,
            parallel_hint: 0,
            enc_time_ns: 0,
            reserved: [0u8; 8],
        }
    }
}


impl HeaderV1 {
    /// Canonical header for tests.
    /// Guaranteed to pass `validate()` unless a regression is introduced.
    pub fn test_header() -> Self {
        Self {
            magic: MAGIC_RSE1,
            version: HEADER_V1,
            alg_profile: AlgProfile::Chacha20Poly1305HkdfSha256 as u16,
            cipher: CipherSuite::Chacha20Poly1305 as u16,
            hkdf_prf: HkdfPrf::Sha256 as u16,
            compression: CompressionCodec::Auto as u16,
            strategy: Strategy::Sequential as u16,
            aad_domain: AadDomain::Generic as u16,
            flags: 0,
            chunk_size: DEFAULT_CHUNK_SIZE as u32,
            plaintext_size: 0,
            crc32: 0,
            dict_id: 0,
            salt: [0xA5; 16],
            key_id: 1,
            parallel_hint: 0,
            enc_time_ns: 0,
            reserved: [0u8; 8],
        }
    }

    pub fn validate(&self) -> Result<(), HeaderError> {
        // Magic
        if self.magic != MAGIC_RSE1 {
            return Err(HeaderError::InvalidMagic {
                have: self.magic,
                need: MAGIC_RSE1,
            });
        }

        // Version
        if self.version == 0 {
            return Err(HeaderError::InvalidVersion { have: self.version });
        }

        // Enums
        AlgProfile::verify(self.alg_profile)?;
        CipherSuite::verify(self.cipher)?;
        HkdfPrf::verify(self.hkdf_prf)?;
        Strategy::verify(self.strategy)?;
        AadDomain::verify(self.aad_domain)?;

        // Compression codec
        CompressionCodec::verify(self.compression)?;

        // Chunk size
        if self.chunk_size == 0 {
            return Err(HeaderError::InvalidChunkSizeZero);
        }
        if self.chunk_size > MAX_CHUNK_SIZE as u32 {
            return Err(HeaderError::InvalidChunkSizeTooLarge {
                have: self.chunk_size,
                max: MAX_CHUNK_SIZE as u32,
            });
        }

        // Salt must not be all zero
        if self.salt.iter().all(|&b| b == 0) {
            return Err(HeaderError::InvalidSalt { salt: self.salt });
        }

        // Reserved bytes must be zero
        if self.reserved.iter().any(|&b| b != 0) {
            return Err(HeaderError::ReservedBytesNonZero {
                reserved: self.reserved,
            });
        }

        // Dict flag consistency
        if (self.flags & flags::DICT_USED) != 0 && self.dict_id == 0 {
            return Err(HeaderError::DictUsedButMissingId);
        }

        Ok(())
    }

    /// Initialize a header with mandatory fields and caller-provided random salt.
    /// - master_key linkage via key_id is set by caller.
    /// - Optional fields (plaintext_size, crc32) are left zero unless flags are set.
    ///
    /// Industry note: per-stream random salt ensures nonce uniqueness across streams.
    pub fn new_with_salt(salt: [u8; 16]) -> Self {
        Self { salt, ..Default::default() }
    }

    /// Marks plaintext_size as present, sets value and flag.
    pub fn set_plaintext_size(&mut self, size: u64) {
        self.plaintext_size = size;
        self.flags |= flags::HAS_TOTAL_LEN;
    }

    /// Marks crc32 as present, sets value and flag.
    pub fn set_crc32(&mut self, crc32: u32) {
        self.crc32 = crc32;
        self.flags |= flags::HAS_CRC32;
    }

    /// Marks dict_id as used.
    pub fn set_dict_id(&mut self, dict_id: u32) {
        self.dict_id = dict_id;
        self.flags |= flags::DICT_USED;
    }

    /// Enables authenticated terminator frame expectation.
    pub fn enable_terminator(&mut self) {
        self.flags |= flags::HAS_TERMINATOR;
    }

    /// Enables authenticated final digest frame expectation.
    pub fn enable_final_digest(&mut self) {
        self.flags |= flags::HAS_FINAL_DIGEST;
    }

    /// Strict AAD domain enforcement (decoder must match).
    pub fn enable_aad_strict(&mut self) {
        self.flags |= flags::AAD_STRICT;
    }
}

pub fn enum_name_or_hex<T>(raw: T::Primitive) -> String
where
    T: TryFromPrimitive + fmt::Debug,
    T::Primitive: fmt::LowerHex,
{
    match T::try_from_primitive(raw) {
        Ok(variant) => format!("{:?}", variant),
        Err(_) => format!("0x{:x}", raw),
    }
}

pub fn fmt_bytes(b: &[u8]) -> String {
    if b.iter().all(|&c| c.is_ascii_graphic() || c == b' ') {
        format!("b\"{}\"", String::from_utf8_lossy(b))
    } else {
        format!("0x{}", hex::encode(b))
    }
}

#[derive(Debug)]
pub enum HeaderError {
    /// Buffer too short to contain a minimal header.
    BufferTooShort { have: usize, need: usize },

    /// Invalid magic marker (expected "RSE1").
    InvalidMagic { have: [u8; 4], need: [u8; 4] },

    /// Invalid version (e.g., zero or unsupported).
    InvalidVersion { have: u16 },

    /// Unknown or unsupported cipher suite.
    UnknownCipherSuite { raw: u16 },

    /// Unknown or unsupported HKDF PRF.
    UnknownHkdfPrf { raw: u16 },

    /// Unknown or unsupported compression codec.
    UnknownCompression { raw: u16 },

    /// Unknown or unsupported strategy.
    UnknownStrategy { raw: u16 },

    /// Unknown or unsupported algorithm profile.
    UnknownAlgProfile { raw: u16 },

    /// Unknown or unsupported AAD domain.
    UnknownAadDomain { raw: u16 },

    /// Salt is invalid (e.g., all zeros).
    InvalidSalt { salt: [u8; 16] },

    /// Invalid chunk size (zero).
    InvalidChunkSizeZero,

    /// Invalid chunk size (too large).
    InvalidChunkSizeTooLarge { have: u32, max: u32 },

    /// Reserved bytes must be zero.
    ReservedBytesNonZero { reserved: [u8; 8] },

    /// Flags indicate dictionary used but dict_id is zero.
    DictUsedButMissingId,
    
    /// Generic validation error with context.
    Validation(String),
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use HeaderError::*;
        match self {
            BufferTooShort { have, need } =>
                write!(f, "header buffer too short: {} < {}", have, need),
            InvalidMagic { have, need  } =>
                write!(f, "invalid magic: expected {}, got {}", fmt_bytes(need), fmt_bytes(have)),

            InvalidVersion { have } =>
                write!(f, "invalid version: {}", have),

            UnknownCipherSuite { raw } =>
                write!(f, "unknown cipher suite: {}",
                    enum_name_or_hex::<CipherSuite>(*raw)),
            UnknownHkdfPrf { raw } =>
                write!(f, "unknown HKDF PRF: {}",
                    enum_name_or_hex::<HkdfPrf>(*raw)),
            UnknownCompression { raw } =>
                write!(f, "unknown compression: {}",
                    enum_name_or_hex::<CompressionCodec>(*raw)),
            UnknownStrategy { raw } =>
                write!(f, "unknown strategy: {}",
                    enum_name_or_hex::<Strategy>(*raw)),
            UnknownAlgProfile { raw } =>
                write!(f, "unknown algorithm profile: {}",
                    enum_name_or_hex::<AlgProfile>(*raw)),
            UnknownAadDomain { raw } =>
                write!(f, "unknown AAD domain: {}",
                    enum_name_or_hex::<AadDomain>(*raw)),

            InvalidSalt { salt } =>
                write!(f, "invalid salt: all zeros ({})", fmt_bytes(salt)),
            InvalidChunkSizeZero =>
                write!(f, "invalid chunk_size: zero"),
            InvalidChunkSizeTooLarge { have, max } =>
                write!(f, "invalid chunk_size: {} > {}", have, max),

            ReservedBytesNonZero { reserved } =>
                write!(f, "reserved bytes must be zero, got {}", fmt_bytes(reserved)),
            DictUsedButMissingId =>
                write!(f, "DICT_USED flag set but dict_id is zero"),
            Validation(msg) =>
                write!(f, "header validation error: {}", msg),
        }
    }
}

/// Allow `?` on std::io::Error
impl From<std::io::Error> for HeaderError {
    fn from(e: std::io::Error) -> Self {
        HeaderError::Validation(e.to_string())
    }
}
impl From<CodecError> for HeaderError {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::UnknownCompression { raw } => HeaderError::UnknownCompression { raw },
        }
    }
}

impl std::error::Error for HeaderError {}
