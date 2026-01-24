

/// Magic number for this envelope version.
/// "RSE1" = Rust Streaming Envelope v1
// - If the constant represents a **protocol magic field** (like `"RSE1"` in a header), use `[u8; 4]`. That way the type itself enforces “exactly 4 bytes” and matches our struct field type (`[u8; 4]`).
pub const MAGIC_RSE1: [u8; 4] = *b"RSE1";
pub const HEADER_V1: u16 = 1;

/// Defaults when Option<T> is None
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024; // 64 KB
/// Industry-standard chunk sizes (in bytes) ✅
pub const ALLOWED_CHUNK_SIZES: &[usize] = &[
    16 * 1024,    // 16 KiB  - IoT/embedded, constrained memory
    32 * 1024,    // 32 KiB  - Mobile devices, network packets
    64 * 1024,    // 64 KiB  - Default (good balance) ✅ RECOMMENDED
    128 * 1024,   // 128 KiB - Desktop apps
    256 * 1024,   // 256 KiB - Server applications
    1024 * 1024,  // 1 MiB   - Bulk data processing
    2048 * 1024,  // 2 MiB   - Large file transfers
    4096 * 1024,  // 4 MiB   - High-throughput systems
];
/// Max chunk size sanity bound (32 MiB).
pub const MAX_CHUNK_SIZE: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub enum ChunkPolicy {
    RoundUp,
    RoundDown,
    Nearest { tolerance: f32 }, // tolerance fraction, e.g. 0.2 = 20%
}

#[derive(Debug, Clone, Copy)]
pub enum RoundingBase {
    Bytes { max_exp: u32 }, // e.g. 2^32 bytes
    KiB   { max_exp: u32 }, // e.g. 2^20 KiB
    MiB   { max_exp: u32 }, // e.g. 2^20 MiB
}

impl RoundingBase {
    pub fn to_unit(&self) -> usize {
        match self {
            RoundingBase::Bytes { .. } => 1,
            RoundingBase::KiB { .. } => 1024,
            RoundingBase::MiB { .. } => 1024 * 1024,
        }
    }

    pub fn max_exponent(&self) -> u32 {
        match self {
            RoundingBase::Bytes { max_exp } => *max_exp,
            RoundingBase::KiB { max_exp } => *max_exp,
            RoundingBase::MiB { max_exp } => *max_exp,
        }
    }
}

/// Cipher suite identifiers (mirrored in headers).
pub mod cipher_ids {
    pub const AES256_GCM: u16        = 0x0001;
    pub const CHACHA20_POLY1305: u16 = 0x0002;
}

/// HKDF PRF identifiers (mirrored in headers).
pub mod prf_ids {
    pub const SHA256: u16  = 0x0001;
    pub const SHA512: u16  = 0x0002;
    pub const SHA3_256: u16  = 0x0003;
    pub const SHA3_512: u16  = 0x0004;
    pub const BLAKE3K: u16 = 0x0005; // keyed BLAKE3 (avoid unless policy requires)
}

/// Flag bitmask for optional features and metadata presence.
pub mod flags {
    pub const HAS_TOTAL_LEN: u16    = 0x0001;
    pub const HAS_CRC32: u16        = 0x0002;
    pub const HAS_TERMINATOR: u16   = 0x0004;
    pub const HAS_FINAL_DIGEST: u16 = 0x0008;
    pub const DICT_USED: u16        = 0x0010;
    pub const AAD_STRICT: u16       = 0x0020;
}
