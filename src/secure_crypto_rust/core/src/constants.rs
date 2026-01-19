

/// Magic number for this envelope version.
/// "RSE1" = Rust Streaming Envelope v1
// - If the constant represents a **protocol magic field** (like `"RSE1"` in a header), use `[u8; 4]`. That way the type itself enforces “exactly 4 bytes” and matches our struct field type (`[u8; 4]`).
pub const MAGIC_RSE1: [u8; 4] = *b"RSE1";
pub const HEADER_V1: u16 = 1;

/// Defaults when Option<T> is None
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024; // 64 KB
/// Industry-standard chunk sizes (in bytes)
pub const ALLOWED_CHUNK_SIZES: &[usize] = &[
    16 * 1024,   // 16 KiB
    32 * 1024,   // 32 KiB
    64 * 1024,   // 64 KiB
    128 * 1024,  // 128 KiB
    256 * 1024,  // 256 KiB
    1024 * 1024, // 1 MiB
    2048 * 1024, // 2 MiB
    4096 * 1024, // 4 MiB
];
/// Max chunk size sanity bound (32 MiB).
pub const MAX_CHUNK_SIZE: usize = 32 * 1024 * 1024;

/// Cipher suite identifiers (mirrored in headers).
pub mod cipher_ids {
    pub const AES256_GCM: u16        = 0x0001;
    pub const CHACHA20_POLY1305: u16 = 0x0002;
}

/// HKDF PRF identifiers (mirrored in headers).
pub mod prf_ids {
    pub const SHA256: u16  = 0x0001;
    pub const SHA512: u16  = 0x0002;
    pub const BLAKE3K: u16 = 0x0003; // keyed BLAKE3 (avoid unless policy requires)
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
