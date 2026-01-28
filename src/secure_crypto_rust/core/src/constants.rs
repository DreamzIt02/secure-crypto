

/// Magic number for this envelope version.
/// "RSE1" = Rust Streaming Envelope v1
// - If the constant represents a **protocol magic field** (like `"RSE1"` in a header), use `[u8; 4]`. That way the type itself enforces “exactly 4 bytes” and matches our struct field type (`[u8; 4]`).
pub const MAGIC_RSE1: [u8; 4] = *b"RSE1";
pub const HEADER_V1: u16 = 1;

// Basic sanity: minimum length and maybe a magic prefix
// require first 4 bytes to be a magic number
// - If the constant is more of a **prefix marker** we’ll check against slices (like `"DICT"` at the start of a dictionary payload), then `&[u8]` is fine:
pub const MAGIC_DICT: &[u8] = b"DICT";
pub const MIN_DICT_LEN: usize = 8;
pub const MAX_DICT_LEN: usize = 1 << 20; // 1 MiB cap for sanity

/// Industry-standard master key lengths (AES-128, AES-192, AES-256)
pub const MASTER_KEY_LENGTHS: &[usize] = &[16, 24, 32];

// ### 📊 Comparison table

// | **Setting** | **Industry Standard** | **Rationale** |
// |-------------|------------------------|---------------|
// | **Queue cap** | **[4–16](guide://action?prefill=Tell%20me%20more%20about%3A%204%E2%80%9316)** | **[low latency, avoids memory bloat](guide://action?prefill=Tell%20me%20more%20about%3A%20low%20latency%2C%20avoids%20memory%20bloat)** |
// | **Workers** | **[match physical cores](guide://action?prefill=Tell%20me%20more%20about%3A%20match%20physical%20cores)** (usually 4–16) | **[CPU‑bound crypto tasks scale linearly](guide://action?prefill=Tell%20me%20more%20about%3A%20CPU%E2%80%91bound%20crypto%20tasks%20scale%20linearly)** |
// | **Beyond 16** | **[rarely beneficial](guide://action?prefill=Tell%20me%20more%20about%3A%20rarely%20beneficial)** | **[context switching overhead dominates](guide://action?prefill=Tell%20me%20more%20about%3A%20context%20switching%20overhead%20dominates)** |

// ### 🧩 Why worker count matters
// - **Match physical cores**: Each worker is CPU‑bound (AES, compression, HKDF). Running more workers than cores just adds context‑switch overhead.  
// - **Typical range**: 4–16 workers for server‑class CPUs; 2–8 for laptops.  
// - **Scaling**: Beyond 16 workers, diminishing returns set in unless we’re on a many‑core server (32+ cores).  
pub const WORKERS_COUNT: &[usize] = &[2, 4, 8, 16];

// ### 🧩 Why queue cap matters
// - **Small queue (2–16)**: Keeps latency low, avoids excessive buffering, and ensures back‑pressure works correctly.  
// - **Large queue (>32)**: Can cause memory bloat, uneven scheduling, and delayed error propagation. Most cryptographic pipelines (AES, VPNs, TLS offload) deliberately cap queues at small powers of two.  
// - **Industry practice**: VPN engines, GPU crypto libraries, and parallel AES implementations typically use **queue caps of 4–16**.
pub const QUEUE_CAPS: &[usize] = &[2, 4, 8, 16];
pub const DEFAULT_WORKERS: usize = 2;            // or num_cpus::get()
pub const DEFAULT_QUEUE_CAP: usize = 4;          // or workers * 2

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
