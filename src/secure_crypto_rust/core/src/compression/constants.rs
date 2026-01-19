/// Stable codec IDs (u16) for headers and wire format.
pub mod codec_ids {
    pub const AUTO: u16    = 0x0000;
    pub const ZSTD: u16    = 0x0001;
    pub const LZ4: u16     = 0x0002;
    pub const DEFLATE: u16 = 0x0003;
}

/// Default compression levels (balanced).
pub const DEFAULT_LEVEL_ZSTD: i32 = 6;
pub const DEFAULT_LEVEL_LZ4: i32 = 0; // fast mode
pub const DEFAULT_LEVEL_DEFLATE: i32 = 6;

/// Max chunk size sanity bound (32 MiB).
pub const MAX_CHUNK_SIZE: usize = 32 * 1024 * 1024;
