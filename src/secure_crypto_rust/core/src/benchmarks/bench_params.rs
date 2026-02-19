
// Plaintext sizes in bytes
pub const PLAINTEXT_SIZES: [usize; 6] = [
    1 * 1024,
    10 * 1024,
    100 * 1024,
    1 * 1024 * 1024,
    10 * 1024 * 1024,
    100 * 1024 * 1024,
];

// Compression modes (string identifiers for now)
pub static COMPRESSION_MODES: [&str; 3] = [
    "none",
    "lz4",
    "zlib",
    // We can extend with "zstd", "brotli", etc.
];

// Chunk sizes in bytes
pub const CHUNK_SIZES: [usize; 5] = [
    4 * 1024,
    16 * 1024,
    64 * 1024,
    256 * 1024,
    1 * 1024 * 1024,
];

// Number of repeats per configuration
pub const REPEATS: usize = 1;

// ### 🧩 Key Notes
// - `PLAINTEXT_SIZES` and `CHUNK_SIZES` are fixed-size arrays of `usize`.
// - `COMPRESSION_MODES` is a `static` array of string slices (`&str`), which we can later replace with an enum if we want stronger typing.
// - `REPEATS` is a simple constant.
