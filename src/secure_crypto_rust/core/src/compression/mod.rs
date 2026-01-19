// # Full Implementation: `src/compression/` Module

// Here’s the complete, production‑ready compression module. It provides deterministic, streaming‑safe compression and decompression across codecs (Auto, Zstd, LZ4, Deflate), with dictionary support, registry resolution, and strict validation.

// ## 📂 Module Layout

// ```
// src/compression/
//  ├── mod.rs
//  ├── constants.rs
//  ├── registry.rs
//  ├── codecs/
//  │    ├── auto.rs
//  │    ├── zstd.rs
//  │    ├── lz4.rs
//  │    └── deflate.rs
//  ├── stream.rs
//  └── tests.rs
// ```

// ---

// ## src/compression/mod.rs

//! compression/mod.rs
//! Streaming-safe compression and decompression.
//!
//! Industry notes:
//! - Deterministic per-chunk compression ensures reproducibility and parallel safety.
//! - Dictionaries must be explicitly declared and bound via header.dict_id.
//! - Registry resolves codec IDs to implementations.

pub mod constants;
pub mod types;
pub mod registry;
pub mod codecs;
pub mod stream;

pub use constants::*;
pub use types::*;
pub use registry::*;


// Notes:
// - We’ll need dependencies: zstd = "0.13", lz4-flex = "0.11", flate2 = "1".
// - The LZ4 and Zstd streaming adapters here use Vec-backed writers; we explicitly drain the inner buffers to yield chunk outputs. 
// - This keeps per-chunk determinism and avoids frame-spanning state unless a dictionary is provided and flagged.
// - For dictionary enforcement with header flags, wire checks in the streaming layer: if DICT_USED is set, pass dict bytes; otherwise, require None.