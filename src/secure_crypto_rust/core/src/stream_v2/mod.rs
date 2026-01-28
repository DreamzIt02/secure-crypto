// ## 1️⃣ `mod.rs` — public façade + re-exports

//! stream_v2 — fully parallel, segment-based streaming encryption/decryption.
//!
//! This module exposes a **stable public API** for Rust, Python (via PyO3),
//! CLI tools, and services. Internals are strictly layered.


pub mod compression_worker;
pub mod compression_pipeline;
pub mod parallelism;
pub mod pipeline;
pub mod io;
pub mod core;

pub mod segmenting;
pub mod segment_worker;
pub mod framing;
pub mod frame_worker;

pub use io::{
    InputSource,
    OutputSink,
};

pub use core::{
    encrypt_stream_v2,
    decrypt_stream_v2,
};


