//! Wire compression for stream_v2.
//!
//! Responsibilities:
//! - Compress segments into a canonical byte layout
//! - Decompress segments with strict validation
//!
//! Non-responsibilities:
//! - Cryptography
//! - IO
//! - Parallelism

pub mod types;
pub mod worker_cpu;
pub mod worker_gpu;
pub mod worker;

pub use types::{
    CompressionBackend,
    CodecInfo,
    CompressionWorkerError,
};
pub use worker::{
    make_backend,
    run_compression_worker,
    run_decompression_worker,
};
pub use worker_cpu::{
    CpuCompressionBackend
};
pub use worker_gpu::{
    GpuCompressionBackend
};