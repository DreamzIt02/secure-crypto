// # Full Implementation: `src/telemetry/` Module  

// This module provides **immutable telemetry snapshots** for streaming pipelines. It centralizes counters, ratios, and stage timings, ensuring observability and reproducibility across sequential and parallel encrypt/decrypt flows.

// ## 📂 File Layout

// ```
// src/telemetry/
//  ├── mod.rs
//  ├── counters.rs
//  ├── timers.rs
//  ├── snapshot.rs
//  └── tests.rs
// ```

// ## src/telemetry/mod.rs

// ## ✅ Industry Notes

// - **Compression ratio:** `bytes_compressed / bytes_plaintext` is a standard metric in storage and backup systems.  
// - **Throughput:** `bytes_plaintext / elapsed_time` mirrors performance reporting in TLS/QUIC and file systems.  
// - **Stage timers:** Provide granular visibility into bottlenecks (e.g., compression vs. crypto).  
// - **Immutable snapshot:** Ensures reproducibility and safe FFI exposure.

//! telemetry/mod.rs
//! Unified telemetry module: counters, timers, and immutable snapshots.
//!
//! Industry notes:
//! - Telemetry is critical for benchmarking and observability in streaming systems.
//! - Immutable snapshots prevent accidental mutation and ensure reproducibility.
//! - Stage timers mirror practices in TLS/QUIC libraries where per-record timings are tracked.
//! - #[repr(C)] mirror structs provide ABI stability for FFI consumers.

pub mod counters;
pub mod timers;
pub mod snapshot;

pub use counters::*;
pub use timers::*;
pub use snapshot::*;
