//! crypto-core
//!
//! Pure Rust streaming encryption engine.
//! No Python, no PyO3, no FFI.

#![forbid(unsafe_code)]

// Shared and top level
pub mod constants;
pub mod types;
pub mod utils;

// Shared and top level module
pub mod compression;
pub mod headers;
pub mod crypto;
pub mod telemetry;

pub mod recovery;
pub mod scheduler;

// Stream layers
pub mod stream_v2;

// -----------------------------------------------------------------------------
// Prelude (Rust users)
// -----------------------------------------------------------------------------
pub mod prelude {

}
