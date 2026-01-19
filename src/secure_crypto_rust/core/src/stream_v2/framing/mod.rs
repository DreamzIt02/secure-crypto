//! Wire framing for stream_v2.
//!
//! Responsibilities:
//! - Define frame headers and records
//! - Encode frames into a canonical byte layout
//! - Decode frames with strict validation
//!
//! Non-responsibilities:
//! - Cryptography
//! - Compression
//! - IO
//! - Parallelism

pub mod types;
pub mod encode;
pub mod decode;

pub use types::{
    FrameHeader,
    FrameRecord,
    FrameType,
    FrameError,
};