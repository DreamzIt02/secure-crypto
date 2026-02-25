//! Segment-level workers for stream_v2.
//!
//! A segment is a *bounded batch of frames* processed independently.
//! Segment workers:
//! - fan-in frame workers
//! - preserve per-segment ordering
//! - emit a single contiguous wire blob
//!
//! They are:
//! - CPU-bound
//! - Stateless between segments
//! - Fully parallelizable

pub mod types;
pub mod encrypt;
pub mod decrypt;
pub mod enc_helpers;
pub mod dec_helpers;

pub use types::{
    EncryptSegmentInput,
    DecryptSegmentInput,
    EncryptedSegment,
    DecryptedSegment,
    EncryptContext,
    DecryptContext,
    SegmentWorkerError,
};

pub use encrypt::EncryptSegmentWorker1;
pub use decrypt::DecryptSegmentWorker1;
