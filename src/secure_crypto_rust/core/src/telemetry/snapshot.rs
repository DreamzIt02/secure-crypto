// ## src/telemetry/snapshot.rs

// //! src/telemetry/snapshot.rs
// //!
// //! Telemetry snapshot structures and conversions.
// //!
// //! Design notes:
// //! - `TelemetrySnapshot` is the core Rust struct with rich types (Duration, HashMap).
// //! - Stage times are flattened into fixed fields for ABI stability.
// //! - Conversions ensure elapsed time is represented in milliseconds for cross-language parity.

use std::time::Duration;
use serde::{Serialize, Deserialize};

use crate::telemetry::counters::TelemetryCounters;
use crate::telemetry::timers::{TelemetryTimer, StageTimes, Stage};

/// Core telemetry snapshot.
/// Captures counters, ratios, throughput, stage timings, and elapsed duration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub segments_processed: u64,
    pub frames_data: u64,
    pub frames_terminator: u64,
    pub frames_digest: u64,
    pub bytes_plaintext: u64,
    pub bytes_compressed: u64,
    pub bytes_ciphertext: u64,
    pub bytes_overhead: u64,
    pub compression_ratio: f64,
    pub throughput_plaintext_bytes_per_sec: f64,
    pub elapsed: Duration,
    pub stage_times: StageTimes, // HashMap<Stage, Duration>
    /// The final encrypted stream bytes, if the output sink was memory-backed.
    /// 
    /// - `None` if the output was written directly to a file or external sink.
    /// - `Some(Vec<u8>)` if the pipeline wrote into an in-memory buffer.
    /// 
    /// This field is primarily useful in tests, benchmarks, or integrations
    /// where we want to inspect the produced ciphertext alongside telemetry
    /// counters and stage timings.
    pub output: Option<Vec<u8>>,
}

impl TelemetrySnapshot {
    pub fn from(counters: &TelemetryCounters, timer: &TelemetryTimer, segments: Option<u32>) -> Self {
        let elapsed = timer.elapsed();

        let mut compression_ratio = if counters.bytes_plaintext > 0 {
            counters.bytes_compressed as f64 / counters.bytes_plaintext as f64
        } else {
            0.0
        };
        compression_ratio = compression_ratio.min(1.0);

        let throughput = if elapsed.as_secs_f64() > 0.0 {
            counters.bytes_plaintext as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        Self {
            segments_processed: segments.unwrap_or_default() as u64,
            frames_data: counters.frames_data,
            frames_terminator: counters.frames_terminator,
            frames_digest: counters.frames_digest,
            bytes_plaintext: counters.bytes_plaintext,
            bytes_compressed: counters.bytes_compressed,
            bytes_ciphertext: counters.bytes_ciphertext,
            bytes_overhead: counters.bytes_overhead,
            compression_ratio: compression_ratio,
            throughput_plaintext_bytes_per_sec: throughput,
            elapsed: elapsed,
            stage_times: timer.stage_times.clone(),
            output: None, // 🔧 initialize empty
        }
    }

    pub fn total_stage_time(&self) -> Duration {
        self.stage_times.iter().map(|(_, d)| *d).sum()
    }

    // - **Stage coverage sanity**  
    // Add a helper that asserts all expected `Stage` variants are present in `stage_times`. 
    // This prevents silent omissions when new stages are introduced.  
    pub fn has_all_stages(&self, expected: &[Stage]) -> bool {
        expected.iter().all(|s| self.stage_times.get(*s) > Duration::ZERO)
        // expected.iter().all(|s| {
        //     self.stage_times.get(s).map_or(false, |d| *d > Duration::ZERO)
        // })
    }

    // - **Consistency checks**  
    // Provide a method that validates internal invariants:  
    // - `bytes_ciphertext >= bytes_compressed`  
    // - `compression_ratio <= 1.0`  
    // - `total_stage_time() <= elapsed`  

    pub fn sanity_check(&self) -> bool {
        self.bytes_ciphertext >= self.bytes_compressed &&
        self.compression_ratio <= 1.0 &&
        self.total_stage_time() <= self.elapsed
    }
    
    pub fn output_bytes(&self) -> u64 {
        self.bytes_ciphertext
    }

    /// 🔧 Attach output buffer to snapshot
    pub fn attach_output(&mut self, buf: Vec<u8>) {
        self.output = Some(buf);
    }
}

