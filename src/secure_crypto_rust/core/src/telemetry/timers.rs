// ## src/telemetry/timers.rs

//! telemetry/timers.rs
//! Stage timers for streaming pipelines.
//!
//! Summary: Records durations for read, compress, encrypt/decrypt, and write stages.
//! Industry notes: TLS/QUIC libraries track per-record timings for performance analysis.

// ### `Stage` enum with `Display`

use std::fmt;
use std::time::Instant;
use std::time::Duration;
use std::collections::{HashMap, hash_map};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Stage {
    Read,
    Write,
    Encode,
    Decode,
    Compress,
    Decompress,
    Encrypt,
    Decrypt,
    Validate,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Stage::Read       => "read",
            Stage::Write      => "write",
            Stage::Encode     => "encode",
            Stage::Decode     => "decode",
            Stage::Compress   => "compress",
            Stage::Decompress => "decompress",
            Stage::Encrypt    => "encrypt",
            Stage::Decrypt    => "decrypt",
            Stage::Validate   => "validate",
        };
        f.write_str(name)
    }
}

// ### Benefits
// - **Type safety**: we call `Stage::Encrypt` instead of `"encrypt"`.  
// - **Human‑readable output**: `format!("{}", Stage::Encrypt)` → `"encrypt"`.  
// - **FFI/logging friendly**: we can pass stage names to telemetry snapshots or JSON without stringly‑typed code.  
// - **Extensible**: add new stages by extending the enum and updating the `Display` match.

// - **Microsecond precision**: expose both microseconds and milliseconds helpers, but keep `Duration` internally (nanosecond precision).  
// - **Type‑safe iteration**: implement `IntoIterator` so we can loop over `(Stage, Duration)` pairs directly.  
// - **Cleaner API**: replace `get_ms` with `get_ms` and `get_us`, and add a generic `get_in_unit` if we want flexibility.  
// - **Extensibility**: we can add new stages without changing the struct internals.

// ### ⚠️ Note on `Duration`
// `std::time::Duration` already implements `Serialize` and `Deserialize` (via the `serde` crate), so we don’t need to do anything extra there.

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StageTimes {
    times: HashMap<Stage, Duration>,
}
// ### 🚀 Summary
// - Add `#[derive(Serialize, Deserialize)]` to `Stage`.
// - Keep `StageTimes` deriving `Serialize, Deserialize`.
// - Now `TelemetrySnapshot` can derive `Serialize, Deserialize` without errors.

impl StageTimes {
    /// Add duration to a stage (accumulates if already present).
    pub fn add(&mut self, stage: Stage, dur: Duration) {
        *self.times.entry(stage).or_insert(Duration::ZERO) += dur;
    }

    /// Get total duration for a stage.
    pub fn get(&self, stage: Stage) -> Duration {
        self.times.get(&stage).copied().unwrap_or(Duration::ZERO)
    }

    /// Get duration in milliseconds (f64).
    pub fn get_ms(&self, stage: Stage) -> f64 {
        self.get(stage).as_secs_f64() * 1_000.0
    }

    /// Get duration in microseconds (f64).
    pub fn get_us(&self, stage: Stage) -> f64 {
        self.get(stage).as_secs_f64() * 1_000_000.0
    }

    /// Get duration in nanoseconds (u128).
    pub fn get_ns(&self, stage: Stage) -> u128 {
        self.get(stage).as_nanos()
    }

    /// Sum all stage durations.
    pub fn total(&self) -> Duration {
        self.times.values().copied().sum()
    }

    /// Return all stage times.
    pub fn all(&self) -> &HashMap<Stage, Duration> {
        &self.times
    }

    /// Check if all expected stages are present (non-zero).
    pub fn has_all(&self, expected: &[Stage]) -> bool {
        expected.iter().all(|s| self.get(*s) > Duration::ZERO)
    }

    // ### Example usage

    // ```rust
    // let mut timer = TelemetryTimer::new();
    // timer.add_stage_time(Stage::Encrypt, Duration::from_micros(420));
    // timer.add_stage_time(Stage::Read, Duration::from_micros(100));

    // println!("Total stage time: {} µs", timer.stage_times.total().as_micros());

    // let expected = [Stage::Read, Stage::Encrypt];
    // assert!(timer.stage_times.has_all(&expected));
    // ```

    // Output:

    // ```
    // Total stage time: 520 µs
    // ```

    // ### ✅ Benefits
    // - **Telemetry sanity**: compare `StageTimes::total()` against `TelemetrySnapshot.elapsed` to ensure no stage time exceeds total elapsed.  
    // - **Coverage check**: `has_all()` lets us assert that all critical stages were measured.  
    // - **Precision**: we can report totals in microseconds or nanoseconds without losing detail.

    pub fn iter(&self) -> impl Iterator<Item = (&Stage, &Duration)> {
        self.times.iter()
    }
}

/// Allow iteration over owned StageTimes.
impl IntoIterator for StageTimes {
    type Item = (Stage, Duration);
    type IntoIter = hash_map::IntoIter<Stage, Duration>;

    fn into_iter(self) -> Self::IntoIter {
        self.times.into_iter()
    }
}

/// Allow iteration over borrowed StageTimes.
impl<'a> IntoIterator for &'a StageTimes {
    type Item = (&'a Stage, &'a Duration);
    type IntoIter = hash_map::Iter<'a, Stage, Duration>;

    fn into_iter(self) -> Self::IntoIter {
        self.times.iter()
    }
}

// ### ✅ Benefits
// - **Precision**: we can now report in microseconds or nanoseconds, not just milliseconds.  
// - **Flexibility**: `get_ms`, `get_us`, and `get_ns` cover most telemetry needs.  
// - **Iteration**: we can loop over all stages easily in tests or telemetry snapshots.  
// - **Extensibility**: adding new stages only requires updating the `Stage` enum, not this struct.

// Example usage:

// ```rust
// timer.add_stage_time(Stage::Encrypt, t.elapsed());
// println!("Encrypt stage took {:.2} µs", timer.stage_times.get_us(Stage::Encrypt));

// for (stage, dur) in &timer.stage_times {
//     println!("Stage {} took {} ns", stage, dur.as_nanos());
// }
// ```

// ### ✅ Benefits
// - Clean iteration without exposing `HashMap` internals.
// - Works for both owned (`StageTimes`) and borrowed (`&StageTimes`) contexts.
// - Plays nicely with our `Display` impl for `Stage`.


// ### ✅ TelemetryTimer with Enum

// Now `TelemetryTimer` can use the enum directly:

#[derive(Clone, Debug)]
pub struct TelemetryTimer {
    pub start_time: Instant,
    pub end_time: Option<Instant>,
    pub stage_times: StageTimes,
}

impl TelemetryTimer {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            end_time: None,
            stage_times: StageTimes::default(),
        }
    }

    pub fn finish(&mut self) {
        self.end_time = Some(Instant::now());
    }

    pub fn add_stage_time(&mut self, stage: Stage, dur: Duration) {
        self.stage_times.add(stage, dur);
    }

    pub fn elapsed(&self) -> Duration {
        match self.end_time {
            Some(end) => end.duration_since(self.start_time),
            None => Instant::now().duration_since(self.start_time),
        }
    }
}

// Usage becomes type‑safe:

// ```rust
// timer.add_stage_time(Stage::Encrypt, res.encrypt);
// timer.add_stage_time(Stage::Read, t.elapsed());
// ```

// ### 🚀 Improvements over current design
// - **Type safety**: no silent typos in stage names.  
// - **Extensibility**: add new stages by extending the `Stage` enum, no need to touch `StageTimes` internals.  
// - **Cleaner API**: `get_ms(stage)` instead of separate `read_ms()`, `compress_ms()`, etc.  
// - **Telemetry snapshot sanity**: we can iterate over `stage_times.all()` to check that all expected stages are present.
