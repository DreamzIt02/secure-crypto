# Plan for `src/telemetry/` Module

The **telemetry module** provides immutable, structured performance and usage statistics. This module will unify counters, ratios, and timings into a snapshot returned by pipelines.

---

## 🎯 Purpose

- Collect **streaming statistics**: frame counts, byte counts, compression ratios.  
- Record **timings per stage** (read, compress, seal/open, write).  
- Provide an **immutable snapshot** (`TelemetrySnapshot`) at pipeline end.  
- Enable **observability** for benchmarking, debugging, and user feedback.  
- Ensure **cross‑language parity**: identical telemetry fields in Rust and Python bindings.

---

## 📂 Module Layout

```bash
src/telemetry/
 ├── mod.rs
 ├── counters.rs
 ├── snapshot.rs
 ├── timers.rs
 └── tests.rs
```

---

## 🔑 Design Invariants

- **Counters (`counters.rs`):**
  - Mutable struct `TelemetryCounters` used during streaming.
  - Fields: `frames_data`, `frames_terminator`, `frames_digest`, `bytes_plaintext`, `bytes_compressed`, `bytes_ciphertext`.
  - Updated via helpers in `stream_common`.

- **Snapshot (`snapshot.rs`):**
  - Immutable struct `TelemetrySnapshot`.
  - Derived from counters at pipeline end.
  - Adds computed fields: compression ratio, throughput (bytes/sec), elapsed time.

- **Timers (`timers.rs`):**
  - Stage timers: `time_read`, `time_compress`, `time_encrypt`, `time_decrypt`, `time_write`.
  - Use monotonic clock (`std::time::Instant`).
  - Each pipeline records durations per stage; snapshot aggregates.

- **Conversion:**
  - `impl From<TelemetryCounters> for TelemetrySnapshot` (already used in sequential/parallel).
  - Extended to include timers.

---

## 📐 Interfaces

```rust
pub struct TelemetryCounters {
    pub frames_data: u64,
    pub frames_terminator: u64,
    pub frames_digest: u64,
    pub bytes_plaintext: u64,
    pub bytes_compressed: u64,
    pub bytes_ciphertext: u64,
    pub start_time: Instant,
    pub end_time: Option<Instant>,
    pub stage_times: StageTimes,
}

pub struct StageTimes {
    pub read: Duration,
    pub compress: Duration,
    pub encrypt: Duration,
    pub decrypt: Duration,
    pub write: Duration,
}

pub struct TelemetrySnapshot {
    pub frames_data: u64,
    pub frames_terminator: u64,
    pub frames_digest: u64,
    pub bytes_plaintext: u64,
    pub bytes_compressed: u64,
    pub bytes_ciphertext: u64,
    pub compression_ratio: f64,
    pub throughput_bytes_per_sec: f64,
    pub stage_times: StageTimes,
    pub elapsed: Duration,
}
```

---

## ⚖️ Industry Notes

- **TLS/QUIC analogy:** Libraries expose counters for records processed and bytes transmitted; telemetry here serves similar observability.  
- **Compression systems:** Ratios and throughput are standard metrics for benchmarking.  
- **Best practice:** Immutable snapshots prevent accidental mutation and ensure reproducibility in logs/tests.

---

## ✅ Testing Plan

- **Unit tests:**
  - Counters increment correctly for encrypt/decrypt paths.
  - Snapshot computes compression ratio accurately (`bytes_compressed / bytes_plaintext`).
  - Throughput calculation matches elapsed time.
  - Stage timers accumulate durations correctly.

- **Integration tests:**
  - Sequential and parallel pipelines return consistent telemetry for same input.
  - Large file tests: verify throughput and ratios remain stable.

---

### 🧩 Telemetry Module Recap

**1. `TelemetryCounters` (counters.rs)**

- Tracks deterministic counts: frames, bytes (plaintext, compressed, ciphertext, overhead).
- Provides helpers:
  - `add_header`, `add_encrypt_data`, `add_decrypt_data`, `add_terminator`, `add_digest`.
  - `merge` and `AddAssign` for combining counters across workers.
- Purpose: lightweight, lock‑free accumulation of per‑segment stats.

**2. `TelemetryTimer` + `StageTimes` (timers.rs)**

- Records elapsed time and per‑stage durations (`Read`, `Write`, `Compress`, `Encrypt`, etc.).
- `StageTimes` is a `HashMap<Stage, Duration>` with helpers to add, query, and sum.
- Purpose: measure performance and stage breakdown.

**3. `TelemetrySnapshot` (snapshot.rs)**

- Aggregates counters + timer into a serializable struct.
- Computes derived metrics: compression ratio, throughput, elapsed.
- Provides helpers:
  - `sanity_check`, `has_all_stages`, `attach_output`.
- Purpose: stable ABI snapshot for reporting telemetry externally.

---

### 🔧 Integration Implication

- **Segment workers** (`encrypt.rs`, `decrypt.rs`) already produce per‑segment telemetry objects.
- **Pipeline** (`pipeline.rs`) should merge those per‑segment counters into a global `TelemetryCounters` and accumulate stage times into `TelemetryTimer`.
- **Core API** (`core.rs`) doesn’t need to manage telemetry directly — it just returns the `TelemetrySnapshot` produced by the pipeline.

---
