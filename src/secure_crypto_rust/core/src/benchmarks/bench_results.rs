use std::collections::HashMap;
use std::time::Instant;
use serde::Serialize;

use crate::benchmarks::bench_utils::{measure_cpu_percent, measure_memory_mb, get_timestamp};

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkResult {
    pub mode: String,
    pub op: String,
    pub size: usize,
    pub compression: String,
    pub chunk_size: usize,
    pub elapsed: f64,
    pub mb_per_s: f64,
    pub ratio: Option<f64>,
    pub cpu_percent: f64,
    pub mem_before: f64,
    pub mem_after: f64,
    pub timestamp: String,
    pub scenario: Option<String>,
    pub traces: Option<HashMap<String, String>>,
}

impl BenchmarkResult {
    pub fn pretty_row(&self) -> String {
        let mb = self.size as f64 / 1e6;
        let ratio_str = match self.ratio {
            Some(r) => format!("{:.3}", r),
            None => "-".to_string(),
        };
        format!(
            "{:5} | {:8} | {:8.2} MB | {:7}  | {:6.0} KB | {:8.2} ms | {:8.2} MB/s | {:7} | {:6.1}% | {:6.1} → {:6.1} MB",
            self.mode,
            self.op,
            mb,
            self.compression,
            self.chunk_size as f64 / 1024.0,
            self.elapsed * 1000.0,
            self.mb_per_s,
            ratio_str,
            self.cpu_percent,
            self.mem_before,
            self.mem_after
        )
    }
}

pub fn pretty_row_header() -> String {
    format!(
        "mode  | op       | size MB     | compress | ch_size   | elapsed     | MB/s          | ratio   |  CPU%   | RSS (MB)"
    )
}

pub fn print_results(results: &[BenchmarkResult], title: &str) {
    let len_line = 125;
    println!("\n{}", "=".repeat(len_line));
    println!("{}", title);
    println!("{}", "=".repeat(len_line));

    println!("{}", pretty_row_header());
    println!("{}", "-".repeat(len_line));

    let mut current_scenario: Option<String> = None;

    let mut sorted_results = results.to_vec();
    sorted_results.sort_by(|a, b| a.scenario.cmp(&b.scenario));

    for r in sorted_results {
        if current_scenario != r.scenario {
            if current_scenario.is_some() {
                println!("{}", "-".repeat(len_line));
            }
            current_scenario = r.scenario.clone();
            if let Some(s) = &current_scenario {
                println!("{}", s);
                println!("{}", "-".repeat(len_line));
            }
        }
        println!("{}", r.pretty_row());
    }

    println!("{}", "=".repeat(len_line));
}

/// Rust equivalent of Python's make_result_v2
pub fn make_result_v2(
    scenario: &str,
    op: &str,
    mode: &str,
    size: usize,
    compression: &str,
    chunk_size: usize,
    start: Instant,
    mem_before: f64,
    total_ct: Option<usize>,
    traces: Option<HashMap<String, String>>,
) -> BenchmarkResult {
    let elapsed = start.elapsed().as_secs_f64();
    let cpu_percent = measure_cpu_percent(elapsed);
    let mem_after = measure_memory_mb();

    let mut mbps = 0.0;
    let mut ratio = None;

    if size > 0 {
        mbps = size as f64 / elapsed / 1e6;
        if let Some(ct) = total_ct {
            // ✅ ratio is only meaningful during encryption
            if compression != "none" && op == "encrypt" {
                ratio = Some(ct as f64 / size as f64);
            }
        }
    }

    BenchmarkResult {
        scenario: Some(scenario.to_string()),
        op: op.to_string(),
        mode: mode.to_string(),
        size,
        compression: compression.to_string(),
        chunk_size,
        elapsed,
        mb_per_s: mbps,
        ratio,
        cpu_percent,
        mem_before,
        mem_after,
        timestamp: get_timestamp(),
        traces,
    }
}

// ### 🧩 Key Notes
// - **Elapsed time**: Uses `Instant` to measure duration (`start.elapsed().as_secs_f64()`).
// - **Throughput (MB/s)**: `size / elapsed / 1e6`.
// - **Ratio**: Only set during encryption and when compression is not `"none"`.
// - **Scenario & traces**: Optional fields, consistent with our struct.
// - **Helpers**: `measure_cpu_percent`, `measure_memory_mb`, and `get_timestamp` are placeholders — we’ll plug in our real implementations.
