use crate::benchmarks::bench_results::BenchmarkResult;
use serde_json::json;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Summary {
    pub total_tests: usize,
    pub avg_throughput_mb_s: f64,
    pub min_throughput_mb_s: f64,
    pub max_throughput_mb_s: f64,
    pub avg_latency_ms: f64,
    pub stddev_latency_ms: f64,
}

impl Summary {
    pub fn to_json_map(&self) -> HashMap<String, serde_json::Value> {
        let mut map = HashMap::new();
        map.insert("total_tests".to_string(), json!(self.total_tests));
        map.insert("avg_throughput_mb_s".to_string(), json!(self.avg_throughput_mb_s));
        map.insert("min_throughput_mb_s".to_string(), json!(self.min_throughput_mb_s));
        map.insert("max_throughput_mb_s".to_string(), json!(self.max_throughput_mb_s));
        map.insert("avg_latency_ms".to_string(), json!(self.avg_latency_ms));
        map.insert("stddev_latency_ms".to_string(), json!(self.stddev_latency_ms));
        map
    }
}

pub fn compute_summary(results: &[BenchmarkResult]) -> Summary {
    let throughputs: Vec<f64> = results.iter().map(|r| r.mb_per_s).collect();
    let latencies: Vec<f64> = results.iter().map(|r| r.elapsed * 1000.0).collect();

    let total_tests = results.len();

    let avg_throughput = mean(&throughputs);
    let min_throughput = throughputs
        .iter()
        .cloned()
        .fold(f64::INFINITY, f64::min);
    let max_throughput = throughputs
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max);

    let avg_latency = mean(&latencies);
    let stddev_latency = stddev_population(&latencies);

    Summary {
        total_tests,
        avg_throughput_mb_s: avg_throughput,
        min_throughput_mb_s: min_throughput,
        max_throughput_mb_s: max_throughput,
        avg_latency_ms: avg_latency,
        stddev_latency_ms: stddev_latency,
    }
}

/// Compute mean of a slice
fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

/// Population standard deviation
fn stddev_population(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let m = mean(values);
    let variance = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / values.len() as f64;
    variance.sqrt()
}

// ### 🧩 Key Notes
// - `Summary` struct mirrors the Python dictionary return value.
// - `mean` and `stddev_population` are helper functions to replicate `statistics.mean` and `statistics.pstdev`.
// - Latency is converted to milliseconds (`elapsed * 1000.0`).
// - Throughput stats (avg, min, max) are computed directly from the results.
