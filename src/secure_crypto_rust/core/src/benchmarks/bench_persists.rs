
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs;
use std::path::{PathBuf};
use std::collections::HashMap;

use crate::benchmarks::bench_metadata::collect_metadata;
use crate::benchmarks::bench_results::BenchmarkResult;
use crate::benchmarks::bench_summary::compute_summary;

// Constants for parameters
// const PLAINTEXT_SIZES: &[usize] = &[1024, 2048];
// const CHUNK_SIZES: &[usize] = &[512, 1024];
// const COMPRESSION_MODES: &[&str] = &["none", "zstd"];
// const REPEATS: usize = 3;

#[derive(Serialize)]
struct Output<'a> {
    metadata: HashMap<String, serde_json::Value>,
    parameters: HashMap<&'a str, serde_json::Value>,
    summary: HashMap<String, serde_json::Value>,
    results: Vec<HashMap<String, serde_json::Value>>,
    traces: HashMap<String, Option<HashMap<String, String>>>,
}

pub fn save_json(results: &[BenchmarkResult], file_name: Option<&str>, folder_name: Option<&str>) {
    let metadata = collect_metadata();
    let summary = compute_summary(results);

    // Parameters block
    let parameters = HashMap::new();
    // parameters.insert("plaintext_sizes", serde_json::json!(PLAINTEXT_SIZES));
    // parameters.insert("chunk_sizes", serde_json::json!(CHUNK_SIZES));
    // parameters.insert("compression_modes", serde_json::json!(COMPRESSION_MODES));
    // parameters.insert("repeats", serde_json::json!(REPEATS));
    // parameters.insert("async_available", serde_json::json!(true));

    // Results + traces
    let mut json_results = Vec::new();
    let mut traces = HashMap::new();
    for r in results {
        let mut entry = HashMap::new();
        entry.insert("scenario".to_string(), serde_json::json!(r.scenario));
        entry.insert("mode".to_string(), serde_json::json!(r.mode));
        entry.insert("operation".to_string(), serde_json::json!(r.op));
        entry.insert("size_bytes".to_string(), serde_json::json!(r.size));
        entry.insert("compression".to_string(), serde_json::json!(r.compression));
        entry.insert("chunk_size".to_string(), serde_json::json!(r.chunk_size));
        entry.insert("elapsed_ms".to_string(), serde_json::json!(r.elapsed));
        entry.insert("throughput_mb_s".to_string(), serde_json::json!(r.mb_per_s));
        entry.insert("compression_ratio".to_string(), serde_json::json!(r.ratio));
        entry.insert("cpu_percent".to_string(), serde_json::json!(r.cpu_percent));
        entry.insert("memory_before_mb".to_string(), serde_json::json!(r.mem_before));
        entry.insert("memory_after_mb".to_string(), serde_json::json!(r.mem_after));
        entry.insert("timestamp".to_string(), serde_json::json!(r.timestamp));
        json_results.push(entry);

        traces.insert(r.timestamp.clone(), r.traces.clone());
    }

    let output = Output {
        metadata,
        parameters,
        summary: summary.to_json_map(),
        results: json_results,
        traces,
    };

    // Folder handling
    let folder_name = folder_name.unwrap_or("results");
    let out_dir = PathBuf::from(folder_name);
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("Error creating folder: {}", e);
        return;
    }

    // File name
    let file_name = file_name.map(|s| s.to_string()).unwrap_or_else(|| {
        let timestamp: DateTime<Utc> = Utc::now();
        format!("benchmark_{}.json", timestamp.format("%Y%m%d_%H%M%S"))
    });

    let file_path = out_dir.join(file_name);

    // Save JSON
    match fs::write(&file_path, serde_json::to_string_pretty(&output).unwrap()) {
        Ok(_) => println!("\n💾 Results saved to: {}", file_path.display()),
        Err(e) => eprintln!("Error saving file: {}", e),
    }
}

// ### 🔑 Key Notes
// - `BenchmarkResult` is a placeholder; adapt it to our actual struct.
// - `serde_json::json!` makes it easy to insert constants into the parameters block.
// - `PathBuf` + `fs::create_dir_all` ensures the folder exists.
// - File name defaults to `benchmark_<timestamp>.json` if not provided.
