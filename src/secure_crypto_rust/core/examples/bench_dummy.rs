use chrono::Utc;

use crypto_core::benchmarks::bench_results::{BenchmarkResult, print_results};

fn dummy_benchmarks() {
    let now = Utc::now().to_rfc3339();

    let results = vec![
        BenchmarkResult {
            mode: "enc".to_string(),
            op: "encrypt".to_string(),
            size: 10_000_000,
            compression: "none".to_string(),
            chunk_size: 4096,
            elapsed: 0.123,
            mb_per_s: 81.3,
            ratio: None,
            cpu_percent: 45.2,
            mem_before: 120.0,
            mem_after: 125.5,
            timestamp: now.clone(),
            scenario: Some("Memory→Memory".to_string()),
            traces: None,
        },
        BenchmarkResult {
            mode: "dec".to_string(),
            op: "decrypt".to_string(),
            size: 10_000_000,
            compression: "none".to_string(),
            chunk_size: 4096,
            elapsed: 0.150,
            mb_per_s: 66.7,
            ratio: None,
            cpu_percent: 42.0,
            mem_before: 125.5,
            mem_after: 126.0,
            timestamp: now.clone(),
            scenario: Some("Memory→Memory".to_string()),
            traces: None,
        },
        BenchmarkResult {
            mode: "enc".to_string(),
            op: "encrypt".to_string(),
            size: 50_000_000,
            compression: "lz4".to_string(),
            chunk_size: 8192,
            elapsed: 0.800,
            mb_per_s: 62.5,
            ratio: Some(0.45),
            cpu_percent: 70.0,
            mem_before: 126.0,
            mem_after: 140.0,
            timestamp: now.clone(),
            scenario: Some("File→File".to_string()),
            traces: None,
        },
    ];

    print_results(&results, "Dummy Benchmark Results");
}

fn main() {
    dummy_benchmarks();
}

// ## ▶️ Example Output

// ```
// =============================================================================================================================
// Dummy Benchmark Results
// =============================================================================================================================
// mode  | op       | size MB     | compress | ch_size   | elapsed     | MB/s          | ratio   |  CPU%   | RSS (MB)
// -----------------------------------------------------------------------------------------------------------------------------
// File→File
// -----------------------------------------------------------------------------------------------------------------------------
// enc   | encrypt  |    50.00 MB | lz4      |   8 KB |   800.00 ms |    62.50 MB/s |   0.450 |   70.0% |  126.0 →  140.0 MB
// -----------------------------------------------------------------------------------------------------------------------------
// Memory→Memory
// -----------------------------------------------------------------------------------------------------------------------------
// enc   | encrypt  |    10.00 MB | none     |   4 KB |   123.00 ms |    81.30 MB/s |       - |   45.2% |  120.0 →  125.5 MB
// dec   | decrypt  |    10.00 MB | none     |   4 KB |   150.00 ms |    66.70 MB/s |       - |   42.0% |  125.5 →  126.0 MB
// =============================================================================================================================
// ```
