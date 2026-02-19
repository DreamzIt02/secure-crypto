// ### `bench_v2_memory.rs`

use crypto_core::{
    benchmarks::{bench_results::BenchmarkResult, bench_runner::{BenchFuture, bench_v2_main}, bench_utils::{dummy_master_key, random_bytes}, bench_v2_decrypt_memory::{bench_v2_decrypt_memory_2_file_sync, bench_v2_decrypt_memory_2_memory_sync, bench_v2_decrypt_memory_2_writer_sync}, bench_v2_encrypt_memory::{bench_v2_encrypt_memory_2_file_sync, bench_v2_encrypt_memory_2_memory_sync, bench_v2_encrypt_memory_2_writer_sync}}, 
    compression::CompressionCodec, 
    stream_v2::{core::MasterKey, parallelism::ParallelismConfig}
};

// Sync benchmarks
pub fn run_sync_benchmarks(_master_key: &MasterKey) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();

    // Example payload and chunk size
    let payload_size = 64 * 1024 * 1024; // 64 MB
    let chunk_size = 2 * 1024 * 1024;    // 2 MB
    let compression = CompressionCodec::Auto;
    let parallelism = ParallelismConfig::new(4, 0, 0.5, 64);
    let payload = random_bytes(payload_size);
    // let payload = b"hello world ".repeat(10_000_000);

    // Encrypt from Memory → Memory
    let (enc_result_mem, ciphertext_mem, _) = bench_v2_encrypt_memory_2_memory_sync(
        payload.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt Memory→Memory result: {:?}", enc_result_mem);
    println!("Ciphertext length: {:?}", ciphertext_mem.as_ref().map(|v| v.len()));

    // Unwrap once 
    let ciphertext = ciphertext_mem.expect("ciphertext missing");

    // Decrypt from Memory → Memory
    let (dec_result_mem, plaintext_mem, _) = bench_v2_decrypt_memory_2_memory_sync(
        ciphertext.clone(), // feed ciphertext buffer
        chunk_size, compression, parallelism.clone()
    );
    println!("Decrypt Memory→Memory result: {:?}", dec_result_mem);
    println!("Plaintext length: {:?}", plaintext_mem.as_ref().map(|v| v.len()));

    // Memory → Memory sync benchmark
    results.extend([enc_result_mem, dec_result_mem]);

    // Encrypt from Memory → File
    let (enc_res_file, _, enc_file_path) = bench_v2_encrypt_memory_2_file_sync(
        payload.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt Memory→File result: {:?}", enc_res_file);
    println!("Ciphertext written to: {:?}", enc_file_path);

    // Decrypt from Memory → File
    let (dec_result_file, _, dec_file_path) = bench_v2_decrypt_memory_2_file_sync(
        ciphertext.clone(),
        chunk_size, compression, parallelism.clone()
    );
    println!("Decrypt Memory→File result: {:?}", dec_result_file);
    println!("Plaintext written to: {:?}", dec_file_path);

    // Memory → File sync benchmark
    results.extend([enc_res_file, dec_result_file]);

    // Encrypt from Memory → Writer
    let (enc_res_writer, ciphertext_writer, _) = bench_v2_encrypt_memory_2_writer_sync(
        payload, chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt Memory→Writer result: {:?}", enc_res_writer);
    println!("Ciphertext length: {:?}", ciphertext_writer.as_ref().map(|v| v.len()));
        
    // Decrypt from Memory → Writer
    let (dec_result_writer, plaintext_writer, _) = bench_v2_decrypt_memory_2_writer_sync(
        ciphertext.clone(),
        chunk_size, compression, parallelism
    );
    println!("Decrypt Memory→Writer result: {:?}", dec_result_writer);
    println!("Plaintext length: {:?}", plaintext_writer.as_ref().map(|v| v.len()));

    // Memory → Writer sync benchmark
    results.extend([enc_res_writer, dec_result_writer]);

    if let Some(path) = enc_file_path {
        if path.exists() {
            std::fs::remove_file(&path).expect("Failed to delete temp file");
        }
    }
    if let Some(path) = dec_file_path {
        if path.exists() {
            std::fs::remove_file(&path).expect("Failed to delete temp file");
        }
    }
    results
}

// Async benchmarks
pub async fn run_async_benchmarks(_master_key: &MasterKey) -> Vec<BenchmarkResult> {
    let results = Vec::new();
    // Mirror sync suite with async versions once implemented
    results
}
    
// -------------------------------
// MAIN RUNNER
// -------------------------------
pub fn main() {
    // Generate a master key once
    let master_key = dummy_master_key(); // own it

    // Pass the functions themselves, not their results
    let sync_fn: Box<dyn Fn() -> Vec<BenchmarkResult>> = Box::new({
        let master_key = master_key.clone();
        move || run_sync_benchmarks(&master_key)
    });

    let async_fn: Box<dyn Fn() -> BenchFuture + Send> = Box::new({
        let master_key = master_key.clone();
        move || {
            let key = master_key.clone();
            Box::pin(async move {
                run_async_benchmarks(&key).await
            })
        }
    });

    // Run the orchestrator with our local suite
    bench_v2_main(Some(sync_fn), Some(async_fn));

    // Wrap sync and async functions so they capture master_key 
}

// ### How It Works
// - `bench_v2_memory.rs` defines its own `main`.
// - When we run this file as a binary (`cargo run -p crypto-core --bin bench_v2_memory`), it executes our local `main`.
// - That `main` calls `bench_v2_main`, but passes in our **local suite functions** (`run_sync_benchmarks`, `run_async_benchmarks`) instead of using the empty defaults in `bench_runner.rs`.
// - This mirrors the Python `partial` style: we bind the `master_key` once and pass the functions themselves.
