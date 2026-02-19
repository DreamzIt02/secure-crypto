// ### `bench_v2_file.rs`

use crypto_core::{
    benchmarks::{bench_results::BenchmarkResult, bench_runner::{BenchFuture, bench_v2_main}, bench_utils::{dummy_master_key, random_bytes}, bench_v2_decrypt_file::{bench_v2_decrypt_file_2_file_sync, bench_v2_decrypt_file_2_memory_sync, bench_v2_decrypt_file_2_writer_sync}, bench_v2_encrypt_file::{bench_v2_encrypt_file_2_file_sync, bench_v2_encrypt_file_2_memory_sync, bench_v2_encrypt_file_2_writer_sync}}, 
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

    // Write payload to temp file
    let input_file = std::env::temp_dir().join("bench_input.bin");
    std::fs::write(&input_file, &payload).expect("Failed to write input file");

    // Encrypt File → File
    let (enc_res_file, _, enc_file_path) = bench_v2_encrypt_file_2_file_sync(
        input_file.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt File→File result: {:?}", enc_res_file);
    println!("Ciphertext written to: {:?}", enc_file_path);

    // Unwrap once 
    let ciphertext_path = enc_file_path.expect("ciphertext missing");

    // Decrypt File → File
    let (dec_result_file, _, dec_file_path) = bench_v2_decrypt_file_2_file_sync(
        ciphertext_path.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Decrypt File→File result: {:?}", dec_result_file);
    println!("Plaintext written to: {:?}", dec_file_path);

    results.extend([enc_res_file, dec_result_file]);

    // Encrypt File → Memory
    let (enc_result_mem, ciphertext_mem, _) = bench_v2_encrypt_file_2_memory_sync(
        input_file.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt File→Memory result: {:?}", enc_result_mem);
    println!("Ciphertext length: {:?}", ciphertext_mem.as_ref().map(|v| v.len()));

    // Decrypt File → Memory
    let (dec_result_mem, plaintext_mem, _) = bench_v2_decrypt_file_2_memory_sync(
        ciphertext_path.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Decrypt File→Memory result: {:?}", dec_result_mem);
    println!("Plaintext length: {:?}", plaintext_mem.as_ref().map(|v| v.len()));

    results.extend([enc_result_mem, dec_result_mem]);

    // Encrypt File → Writer
    let (enc_res_writer, ciphertext_writer, _) = bench_v2_encrypt_file_2_writer_sync(
        input_file.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt File→Writer result: {:?}", enc_res_writer);
    println!("Ciphertext length: {:?}", ciphertext_writer.as_ref().map(|v| v.len()));

    // Decrypt File → Writer
    let (dec_result_writer, plaintext_writer, _) = bench_v2_decrypt_file_2_writer_sync(
        ciphertext_path.clone(), chunk_size, compression, parallelism
    );
    println!("Decrypt File→Writer result: {:?}", dec_result_writer);
    println!("Plaintext length: {:?}", plaintext_writer.as_ref().map(|v| v.len()));

    results.extend([enc_res_writer, dec_result_writer]);
    
    // Cleanup temp files
    if let Some(path) = Some(input_file) {
        if path.exists() {
            std::fs::remove_file(&path).expect("Failed to delete temp ciphertext file");
        }
    }
    if let Some(path) = Some(ciphertext_path) {
        if path.exists() {
            std::fs::remove_file(&path).expect("Failed to delete temp ciphertext file");
        }
    }
    if let Some(path) = dec_file_path {
        if path.exists() {
            std::fs::remove_file(&path).expect("Failed to delete temp plaintext file");
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
// - `bench_v2_file.rs` defines its own `main`.
// - When we run this file as a binary (`cargo run -p crypto-core --bin bench_v2_file`), it executes our local `main`.
// - That `main` calls `bench_v2_main`, but passes in our **local suite functions** (`run_sync_benchmarks`, `run_async_benchmarks`) instead of using the empty defaults in `bench_runner.rs`.
// - This mirrors the Python `partial` style: we bind the `master_key` once and pass the functions themselves.

// ### What changed
// - Payload is written to a temp file (`bench_input.bin`) and used as the input source for all encrypt/decrypt variants.  
// - Each variant (Memory, File, Writer) now starts from **File input**.  
// - Cleanup removes the input file and any ciphertext/plaintext files created.  