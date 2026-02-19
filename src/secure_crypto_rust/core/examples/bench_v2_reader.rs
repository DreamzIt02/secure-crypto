// ### bench_v2_reader.rs

use crypto_core::{
    benchmarks::{
        bench_results::BenchmarkResult,
        bench_runner::{BenchFuture, bench_v2_main},
        bench_utils::{dummy_master_key, random_bytes},
        bench_v2_decrypt_reader::{
            bench_v2_decrypt_reader_2_file_sync,
            bench_v2_decrypt_reader_2_memory_sync,
            bench_v2_decrypt_reader_2_writer_sync
        },
        bench_v2_encrypt_reader::{
            bench_v2_encrypt_reader_2_file_sync,
            bench_v2_encrypt_reader_2_memory_sync,
            bench_v2_encrypt_reader_2_writer_sync
        }
    },
    compression::CompressionCodec,
    stream_v2::{core::MasterKey, parallelism::ParallelismConfig}
};
use std::io::Cursor;

// Sync benchmarks
pub fn run_sync_benchmarks(_master_key: &MasterKey) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();

    // Example payload and chunk size
    let payload_size = 64 * 1024 * 1024; // 64 MB
    let chunk_size = 2 * 1024 * 1024;    // 2 MB
    let compression = CompressionCodec::Auto;
    let parallelism = ParallelismConfig::new(4, 0, 0.5, 64);
    let payload = random_bytes(payload_size);

    // Wrap payload in a reader
    let input_reader = Cursor::new(payload);

    // Encrypt Reader → Memory
    let (enc_result_mem, ciphertext_mem, _) = bench_v2_encrypt_reader_2_memory_sync(
        input_reader.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt Reader→Memory result: {:?}", enc_result_mem);
    println!("Ciphertext length: {:?}", ciphertext_mem.as_ref().map(|v| v.len()));

    // Wrap encrypted output in a reader
    let ciphertext = ciphertext_mem.expect("ciphertext missing");
    let output_reader = Cursor::new(ciphertext);

    // Decrypt Reader → Memory
    let (dec_result_mem, plaintext_mem, _) = bench_v2_decrypt_reader_2_memory_sync(
        output_reader.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Decrypt Reader→Memory result: {:?}", dec_result_mem);
    println!("Plaintext length: {:?}", plaintext_mem.as_ref().map(|v| v.len()));

    results.extend([enc_result_mem, dec_result_mem]);

    // Encrypt Reader → Writer
    let (enc_res_writer, ciphertext_writer, _) = bench_v2_encrypt_reader_2_writer_sync(
        input_reader.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt Reader→Writer result: {:?}", enc_res_writer);
    println!("Ciphertext length: {:?}", ciphertext_writer.as_ref().map(|v| v.len()));

    // Decrypt Reader → Writer
    let (dec_result_writer, plaintext_writer, _) = bench_v2_decrypt_reader_2_writer_sync(
        output_reader.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Decrypt Reader→Writer result: {:?}", dec_result_writer);
    println!("Plaintext length: {:?}", plaintext_writer.as_ref().map(|v| v.len()));

    results.extend([enc_res_writer, dec_result_writer]);

    // Encrypt Reader → File
    let (enc_res_file, _, enc_file_path) = bench_v2_encrypt_reader_2_file_sync(
        input_reader.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Encrypt Reader→File result: {:?}", enc_res_file);
    println!("Ciphertext written to: {:?}", enc_file_path);

    // Decrypt Reader → File
    let (dec_result_file, _, dec_file_path) = bench_v2_decrypt_reader_2_file_sync(
        output_reader.clone(), chunk_size, compression, parallelism.clone()
    );
    println!("Decrypt Reader→File result: {:?}", dec_result_file);
    println!("Plaintext written to: {:?}", dec_file_path);

    results.extend([enc_res_file, dec_result_file]);

    // Cleanup temp files
    if let Some(path) = enc_file_path {
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
    let master_key = dummy_master_key();

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

    bench_v2_main(Some(sync_fn), Some(async_fn));
}

// ### Key Notes
// - `Cursor::new(payload)` wraps our `Vec<u8>` into a `Read` implementation, so we can benchmark **Reader input** consistently.
// - Each variant (Reader→File, Reader→Memory, Reader→Writer) mirrors the file suite but swaps the input source.
// - Cleanup removes any temporary ciphertext/plaintext files created during the run.
