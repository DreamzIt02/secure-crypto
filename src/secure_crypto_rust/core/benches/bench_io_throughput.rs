// `secure_crypto_rust/core/benches/bench_io_throughput.rs`

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::benchmarks::bench_utils::dummy_master_key;
use crypto_core::headers::HeaderV1;
use crypto_core::stream_v2::{encrypt_stream_v2, decrypt_stream_v2};
use crypto_core::stream_v2::{InputSource, OutputSink, EncryptParams, DecryptParams, ApiConfig};
use std::fs::{File};
use std::io::Write;
use tempfile::tempdir;


fn dummy_header() -> HeaderV1 {
    HeaderV1 {
        chunk_size: 64 * 1024,
        // fill in other required fields with defaults or dummy values
        ..HeaderV1::test_header()
    }
}

/// Helper to create deterministic input data
fn make_input(size: usize) -> Vec<u8> {
    vec![42u8; size] // fixed byte pattern
}

/// Benchmark: Memory → Memory
fn bench_memory_to_memory(c: &mut Criterion) {
    let input_data = make_input(100 * 1024 * 1024); // 100 MB

    let master_key = dummy_master_key();
    let header = dummy_header();

    let params = EncryptParams { header, dict: None };
    let config = ApiConfig { 
        with_buf: Some(true), 
        collect_metrics: Some(true), 
        alg: None, 
        parallelism: None 
    };

    // 🔑 Precompute ciphertext once outside the loop
    let enc_snapshot = encrypt_stream_v2(
        InputSource::Memory(input_data.clone()),
        OutputSink::Memory,
        &master_key,
        params.clone(),
        config.clone(),
    ).expect("encryption failed");

    let encrypted_buf = enc_snapshot
        .output
        .expect("no encrypted output captured");

    // Benchmark encryption throughput
    c.bench_function("encrypt_memory_to_memory", |b| {
        b.iter(|| {
            let _snapshot = encrypt_stream_v2(
                InputSource::Memory(input_data.clone()),
                OutputSink::Memory,
                &master_key,
                params.clone(),
                config.clone(),
            ).unwrap();
        });
    });

    // Benchmark decryption throughput using precomputed ciphertext
    c.bench_function("decrypt_memory_to_memory", |b| {
        b.iter(|| {
            let _dec_snapshot = decrypt_stream_v2(
                InputSource::Memory(encrypted_buf.clone()),
                OutputSink::Memory,
                &master_key,
                DecryptParams,
                config.clone(),
            ).unwrap();
        });
    });
}

/// Benchmark: File → File
fn bench_file_to_file(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    let enc_path = dir.path().join("encrypted.bin");
    let dec_path = dir.path().join("decrypted.bin");

    // Write deterministic input file
    let mut f = File::create(&input_path).unwrap();
    f.write_all(&make_input(10 * 1024 * 1024)).unwrap();

    let master_key = dummy_master_key();
    let header = dummy_header();
    let params = EncryptParams { header, dict: None };
    let config = ApiConfig { with_buf: None, collect_metrics: Some(true), alg: None, parallelism: None };

    // Encryption benchmark
    c.bench_function("encrypt_file_to_file", |b| {
        b.iter(|| {
            let _enc_snapshot = encrypt_stream_v2(
                InputSource::File(input_path.clone()),
                OutputSink::File(enc_path.clone()),
                &master_key,
                params.clone(),
                config.clone(),
            ).unwrap();
        });
    });

    // Decryption benchmark
    c.bench_function("decrypt_file_to_file", |b| {
        b.iter(|| {
            // Step 1: Encrypt first, capture ciphertext file
            let _enc_snapshot = encrypt_stream_v2(
                InputSource::File(input_path.clone()),
                OutputSink::File(enc_path.clone()),
                &master_key,
                params.clone(),
                config.clone(),
            ).unwrap();

            // Step 2: Decrypt ciphertext file → plaintext output
            let _dec_snapshot = decrypt_stream_v2(
                InputSource::File(enc_path.clone()),
                OutputSink::File(dec_path.clone()),
                &master_key,
                DecryptParams,
                config.clone(),
            ).unwrap();
        });
    });
}

/// Benchmark: File → File
fn bench_file_to_file_uni(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    let enc_path = dir.path().join("encrypted.bin");
    let dec_path = dir.path().join("decrypted.bin");

    // Write deterministic input file once
    let mut f = File::create(&input_path).unwrap();
    f.write_all(&vec![42u8; 100 * 1024 * 1024]).unwrap();

    let master_key = dummy_master_key();
    let header = dummy_header();
    let params = EncryptParams { header, dict: None };
    let config = ApiConfig::default();

    // 🔑 Precompute ciphertext once outside the benchmark loop
    encrypt_stream_v2(
        InputSource::File(input_path.clone()),
        OutputSink::File(enc_path.clone()),
        &master_key,
        params.clone(),
        config.clone(),
    ).expect("encryption failed");

    // Benchmark encryption throughput separately
    c.bench_function("encrypt_file_to_file_uni", |b| {
        b.iter(|| {
            let _ = encrypt_stream_v2(
                InputSource::File(input_path.clone()),
                OutputSink::File(enc_path.clone()),
                &master_key,
                params.clone(),
                config.clone(),
            ).unwrap();
        });
    });

    // Benchmark decrypt throughput using precomputed ciphertext
    c.bench_function("decrypt_file_to_file_uni", |b| {
        b.iter(|| {
            let _ = decrypt_stream_v2(
                InputSource::File(enc_path.clone()),
                OutputSink::File(dec_path.clone()),
                &master_key,
                DecryptParams,
                config.clone(),
            ).unwrap();
        });
    });
}

/// Benchmark: File → Memory
fn bench_file_to_memory(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.bin");

    let mut f = File::create(&input_path).unwrap();
    f.write_all(&make_input(10 * 1024 * 1024)).unwrap();

    let master_key = dummy_master_key();
    let header = dummy_header();
    let params = EncryptParams { header, dict: None };
    let config = ApiConfig { with_buf: Some(true), collect_metrics: Some(true), alg: None, parallelism: None };

    c.bench_function("encrypt_file_to_memory", |b| {
        b.iter(|| {
            let _ = encrypt_stream_v2(
                InputSource::File(input_path.clone()),
                OutputSink::Memory,
                &master_key,
                params.clone(),
                config.clone(),
            ).unwrap();
        });
    });
}

/// Benchmark: Memory → File
fn bench_memory_to_file(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("output.bin");

    let input_data = make_input(10 * 1024 * 1024);

    let master_key = dummy_master_key();
    let header = dummy_header();
    let params = EncryptParams { header, dict: None };
    let config = ApiConfig { with_buf: None, collect_metrics: Some(true), alg: None, parallelism: None };

    c.bench_function("encrypt_memory_to_file", |b| {
        b.iter(|| {
            let _ = encrypt_stream_v2(
                InputSource::Memory(input_data.clone()),
                OutputSink::File(output_path.clone()),
                &master_key,
                params.clone(),
                config.clone(),
            ).unwrap();
        });
    });
}

/// Benchmark: Socket → Socket (stub / optional)
fn bench_socket_to_socket(_c: &mut Criterion) {
    // TODO: integrate with TcpStream or UnixStream
    // For now, left as a placeholder
}

criterion_group!(
    benches,
    bench_memory_to_memory,
    bench_file_to_file,
    bench_file_to_file_uni,
    bench_file_to_memory,
    bench_memory_to_file,
    bench_socket_to_socket
);
criterion_main!(benches);

// ### 🧩 Notes
// - Uses `tempfile` crate for safe temporary file handling.
// - Deterministic input payload (`vec![42u8; size]`) ensures reproducibility.
// - Each benchmark runs both encrypt and decrypt where applicable.
// - Socket→Socket left as a stub since it requires networking setup.

// ### ▶️ Run
// From inside `core`:

// ```bash
// cargo bench --bench bench_io_throughput
// ```

// Criterion will produce timing results in `target/criterion/bench_io_throughput/`.
