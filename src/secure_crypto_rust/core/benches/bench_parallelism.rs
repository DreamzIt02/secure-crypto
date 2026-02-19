// `secure_crypto_rust/core/benches/bench_parallelism.rs`

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::benchmarks::bench_utils::dummy_master_key;
use crypto_core::headers::HeaderV1;
use crypto_core::stream_v2::parallelism::ParallelismConfig;
use crypto_core::stream_v2::{
    encrypt_stream_v2, decrypt_stream_v2,
    InputSource, OutputSink,
    EncryptParams, DecryptParams,
    ApiConfig,
};
use std::fs::File;
use std::io::Write;

fn dummy_header() -> HeaderV1 {
    HeaderV1 {
        chunk_size: 64 * 1024,
        // fill in other required fields with defaults or dummy values
        ..HeaderV1::test_header()
    }
}

/// Helper: create deterministic input file of given size
// fn make_input_file(size: usize) -> std::path::PathBuf {
//     let dir = tempdir().unwrap();
//     let path = dir.path().join("input.bin");
//     let mut f = File::create(&path).unwrap();
//     f.write_all(&vec![42u8; size]).unwrap();
//     path
// }

/// Benchmark: File → File
fn bench_parallelism(c: &mut Criterion) {
    // Keep tempdir alive for the whole function
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("input.bin");
    let enc_path = dir.path().join("encrypted.bin");
    let dec_path = dir.path().join("decrypted.bin");

    // Write deterministic input file
    let mut f = File::create(&input_path).unwrap();
    f.write_all(&vec![42u8; 100 * 1024 * 1024]).unwrap();

    let master_key = dummy_master_key();
    let header = dummy_header();
    let params = EncryptParams { header, dict: None };

    // Precompute ciphertext once
    let config_base = ApiConfig {
        with_buf: Some(true),
        collect_metrics: Some(true),
        alg: None,
        parallelism: None,
    };

    encrypt_stream_v2(
        InputSource::File(input_path.clone()),
        OutputSink::File(enc_path.clone()),
        &master_key,
        params.clone(),
        config_base.clone(),
    ).expect("encryption failed");

    for &workers in &[1, 2, 4, 8] {
        let config = ApiConfig {
            with_buf: Some(true),
            collect_metrics: Some(true),
            alg: None,
            parallelism: Some(ParallelismConfig::new(workers, workers, 0.50, 16)),
        };

        let enc_label = format!("encrypt_file_to_file_parallel_{}w", workers);
        c.bench_function(&enc_label, |b| {
            b.iter(|| {
                encrypt_stream_v2(
                    InputSource::File(input_path.clone()),
                    OutputSink::File(enc_path.clone()),
                    &master_key,
                    params.clone(),
                    config.clone(),
                ).unwrap();
            });
        });

        let dec_label = format!("decrypt_file_to_file_parallel_{}w", workers);
        c.bench_function(&dec_label, |b| {
            b.iter(|| {
                decrypt_stream_v2(
                    InputSource::File(enc_path.clone()),
                    OutputSink::File(dec_path.clone()),
                    &master_key,
                    DecryptParams,
                    config.clone(),
                ).unwrap();
            });
        });
    }

    // TempDir is dropped here, after all benchmarks finish
}

criterion_group!(benches, bench_parallelism);
criterion_main!(benches);

// ### 🧩 Key Features
// - **Precomputes ciphertext once** before decrypt benchmarks, so decrypt measures only decryption throughput.
// - **Iterates over parallelism levels** (`1, 2, 4, 8` workers) using `ParallelismConfig::Workers(N)`.
// - **Separate labels** for each benchmark (`encrypt_file_to_file_parallel_Xw`, `decrypt_file_to_file_parallel_Xw`).
// - **100 MB payload** ensures meaningful scaling and smooths variance.
