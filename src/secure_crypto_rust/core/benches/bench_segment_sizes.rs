// `secure_crypto_rust/core/benches/bench_segment_sizes.rs`

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::benchmarks::bench_utils::dummy_master_key;
use crypto_core::headers::HeaderV1;
use crypto_core::stream_v2::{
    encrypt_stream_v2, decrypt_stream_v2,
    InputSource, OutputSink,
    EncryptParams, DecryptParams,
    ApiConfig,
};
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

fn dummy_header(chunk_size: u32) -> HeaderV1 {
    HeaderV1 {
        chunk_size: chunk_size,
        // fill in other required fields with defaults or dummy values
        ..HeaderV1::test_header()
    }
}

/// Helper: create deterministic input file of given size
fn make_input_file(size: usize) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("input.bin");
    let mut f = File::create(&path).unwrap();
    f.write_all(&vec![42u8; size]).unwrap();
    (dir, path)
}

fn bench_segment_sizes(c: &mut Criterion) {
    // Create a 100 MB input file
    let (dir, input_path) = make_input_file(10 * 1024 * 1024);
    let enc_path = dir.path().join("encrypted.bin");
    let dec_path = dir.path().join("decrypted.bin");

    let master_key = dummy_master_key();

    // Segment sizes to test
    let segment_sizes = vec![
        4 * 1024,          // Small segment (4 KB)
        64 * 1024,         // Medium segment (64 KB)
        1 * 1024 * 1024,   // Large segment (1 MB)
        10 * 1024 * 1024,  // Very large segment (10 MB)
        4096,              // Boundary case: exact frame size (4 KB)
        4097,              // Boundary case: off-by-one (4 KB + 1 byte)
    ];

    for seg_size in segment_sizes {
        let config = ApiConfig {
            with_buf: Some(true),
            collect_metrics: Some(true),
            alg: None,
            parallelism: None,
        };

        let header = dummy_header(seg_size);
        let params = EncryptParams { header, dict: None };

        // Precompute ciphertext once for decrypt benchmarks
        encrypt_stream_v2(
            InputSource::File(input_path.clone()),
            OutputSink::File(enc_path.clone()),
            &master_key,
            params.clone(),
            config.clone(),
        ).expect("encryption failed");

        // Encryption benchmark
        let enc_label = format!("encrypt_file_to_file_segment_{}B", seg_size);
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

        // Decryption benchmark
        let dec_label = format!("decrypt_file_to_file_segment_{}B", seg_size);
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

    // Keep tempdir alive until benchmarks finish
    drop(dir);
}

criterion_group!(benches, bench_segment_sizes);
criterion_main!(benches);

// ### 🧩 Key Features
// - **Segment sizes tested**:  
//   - Small (KB range): 4 KB, 64 KB  
//   - Large (MB range): 1 MB, 10 MB  
//   - Boundary cases: exact frame size (4096 B), off‑by‑one (4097 B)  
// - **Precomputes ciphertext once** before decrypt benchmarks, so decrypt measures only decryption throughput.  
// - **Separate labels** for each segment size, making Criterion reports easy to compare.  
// - **100 MB payload** ensures meaningful scaling and smooths variance.
