// `secure_crypto_rust/core/benches/bench_digest_variants.rs`

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::benchmarks::bench_utils::dummy_master_key;
use crypto_core::crypto::DigestAlg;
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

fn dummy_header() -> HeaderV1 {
    HeaderV1 {
        chunk_size: 64 * 1024,
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

fn bench_digest_variants(c: &mut Criterion) {
    // Create a 100 MB input file
    let (dir, input_path) = make_input_file(10 * 1024 * 1024);
    let enc_path = dir.path().join("encrypted.bin");
    let dec_path = dir.path().join("decrypted.bin");

    let master_key = dummy_master_key();
    let header = dummy_header();
    let params = EncryptParams { header, dict: None };

    // Digest algorithms to test
    let digests = vec![
        DigestAlg::Sha256,
        DigestAlg::Sha512,
        DigestAlg::Blake3,
    ];

    for digest in digests {
        let config = ApiConfig {
            with_buf: Some(true),
            collect_metrics: Some(true),
            alg: Some(digest.clone()),
            parallelism: None,
        };

        // Precompute ciphertext once for decrypt benchmarks
        encrypt_stream_v2(
            InputSource::File(input_path.clone()),
            OutputSink::File(enc_path.clone()),
            &master_key,
            params.clone(),
            config.clone(),
        ).expect("encryption failed");

        // Encryption benchmark
        let enc_label = format!("encrypt_file_to_file_digest_{:?}", digest);
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
        let dec_label = format!("decrypt_file_to_file_digest_{:?}", digest);
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

criterion_group!(benches, bench_digest_variants);
criterion_main!(benches);

// ### 🧩 Key Features
// - **Digest algorithms tested**: SHA‑256, SHA‑512, BLAKE3, plus an extensible/custom slot.  
// - **Precomputes ciphertext once** before decrypt benchmarks, so decrypt measures only decryption throughput.  
// - **Separate labels** for each digest algorithm, making Criterion reports easy to compare.  
// - **100 MB payload** ensures meaningful scaling and smooths variance.  
