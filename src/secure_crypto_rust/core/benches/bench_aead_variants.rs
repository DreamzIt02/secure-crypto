// 📂 benches/bench_aead_variants.rs

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use crypto_core::{constants::cipher_ids, crypto::{AeadImpl, NONCE_LEN_12}, headers::HeaderV1};
use rand::Rng;

fn bench_aead(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();
    let nonce: [u8; NONCE_LEN_12] = rng.gen();
    let aad = b"benchmark-aad";

    // Different input sizes
    let sizes = [
        1024,
        4 * 1024,
        32 * 1024,
        64 * 1024,
        1024 * 1024,
        2 * 1024 * 1024,
        4 * 1024 * 1024,
    ]; // 1 KiB, 4 KiB, 32 KiB, 64 KiB, 1 MiB, 2 MiB, 4 MiB

    let ciphers = [cipher_ids::AES256_GCM, cipher_ids::CHACHA20_POLY1305];

    for &size in &sizes {
        let plaintext = vec![0u8; size];

        let mut group = c.benchmark_group("aead");
        group.throughput(Throughput::Bytes(size as u64));

        for &cipher_id in &ciphers {
            let header = HeaderV1 { cipher: cipher_id, ..HeaderV1::test_header() };
            let aead = AeadImpl::from_header_and_key(&header, &key).unwrap();

            let bench_name = format!("cipher {} size {}", cipher_ids::name(cipher_id), size);

            // Seal benchmark
            group.bench_with_input(
                BenchmarkId::new(format!("seal {}", bench_name), size),
                &plaintext,
                |b, plaintext| {
                    b.iter(|| {
                        let ciphertext = aead.seal(&nonce, aad, plaintext).unwrap();
                        criterion::black_box(ciphertext);
                    });
                },
            );

            // Open benchmark (using ciphertext from seal)
            let ciphertext = aead.seal(&nonce, aad, &plaintext).unwrap();
            group.bench_with_input(
                BenchmarkId::new(format!("open {}", bench_name), size),
                &ciphertext,
                |b, ciphertext| {
                    b.iter(|| {
                        let decrypted = aead.open(&nonce, aad, ciphertext).unwrap();
                        criterion::black_box(decrypted);
                    });
                },
            );
        }

        group.finish();
    }
}

criterion_group!(benches, bench_aead);
criterion_main!(benches);

// ### How to run
// ```bash
// cargo bench
// ```

// Criterion will output per‑cipher, per‑size statistics with confidence intervals. We’ll see whether AES‑GCM catches up at larger sizes (especially if AES‑NI is enabled with `RUSTFLAGS="-C target-cpu=native"`), and how ChaCha scales.

// ### What we’ll learn
// - **Scaling curve:** AES‑GCM often improves relative to ChaCha as input size grows, but only with hardware acceleration.  
// - **Consistency:** ChaCha throughput is steady across sizes and platforms.  
// - **Environment impact:** On CPUs without AES‑NI, ChaCha will dominate. On modern Intel/AMD with AES‑NI, AES‑GCM can exceed hundreds of MB/s.
