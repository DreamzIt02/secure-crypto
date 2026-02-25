// 📂 benches/bench_frame_worker.rs

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use crossbeam::channel::unbounded;
use crypto_core::{constants::cipher_ids, headers::HeaderV1, stream_v2::{frame_worker::{FrameInput, decrypt::DecryptFrameWorker1, encrypt::EncryptFrameWorker1}, framing::FrameType}, types::StreamError};
use rand::Rng;
use bytes::Bytes;

fn bench_frame_worker(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();

    // Different input sizes
    let sizes = [
        1024,
        4 * 1024,
        32 * 1024,
        64 * 1024,
        1024 * 1024,
        2 * 1024 * 1024,
        4 * 1024 * 1024,
    ];

    let ciphers = [cipher_ids::AES256_GCM, cipher_ids::CHACHA20_POLY1305];

    for &size in &sizes {
        let plaintext = Bytes::from(vec![0u8; size]);

        let mut group = c.benchmark_group("frame_worker");
        group.throughput(Throughput::Bytes(size as u64));

        for &cipher_id in &ciphers {
            let header = HeaderV1 { cipher: cipher_id, ..HeaderV1::test_header() };

            // Construct workers
            let fatal_tx = unbounded::<StreamError>().0;
            let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

            let enc_worker = EncryptFrameWorker1::new(header.clone(), &key, fatal_tx.clone(), cancelled.clone()).unwrap();
            let dec_worker = DecryptFrameWorker1::new(header.clone(), &key, fatal_tx.clone(), cancelled.clone()).unwrap();

            let bench_name = format!("cipher {} size {}", cipher_ids::name(cipher_id), size);

            // Encrypt benchmark
            let frame_input = FrameInput {
                payload: plaintext.clone(),
                frame_type: FrameType::Data,
                segment_index: 0,
                frame_index: 0,
            };
            group.bench_with_input(
                BenchmarkId::new(format!("encrypt {}", bench_name), size),
                &frame_input,
                |b, input| {
                    b.iter(|| {
                        let frame = enc_worker.encrypt_frame(input).unwrap();
                        criterion::black_box(frame);
                    });
                },
            );

            // Decrypt benchmark (using ciphertext from encrypt)
            let encrypted = enc_worker.encrypt_frame(&frame_input).unwrap();
            group.bench_with_input(
                BenchmarkId::new(format!("decrypt {}", bench_name), size),
                &encrypted.wire,
                |b, wire| {
                    b.iter(|| {
                        let frame = dec_worker.decrypt_frame(wire.clone()).unwrap();
                        criterion::black_box(frame);
                    });
                },
            );
        }

        group.finish();
    }
}

criterion_group!(benches, bench_frame_worker);
criterion_main!(benches);

// ### Key points
// - **Encrypt path**: Uses `EncryptFrameWorker1::encrypt_frame` directly with a constructed `FrameInput`.
// - **Decrypt path**: Feeds the `wire` bytes from the encrypted frame into `DecryptFrameWorker1::decrypt_frame`.
// - **Symmetry**: Both seal/open are benchmarked under `"encrypt …"` and `"decrypt …"` labels, so Criterion reports them separately.
// - **Throughput**: Set per input size, just like our AEAD benchmark.
