
// 📂 benches/bench_frame_workers.rs (FIXED VERSION)
// # 🛠 Correct Parallel Benchmark (Real Scaling)
// # 🔥 Correct Way To Benchmark Parallel Scaling

// We must:

// * Spawn threads once
// * Reuse them
// * Let each thread loop
// * Synchronize start with barrier
// * Measure steady-state throughput

// That measures CPU scaling, not OS overhead.

// This keeps threads alive during the whole measurement.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use crossbeam::channel::unbounded;
use crypto_core::{
    constants::cipher_ids,
    headers::HeaderV1,
    stream_v2::{
        frame_worker::{
            FrameInput, decrypt::DecryptFrameWorker1, encrypt::EncryptFrameWorker1
        },
        framing::FrameType,
    },
    types::StreamError,
};
use rand::Rng;
use bytes::Bytes;
use std::sync::{
    Arc, Barrier, Mutex, atomic::AtomicBool
};
use std::thread;

fn bench_frame_workers(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();

    let sizes = [64 * 1024, 1024 * 1024];
    let thread_counts = [2, 4];
    let ciphers = [cipher_ids::AES256_GCM, cipher_ids::CHACHA20_POLY1305];

    for &size in &sizes {
        let plaintext = Bytes::from(vec![0u8; size]);

        let mut group = c.benchmark_group("frame_workers_parallel");
        group.throughput(Throughput::Bytes(size as u64));

        for &cipher_id in &ciphers {
            for &threads in &thread_counts {

                let header = HeaderV1 {
                    cipher: cipher_id,
                    ..HeaderV1::test_header()
                };

                let bench_name = format!(
                    "{} size {} threads {}",
                    cipher_ids::name(cipher_id),
                    size,
                    threads
                );

                group.bench_function(BenchmarkId::new("encrypt_parallel", bench_name), |b| {
                    b.iter_custom(|iters| {
                        let barrier = Arc::new(Barrier::new(threads + 1));
                        let mut handles = Vec::new();

                        for _ in 0..threads {
                            let header = header.clone();
                            let key = key.clone();
                            let plaintext = plaintext.clone();
                            let barrier = barrier.clone();

                            handles.push(thread::spawn(move || {
                                let fatal_tx = unbounded::<StreamError>().0;
                                let cancelled = Arc::new(AtomicBool::new(false));

                                let worker = EncryptFrameWorker1::new(
                                    header,
                                    &key,
                                    fatal_tx,
                                    cancelled,
                                ).unwrap();
                                
                                let input = FrameInput {
                                    payload: plaintext,
                                    frame_type: FrameType::Data,
                                    segment_index: 0,
                                    frame_index: 0,
                                };

                                barrier.wait(); // sync start

                                for _ in 0..iters {
                                    let frame = worker.encrypt_in_place(&input).unwrap();
                                    criterion::black_box(frame);
                                }
                            }));
                        }

                        barrier.wait(); // start timing
                        let start = std::time::Instant::now();

                        for handle in handles {
                            handle.join().unwrap();
                        }

                        start.elapsed()
                    });
                });
            }
        }

        group.finish();
    }
}


fn bench_frame_workers_roundtrip(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();

    let sizes = [64 * 1024, 1024 * 1024];
    let thread_counts = [2, 4];
    let ciphers = [cipher_ids::AES256_GCM, cipher_ids::CHACHA20_POLY1305];

    for &size in &sizes {
        let plaintext = Bytes::from(vec![0u8; size]);

        let mut group = c.benchmark_group("frame_workers_parallel");
        group.throughput(Throughput::Bytes(size as u64));

        for &cipher_id in &ciphers {
            for &threads in &thread_counts {
                let header = HeaderV1 {
                    cipher: cipher_id,
                    ..HeaderV1::test_header()
                };

                let bench_name = format!(
                    "{} size {} threads {}",
                    cipher_ids::name(cipher_id),
                    size,
                    threads
                );

                // Shared buffer for encrypted frames
                let encrypted_frames: Arc<Mutex<Vec<(u32, Arc<Bytes>)>>> = Arc::new( Mutex::new(Vec::new()));

                // Encrypt benchmark: fill the buffer
                group.bench_function(BenchmarkId::new("encrypt", bench_name.clone()), |b| {
                    let frames = encrypted_frames.clone();
                    b.iter_custom(|iters| {
                        let barrier = Arc::new(Barrier::new(threads + 1));
                        let mut handles = Vec::new();

                        for _ in 0..threads {
                            let header = header.clone();
                            let key = key.clone();
                            let plaintext = plaintext.clone();
                            let barrier = barrier.clone();
                            let frames = frames.clone();

                            handles.push(thread::spawn(move || {
                                let fatal_tx = unbounded::<StreamError>().0;
                                let cancelled = Arc::new(AtomicBool::new(false));

                                let enc_worker = EncryptFrameWorker1::new(
                                    header,
                                    &key,
                                    fatal_tx,
                                    cancelled,
                                ).unwrap();

                                let input = FrameInput {
                                    payload: plaintext,
                                    frame_type: FrameType::Data,
                                    segment_index: 0,
                                    frame_index: 0,
                                };

                                barrier.wait();

                                for i in 0..iters {
                                    let idx = i as u32; // convert once to u32

                                    let mut input_i = input.clone();
                                    input_i.frame_index = idx; // frame_index is u32

                                    let enc_frame = enc_worker.encrypt_in_place(&input_i).unwrap();
                                    criterion::black_box(&enc_frame);

                                    // Store wire with u32 index
                                    frames.lock().unwrap().push((idx, Arc::new(enc_frame.wire.clone())));
                                }

                            }));
                        }

                        barrier.wait();
                        let start = std::time::Instant::now();
                        for handle in handles {
                            handle.join().unwrap();
                        }
                        start.elapsed()
                    });
                });

                // Decrypt benchmark: consume precomputed frames
                group.bench_function(BenchmarkId::new("decrypt", bench_name.clone()), |b| {
                    let frames = encrypted_frames.clone();
                    b.iter_custom(|iters| {
                        let barrier = Arc::new(Barrier::new(threads + 1));
                        let mut handles = Vec::new();

                        for _ in 0..threads {
                            let header = header.clone();
                            let key = key.clone();
                            let barrier = barrier.clone();
                            let frames = frames.clone();

                            handles.push(thread::spawn(move || {
                                let fatal_tx = unbounded::<StreamError>().0;
                                let cancelled = Arc::new(AtomicBool::new(false));

                                let dec_worker = DecryptFrameWorker1::new(
                                    header,
                                    &key,
                                    fatal_tx,
                                    cancelled,
                                ).unwrap();

                                barrier.wait();

                                for (idx, wire) in frames.lock().unwrap().iter().take(iters as usize) {
                                    let dec_frame = dec_worker.decrypt_in_place(wire.as_ref().clone()).unwrap();
                                    criterion::black_box((idx, dec_frame));
                                }

                            }));
                        }

                        barrier.wait();
                        let start = std::time::Instant::now();
                        for handle in handles {
                            handle.join().unwrap();
                        }
                        start.elapsed()
                    });
                });

            }
        }

        group.finish();
    }
}

criterion_group!(benches, bench_frame_workers, bench_frame_workers_roundtrip);
criterion_main!(benches);

// # 🚀 What This Will Show

// Now we should see:

// For AES 1 MiB:

// | Threads | Expected       |
// | ------- | -------------- |
// | 1       | ~500 MiB/s     |
// | 2       | ~950 MiB/s     |
// | 4       | ~1.8–2.0 GiB/s |
// | 8       | ~2.1 GiB/s     |

// For ChaCha:

// | Threads | Expected       |
// | ------- | -------------- |
// | 1       | ~700 MiB/s     |
// | 2       | ~1.3 GiB/s     |
// | 4       | ~2.6–2.8 GiB/s |
// | 8       | ~3.0 GiB/s     |

// That would be healthy scaling.
