// 📂 benches/bench_segment_workers.rs
// # 🛠 Parallel Benchmarks for SegmentWorkers
// # 🔒 Channel-driven run_v1 orchestration, shared buffer for decrypt

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use crossbeam::channel::unbounded;
use crypto_core::{
    constants::cipher_ids, crypto::{DigestAlg, KEY_LEN_32}, headers::{CipherSuite, HeaderV1}, recovery::AsyncLogManager, stream_v2::{
        parallelism::HybridParallelismProfile, segment_worker::{
            DecryptContext, DecryptSegmentInput, DecryptSegmentWorker1, EncryptContext, EncryptSegmentInput, EncryptSegmentWorker1, EncryptedSegment
        }, segmenting::types::SegmentFlags
    }, types::StreamError
};
use bytes::Bytes;
use std::sync::{Arc, Barrier, Mutex, atomic::AtomicBool};
use std::thread;

fn setup_enc_context(alg: DigestAlg, chunk_size: usize, cipher_id: CipherSuite) -> (EncryptContext, Arc<AsyncLogManager>) {
    let header = HeaderV1{ chunk_size: chunk_size as u32, cipher: cipher_id as u16, ..HeaderV1::test_header() }; // Mock header
    let profile = HybridParallelismProfile::semi_dynamic(header.chunk_size as u32, 0.50, 64);
    // Create a Vec of 32 bytes
    let session_key = vec![0x42u8; KEY_LEN_32];
    let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
    
    let context = EncryptContext::new(
        header,
        profile,
        &session_key,
        alg,
    ).unwrap();
    (context, log_manager)
}

fn setup_dec_context(alg: DigestAlg, chunk_size: usize, cipher_id: CipherSuite) -> (DecryptContext, Arc<AsyncLogManager>) {
    let header = HeaderV1{ chunk_size: chunk_size as u32, cipher: cipher_id as u16, ..HeaderV1::test_header() }; // Mock header
    let profile = HybridParallelismProfile::semi_dynamic(header.chunk_size as u32, 0.50, 64);
    // Create a Vec of 32 bytes
    let session_key = vec![0x42u8; KEY_LEN_32];
    let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
    
    let context = DecryptContext::from_stream_header(
        header,
        profile,
        &session_key,
        alg,
    ).unwrap();
    (context, log_manager)
}

fn run_segment_encrypt(worker: EncryptSegmentWorker1, input: EncryptSegmentInput)
    -> Result<crypto_core::stream_v2::segment_worker::EncryptedSegment, StreamError>
{
    let (tx, rx) = unbounded();
    let (mid_tx, mid_rx) = unbounded();

    let handle = thread::spawn(move || {
        worker.run_v1(rx, mid_tx);
    });

    tx.send(input).map_err(|_| StreamError::ChannelSend)?;
    drop(tx);

    let result = mid_rx.recv()
        .map_err(|_| StreamError::ChannelRecv)?
        .map_err(StreamError::SegmentWorker)?;

    handle.join().map_err(|_| StreamError::ThreadPanic)?;
    Ok(result)
}

fn run_segment_decrypt(worker: DecryptSegmentWorker1, input: DecryptSegmentInput)
    -> Result<crypto_core::stream_v2::segment_worker::DecryptedSegment, StreamError>
{
    let (bridge_tx, bridge_rx) = unbounded();
    let (dec_tx, dec_rx) = unbounded();

    let handle = thread::spawn(move || {
        worker.run_v1(bridge_rx, dec_tx);
    });

    bridge_tx.send(input).map_err(|_| StreamError::ChannelSend)?;
    drop(bridge_tx);

    let result = dec_rx.recv()
        .map_err(|_| StreamError::ChannelRecv)?
        .map_err(StreamError::SegmentWorker)?;

    handle.join().map_err(|_| StreamError::ThreadPanic)?;
    Ok(result)
}

fn bench_segment_workers(c: &mut Criterion) {
    let size = 10 * 1024 * 1024;
    let chunk_sizes = [64 * 1024, 1 * 1024 * 1024]; // , 2 * 1024 * 1024, 4 * 1024 * 1024
    let thread_counts = [2, 4]; // 
    let ciphers = [CipherSuite::Aes256Gcm, CipherSuite::Chacha20Poly1305]; // 
    let plaintext = Bytes::from(vec![0u8; size]);
    
    for &chunk_size in &chunk_sizes {
        let mut group = c.benchmark_group("segment_workers_parallel");
        group.throughput(Throughput::Bytes(size as u64));

        for &cipher_id in &ciphers {
            for &threads in &thread_counts {
                let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Blake3, chunk_size, cipher_id);
                let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Blake3, chunk_size, cipher_id);
                let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
                let cancelled = Arc::new(AtomicBool::new(false));

                let enc_worker = EncryptSegmentWorker1::new(
                    Arc::new(crypto_enc),
                    log_enc,
                    fatal_tx.clone(),
                    cancelled.clone(),
                );

                let dec_worker = DecryptSegmentWorker1::new(
                    Arc::new(crypto_dec),
                    log_dec,
                    fatal_tx,
                    cancelled,
                );

                let bench_name = format!(
                    "{} chunk_size {} threads {}",
                    cipher_ids::name(cipher_id as u16),
                    size,
                    threads
                );

                // ✅ Reset buffer for this cipher/thread combo 
                let encrypted_segments: Arc<Mutex<Vec<(u32, Arc<EncryptedSegment>)>>> = Arc::new(Mutex::new(Vec::new()));
                
                // Encrypt benchmark: fill buffer
                group.bench_function(BenchmarkId::new("encrypt", bench_name.clone()), |b| {
                    let segments = encrypted_segments.clone();
                    b.iter_custom(|iters| {
                        let barrier = Arc::new(Barrier::new(threads + 1));
                        let mut handles = Vec::new();

                        for tid in 0..threads {
                            let plaintext = plaintext.clone();
                            let barrier = barrier.clone();
                            let segments = segments.clone();
                                let enc_worker = enc_worker.clone();

                            handles.push(thread::spawn(move || {
                                let enc_worker = enc_worker.clone();

                                barrier.wait();

                                for i in 0..iters {
                                    let idx = i as u32;
                                    let input = EncryptSegmentInput {
                                        segment_index: tid as u32,
                                        bytes: plaintext.clone(),
                                        flags: SegmentFlags::empty(),
                                        stage_times: Default::default(),
                                    };

                                    let enc_segment = run_segment_encrypt(enc_worker.clone(), input).unwrap();
                                    criterion::black_box(&enc_segment);

                                    segments.lock().unwrap().push((idx, Arc::new(enc_segment)));
                                }
                            }));
                        }

                        barrier.wait();
                        let start = std::time::Instant::now();
                        for h in handles { h.join().unwrap(); }
                        start.elapsed()
                    });
                });

                // Decrypt benchmark: consume precomputed buffer
                group.bench_function(BenchmarkId::new("decrypt", bench_name.clone()), |b| {
                    let segments = encrypted_segments.clone();
                    
                    b.iter_custom(|iters| {
                        let barrier = Arc::new(Barrier::new(threads + 1));
                        let mut handles = Vec::new();

                        for _ in 0..threads {
                            let barrier = barrier.clone();
                            let segments = segments.clone();
                            let dec_worker = dec_worker.clone();
                             
                            handles.push(thread::spawn(move || {
                                let segments = segments.clone();
                                let dec_worker = dec_worker.clone();

                                barrier.wait();
                                
                                for (idx, enc_arc) in segments.lock().unwrap().iter().take(iters as usize) {
                                    // Arc<EncryptedSegment> → EncryptedSegment
                                    let enc_seg: EncryptedSegment = enc_arc.as_ref().clone();
                                    let input = DecryptSegmentInput::from(enc_seg);
                                    let dec_seg = run_segment_decrypt(dec_worker.clone(), input).unwrap();
                                    criterion::black_box((idx, dec_seg));
                                }
                            }));
                        }

                        barrier.wait();
                        let start = std::time::Instant::now();
                        for h in handles { h.join().unwrap(); }
                        start.elapsed()
                    });
                });
            }
        }

        group.finish();
    }
}

criterion_group!(benches, bench_segment_workers);
criterion_main!(benches);

// ### 🔑 What Changed
// - **No `encrypt_in_place` / `decrypt_in_place`:** replaced with `run_segment_encrypt` and `run_segment_decrypt` helpers that use `run_v1` and channels, exactly like our test code.
// - **Shared buffer:** `Arc<Mutex<Vec<(u32, Arc<Bytes>)>>>` holds encrypted wires so decrypt doesn’t redo encrypt.
// - **Decrypt benchmark:** consumes precomputed wires, calling `run_segment_decrypt` on each.
