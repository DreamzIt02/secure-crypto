// # 📂 src/stream_v2/pipeline.rs

// ## 📂 File: `src/stream_v2/pipeline.rs`
// ## Pure pipeline wiring (no crypto logic)

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use bytes::Bytes;
use crossbeam::channel::{bounded};

use crate::headers::HeaderV1;
use crate::stream_v2::compression_pipeline::{spawn_compression_workers, spawn_decompression_workers};
use crate::stream_v2::compression_worker::{CodecInfo, CompressionWorkerError};
use crate::stream_v2::io::{self, PayloadReader};
use crate::stream_v2::parallelism::HybridParallelismProfile;
use crate::stream_v2::segment_worker::{
    DecryptSegmentInput, DecryptSegmentWorker, DecryptedSegment, EncryptSegmentInput, EncryptSegmentWorker, EncryptedSegment, EncryptContext, DecryptContext, SegmentWorkerError
};
use crate::stream_v2::segmenting::types::SegmentFlags;
use crate::telemetry::{Stage, StageTimes, TelemetryCounters, TelemetrySnapshot, TelemetryTimer};
use crate::types::StreamError;
use crate::recovery::persist::AsyncLogManager;

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub profile: HybridParallelismProfile,
    /// The final encrypted stream bytes, if the output sink was memory-backed.
    /// 
    /// - `None` if the output was written directly to a file or external sink.
    /// - `Some(Vec<u8>)` if the pipeline wrote into an in-memory buffer.
    /// 
    /// This field is primarily useful in tests, benchmarks, or integrations
    /// where we want to inspect the produced ciphertext alongside telemetry
    /// counters and stage timings.
    pub buf: Option<Arc<Mutex<Vec<u8>>>>,
}

impl PipelineConfig {
    pub fn new(profile: HybridParallelismProfile, buf: Option<Arc<Mutex<Vec<u8>>>>) -> Self {
        Self {
            profile,
            buf,
        }
    }
    pub fn with_buf(profile: HybridParallelismProfile) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Self { profile, buf: Some(buf.clone()) }, buf)
    }
}


// ============================================================
// Encrypt pipeline
// ============================================================
pub fn run_encrypt_pipeline<R, W>(
    mut reader: &mut PayloadReader<R>,
    mut writer: W,
    crypto: &mut EncryptContext, // borrow mutably
    config: &PipelineConfig, // borrow instead of move
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    let mut counters = TelemetryCounters::default();
    let mut timer = TelemetryTimer::new();
    let mut segment_index = 0u32;

    eprintln!("[PIPELINE] Start encrypt pipeline");

    // ---- Write stream header ----
    let start = Instant::now();
    io::write_header(&mut writer, &crypto.header)?;
    timer.stage_times.add(Stage::Write, start.elapsed());
    counters.bytes_overhead += HeaderV1::LEN as u64; // record stream header overhead
    eprintln!("[PIPELINE] Header written");

    // ---- Channels ----
    let (comp_tx, comp_rx) = bounded::<EncryptSegmentInput>(config.profile.inflight_segments());
    let (seg_tx, seg_rx_raw) = bounded::<Result<EncryptSegmentInput, CompressionWorkerError>>(config.profile.inflight_segments());
    let (seg_tx_clean, seg_rx_clean) = bounded::<EncryptSegmentInput>(config.profile.inflight_segments());
    let (out_tx, out_rx) = bounded::<Result<EncryptedSegment, SegmentWorkerError>>(config.profile.inflight_segments());

    // ---- Spawn compression workers ----
    let mut codec_info = CodecInfo::from_header(&crypto.header, None);
    codec_info.gpu = config.profile.gpu();

    // Compression / segment
    spawn_compression_workers(config.profile.clone(), codec_info, comp_rx, seg_tx.clone());

    drop(seg_tx); // Important: drop seg_tx here so seg_rx_raw eventually closes

    let counters_read = Arc::new(Mutex::new(TelemetryCounters::default()));
    let read_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let compression_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let mut encryption_stage_times = StageTimes::default();

    thread::scope(|scope| {
        // ---- Reader thread ----
        scope.spawn(|| -> Result<(), StreamError> {
            let chunk_size = crypto.base.segment_size;
            let read_stage_times = Arc::clone(&read_stage_times);
            let counters_read = Arc::clone(&counters_read);

            loop {
                let mut times = read_stage_times.lock().unwrap();
                // Read / chunking / before compress
                let start = Instant::now();
                let buf = io::read_exact_or_eof(&mut reader, chunk_size)?;
                
                if buf.is_empty() {
                    eprintln!("[READER] EOF reached, dispatching final empty segment {}", segment_index);
                    if segment_index > 0 {
                        comp_tx.send(EncryptSegmentInput {
                            segment_index,
                            bytes: Bytes::new(),
                            flags: SegmentFlags::FINAL_SEGMENT,
                            stage_times: StageTimes::default(),
                        }).map_err(|_| StreamError::PipelineError("encrypt segment channel closed".into()))?;
                    }
                    times.add(Stage::Read, start.elapsed());
                    break;
                }
                eprintln!("[READER] Dispatching segment {}", segment_index);
                // counters bytes_plaintext
                counters_read.lock().unwrap().bytes_plaintext += buf.len() as u64;

                comp_tx.send(EncryptSegmentInput {
                    segment_index,
                    bytes: buf,
                    flags: SegmentFlags::empty(),
                    stage_times: StageTimes::default(),
                }).map_err(|_| StreamError::PipelineError("encrypt segment channel closed".into()))?;
                
                times.add(Stage::Read, start.elapsed());
                segment_index += 1;

            }
            
            eprintln!("[READER] Finished, dropping comp_tx");
            drop(comp_tx);

            Ok(())
        });

        // Adapter thread: unwrap compression results
        scope.spawn({
            let seg_rx_raw = seg_rx_raw.clone();
            let seg_tx_clean = seg_tx_clean.clone();
            let out_tx = out_tx.clone();
            let compression_stage_times = Arc::clone(&compression_stage_times);
            let counters_read = Arc::clone(&counters_read);

            move || {
                for res in seg_rx_raw.iter() {
                    match res {
                        Ok(seg) => {
                            // merge compression stage_times 
                            let mut times = compression_stage_times.lock().unwrap(); 
                            for (stage, dur) in seg.stage_times.iter() { times.add(*stage, *dur); }

                            // counters bytes_compressed
                            counters_read.lock().unwrap().bytes_compressed += seg.bytes.len() as u64;

                            let _ = seg_tx_clean.send(seg);

                        }
                        Err(e) => {
                            eprintln!("[PIPELINE] compression worker error: {e}");
                            let _ = out_tx.send(Err(SegmentWorkerError::StateError(e.to_string())));
                            break;
                        }
                    }
                }
            }
        });

        drop(seg_tx_clean); // Drop seg_tx_clean when adapter finishes

        // ---- Crypto workers ----
        for _ in 0..config.profile.cpu_workers() {
            let worker = EncryptSegmentWorker::new(crypto.clone(), log_manager.clone());
            let rx = seg_rx_clean.clone();
            let tx = out_tx.clone();

            scope.spawn(move || worker.run_v2(rx, tx));
        }

        drop(out_tx); // drop out_tx in main thread
        eprintln!("[PIPELINE] dropped out_tx in main thread");

        // ---- Ordered writer ----
        let mut ordered_writer = io::OrderedEncryptedWriter::new(&mut writer);

        for res in out_rx.iter() {
            eprintln!("[WRITER] receiving segment result");
            match res {
                Ok(encrypted) => {
                    eprintln!("[WRITER] received segment {}", encrypted.header.segment_index);
                    // merge encryption stage_times
                    encryption_stage_times.merge(&encrypted.stage_times);

                    // 🔥 Merge telemetry from this segment worker
                    counters.merge(&encrypted.counters);

                    // Writing / wiring
                    let start = Instant::now();
                    ordered_writer.push(encrypted)?;
                    encryption_stage_times.add(Stage::Write, start.elapsed());
                }
                Err(e) => {
                    eprintln!("[PIPELINE] crypto/compression worker error: {e}");
                    return Err(StreamError::SegmentWorker(e));
                }
            }
        }
        
        eprintln!("[WRITER] out_rx closed, finishing writer");
        ordered_writer.finish()?;
        
        Ok::<(), StreamError>(())
    })?;

    timer.finish();

    // thread::scope(|scope| {
    // spawn reader, adapter, crypto workers, writer
    // })?;
    // Now safe to merge telemetry
    // merge read stage_times
    // let final_times = read_stage_times.lock().unwrap(); 
    // for (stage, dur) in final_times.iter() { timer.add_stage_time(*stage, *dur); }
    for (stage, dur) in read_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*stage, *dur);
    }
    // merge compression stage_times
    for (stage, dur) in compression_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*stage, *dur);
    }
    // merge encryption stage_times
    for (stage, dur) in encryption_stage_times.iter() {
        timer.add_stage_time(*stage, *dur);
    }
    // update bytes_plaintext len
    counters.bytes_plaintext = counters_read.lock().unwrap().bytes_plaintext;
    // update bytes_compressed len
    counters.bytes_compressed = counters_read.lock().unwrap().bytes_compressed;

    // After pipeline finishes: 
    if let Some(ref arc_buf) = config.buf { 
        let buf = arc_buf.lock().unwrap(); 
        println!("Captured output: {:?}", String::from_utf8_lossy(&buf)); 
    }

    Ok(TelemetrySnapshot::from(
        &counters, 
        &timer, 
        Some(segment_index + 1)
    ))
}

// ============================================================
// Decrypt pipeline
// ============================================================
pub fn run_decrypt_pipeline<R, W>(
    mut reader: &mut PayloadReader<R>,
    mut writer: W,
    crypto: &mut DecryptContext, // borrow mutably
    config: &PipelineConfig, // borrow instead of move
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    let mut counters = TelemetryCounters::default();
    let mut timer = TelemetryTimer::new();
    let mut last_segment_index = 0;

    eprintln!("[PIPELINE] Start decrypt pipeline");

    // ---- Read stream header ----
    // Validation / stream header
    let start = Instant::now();
    crypto.header.validate().map_err(StreamError::Header)?;
    timer.stage_times.add(Stage::Validate, start.elapsed());
    // Calculate len of overhead bytes / stream header
    counters.bytes_overhead += HeaderV1::LEN as u64;
    eprintln!("[PIPELINE] Header validated");

    // ---- Channels ----
    let (seg_tx, seg_rx) = bounded::<DecryptSegmentInput>(config.profile.inflight_segments());
    let (crypto_out_tx, crypto_out_rx) = bounded::<Result<DecryptedSegment, SegmentWorkerError>>(config.profile.inflight_segments());
    let (decomp_out_tx, decomp_out_rx) = bounded::<Result<DecryptedSegment, CompressionWorkerError>>(config.profile.inflight_segments());
    let (decomp_in_tx, decomp_in_rx) = bounded::<DecryptedSegment>(config.profile.inflight_segments());

    // ---- Spawn decompression workers ----
    let mut codec_info = CodecInfo::from_header(&crypto.header, None);
    codec_info.gpu = config.profile.gpu();

    let counters_read = Arc::new(Mutex::new(TelemetryCounters::default()));
    let counters_segment = Arc::new(Mutex::new(TelemetryCounters::default()));
    let read_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let decryption_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let mut decompression_stage_times = StageTimes::default();

    thread::scope(|scope| {
        // ---- Reader thread ----
        scope.spawn(|| -> Result<(), StreamError> {
            eprintln!("[READER] Thread started");
            let read_stage_times = Arc::clone(&read_stage_times);
            let counters_read = Arc::clone(&counters_read);

            // Read / chunking / before decompress
            let mut start = Instant::now();            
            while let Some((header, wire)) = io::read_segment(&mut reader)? {
                eprintln!("[READER] Dispatching segment {}", header.segment_index);
                let mut times = read_stage_times.lock().unwrap();
                
                counters_read.lock().unwrap().bytes_ciphertext += wire.len() as u64;

                seg_tx.send(DecryptSegmentInput { header, wire })
                    .map_err(|_| StreamError::PipelineError("decrypt segment channel closed".into()))?;

                times.add(Stage::Read, start.elapsed());
                start = Instant::now();
            }

            eprintln!("[READER] Finished, dropping seg_tx");
            drop(seg_tx);

            Ok(())
        });

        // ---- Crypto workers ----
        for _ in 0..config.profile.cpu_workers() {
            let worker = DecryptSegmentWorker::new(crypto.clone(), log_manager.clone());
            let rx = seg_rx.clone();
            let tx = crypto_out_tx.clone();

            scope.spawn(move || worker.run_v2(rx, tx));
        }

        drop(crypto_out_tx);
        eprintln!("[PIPELINE] dropped out_tx in main thread");

        // Adapter: forward successful segments, propagate errors
        scope.spawn({
            let decomp_in_tx = decomp_in_tx.clone();
            let decomp_out_tx = decomp_out_tx.clone();
            let decryption_stage_times = Arc::clone(&decryption_stage_times);
            let counters_segment = Arc::clone(&counters_segment);

            move || {
                for res in crypto_out_rx.iter() {
                    match res {
                        Ok(seg) => {
                            let mut times = decryption_stage_times.lock().unwrap();
                            for (stage, dur) in seg.stage_times.iter() { times.add(*stage, *dur); }

                            // 🔥 Merge telemetry from this segment
                            counters_segment.lock().unwrap().merge(&seg.counters);

                            let _ = decomp_in_tx.send(seg);
                        }
                        Err(e) => {
                            eprintln!("[PIPELINE] crypto worker error: {e}");
                            let _ = decomp_out_tx.send(Err(CompressionWorkerError::StateError(e.to_string())));
                            break;
                        }
                    }
                }
            }
        });

        // Drop decomp_in_tx when adapter finishes
        drop(decomp_in_tx);

        // Now spawn decompression workers on decomp_in_rx
        spawn_decompression_workers(config.profile.clone(), codec_info, decomp_in_rx, decomp_out_tx.clone());
        
        drop(decomp_out_tx); // Drop decomp_out_tx here locally for main thread

        // ---- Ordered plaintext writer ----
        let mut ordered_writer = io::OrderedPlaintextWriter::new(&mut writer);

        for res in decomp_out_rx.iter() {

            match res {
                Ok(segment) => {
                    eprintln!("[WRITER] receiving segment {}", segment.header.segment_index);
                    // merge decompression stage_times
                    decompression_stage_times.merge(&segment.stage_times);
                    // Writing / wiring
                    let start = Instant::now();

                    if segment.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && segment.bytes.is_empty() {
                        eprintln!("[WRITER] final empty segment {}", segment.header.segment_index);
                        last_segment_index = segment.header.segment_index;

                        // ✅ Push the final marker so OrderedPlaintextWriter sees it
                    }
                    // update bytes_plaintext
                    counters.bytes_plaintext += segment.bytes.len() as u64;

                    // Push plaintext
                    ordered_writer.push(&segment)?;
                    decompression_stage_times.add(Stage::Write, start.elapsed());
                }
                Err(e) => {
                    eprintln!("[PIPELINE] decompression worker error: {e}");
                    return Err(StreamError::CompressionWorker(e));
                }
            }
        }

        eprintln!("[WRITER] out_rx closed, finishing writer");
        ordered_writer.finish()?;
        
        Ok::<(), StreamError>(())
    })?;

    timer.finish();

    // thread::scope(|scope| {
    // spawn reader, adapter, crypto workers, writer
    // })?;
    // Now safe to merge telemetry
    // merge read stage_times
    // let final_times = read_stage_times.lock().unwrap(); 
    // for (stage, dur) in final_times.iter() { timer.add_stage_time(*stage, *dur); }
    for (stage, dur) in read_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*stage, *dur);
    }
    // merge decryption stage_times
    for (stage, dur) in decryption_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*stage, *dur);
    }
    // merge decompression stage_times
    for (stage, dur) in decompression_stage_times.iter() {
        timer.add_stage_time(*stage, *dur);
    }

    // update bytes_ciphertext len
    counters.bytes_ciphertext = counters_read.lock().unwrap().bytes_ciphertext;
    // 🔥 Merge telemetry from this segment worker
    counters.merge(&counters_segment.lock().unwrap());

    // After pipeline finishes: 
    if let Some(ref arc_buf) = config.buf { 
        let buf = arc_buf.lock().unwrap(); 
        println!("Captured output: {:?}", String::from_utf8_lossy(&buf)); 
    }

    Ok(TelemetrySnapshot::from(
        &counters,
        &timer,
        Some(last_segment_index + 1),
    ))
}

