// # 📂 src/stream_v2/pipeline.rs

// ## 📂 File: `src/stream_v2/pipeline.rs`
// ## Pure pipeline wiring (no crypto logic)

use std::io::{Read, Write};
use std::sync::atomic::{Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use bytes::Bytes;
use crossbeam::channel::{bounded};
use tracing::{debug, error};

use crate::headers::HeaderV1;
use crate::stream_v2::compression_pipeline::{spawn_compression_workers_scoped, spawn_decompression_workers_scoped};
use crate::stream_v2::compression_worker::{CodecInfo, CompressionWorkerError};
use crate::stream_v2::io::{self, PayloadReader};
use crate::stream_v2::pipeline::types::Cancellation;
use crate::stream_v2::pipeline::{PipelineCancellation, PipelineConfig};
use crate::stream_v2::segment_worker::decrypt::DecryptSegmentWorker1;
use crate::stream_v2::segment_worker::encrypt::EncryptSegmentWorker1;
use crate::stream_v2::segment_worker::{
    DecryptSegmentInput, DecryptedSegment, EncryptSegmentInput, EncryptedSegment, EncryptContext, DecryptContext, SegmentWorkerError
};
use crate::stream_v2::segmenting::types::SegmentFlags;
use crate::telemetry::{Stage, StageTimes, TelemetryCounters, TelemetrySnapshot, TelemetryTimer};
use crate::types::StreamError;
use crate::recovery::persist::AsyncLogManager;
use crate::utils::tracing_logger;

// ============================================================
// Encrypt pipeline
// ============================================================
pub fn encrypt_pipeline<R, W>(
    mut reader: &mut PayloadReader<R>,
    mut writer: W,
    crypto: Arc<EncryptContext>,
    config: &PipelineConfig,
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    // explicitly set DEBUG level
    tracing_logger(Some(tracing::Level::DEBUG));

    let mut counters = TelemetryCounters::default();
    let mut timer = TelemetryTimer::new();
    let mut segment_index = 0u32;
    let mut last_segment_index = 0u32;

    debug!("[PIPELINE] Start encrypt pipeline");

    // Header validation + emission
    let start = Instant::now();
    crypto.header.validate().map_err(StreamError::Header)?;
    timer.stage_times.add(Stage::Validate, start.elapsed());

    let start = Instant::now();
    io::write_header(&mut writer, &crypto.header)?;
    timer.stage_times.add(Stage::Write, start.elapsed());
    counters.bytes_overhead += HeaderV1::LEN as u64;

    // Channels
    let (comp_tx, comp_rx) = bounded::<EncryptSegmentInput>(config.profile.inflight_segments());
    let (seg_tx, seg_rx_raw) = bounded::<Result<EncryptSegmentInput, CompressionWorkerError>>(
        config.profile.inflight_segments(),
    );
    let (seg_tx_clean, seg_rx_clean) = bounded::<EncryptSegmentInput>(config.profile.inflight_segments());
    let (out_tx, out_rx) = bounded::<Result<EncryptedSegment, SegmentWorkerError>>(
        config.profile.inflight_segments(),
    );

    // Pipeline cancellation - DON'T monitor out_tx/out_rx
    let (cancel, fatal_rx) = PipelineCancellation::new(
        vec![
            // Don't store senders - they need to close naturally

            // Box::new(comp_tx.clone()),
            // Box::new(seg_tx.clone()),
            // Box::new(seg_tx_clean.clone()),
            // Box::new(out_tx.clone()),
            // DON'T add out_tx here - writer is in main thread
        ],
        vec![
            Box::new(comp_rx.clone()),
            Box::new(seg_rx_raw.clone()),
            Box::new(seg_rx_clean.clone()),
            Box::new(out_rx.clone()),
            // DON'T add out_rx here - writer is in main thread
        ],
    );

    // Compression workers
    // let mut codec_info = CodecInfo::from_header(&crypto.header, None);
    // codec_info.gpu = config.profile.gpu();
    // spawn_compression_workers(config.profile.clone(), codec_info, comp_rx, seg_tx.clone());
    // drop(seg_tx);

    // Telemetry state
    let counters_read = Arc::new(Mutex::new(TelemetryCounters::default()));
    let read_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let compression_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let mut encryption_stage_times = StageTimes::default();

    // Store first fatal error for propagation
    let fatal_error: Arc<Mutex<Option<StreamError>>> = Arc::new(Mutex::new(None));

    thread::scope(|scope| {
        // ===============================================================
        // Monitor thread - non-blocking check for fatal errors
        // ===============================================================
        let cancel_m = cancel.clone();
        let fatal_error_m = fatal_error.clone();

        scope.spawn(move || {
            // Use recv() which blocks until error or channel closes
            match fatal_rx.recv() {
                Ok(err) => {
                    error!("[PIPELINE] fatal error: {err}");
                    // Store the error for later propagation
                    *fatal_error_m.lock().unwrap() = Some(err);

                    // Signal cancellation
                    cancel_m.cancelled.store(true, Ordering::Relaxed);

                    // Drop all channels to unblock workers
                    cancel_m.senders.lock().unwrap().clear();
                    cancel_m.receivers.lock().unwrap().clear();
                }
                
                Err(_) => {
                    // Channel closed normally - pipeline completed successfully
                    debug!("[MONITOR] pipeline completed successfully");
                }
            }
        });

        // ===============================================================
        // Compression workers - NOW INSIDE SCOPE
        // ===============================================================
        let mut codec_info = CodecInfo::from_header(&crypto.header, None);
        codec_info.gpu = config.profile.gpu();
        
        spawn_compression_workers_scoped(
            scope,  // Pass the scope!
            config.profile.clone(),
            codec_info,
            comp_rx.clone(),
            seg_tx.clone()
        );
        
        drop(seg_tx);

        // ===============================================================
        // Reader thread
        // ===============================================================
        let cancel_r = cancel.handle();
        let comp_tx_r = comp_tx.clone();
        let counters_read_r = counters_read.clone();
        let read_stage_times_r = read_stage_times.clone();
        let crypto_r = crypto.clone();

        scope.spawn(move || -> Result<(), StreamError> {
            let chunk_size = crypto_r.base.segment_size;

            loop {
                if cancel_r.is_cancelled() {
                    break;
                }

                let start = Instant::now();
                // let buf = io::read_exact_or_eof(&mut reader, chunk_size)?;
                match io::read_exact_or_eof(&mut reader, chunk_size) {
                    Ok(buf) => {
                        read_stage_times_r.lock().unwrap().add(Stage::Read, start.elapsed());

                        if buf.is_empty() {
                            if segment_index > 0 {
                                let _ = comp_tx_r.send(EncryptSegmentInput {
                                    segment_index,
                                    bytes: Bytes::new(),
                                    flags: SegmentFlags::FINAL_SEGMENT,
                                    stage_times: StageTimes::default(),
                                });
                            }
                            // This signals that no more segments will ever arrive.
                            cancel_r.finish(); // 🔴 ensures workers exit
                            break;
                        }

                        counters_read_r.lock().unwrap().bytes_plaintext += buf.len() as u64;
                        // println!("[READER] read plaintext segment: {}", segment_index);

                        let _ = comp_tx_r.send(EncryptSegmentInput {
                            segment_index,
                            bytes: buf,
                            flags: SegmentFlags::empty(),
                            stage_times: StageTimes::default(),
                        });

                        segment_index += 1;
                    }
                    Err(e) => {
                        // 🔴 THIS IS THE PLACE CATCH READ ERROR
                        cancel_r.fatal(StreamError::Io(e.to_string()));
                        break;
                    }
                }
            }

            debug!("[READER] loop exited, dropping comp_tx_r");
            drop(comp_tx_r);
            debug!("[READER] comp_tx_r dropped at {:?}", std::time::Instant::now());

            Ok(())
        });
        debug!("[MAIN] comp_tx dropped (inside scope)");
        drop(comp_tx);

        // ===============================================================
        // Adapter thread
        // ===============================================================
        let cancel_a = cancel.handle();
        let counters_read_a = counters_read.clone();
        let compression_stage_times_a = compression_stage_times.clone();
        let seg_rx_raw_a = seg_rx_raw.clone();
        let seg_tx_clean_a = seg_tx_clean.clone();
        let out_tx_a = out_tx.clone();

        scope.spawn(move || {
            debug!("[ADAPTER] thread started");

            for res in seg_rx_raw_a.iter() {
                if cancel_a.is_cancelled() {
                    break;
                }

                match res {
                    Ok(seg) => {
                        for (stage, dur) in seg.stage_times.iter() {
                            compression_stage_times_a.lock().unwrap().add(*stage, *dur);
                        }
                        counters_read_a.lock().unwrap().bytes_compressed += seg.bytes.len() as u64;
                        let _ = seg_tx_clean_a.send(seg);
                    }
                    Err(e) => {
                        cancel_a.fatal(StreamError::CompressionWorker(e));
                        let _ = out_tx_a.send(Err(SegmentWorkerError::StateError(
                            "compression failed".into(),
                        )));
                        break;
                    }
                }
            }

            debug!("[ADAPTER] seg_rx_raw closed, exiting");
        });

        drop(seg_rx_raw);
        drop(seg_tx_clean);

        // ===============================================================
        // Crypto workers
        // ===============================================================
        for _ in 0..config.profile.cpu_workers() {
            let cancel_w = cancel.handle();
            let crypto_w = crypto.clone();
            let log_w = log_manager.clone();
            let rx = seg_rx_clean.clone();
            let tx = out_tx.clone();

            let fatal_tx = cancel_w.fatal_tx.clone();
            let cancelled = cancel_w.cancelled.clone();
            scope.spawn(move || {
                let worker = EncryptSegmentWorker1::new(
                    crypto_w,
                    log_w,
                    fatal_tx,
                    cancelled,
                );
                worker.run_v1(rx, tx);
            });
        }

        drop(seg_rx_clean);
        drop(out_tx);

        // ===============================================================
        // Ordered writer
        // ===============================================================
        let cancel_w = cancel.handle();
        let mut ordered_writer = io::OrderedEncryptedWriter::new(&mut writer);

        for res in out_rx.iter() {
            if cancel_w.is_cancelled() {
                error!("[WRITER] cancelled, exiting loop");
                break;
            }

            match res {
                Ok(seg) => {
                    encryption_stage_times.merge(&seg.stage_times);
                    counters.merge(&seg.counters);

                    let start = Instant::now();
                    let is_final = seg.header.flags().contains(SegmentFlags::FINAL_SEGMENT);
                    let idx = seg.header.segment_index();
                    // println!("[WRITER] received encrypted segment: {}", idx);

                    // ✅ CRITICAL: Check the error here
                    if let Err(e) = ordered_writer.push(seg) {
                        error!("[WRITER] ❌ push() failed: {}", e);
                        cancel_w.fatal(e);
                        break;
                    }

                    encryption_stage_times.add(Stage::Write, start.elapsed());

                    // 🔴 Stop after writing the final empty segment
                    if is_final {
                        debug!("[WRITER] final segment {} written, exiting loop", idx);
                        last_segment_index = idx;
                    }
                }
                Err(e) => {
                    error!("[WRITER] ❌ Received error from channel: {}", e);
                    cancel_w.fatal(StreamError::SegmentWorker(e));
                    break;
                }
            }
        }

        // Only finish if not cancelled
        if !cancel_w.is_cancelled() {
            debug!("[WRITER] Calling finish()");
            if let Err(e) = ordered_writer.finish() {
                error!("[WRITER] ❌ finish() failed: {}", e);
                cancel_w.fatal(e);
            }
        }

        // IMPORTANT: Always call finish() to drop fatal_tx and unblock monitor
        // This allows monitor thread to exit gracefully
        cancel.finish();

        // Return the fatal error if one occurred
        if let Some(err) = fatal_error.lock().unwrap().take() {
            return Err(err);
        }
        //
        Ok::<(), StreamError>(())
    })?; // scope ends, writer.finish() has run

    // Check if a fatal error occurred during pipeline execution
    if let Some(err) = fatal_error.lock().unwrap().take() {
        return Err(err);
    }

    // Final telemetry aggregation
    timer.finish();

    for (s, d) in read_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*s, *d);
    }
    for (s, d) in compression_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*s, *d);
    }
    for (s, d) in encryption_stage_times.iter() {
        timer.add_stage_time(*s, *d);
    }

    counters.bytes_plaintext = counters_read.lock().unwrap().bytes_plaintext;
    counters.bytes_compressed = counters_read.lock().unwrap().bytes_compressed;

    // Last segment index is the index of terminator segment (which is fed after all the data segments)
    Ok(TelemetrySnapshot::from(&counters, &timer, Some(last_segment_index)))
}

pub fn encrypt_pipeline_1<R, W>(
    mut reader: &mut PayloadReader<R>,
    mut writer: W,
    crypto: Arc<EncryptContext>,
    config: &PipelineConfig,
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    // explicitly set DEBUG level
    tracing_logger(Some(tracing::Level::DEBUG));

    let mut counters = TelemetryCounters::default();
    let mut timer = TelemetryTimer::new();
    let mut segment_index = 0u32;
    let mut last_segment_index = 0u32;

    debug!("[PIPELINE] Start encrypt pipeline");

    // Header validation + emission
    let start = Instant::now();
    crypto.header.validate().map_err(StreamError::Header)?;
    timer.stage_times.add(Stage::Validate, start.elapsed());

    let start = Instant::now();
    io::write_header(&mut writer, &crypto.header)?;
    timer.stage_times.add(Stage::Write, start.elapsed());
    counters.bytes_overhead += HeaderV1::LEN as u64;

    // Channels
    let (comp_tx, comp_rx) = bounded::<EncryptSegmentInput>(config.profile.inflight_segments());
    let (seg_tx, seg_rx_raw) = bounded::<Result<EncryptSegmentInput, CompressionWorkerError>>(
        config.profile.inflight_segments(),
    );
    let (seg_tx_clean, seg_rx_clean) = bounded::<EncryptSegmentInput>(config.profile.inflight_segments());
    let (out_tx, out_rx) = bounded::<Result<EncryptedSegment, SegmentWorkerError>>(
        config.profile.inflight_segments(),
    );

    // Pipeline cancellation - DON'T monitor out_tx/out_rx
    let (cancel, fatal_rx) = PipelineCancellation::new(
        vec![
            // Don't store senders - they need to close naturally

            // Box::new(comp_tx.clone()),
            // Box::new(seg_tx.clone()),
            // Box::new(seg_tx_clean.clone()),
            // Box::new(out_tx.clone()),
            // DON'T add out_tx here - writer is in main thread
        ],
        vec![
            Box::new(comp_rx.clone()),
            Box::new(seg_rx_raw.clone()),
            Box::new(seg_rx_clean.clone()),
            Box::new(out_rx.clone()),
        ],
    );

    // Compression workers
    // let mut codec_info = CodecInfo::from_header(&crypto.header, None);
    // codec_info.gpu = config.profile.gpu();
    // spawn_compression_workers(config.profile.clone(), codec_info, comp_rx, seg_tx.clone());
    // drop(seg_tx);

    // Telemetry state
    let counters_read = Arc::new(Mutex::new(TelemetryCounters::default()));
    let read_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let compression_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let mut encryption_stage_times = StageTimes::default();

    // ✅ FIX: Use Result instead of Option to preserve error details
    let pipeline_result: Arc<Mutex<Result<(), StreamError>>> = Arc::new(Mutex::new(Ok(())));

    thread::scope(|scope| {
        // ===============================================================
        // Monitor thread - MUST stay alive until all workers finish
        // ===============================================================
        let pipeline_result_m = pipeline_result.clone();

        let monitor_handle = scope.spawn(move || {
            debug!("[MONITOR] Starting to listen for errors");
            
            match fatal_rx.recv() {
                Ok(err) => {
                    error!("[MONITOR] ❌ Fatal error received: {}", err);
                    *pipeline_result_m.lock().unwrap() = Err(err);
                }
                Err(_) => {
                    debug!("[MONITOR] Channel closed - pipeline completed");
                }
            }
            
            debug!("[MONITOR] Exiting");
        });

        // ===============================================================
        // Compression workers - NOW INSIDE SCOPE
        // ===============================================================
        let mut codec_info = CodecInfo::from_header(&crypto.header, None);
        codec_info.gpu = config.profile.gpu();
        
        spawn_compression_workers_scoped(
            scope,  // Pass the scope!
            config.profile.clone(),
            codec_info,
            comp_rx.clone(),
            seg_tx.clone()
        );
        
        drop(seg_tx);

        // ===============================================================
        // Reader thread
        // ===============================================================
        let cancel_r = cancel.handle();
        let comp_tx_r = comp_tx.clone();
        let counters_read_r = counters_read.clone();
        let read_stage_times_r = read_stage_times.clone();
        let crypto_r = crypto.clone();

        scope.spawn(move || {
            let chunk_size = crypto_r.base.segment_size;

            loop {
                if cancel_r.is_cancelled() {
                    error!("[READER] Cancelled, exiting");
                    break;
                }

                let start = Instant::now();
                match io::read_exact_or_eof(&mut reader, chunk_size) {
                    Ok(buf) => {
                        read_stage_times_r.lock().unwrap().add(Stage::Read, start.elapsed());

                        if buf.is_empty() {
                            if segment_index > 0 {
                                let _ = comp_tx_r.send(EncryptSegmentInput {
                                    segment_index,
                                    bytes: Bytes::new(),
                                    flags: SegmentFlags::FINAL_SEGMENT,
                                    stage_times: StageTimes::default(),
                                });
                            }
                            break;
                        }

                        counters_read_r.lock().unwrap().bytes_plaintext += buf.len() as u64;

                        let _ = comp_tx_r.send(EncryptSegmentInput {
                            segment_index,
                            bytes: buf,
                            flags: SegmentFlags::empty(),
                            stage_times: StageTimes::default(),
                        });

                        segment_index += 1;
                    }
                    Err(e) => {
                        error!("[READER] ❌ Read error: {}", e);
                        cancel_r.fatal(StreamError::Io(e.to_string()));
                        break;
                    }
                }
            }

            debug!("[READER] Exiting, dropping comp_tx_r");
            drop(comp_tx_r);
        });

        drop(comp_tx);

        // ===============================================================
        // Adapter thread
        // ===============================================================
        let cancel_a = cancel.handle();
        let counters_read_a = counters_read.clone();
        let compression_stage_times_a = compression_stage_times.clone();
        let seg_rx_raw_a = seg_rx_raw.clone();
        let seg_tx_clean_a = seg_tx_clean.clone();
        let out_tx_a = out_tx.clone();

        scope.spawn(move || {
            debug!("[ADAPTER] Started");

            for res in seg_rx_raw_a.iter() {
                if cancel_a.is_cancelled() {
                    error!("[ADAPTER] Cancelled, exiting");
                    break;
                }

                match res {
                    Ok(seg) => {
                        for (stage, dur) in seg.stage_times.iter() {
                            compression_stage_times_a.lock().unwrap().add(*stage, *dur);
                        }
                        counters_read_a.lock().unwrap().bytes_compressed += seg.bytes.len() as u64;
                        let _ = seg_tx_clean_a.send(seg);
                    }
                    Err(e) => {
                        error!("[ADAPTER] ❌ Compression error: {}", e);
                        cancel_a.fatal(StreamError::CompressionWorker(e));
                        let _ = out_tx_a.send(Err(SegmentWorkerError::StateError(
                            "compression failed".into(),
                        )));
                        break;
                    }
                }
            }

            debug!("[ADAPTER] Exiting");
        });

        drop(seg_rx_raw);
        drop(seg_tx_clean);

        // ===============================================================
        // Crypto workers
        // ===============================================================
        for i in 0..config.profile.cpu_workers() {
            let cancel_w = cancel.handle();
            let crypto_w = crypto.clone();
            let log_w = log_manager.clone();
            let rx = seg_rx_clean.clone();
            let tx = out_tx.clone();

            let fatal_tx = cancel_w.fatal_tx.clone();
            let cancelled = cancel_w.cancelled.clone();
            
            scope.spawn(move || {
                debug!("[ENCRYPT WORKER {}] Started", i);
                let worker = EncryptSegmentWorker1::new(
                    crypto_w,
                    log_w,
                    fatal_tx,
                    cancelled,
                );
                worker.run_v1(rx, tx);
                debug!("[ENCRYPT WORKER {}] Exiting", i);
            });
        }

        drop(seg_rx_clean);
        drop(out_tx);

        // ===============================================================
        // Ordered writer - MAIN THREAD (not spawned)
        // ===============================================================
        let cancel_w = cancel.handle();
        let mut ordered_writer = io::OrderedEncryptedWriter::new(&mut writer);

        for res in out_rx.iter() {
            if cancel_w.is_cancelled() {
                error!("[WRITER] Cancelled, exiting loop");
                break;
            }

            match res {
                Ok(seg) => {
                    encryption_stage_times.merge(&seg.stage_times);
                    counters.merge(&seg.counters);

                    let start = Instant::now();
                    let is_final = seg.header.flags().contains(SegmentFlags::FINAL_SEGMENT);
                    let idx = seg.header.segment_index();

                    if let Err(e) = ordered_writer.push(seg) {
                        error!("[WRITER] ❌ push() failed: {}", e);
                        cancel_w.fatal(e);
                        break;
                    }

                    encryption_stage_times.add(Stage::Write, start.elapsed());

                    if is_final {
                        debug!("[WRITER] Final segment {} written, exiting loop", idx);
                        last_segment_index = idx;
                        break;  // ✅ Exit immediately after final segment
                    }
                }
                Err(e) => {
                    error!("[WRITER] ❌ Received error from channel: {}", e);
                    cancel_w.fatal(StreamError::SegmentWorker(e));
                    break;
                }
            }
        }

        // Finish writer only if not cancelled
        if !cancel_w.is_cancelled() {
            debug!("[WRITER] Calling finish()");
            if let Err(e) = ordered_writer.finish() {
                error!("[WRITER] ❌ finish() failed: {}", e);
                cancel_w.fatal(e);
            }
        }

        // ✅ CRITICAL: Drop worker handles BEFORE cancel.finish()
        // This ensures fatal_tx stays alive until all workers exit
        drop(cancel_w);
        
        // ✅ Wait a moment for monitor to receive any pending errors
        std::thread::sleep(Duration::from_millis(10));
        
        // ✅ Now drop cancel to close fatal_tx
        cancel.finish();
        
        // ✅ Wait for monitor thread to finish
        let _ = monitor_handle.join();

        // ✅ Check the result
        pipeline_result.lock().unwrap().clone()
    })?; // scope ends, writer.finish() has run

    // Final telemetry aggregation
    timer.finish();

    for (s, d) in read_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*s, *d);
    }
    for (s, d) in compression_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*s, *d);
    }
    for (s, d) in encryption_stage_times.iter() {
        timer.add_stage_time(*s, *d);
    }

    counters.bytes_plaintext = counters_read.lock().unwrap().bytes_plaintext;
    counters.bytes_compressed = counters_read.lock().unwrap().bytes_compressed;

    debug!("[PIPELINE] Completed successfully");

    // Last segment index is the index of terminator segment (which is fed after all the data segments)
    Ok(TelemetrySnapshot::from(&counters, &timer, Some(last_segment_index)))
}

// ============================================================
// Decrypt pipeline
// ============================================================
pub fn decrypt_pipeline<R, W>(
    mut reader: &mut PayloadReader<R>,
    mut writer: W,
    crypto: Arc<DecryptContext>,
    config: &PipelineConfig,
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    // explicitly set DEBUG level
    tracing_logger(Some(tracing::Level::DEBUG));

    let mut counters = TelemetryCounters::default();
    let mut timer = TelemetryTimer::new();
    let mut last_segment_index = 0;

    debug!("[PIPELINE] Start decrypt pipeline");

    // ---------------------------------------------------------------------
    // Header validation
    // ---------------------------------------------------------------------
    let start = Instant::now();
    crypto.header.validate().map_err(StreamError::Header)?;
    timer.stage_times.add(Stage::Validate, start.elapsed());
    counters.bytes_overhead += HeaderV1::LEN as u64;

    // ---------------------------------------------------------------------
    // Data-plane channels
    // ---------------------------------------------------------------------
    let (seg_tx, seg_rx) =
        bounded::<DecryptSegmentInput>(config.profile.inflight_segments());
    let (crypto_out_tx, crypto_out_rx) =
        bounded::<Result<DecryptedSegment, SegmentWorkerError>>(
            config.profile.inflight_segments(),
        );
    let (decomp_in_tx, decomp_in_rx) =
        bounded::<DecryptedSegment>(config.profile.inflight_segments());
    let (decomp_out_tx, decomp_out_rx) =
        bounded::<Result<DecryptedSegment, CompressionWorkerError>>(
            config.profile.inflight_segments(),
        );

    // ---------------------------------------------------------------------
    // Cancellation + fatal signaling
    // ---------------------------------------------------------------------
    // Pipeline cancellation - only store receivers for emergency shutdown
    let (cancel, fatal_rx) = PipelineCancellation::new(
        vec![
            // Don't store senders - they need to close naturally
        ],
        vec![
            Box::new(seg_rx.clone()),
            Box::new(crypto_out_rx.clone()),
            Box::new(decomp_in_rx.clone()),
            Box::new(decomp_out_rx.clone()),
        ],
    );

    // ---------------------------------------------------------------------
    // Telemetry state
    // ---------------------------------------------------------------------
    let counters_read = Arc::new(Mutex::new(TelemetryCounters::default()));
    let counters_segment = Arc::new(Mutex::new(TelemetryCounters::default()));
    let read_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let decryption_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let mut decompression_stage_times = StageTimes::default();

    // Store first fatal error for propagation
    let fatal_error: Arc<Mutex<Option<StreamError>>> = Arc::new(Mutex::new(None));

    // ---------------------------------------------------------------------
    // Thread scope
    // ---------------------------------------------------------------------
    thread::scope(|scope| {
        // ===============================================================
        // Monitor thread (fatal only)
        // ===============================================================
        let cancel_m = cancel.clone();
        let fatal_error_m = fatal_error.clone();
        
        scope.spawn(move || {
            match fatal_rx.recv() {
                Ok(err) => {
                    error!("[PIPELINE] fatal error: {err}");
                    
                    // Store the error for later propagation
                    *fatal_error_m.lock().unwrap() = Some(err);
                    
                    // Signal cancellation
                    cancel_m.cancelled.store(true, Ordering::Relaxed);
                }
                Err(_) => {
                    debug!("[MONITOR] pipeline completed successfully");
                }
            }
        });

        // ===============================================================
        // Reader thread (ciphertext → segments)
        // ===============================================================
        let cancel_r = cancel.handle();
        let seg_tx_r = seg_tx.clone();
        let counters_read_r = counters_read.clone();
        let read_stage_times_r = read_stage_times.clone();

        scope.spawn(move || -> Result<(), StreamError> {
            while !cancel_r.is_cancelled() {
                let start = Instant::now();

                match io::read_segment(&mut reader)? {
                    Some((header, wire)) => {
                        counters_read_r.lock().unwrap().bytes_ciphertext += wire.len() as u64;

                        // println!("[READER] read encrypted segment: {}", header.segment_index());
                        seg_tx_r
                            .send(DecryptSegmentInput { header, wire })
                            .map_err(|_| {
                                StreamError::PipelineError(
                                    "decrypt segment channel closed".into(),
                                )
                            })?;

                        read_stage_times_r
                            .lock()
                            .unwrap()
                            .add(Stage::Read, start.elapsed());
                    }
                    None => break,
                }
            }

            drop(seg_tx_r);
            Ok(())
        });

        drop(seg_tx); // main thread relinquishes ownership

        // ===============================================================
        // Crypto workers (decrypt)
        // ===============================================================
        for _ in 0..config.profile.cpu_workers() {
            let cancel_w = cancel.handle();
            let fatal_w = cancel.handle();
            let crypto_w = crypto.clone();
            let log_w = log_manager.clone();
            let rx = seg_rx.clone();
            let tx = crypto_out_tx.clone();

            scope.spawn(move || {
                let worker = DecryptSegmentWorker1::new(
                    crypto_w,
                    log_w,
                    fatal_w.fatal_tx.clone(),
                    cancel_w.cancelled.clone(),
                );
                worker.run_v1(rx, tx);
            });
        }

        drop(crypto_out_tx);
        drop(seg_rx);

        // ===============================================================
        // Adapter (decrypt → decompress)
        // ===============================================================
        let cancel_a = cancel.handle();
        let fatal_a = cancel.handle();
        let decomp_in_tx_a = decomp_in_tx.clone();
        let counters_segment_a = counters_segment.clone();
        let decryption_stage_times_a = decryption_stage_times.clone();

        scope.spawn(move || {
            for res in crypto_out_rx.iter() {
                if cancel_a.is_cancelled() {
                    break;
                }

                match res {
                    Ok(seg) => {
                        for (s, d) in seg.stage_times.iter() {
                            decryption_stage_times_a
                                .lock()
                                .unwrap()
                                .add(*s, *d);
                        }

                        counters_segment_a.lock().unwrap().merge(&seg.counters);
                        let _ = decomp_in_tx_a.send(seg);
                    }
                    Err(e) => {
                        fatal_a.fatal(StreamError::SegmentWorker(e));
                        break;
                    }
                }
            }
        });

        drop(decomp_in_tx);

        // ===============================================================
        // Decompression workers
        // ===============================================================
        let mut codec_info = CodecInfo::from_header(&crypto.header, None);
        codec_info.gpu = config.profile.gpu();

        spawn_decompression_workers_scoped(
            scope,  // Pass the scope!
            config.profile.clone(),
            codec_info,
            decomp_in_rx,
            decomp_out_tx.clone(),
        );
        drop(decomp_out_tx);

        // ===============================================================
        // Ordered plaintext writer (success authority)
        // ===============================================================
        let cancel_w = cancel.handle();
        let mut ordered_writer =
            io::OrderedPlaintextWriter::new(&mut writer);

        for res in decomp_out_rx.iter() {
            if cancel_w.is_cancelled() {
                break;
            }

            match res {
                Ok(seg) => {
                    decompression_stage_times.merge(&seg.stage_times);

                    let idx = seg.header.segment_index();
                    if seg.header.flags().contains(SegmentFlags::FINAL_SEGMENT)
                        && seg.bytes.is_empty()
                    {
                        last_segment_index = idx;
                    }
                    // println!("[WRITER] received decrypted segment: {}", idx);

                    counters.bytes_plaintext += seg.bytes.len() as u64;
                    ordered_writer.push(&seg)?;
                }
                Err(e) => {
                    cancel_w.fatal(StreamError::CompressionWorker(e));
                    break;
                }
            }
        }

        if !cancel_w.is_cancelled() {
            ordered_writer.finish()?;
        }

        // Success = close fatal channel
        cancel.finish();

        // Return the fatal error if one occurred
        if let Some(err) = fatal_error.lock().unwrap().take() {
            return Err(err);
        }

        Ok::<(), StreamError>(())
    })?;

    // Check if a fatal error occurred during pipeline execution
    if let Some(err) = fatal_error.lock().unwrap().take() {
        return Err(err);
    }

    // ---------------------------------------------------------------------
    // Telemetry aggregation
    // ---------------------------------------------------------------------
    timer.finish();

    for (s, d) in read_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*s, *d);
    }
    for (s, d) in decryption_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*s, *d);
    }
    for (s, d) in decompression_stage_times.iter() {
        timer.add_stage_time(*s, *d);
    }

    counters.bytes_ciphertext = counters_read.lock().unwrap().bytes_ciphertext;
    counters.merge(&counters_segment.lock().unwrap());

    // Last segment index is the index of terminator segment (which is fed after all the data segments)
    Ok(TelemetrySnapshot::from(&counters, &timer, Some(last_segment_index),))
}

pub fn decrypt_pipeline_1<R, W>(
    mut reader: &mut PayloadReader<R>,
    mut writer: W,
    crypto: Arc<DecryptContext>,
    config: &PipelineConfig,
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    // explicitly set DEBUG level
    tracing_logger(Some(tracing::Level::DEBUG));

    let mut counters = TelemetryCounters::default();
    let mut timer = TelemetryTimer::new();
    let mut last_segment_index = 0;

    debug!("[PIPELINE] Start decrypt pipeline");

    // ---------------------------------------------------------------------
    // Header validation
    // ---------------------------------------------------------------------
    let start = Instant::now();
    crypto.header.validate().map_err(StreamError::Header)?;
    timer.stage_times.add(Stage::Validate, start.elapsed());
    counters.bytes_overhead += HeaderV1::LEN as u64;

    // ---------------------------------------------------------------------
    // Data-plane channels
    // ---------------------------------------------------------------------
    let (seg_tx, seg_rx) =
        bounded::<DecryptSegmentInput>(config.profile.inflight_segments());
    let (crypto_out_tx, crypto_out_rx) =
        bounded::<Result<DecryptedSegment, SegmentWorkerError>>(
            config.profile.inflight_segments(),
        );
    let (decomp_in_tx, decomp_in_rx) =
        bounded::<DecryptedSegment>(config.profile.inflight_segments());
    let (decomp_out_tx, decomp_out_rx) =
        bounded::<Result<DecryptedSegment, CompressionWorkerError>>(
            config.profile.inflight_segments(),
        );

    // ---------------------------------------------------------------------
    // Cancellation + fatal signaling
    // ---------------------------------------------------------------------
    let (cancel, fatal_rx) = PipelineCancellation::new(
        vec![],  // Don't store senders
        vec![
            Box::new(seg_rx.clone()),
            Box::new(crypto_out_rx.clone()),
            Box::new(decomp_in_rx.clone()),
            Box::new(decomp_out_rx.clone()),
        ],
    );

    // ---------------------------------------------------------------------
    // Telemetry state
    // ---------------------------------------------------------------------
    let counters_read = Arc::new(Mutex::new(TelemetryCounters::default()));
    let counters_segment = Arc::new(Mutex::new(TelemetryCounters::default()));
    let read_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let decryption_stage_times = Arc::new(Mutex::new(StageTimes::default()));
    let mut decompression_stage_times = StageTimes::default();

    // ✅ FIX: Use Result instead of Option
    let pipeline_result: Arc<Mutex<Result<(), StreamError>>> = Arc::new(Mutex::new(Ok(())));

    // ---------------------------------------------------------------------
    // Thread scope
    // ---------------------------------------------------------------------
    thread::scope(|scope| {
        // ===============================================================
        // Monitor thread - MUST stay alive to receive errors
        // ===============================================================
        let pipeline_result_m = pipeline_result.clone();
        
        let monitor_handle = scope.spawn(move || {
            debug!("[MONITOR] Starting to listen for errors");
            
            match fatal_rx.recv() {
                Ok(err) => {
                    error!("[MONITOR] ❌ Fatal error received: {}", err);
                    *pipeline_result_m.lock().unwrap() = Err(err);
                }
                Err(_) => {
                    debug!("[MONITOR] Channel closed - pipeline completed");
                }
            }
            
            debug!("[MONITOR] Exiting");
        });

        // ===============================================================
        // Reader thread (ciphertext → segments)
        // ===============================================================
        let cancel_r = cancel.handle();
        let seg_tx_r = seg_tx.clone();
        let counters_read_r = counters_read.clone();
        let read_stage_times_r = read_stage_times.clone();

        scope.spawn(move || {
            debug!("[READER] Started");
            
            while !cancel_r.is_cancelled() {
                let start = Instant::now();

                match io::read_segment(&mut reader) {
                    Ok(Some((header, wire))) => {
                        counters_read_r.lock().unwrap().bytes_ciphertext +=
                            wire.len() as u64;

                        if seg_tx_r.send(DecryptSegmentInput { header, wire }).is_err() {
                            error!("[READER] Channel closed, exiting");
                            break;
                        }

                        read_stage_times_r
                            .lock()
                            .unwrap()
                            .add(Stage::Read, start.elapsed());
                    }
                    Ok(None) => {
                        debug!("[READER] EOF reached");
                        break;
                    }
                    Err(e) => {
                        error!("[READER] ❌ Read error: {}", e);
                        cancel_r.fatal(e);
                        break;
                    }
                }
            }

            debug!("[READER] Exiting, dropping seg_tx_r");
            drop(seg_tx_r);
        });

        drop(seg_tx);

        // ===============================================================
        // Crypto workers (decrypt)
        // ===============================================================
        for i in 0..config.profile.cpu_workers() {
            let cancel_w = cancel.handle();
            let crypto_w = crypto.clone();
            let log_w = log_manager.clone();
            let rx = seg_rx.clone();
            let tx = crypto_out_tx.clone();

            let fatal_tx = cancel_w.fatal_tx.clone();
            let cancelled = cancel_w.cancelled.clone();

            scope.spawn(move || {
                debug!("[DECRYPT WORKER {}] Started", i);
                let worker = DecryptSegmentWorker1::new(
                    crypto_w,
                    log_w,
                    fatal_tx,
                    cancelled,
                );
                worker.run_v1(rx, tx);
                debug!("[DECRYPT WORKER {}] Exiting", i);
            });
        }

        drop(crypto_out_tx);
        drop(seg_rx);

        // ===============================================================
        // Adapter (decrypt → decompress)
        // ===============================================================
        let cancel_a = cancel.handle();
        let decomp_in_tx_a = decomp_in_tx.clone();
        let counters_segment_a = counters_segment.clone();
        let decryption_stage_times_a = decryption_stage_times.clone();

        scope.spawn(move || {
            debug!("[ADAPTER] Started");
            
            for res in crypto_out_rx.iter() {
                if cancel_a.is_cancelled() {
                    error!("[ADAPTER] Cancelled, exiting");
                    break;
                }

                match res {
                    Ok(seg) => {
                        for (s, d) in seg.stage_times.iter() {
                            decryption_stage_times_a
                                .lock()
                                .unwrap()
                                .add(*s, *d);
                        }

                        counters_segment_a.lock().unwrap().merge(&seg.counters);
                        
                        if decomp_in_tx_a.send(seg).is_err() {
                            error!("[ADAPTER] Channel closed, exiting");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("[ADAPTER] ❌ Decryption error: {}", e);
                        cancel_a.fatal(StreamError::SegmentWorker(e));
                        break;
                    }
                }
            }
            
            debug!("[ADAPTER] Exiting");
        });

        drop(decomp_in_tx);

        // ===============================================================
        // Decompression workers
        // ===============================================================
        let mut codec_info = CodecInfo::from_header(&crypto.header, None);
        codec_info.gpu = config.profile.gpu();

        spawn_decompression_workers_scoped(
            scope,
            config.profile.clone(),
            codec_info,
            decomp_in_rx,
            decomp_out_tx.clone(),
        );
        drop(decomp_out_tx);

        // ===============================================================
        // Ordered plaintext writer - MAIN THREAD (not spawned)
        // ===============================================================
        let cancel_w = cancel.handle();
        let mut ordered_writer = io::OrderedPlaintextWriter::new(&mut writer);

        for res in decomp_out_rx.iter() {
            if cancel_w.is_cancelled() {
                error!("[WRITER] Cancelled, exiting loop");
                break;
            }

            match res {
                Ok(segment) => {
                    decompression_stage_times.merge(&segment.stage_times);

                    let is_final = segment.header.flags().contains(SegmentFlags::FINAL_SEGMENT)
                        && segment.bytes.is_empty();

                    if is_final {
                        last_segment_index = segment.header.segment_index();
                        debug!("[WRITER] Final segment {} detected", last_segment_index);
                    }

                    counters.bytes_plaintext += segment.bytes.len() as u64;
                    
                    // ✅ CRITICAL: Check push() error
                    if let Err(e) = ordered_writer.push(&segment) {
                        error!("[WRITER] ❌ push() failed: {}", e);
                        cancel_w.fatal(e);
                        break;
                    }

                    if is_final {
                        debug!("[WRITER] Final segment written, exiting loop");
                        break;
                    }
                }
                Err(e) => {
                    error!("[WRITER] ❌ Received error from channel: {}", e);
                    cancel_w.fatal(StreamError::CompressionWorker(e));
                    break;
                }
            }
        }

        // Finish writer only if not cancelled
        if !cancel_w.is_cancelled() {
            debug!("[WRITER] Calling finish()");
            if let Err(e) = ordered_writer.finish() {
                error!("[WRITER] ❌ finish() failed: {}", e);
                cancel_w.fatal(e);
            }
        }

        // ✅ CRITICAL: Drop worker handles BEFORE cancel.finish()
        drop(cancel_w);
        
        // ✅ Small delay to ensure errors are sent
        std::thread::sleep(Duration::from_millis(10));
        
        // ✅ Now close fatal channel
        cancel.finish();
        
        // ✅ Wait for monitor to finish
        let _ = monitor_handle.join();

        // ✅ Check the result
        pipeline_result.lock().unwrap().clone()
    })?;

    // ---------------------------------------------------------------------
    // Telemetry aggregation
    // ---------------------------------------------------------------------
    timer.finish();

    for (s, d) in read_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*s, *d);
    }
    for (s, d) in decryption_stage_times.lock().unwrap().iter() {
        timer.add_stage_time(*s, *d);
    }
    for (s, d) in decompression_stage_times.iter() {
        timer.add_stage_time(*s, *d);
    }

    counters.bytes_ciphertext = counters_read.lock().unwrap().bytes_ciphertext;
    counters.merge(&counters_segment.lock().unwrap());

    debug!("[PIPELINE] Completed successfully");
    Ok(TelemetrySnapshot::from(&counters, &timer, Some(last_segment_index)))
}
