// # 📂 src/stream_v2/pipeline.rs

// ## 📂 File: `src/stream_v2/pipeline.rs`
// ## Pure pipeline wiring (no crypto logic)

use std::any::Any;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, bounded};

use crate::headers::HeaderV1;
use crate::stream_v2::compression_pipeline::{spawn_compression_workers_scoped, spawn_decompression_workers_scoped};
use crate::stream_v2::compression_worker::{CodecInfo, CompressionWorkerError};
use crate::stream_v2::io::{self, PayloadReader};
use crate::stream_v2::parallelism::HybridParallelismProfile;
use crate::stream_v2::segment_worker::decrypt::DecryptSegmentWorker1;
use crate::stream_v2::segment_worker::encrypt::EncryptSegmentWorker1;
use crate::stream_v2::segment_worker::{
    DecryptSegmentInput, DecryptedSegment, EncryptSegmentInput, EncryptedSegment, EncryptContext, DecryptContext, SegmentWorkerError
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

pub trait Cancellation {
    fn fatal(&self, err: StreamError);
    fn is_cancelled(&self) -> bool;
}

#[derive(Clone)]
pub struct PipelineCancellation {
    fatal_tx: Sender<StreamError>, // monitor owns this
    cancelled: Arc<AtomicBool>,
    senders: Arc<Mutex<Vec<Box<dyn Any + Send>>>>,
    receivers: Arc<Mutex<Vec<Box<dyn Any + Send>>>>,
}

#[derive(Clone)]
pub struct CancelHandle {
    fatal_tx: Sender<StreamError>, // workers get plain Sender
    cancelled: Arc<AtomicBool>,
}

impl Cancellation for PipelineCancellation {
    #[inline]
    fn fatal(&self, err: StreamError) {
        let _ = self.fatal_tx.send(err);
        self.cancelled.store(true, Ordering::Relaxed);

        // Drop all monitored channels to unblock workers
        self.senders.lock().unwrap().clear();
        self.receivers.lock().unwrap().clear();
    }

    #[inline]
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

}

impl Cancellation for CancelHandle {
    #[inline]
    fn fatal(&self, err: StreamError) {
        let _ = self.fatal_tx.send(err);
        self.cancelled.store(true, Ordering::Relaxed);
        // CancelHandle doesn’t own channels, so no clearing
    }

    #[inline]
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

impl CancelHandle {
    #[inline]
    pub fn finish(self) {
        // Workers don’t own senders/receivers, so finish is a no‑op
        // Dropping fatal_tx clone signals monitor if this was the last sender
        // drop(self.fatal_tx);
    }
}
impl PipelineCancellation {
    pub fn handle(&self) -> CancelHandle {
        CancelHandle {
            cancelled: self.cancelled.clone(),
            fatal_tx: self.fatal_tx.clone(),
        }
    }

    pub fn new(
        senders: Vec<Box<dyn Any + Send>>,
        receivers: Vec<Box<dyn Any + Send>>,
    ) -> (Self, Receiver<StreamError>) {
        let (fatal_tx, fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        (
            Self {
                cancelled,
                fatal_tx,
                senders: Arc::new(Mutex::new(senders)),
                receivers: Arc::new(Mutex::new(receivers)),
            },
            fatal_rx,
        )
    }

    #[inline]
    pub fn finish(self) {
        // Drop monitored channels to unblock workers on success
        self.senders.lock().unwrap().clear();
        self.receivers.lock().unwrap().clear();

        // Dropping fatal_tx closes channel once worker clones are gone
        // fatal_tx is dropped here when self is consumed
        // drop(self.fatal_tx);
    }
}


// ============================================================
// Encrypt pipeline
// ============================================================
pub fn run_encrypt_pipeline<R, W>(
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
    let mut counters = TelemetryCounters::default();
    let mut timer = TelemetryTimer::new();
    let mut segment_index = 0u32;
    let mut last_segment_index = 0u32;

    eprintln!("[PIPELINE] Start encrypt pipeline");

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
                    eprintln!("[PIPELINE] fatal error: {err}");
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
                    eprintln!("[MONITOR] pipeline completed successfully");
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

            eprintln!("[READER] loop exited, dropping comp_tx_r");
            drop(comp_tx_r);
            eprintln!("[READER] comp_tx_r dropped at {:?}", std::time::Instant::now());

            Ok(())
        });
        eprintln!("[MAIN] comp_tx dropped (inside scope)");
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
            eprintln!("[ADAPTER] thread started");

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

            eprintln!("[ADAPTER] seg_rx_raw closed, exiting");
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
                worker.run_v2(rx, tx);
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
                eprintln!("[WRITER] cancelled, exiting loop");
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
                        cancel_w.fatal(e);
                        break;
                    }
                    encryption_stage_times.add(Stage::Write, start.elapsed());

                    // 🔴 Stop after writing the final empty segment
                    if is_final {
                        eprintln!("[WRITER] final segment {} written, exiting loop", idx);
                        last_segment_index = idx;
                    }
                }
                Err(e) => {
                    cancel_w.fatal(StreamError::SegmentWorker(e));
                    break;
                }
            }
        }

        // Only finish if not cancelled
        if !cancel_w.is_cancelled() {
            if let Err(e) = ordered_writer.finish() {
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

// ============================================================
// Decrypt pipeline
// ============================================================
pub fn run_decrypt_pipeline<R, W>(
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
    let mut counters = TelemetryCounters::default();
    let mut timer = TelemetryTimer::new();
    let mut last_segment_index = 0;

    eprintln!("[PIPELINE] Start decrypt pipeline");

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
                    eprintln!("[PIPELINE] fatal error: {err}");
                    
                    // Store the error for later propagation
                    *fatal_error_m.lock().unwrap() = Some(err);
                    
                    // Signal cancellation
                    cancel_m.cancelled.store(true, Ordering::Relaxed);
                }
                Err(_) => {
                    eprintln!("[MONITOR] pipeline completed successfully");
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
                        counters_read_r.lock().unwrap().bytes_ciphertext +=
                            wire.len() as u64;

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
                worker.run_v2(rx, tx);
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
                Ok(segment) => {
                    decompression_stage_times.merge(&segment.stage_times);

                    if segment.header.flags().contains(SegmentFlags::FINAL_SEGMENT)
                        && segment.bytes.is_empty()
                    {
                        last_segment_index = segment.header.segment_index();
                    }

                    counters.bytes_plaintext += segment.bytes.len() as u64;
                    ordered_writer.push(&segment)?;
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

