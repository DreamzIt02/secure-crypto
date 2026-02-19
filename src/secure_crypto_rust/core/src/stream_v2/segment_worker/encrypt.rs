// # 📂 `src/stream_v2/segment_worker/encrypt.rs`

use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Instant};
use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, bounded, unbounded};

use crate::{
    crypto::{DigestAlg, DigestFrame, SegmentDigestBuilder}, recovery::AsyncLogManager, stream_v2::{
        frame_worker::{EncryptedFrame, FrameInput, FrameWorkerError, encrypt::{EncryptFrameWorker0, EncryptFrameWorker1}},
        framing::{FrameHeader, types::FrameType}, segment_worker::{EncryptContext, SegmentWorkerError}, segmenting::{SegmentHeader, types::SegmentFlags},
    }, telemetry::{Stage, StageTimes, counters::TelemetryCounters}, types::StreamError
};
use super::types::{EncryptSegmentInput, EncryptedSegment};

pub struct EncryptSegmentWorker0 {
    crypto: Arc<EncryptContext>,                 // shared immutable context
    log_manager: Arc<AsyncLogManager>,
    fatal_tx: Arc<Sender<StreamError>>,          // global error channel
    cancelled: Arc<AtomicBool>,                  // global cancellation flag
}

impl EncryptSegmentWorker0 {
    /// Creates a new segment encryption worker
    ///
    /// # Arguments
    /// * `crypto` - Shared encryption context containing keys and configuration
    /// * `log_manager` - Async logging manager for audit trails
    /// * `fatal_tx` - Channel to signal fatal errors to the pipeline monitor
    /// * `cancelled` - Shared cancellation flag for graceful shutdown
    pub fn new(
        crypto: Arc<EncryptContext>,
        log_manager: Arc<AsyncLogManager>,
        fatal_tx: Arc<Sender<StreamError>>,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            crypto,
            log_manager,
            fatal_tx,
            cancelled,
        }
    }

    /// Run loop: consumes plaintext segments, emits encrypted segments.
    pub fn run_v1(
        self,
        rx: Receiver<EncryptSegmentInput>,
        tx: Sender<Result<EncryptedSegment, SegmentWorkerError>>,
    ) {
        let crypto = self.crypto.clone();
        let fatal_tx = self.fatal_tx.clone();
        let cancelled = self.cancelled.clone();

        std::thread::spawn(move || {
            // Spawn frame workers
            let worker_count = crypto.base.profile.cpu_workers();
            let digest_alg = crypto.base.digest_alg;
            let frame_size = crypto.base.frame_size;

            let (frame_tx, frame_rx) = bounded::<FrameInput>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<EncryptedFrame, FrameWorkerError>>();

            for _ in 0..worker_count {
                let fw = EncryptFrameWorker0::new(crypto.header.clone(), &crypto.base.session_key, fatal_tx.clone(), cancelled.clone())
                    .expect("EncryptFrameWorker pool init failed");
                fw.run(frame_rx.clone(), out_tx.clone());
            }
            drop(frame_rx);
            drop(out_tx);

            while let Ok(segment) = rx.recv() {
                if cancelled.load(Ordering::Relaxed) {
                    eprintln!("[WORKER] cancelled, exiting early");
                    break;
                }

                eprintln!("[WORKER] processing segment {}", segment.segment_index);
                let result = process_encrypt_segment_1(
                    &segment,
                    frame_size,
                    digest_alg,
                    &frame_tx,
                    &out_rx,
                    cancelled.clone(),
                );

                match result {
                    Ok(seg) => {
                        if tx.send(Ok(seg)).is_err() {
                            eprintln!("[SEGMENT WORKER] tx send failed, receiver gone");
                            // propagate fatal error so monitor drops channels
                            let _ = fatal_tx.send(StreamError::SegmentWorker(SegmentWorkerError::WorkerDisconnected));
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[SEGMENT WORKER] error: {:?}", e);
                        let _ = fatal_tx.send(StreamError::SegmentWorker(e.clone()));
                        cancelled.store(true, Ordering::Relaxed);
                        let _ = tx.send(Err(e));
                        break;
                    }
                }

            }

            eprintln!("[WORKER] rx closed, exiting loop");
            drop(frame_tx);
            drop(tx);
            eprintln!("[WORKER] dropped tx, worker exiting");
        });
    }

    /// Runs the segment worker loop with an internal frame worker pool
    ///
    /// # Architecture
    /// - Spawns a pool of frame workers for parallel frame encryption
    /// - Processes segments sequentially, frames within segments in parallel
    /// - Each segment is split into frames, encrypted, digested, and serialized
    /// - Coordinates with frame workers via bounded channels
    ///
    /// # Behavior
    /// - Checks cancellation before processing each segment
    /// - Propagates errors via fatal_tx to trigger pipeline shutdown
    /// - Exits gracefully when input channel closes or on cancellation
    pub fn run_v2(
        self,
        rx: Receiver<EncryptSegmentInput>,
        tx: Sender<Result<EncryptedSegment, SegmentWorkerError>>,
    ) {
        let crypto = self.crypto.clone();
        let fatal_tx = self.fatal_tx.clone();
        let cancelled = self.cancelled.clone();

        std::thread::spawn(move || {
            // ---- Initialize frame worker pool ----
            let worker_count = crypto.base.profile.cpu_workers();
            let digest_alg = crypto.base.digest_alg;
            let frame_size = crypto.base.frame_size;

            // Frame processing channels
            let (frame_tx, frame_rx) = bounded::<FrameInput>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<EncryptedFrame, FrameWorkerError>>();

            // Spawn frame encryption workers
            for _ in 0..worker_count {
                let fw = EncryptFrameWorker0::new(
                    crypto.header.clone(),
                    &crypto.base.session_key,
                    fatal_tx.clone(),
                    cancelled.clone(),
                )
                .expect("EncryptFrameWorker pool initialization failed");
                fw.run(frame_rx.clone(), out_tx.clone());
            }

            // Drop original senders so workers know when to exit
            drop(frame_rx);
            drop(out_tx);

            // ---- Process segments sequentially ----
            loop {
                // Check for cancellation before blocking on receive
                if cancelled.load(Ordering::Relaxed) {
                    eprintln!("[ENCRYPT SEGMENT WORKER] cancelled, exiting early");
                    break;
                }

                // Receive next segment (blocks until available or channel closes)
                let segment = match rx.recv() {
                    Ok(segment) => segment,
                    Err(_) => {
                        // Channel closed normally - all segments processed
                        eprintln!("[ENCRYPT SEGMENT WORKER] rx closed, exiting loop");
                        break;
                    }
                };

                let segment_idx = segment.segment_index;
                eprintln!(
                    "[ENCRYPT SEGMENT WORKER] processing segment {}",
                    segment_idx
                );

                // Process the segment (splits into frames, encrypts, digests)
                let result = process_encrypt_segment_1(
                    &segment,
                    frame_size,
                    digest_alg,
                    &frame_tx,
                    &out_rx,
                    cancelled.clone(),
                );

                match result {
                    Ok(encrypted_segment) => {
                        // Send encrypted segment to output
                        if let Err(_) = tx.send(Ok(encrypted_segment)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            eprintln!(
                                "[ENCRYPT SEGMENT WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = fatal_tx.send(StreamError::SegmentWorker(
                                SegmentWorkerError::WorkerDisconnected,
                            ));
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                        // Append log for successfully encrypted segment
                        self.log_manager.console(("[ENCRYPT SEGMENT]: ".to_string() + &segment_idx.to_string() + " successfully encrypted").into());
                    }
                    Err(e) => {
                        // Segment processing failed - this is a fatal error
                        eprintln!("[ENCRYPT SEGMENT WORKER] processing error: {:?}", e);

                        // Signal fatal error to pipeline monitor
                        let _ = fatal_tx.send(StreamError::SegmentWorker(e.clone()));

                        // Set cancellation flag to stop other workers
                        cancelled.store(true, Ordering::Relaxed);

                        // Try to send error to output (best effort)
                        let _ = tx.send(Err(e));
                        break;
                    }
                }
            }

            // Cleanup: drop channels to signal frame workers to exit
            drop(frame_tx);
            drop(tx);
            eprintln!("[ENCRYPT SEGMENT WORKER] dropped channels, thread exiting");
        });
    }

}

pub struct EncryptSegmentWorker1 {
    crypto: Arc<EncryptContext>,                 // shared immutable context
    log_manager: Arc<AsyncLogManager>,
    fatal_tx: Sender<StreamError>,               // global error channel
    cancelled: Arc<AtomicBool>,                  // global cancellation flag
}

impl EncryptSegmentWorker1 {
    /// Creates a new segment encryption worker
    ///
    /// # Arguments
    /// * `crypto` - Shared encryption context containing keys and configuration
    /// * `log_manager` - Async logging manager for audit trails
    /// * `fatal_tx` - Channel to signal fatal errors to the pipeline monitor
    /// * `cancelled` - Shared cancellation flag for graceful shutdown
    pub fn new(
        crypto: Arc<EncryptContext>,
        log_manager: Arc<AsyncLogManager>,
        fatal_tx: Sender<StreamError>,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            crypto,
            log_manager,
            fatal_tx,
            cancelled,
        }
    }

    /// Runs the segment worker loop with an internal frame worker pool
    ///
    /// # Architecture
    /// - Spawns a pool of frame workers for parallel frame encryption
    /// - Processes segments sequentially, frames within segments in parallel
    /// - Each segment is split into frames, encrypted, digested, and serialized
    /// - Coordinates with frame workers via bounded channels
    ///
    /// # Behavior
    /// - Checks cancellation before processing each segment
    /// - Propagates errors via fatal_tx to trigger pipeline shutdown
    /// - Exits gracefully when input channel closes or on cancellation
    pub fn run_v2(
        self,
        rx: Receiver<EncryptSegmentInput>,
        tx: Sender<Result<EncryptedSegment, SegmentWorkerError>>,
    ) {
        let crypto = self.crypto.clone();
        let fatal_tx = self.fatal_tx.clone();
        let cancelled = self.cancelled.clone();

        // Remove thread::spawn - we're already spawned in pipeline
        // std::thread::spawn(move || {
            // ---- Initialize frame worker pool ----
            let worker_count = crypto.base.profile.cpu_workers();
            let digest_alg = crypto.base.digest_alg;
            let frame_size = crypto.base.frame_size;

            // Frame processing channels
            let (frame_tx, frame_rx) = bounded::<FrameInput>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<EncryptedFrame, FrameWorkerError>>();

            // Spawn frame encryption workers
            for _ in 0..worker_count {
                let fw = EncryptFrameWorker1::new(
                    crypto.header.clone(),
                    &crypto.base.session_key,
                    fatal_tx.clone(),
                    cancelled.clone(),
                )
                .expect("EncryptFrameWorker pool initialization failed");

                let rx_clone = frame_rx.clone();
                let tx_clone = out_tx.clone();

                // Spawn in a new thread - frame workers need to run concurrently
                std::thread::spawn(move || {
                    fw.run(rx_clone, tx_clone);
                });
            }

            // Drop original senders so workers know when to exit
            drop(frame_rx);
            drop(out_tx);

            // ---- Process segments sequentially ----
            loop {
                // Check for cancellation before blocking on receive
                if cancelled.load(Ordering::Relaxed) {
                    eprintln!("[ENCRYPT SEGMENT WORKER] cancelled, exiting early");
                    break;
                }

                // Receive next segment (blocks until available or channel closes)
                let segment = match rx.recv() {
                    Ok(segment) => segment,
                    Err(_) => {
                        // Channel closed normally - all segments processed
                        eprintln!("[ENCRYPT SEGMENT WORKER] rx closed, exiting loop");
                        break;
                    }
                };

                let segment_idx = segment.segment_index;
                eprintln!(
                    "[ENCRYPT SEGMENT WORKER] processing segment {}",
                    segment_idx
                );

                // Process the segment (splits into frames, encrypts, digests)
                let result = process_encrypt_segment_1(
                    &segment,
                    frame_size,
                    digest_alg,
                    &frame_tx,
                    &out_rx,
                    cancelled.clone(),
                );

                match result {
                    Ok(encrypted_segment) => {
                        // Send encrypted segment to output
                        if let Err(_) = tx.send(Ok(encrypted_segment)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            eprintln!(
                                "[ENCRYPT SEGMENT WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = fatal_tx.send(StreamError::SegmentWorker(
                                SegmentWorkerError::WorkerDisconnected,
                            ));
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                        // Append log for successfully encrypted segment
                        self.log_manager.console(("[ENCRYPT SEGMENT]: ".to_string() + &segment_idx.to_string() + " successfully encrypted").into());
                    }
                    Err(e) => {
                        // Segment processing failed - this is a fatal error
                        eprintln!("[ENCRYPT SEGMENT WORKER] processing error: {:?}", e);

                        // Signal fatal error to pipeline monitor
                        let _ = fatal_tx.send(StreamError::SegmentWorker(e.clone()));

                        // Set cancellation flag to stop other workers
                        cancelled.store(true, Ordering::Relaxed);

                        // Try to send error to output (best effort)
                        let _ = tx.send(Err(e));
                        break;
                    }
                }
            }

            // Cleanup: drop channels to signal frame workers to exit
            drop(frame_tx);
            drop(tx);
            
            eprintln!("[ENCRYPT SEGMENT WORKER] dropped channels, thread exiting");
        // });

    }

}

/// Processes a single plaintext segment into encrypted wire format
///
/// # Process Flow
/// 1. Validates input and handles empty final segments
/// 2. Splits plaintext into frame-sized chunks
/// 3. Dispatches frames to worker pool for parallel encryption
/// 4. Collects and sorts encrypted frames
/// 5. Computes segment digest over all frame ciphertexts
/// 6. Creates digest frame and terminator frame
/// 7. Serializes all frames into wire format with segment header
///
/// # Arguments
/// * `input` - Input segment containing plaintext and metadata
/// * `frame_size` - Maximum size of plaintext per frame
/// * `digest_alg` - Digest algorithm for segment integrity
/// * `frame_tx` - Channel to dispatch frames to worker pool
/// * `out_rx` - Channel to collect encrypted frames from workers
/// * `cancelled` - Cancellation flag for early exit
pub fn process_encrypt_segment_1(
    input: &EncryptSegmentInput,
    frame_size: usize,
    digest_alg: DigestAlg,
    frame_tx: &Sender<FrameInput>,
    out_rx: &Receiver<Result<EncryptedFrame, FrameWorkerError>>,
    cancelled: Arc<AtomicBool>,
) -> Result<EncryptedSegment, SegmentWorkerError> {
    let mut counters = TelemetryCounters::default();
    let mut stage_times = StageTimes::default();

    eprintln!(
        "[ENCRYPT SEGMENT] processing segment {}",
        input.segment_index
    );

    // ---- Stage 1: Validation ----
    let start = Instant::now();

    // Handle empty final segment (EOF marker)
    if input.bytes.is_empty() && input.flags.contains(SegmentFlags::FINAL_SEGMENT) {
        eprintln!(
            "[ENCRYPT SEGMENT] empty FINAL_SEGMENT at index {}",
            input.segment_index
        );
        let header = SegmentHeader::new(
            &Bytes::new(),
            input.segment_index,
            0, // no bytes
            0, // no frames
            digest_alg as u16,
            input.flags,
        );
        return Ok(EncryptedSegment {
            header,
            wire: Bytes::new(),
            counters,
            stage_times,
        });
    }

    // Count segment header overhead
    counters.add_header(SegmentHeader::LEN);

    // Calculate frame count
    let bytes_len = input.bytes.len();
    let frame_count = (bytes_len + frame_size - 1) / frame_size;
    if frame_count == 0 {
        return Err(SegmentWorkerError::InvalidSegment(
            "Empty segment without FINAL_SEGMENT flag".into(),
        ));
    }

    stage_times.add(Stage::Validate, start.elapsed());

    // ---- Stage 2: Dispatch frames for parallel encryption ----
    let start = Instant::now();
    eprintln!(
        "[ENCRYPT SEGMENT] dispatching {} frames for encryption",
        frame_count
    );

    for (frame_index, chunk) in input.bytes.chunks(frame_size).enumerate() {
        frame_tx
            .send(FrameInput {
                segment_index: input.segment_index,
                frame_index: frame_index as u32,
                frame_type: FrameType::Data,
                plaintext: Bytes::copy_from_slice(chunk),
            })
            .map_err(|_| {
                SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected)
            })?;
    }

    stage_times.add(Stage::Read, start.elapsed());

    // ---- Stage 3: Collect encrypted frames ----
    let mut data_frames = Vec::with_capacity(frame_count);
    let mut data_wire_len = 0;
    let mut received = 0;

    eprintln!(
        "[ENCRYPT SEGMENT] collecting {} encrypted frames",
        frame_count
    );

    while received < frame_count {
        // Check for cancellation during collection
        if cancelled.load(Ordering::Relaxed) {
            return Err(SegmentWorkerError::FrameWorkerError(
                FrameWorkerError::WorkerDisconnected,
            ));
        }

        match out_rx.recv() {
            Ok(Ok(frame)) => {
                received += 1;
                eprintln!(
                    "[ENCRYPT SEGMENT] received frame {} (type {:?})",
                    frame.frame_index, frame.frame_type
                );

                // Merge frame telemetry
                stage_times.merge(&frame.stage_times);
                data_frames.push(frame);
            }
            Ok(Err(e)) => {
                // Frame worker returned an error
                return Err(e.into());
            }
            Err(_) => {
                // Frame output channel closed unexpectedly
                return Err(SegmentWorkerError::FrameWorkerError(
                    FrameWorkerError::WorkerDisconnected,
                ));
            }
        }
    }

    // Ensure we received exactly the expected number of frames
    if data_frames.len() != frame_count {
        return Err(SegmentWorkerError::InvalidSegment(
            format!(
                "Frame count mismatch: expected {}, received {}",
                frame_count,
                data_frames.len()
            ),
        ));
    }

    // Sort frames by index to ensure correct order
    data_frames.sort_unstable_by_key(|f| f.frame_index);
    eprintln!("[ENCRYPT SEGMENT] sorted {} data frames", data_frames.len());

    // ---- Stage 4: Compute segment digest ----
    let start = Instant::now();
    let mut digest_builder =
        SegmentDigestBuilder::new(digest_alg, input.segment_index, frame_count as u32);

    for frame in &data_frames {
        data_wire_len += frame.wire.len();

        // Track overhead: frame header
        counters.bytes_overhead += FrameHeader::LEN as u64;
        // Track ciphertext size
        counters.bytes_ciphertext += frame.ciphertext().len() as u64;

        // Update digest with frame ciphertext
        digest_builder.update_frame(frame.frame_index, frame.ciphertext());
    }

    counters.frames_data = frame_count as u64;

    // Finalize digest
    let digest = digest_builder.finalize();
    let digest_payload = Bytes::from(DigestFrame::new(digest_alg, digest).encode());

    stage_times.add(Stage::Digest, start.elapsed());

    // ---- Stage 5: Create digest frame ----
    frame_tx
        .send(FrameInput {
            segment_index: input.segment_index,
            frame_index: frame_count as u32,
            frame_type: FrameType::Digest,
            plaintext: digest_payload,
        })
        .map_err(|_| {
            SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected)
        })?;

    let digest_frame = match out_rx.recv() {
        Ok(Ok(frame)) => frame,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            return Err(SegmentWorkerError::FrameWorkerError(
                FrameWorkerError::WorkerDisconnected,
            ))
        }
    };

    eprintln!(
        "[ENCRYPT SEGMENT] digest frame created for segment {}",
        input.segment_index
    );
    counters.add_digest(digest_frame.ciphertext().len());

    // ---- Stage 6: Create terminator frame ----
    let start = Instant::now();
    frame_tx
        .send(FrameInput {
            segment_index: input.segment_index,
            frame_index: frame_count as u32 + 1,
            frame_type: FrameType::Terminator,
            plaintext: Bytes::new(),
        })
        .map_err(|_| {
            SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected)
        })?;

    let terminator_frame = match out_rx.recv() {
        Ok(Ok(frame)) => frame,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            return Err(SegmentWorkerError::FrameWorkerError(
                FrameWorkerError::WorkerDisconnected,
            ))
        }
    };

    eprintln!(
        "[ENCRYPT SEGMENT] terminator frame created for segment {}",
        input.segment_index
    );
    counters.add_terminator(terminator_frame.ciphertext().len());
    stage_times.add(Stage::Validate, start.elapsed());

    // ---- Stage 7: Serialize all frames into wire format ----
    let start = Instant::now();
    let total_len = data_wire_len + digest_frame.wire.len() + terminator_frame.wire.len();
    let mut wire_bytes = Vec::with_capacity(total_len);

    // Concatenate: data frames + digest frame + terminator frame
    for frame in data_frames {
        wire_bytes.extend_from_slice(&frame.wire);
    }
    wire_bytes.extend_from_slice(&digest_frame.wire);
    wire_bytes.extend_from_slice(&terminator_frame.wire);

    let wire = Bytes::from(wire_bytes);

    // Create segment header
    let header = SegmentHeader::new(
        &wire,
        input.segment_index,
        bytes_len as u32,
        frame_count as u32,
        digest_alg as u16,
        input.flags,
    );

    stage_times.add(Stage::Write, start.elapsed());

    eprintln!(
        "[ENCRYPT SEGMENT] completed segment {} ({} bytes -> {} frames)",
        input.segment_index, bytes_len, frame_count
    );

    Ok(EncryptedSegment {
        header,
        wire,
        counters,
        stage_times,
    })
}

