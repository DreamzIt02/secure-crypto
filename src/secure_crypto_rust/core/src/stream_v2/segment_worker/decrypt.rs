// # 📂 `src/stream_v2/segment_worker/decrypt.rs`

use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, bounded, unbounded};
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, thread, time::Instant};

use crate::{
    crypto::{DigestAlg, DigestFrame, SegmentDigestVerifier}, recovery::AsyncLogManager, stream_v2::{
        frame_worker::{DecryptedFrame, FrameWorkerError, decrypt::{DecryptFrameWorker0, DecryptFrameWorker1}}, 
        framing::{FrameError, FrameHeader, FrameType}, 
        segment_worker::{DecryptContext, DecryptedSegment, SegmentWorkerError, types::DecryptSegmentInput}, segmenting::{SegmentHeader, types::SegmentFlags}
    }, telemetry::{Stage, StageTimes, counters::TelemetryCounters}, types::StreamError
};

pub struct DecryptSegmentWorker0 {
    crypto: Arc<DecryptContext>,                 // shared immutable context
    log_manager: Arc<AsyncLogManager>,
    fatal_tx: Arc<Sender<StreamError>>,          // global error channel
    cancelled: Arc<AtomicBool>,                  // global cancellation flag
}

impl DecryptSegmentWorker0 {
    /// Creates a new segment decryption worker
    ///
    /// # Arguments
    /// * `crypto` - Shared decryption context containing keys and configuration
    /// * `log_manager` - Async logging manager for audit trails
    /// * `fatal_tx` - Channel to signal fatal errors to the pipeline monitor
    /// * `cancelled` - Shared cancellation flag for graceful shutdown
    pub fn new(
        crypto: Arc<DecryptContext>,
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

    /// Run decrypt loop.
    pub fn run_v1(
        self,
        rx: Receiver<DecryptSegmentInput>,
        tx: Sender<Result<DecryptedSegment, SegmentWorkerError>>,
    ) {
        let crypto = self.crypto.clone();
        let fatal_tx = self.fatal_tx.clone();
        let cancelled = self.cancelled.clone();

        thread::spawn(move || {
            eprintln!("[WORKER] thread spawned");
            let worker_count = crypto.base.profile.cpu_workers();
            let digest_alg = crypto.base.digest_alg;

            // Frame worker pool channels
            let (frame_tx, frame_rx) = bounded::<Bytes>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<DecryptedFrame, FrameWorkerError>>();

            for _ in 0..worker_count {
                let fw = DecryptFrameWorker0::new(
                    crypto.header.clone(),
                    &crypto.base.session_key,
                    fatal_tx.clone(),
                    cancelled.clone(),
                ).expect("DecryptFrameWorker pool init failed");

                fw.run(frame_rx.clone(), out_tx.clone());
            }
            drop(frame_rx);
            drop(out_tx);

            // Main loop: process encrypted segments
            while let Ok(segment) = rx.recv() {
                if cancelled.load(Ordering::Relaxed) {
                    eprintln!("[WORKER] cancelled, exiting early");
                    break;
                }

                eprintln!("[WORKER] processing segment {}", segment.header.segment_index());

                match segment.header.validate(&segment.wire) {
                    Ok(()) => {
                        let result = process_decrypt_segment_1(
                            &segment,
                            &digest_alg,
                            &frame_tx,
                            &out_rx,
                            cancelled.clone(),
                        );

                        match result {
                            Ok(seg) => {
                                if tx.send(Ok(seg)).is_err() {
                                    eprintln!("[DECRYPT SEGMENT WORKER] tx send failed, receiver gone");
                                    // propagate fatal error so monitor drops channels
                                    let _ = fatal_tx.send(StreamError::SegmentWorker(SegmentWorkerError::WorkerDisconnected));
                                    cancelled.store(true, Ordering::Relaxed);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("[DECRYPT SEGMENT WORKER] segment error: {:?}", e);
                                let _ = fatal_tx.send(StreamError::SegmentWorker(e.clone()));
                                cancelled.store(true, Ordering::Relaxed);
                                let _ = tx.send(Err(e));
                                break;
                            }
                        }

                    }
                    Err(e) => {
                        eprintln!("[DECRYPT SEGMENT WORKER] header validation failed: {:?}", e);
                        if tx.send(Err(SegmentWorkerError::SegmentError(e.clone()))).is_err() {
                            eprintln!("[DECRYPT SEGMENT WORKER] tx send failed, receiver gone");
                        }
                        let _ = fatal_tx.send(StreamError::Segment(e.clone()));
                        cancelled.store(true, Ordering::Relaxed);
                        break;
                    }

                }
            }

            eprintln!("[WORKER] rx closed, dropping frame_tx and exiting");
            drop(frame_tx);
            drop(tx);
        });
    }

    /// Runs the segment worker loop with an internal frame worker pool
    ///
    /// # Architecture
    /// - Spawns a pool of frame workers for parallel frame decryption
    /// - Processes segments sequentially, frames within segments in parallel
    /// - Each segment wire is split into frames, decrypted, verified, and reassembled
    /// - Coordinates with frame workers via bounded channels
    ///
    /// # Behavior
    /// - Validates segment headers before processing
    /// - Checks cancellation before processing each segment
    /// - Propagates errors via fatal_tx to trigger pipeline shutdown
    /// - Exits gracefully when input channel closes or on cancellation
    pub fn run_v2(
        self,
        rx: Receiver<DecryptSegmentInput>,
        tx: Sender<Result<DecryptedSegment, SegmentWorkerError>>,
    ) {
        let crypto = self.crypto.clone();
        let fatal_tx = self.fatal_tx.clone();
        let cancelled = self.cancelled.clone();

        thread::spawn(move || {
            eprintln!("[DECRYPT SEGMENT WORKER] thread spawned");

            // ---- Initialize frame worker pool ----
            let worker_count = crypto.base.profile.cpu_workers();
            let digest_alg = crypto.base.digest_alg;

            // Frame processing channels
            let (frame_tx, frame_rx) = bounded::<Bytes>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<DecryptedFrame, FrameWorkerError>>();

            // Spawn frame decryption workers
            for _ in 0..worker_count {
                let fw = DecryptFrameWorker0::new(
                    crypto.header.clone(),
                    &crypto.base.session_key,
                    fatal_tx.clone(),
                    cancelled.clone(),
                )
                .expect("DecryptFrameWorker pool initialization failed");

                fw.run(frame_rx.clone(), out_tx.clone());
            }

            // Drop original senders so workers know when to exit
            drop(frame_rx);
            drop(out_tx);

            // ---- Process segments sequentially ----
            loop {
                // Check for cancellation before blocking on receive
                if cancelled.load(Ordering::Relaxed) {
                    eprintln!("[DECRYPT SEGMENT WORKER] cancelled, exiting early");
                    break;
                }

                // Receive next segment (blocks until available or channel closes)
                let segment = match rx.recv() {
                    Ok(segment) => segment,
                    Err(_) => {
                        // Channel closed normally - all segments processed
                        eprintln!("[DECRYPT SEGMENT WORKER] rx closed, exiting");
                        break;
                    }
                };

                let segment_idx = segment.header.segment_index();
                eprintln!(
                    "[DECRYPT SEGMENT WORKER] processing segment {}",
                    segment_idx
                );

                // Validate segment header before processing
                match segment.header.validate(&segment.wire) {
                    Ok(()) => {
                        // Process the segment (splits frames, decrypts, verifies digest)
                        let result = process_decrypt_segment_1(
                            &segment,
                            &digest_alg,
                            &frame_tx,
                            &out_rx,
                            cancelled.clone(),
                        );

                        match result {
                            Ok(decrypted_segment) => {
                                // Send decrypted segment to output
                                if let Err(_) = tx.send(Ok(decrypted_segment)) {
                                    // Output channel closed unexpectedly - pipeline is shutting down
                                    eprintln!(
                                        "[DECRYPT SEGMENT WORKER] tx send failed, receiver disconnected"
                                    );
                                    let _ = fatal_tx.send(StreamError::SegmentWorker(
                                        SegmentWorkerError::WorkerDisconnected,
                                    ));
                                    cancelled.store(true, Ordering::Relaxed);
                                    break;
                                }
                                // Append log for successfully decrypted segment
                                self.log_manager.console(("[DECRYPT SEGMENT]: ".to_string() + &segment_idx.to_string() + " successfully decrypted").into());
                            }
                            Err(e) => {
                                // Segment processing failed - this is a fatal error
                                eprintln!(
                                    "[DECRYPT SEGMENT WORKER] processing error: {:?}",
                                    e
                                );

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
                    Err(e) => {
                        // Header validation failed - this is a fatal error
                        eprintln!(
                            "[DECRYPT SEGMENT WORKER] header validation failed: {:?}",
                            e
                        );

                        // Try to send error to output (best effort)
                        let _ = tx.send(Err(SegmentWorkerError::SegmentError(e.clone())));

                        // Signal fatal error to pipeline monitor
                        let _ = fatal_tx.send(StreamError::Segment(e));

                        // Set cancellation flag to stop other workers
                        cancelled.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }

            // Cleanup: drop channels to signal frame workers to exit
            eprintln!("[DECRYPT SEGMENT WORKER] dropping frame_tx and exiting");
            drop(frame_tx);
            drop(tx);
        });
    }

}

pub struct DecryptSegmentWorker1 {
    crypto: Arc<DecryptContext>,                 // shared immutable context
    log_manager: Arc<AsyncLogManager>,
    fatal_tx: Sender<StreamError>,               // global error channel
    cancelled: Arc<AtomicBool>,                  // global cancellation flag
}

impl DecryptSegmentWorker1 {
    /// Creates a new segment decryption worker
    ///
    /// # Arguments
    /// * `crypto` - Shared decryption context containing keys and configuration
    /// * `log_manager` - Async logging manager for audit trails
    /// * `fatal_tx` - Channel to signal fatal errors to the pipeline monitor
    /// * `cancelled` - Shared cancellation flag for graceful shutdown
    pub fn new(
        crypto: Arc<DecryptContext>,
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
    /// - Spawns a pool of frame workers for parallel frame decryption
    /// - Processes segments sequentially, frames within segments in parallel
    /// - Each segment wire is split into frames, decrypted, verified, and reassembled
    /// - Coordinates with frame workers via bounded channels
    ///
    /// # Behavior
    /// - Validates segment headers before processing
    /// - Checks cancellation before processing each segment
    /// - Propagates errors via fatal_tx to trigger pipeline shutdown
    /// - Exits gracefully when input channel closes or on cancellation
    pub fn run_v2(
        self,
        rx: Receiver<DecryptSegmentInput>,
        tx: Sender<Result<DecryptedSegment, SegmentWorkerError>>,
    ) {
        let crypto = self.crypto.clone();
        let fatal_tx = self.fatal_tx.clone();
        let cancelled = self.cancelled.clone();

        // Remove thread::spawn - we're already in a scoped thread!
            eprintln!("[DECRYPT SEGMENT WORKER] thread spawned");

            // ---- Initialize frame worker pool ----
            let worker_count = crypto.base.profile.cpu_workers();
            let digest_alg = crypto.base.digest_alg;

            // Frame processing channels
            let (frame_tx, frame_rx) = bounded::<Bytes>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<DecryptedFrame, FrameWorkerError>>();

            // Spawn frame decryption workers
            for _ in 0..worker_count {
                let fw = DecryptFrameWorker1::new(
                    crypto.header.clone(),
                    &crypto.base.session_key,
                    fatal_tx.clone(),
                    cancelled.clone(),
                )
                .expect("DecryptFrameWorker pool initialization failed");

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
                    eprintln!("[DECRYPT SEGMENT WORKER] cancelled, exiting early");
                    break;
                }

                // Receive next segment (blocks until available or channel closes)
                let segment = match rx.recv() {
                    Ok(segment) => segment,
                    Err(_) => {
                        // Channel closed normally - all segments processed
                        eprintln!("[DECRYPT SEGMENT WORKER] rx closed, exiting");
                        break;
                    }
                };

                let segment_idx = segment.header.segment_index();
                eprintln!(
                    "[DECRYPT SEGMENT WORKER] processing segment {}",
                    segment_idx
                );
                // Validate segment header before processing
                match segment.header.validate(&segment.wire) {
                    Ok(()) => {
                        // Process the segment (splits frames, decrypts, verifies digest)
                        let result = process_decrypt_segment_1(
                            &segment,
                            &digest_alg,
                            &frame_tx,
                            &out_rx,
                            cancelled.clone(),
                        );

                        match result {
                            Ok(decrypted_segment) => {
                                // Send decrypted segment to output
                                if let Err(_) = tx.send(Ok(decrypted_segment)) {
                                    // Output channel closed unexpectedly - pipeline is shutting down
                                    eprintln!(
                                        "[DECRYPT SEGMENT WORKER] tx send failed, receiver disconnected"
                                    );
                                    let _ = fatal_tx.send(StreamError::SegmentWorker(
                                        SegmentWorkerError::WorkerDisconnected,
                                    ));
                                    cancelled.store(true, Ordering::Relaxed);
                                    break;
                                }
                                // Append log for successfully decrypted segment
                                self.log_manager.console(("[DECRYPT SEGMENT]: ".to_string() + &segment_idx.to_string() + " successfully decrypted").into());
                            }
                            Err(e) => {
                                // Segment processing failed - this is a fatal error
                                eprintln!(
                                    "[DECRYPT SEGMENT WORKER] processing error: {:?}",
                                    e
                                );

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
                    Err(e) => {
                        // Header validation failed - this is a fatal error
                        eprintln!(
                            "[DECRYPT SEGMENT WORKER] header validation failed: {:?}",
                            e
                        );

                        // Try to send error to output (best effort)
                        let _ = tx.send(Err(SegmentWorkerError::SegmentError(e.clone())));

                        // Signal fatal error to pipeline monitor
                        let _ = fatal_tx.send(StreamError::Segment(e));

                        // Set cancellation flag to stop other workers
                        cancelled.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }

            // Cleanup: drop channels to signal frame workers to exit
            eprintln!("[DECRYPT SEGMENT WORKER] dropping frame_tx and exiting");
            drop(frame_tx);
            drop(tx);

    }

}


/// Processes a single encrypted segment into plaintext
///
/// # Process Flow
/// 1. Validates segment header and handles empty final segments
/// 2. Parses frame boundaries from wire format (zero-copy slicing)
/// 3. Dispatches frame slices to worker pool for parallel decryption
/// 4. Collects and sorts decrypted data frames
/// 5. Verifies segment digest over all frame ciphertexts
/// 6. Validates terminator frame
/// 7. Reassembles plaintext from all data frames
///
/// # Arguments
/// * `input` - Input segment containing encrypted wire data and header
/// * `digest_alg` - Digest algorithm for segment integrity verification
/// * `frame_tx` - Channel to dispatch frame slices to worker pool
/// * `out_rx` - Channel to collect decrypted frames from workers
/// * `cancelled` - Cancellation flag for early exit

pub fn process_decrypt_segment_1(
    input: &DecryptSegmentInput,
    digest_alg: &DigestAlg,
    frame_tx: &Sender<Bytes>,
    out_rx: &Receiver<Result<DecryptedFrame, FrameWorkerError>>,
    cancelled: Arc<AtomicBool>,
) -> Result<DecryptedSegment, SegmentWorkerError> {
    let mut counters = TelemetryCounters::default();
    let mut stage_times = StageTimes::default();

    eprintln!(
        "[DECRYPT SEGMENT] processing segment {}",
        input.header.segment_index()
    );

    // ---- Stage 1: Validation ----
    let start = Instant::now();

    // Handle empty final segment (EOF marker)
    if input.wire.is_empty() && input.header.flags().contains(SegmentFlags::FINAL_SEGMENT) {
        eprintln!(
            "[DECRYPT SEGMENT] empty FINAL_SEGMENT at index {}",
            input.header.segment_index()
        );
        return Ok(DecryptedSegment {
            header: input.header.clone(),
            bytes: Bytes::new(),
            counters,
            stage_times,
        });
    }

    // Verify CRC32 checksum of segment wire
    input
        .header
        .validate(&input.wire)
        .map_err(SegmentWorkerError::SegmentError)?;

    stage_times.add(Stage::Validate, start.elapsed());

    // Count segment header overhead
    counters.add_header(SegmentHeader::LEN);

    // ---- Stage 2: Parse frame boundaries and dispatch for decryption ----
    let start = Instant::now();
    let mut offset = 0;
    let mut frame_count: usize = 0;

    eprintln!(
        "[DECRYPT SEGMENT] parsing frames from wire (length: {} bytes)",
        input.wire.len()
    );

    while offset < input.wire.len() {
        // Parse frame header to determine frame length
        let header = FrameHeader::from_bytes(&input.wire[offset..])?;
        let frame_len = FrameHeader::LEN + header.ciphertext_len() as usize;
        let end = offset + frame_len;

        // Validate frame doesn't extend beyond wire boundary
        if end > input.wire.len() {
            eprintln!("[DECRYPT SEGMENT] frame truncated at offset {}", offset);
            return Err(FrameError::Truncated.into());
        }

        eprintln!(
            "[DECRYPT SEGMENT] dispatching frame {} (segment {}, length: {} bytes)",
            frame_count,
            input.header.segment_index(),
            frame_len
        );

        // Dispatch frame slice for decryption (zero-copy using Bytes::slice)
        frame_tx
            .send(input.wire.slice(offset..end))
            .map_err(|_| {
                SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected)
            })?;

        offset = end;
        frame_count += 1;
    }

    stage_times.add(Stage::Read, start.elapsed());

    // Validate we found at least one frame
    if frame_count == 0 {
        eprintln!(
            "[DECRYPT SEGMENT] no frames found in non-final segment {}",
            input.header.segment_index()
        );
        return Err(SegmentWorkerError::InvalidSegment(
            "Segment contains no frames".into(),
        ));
    }

    // ---- Stage 3: Collect decrypted frames ----
    let mut data_frames = Vec::with_capacity(frame_count.saturating_sub(2));
    let mut digest_frame: Option<DecryptedFrame> = None;
    let mut terminator_frame: Option<DecryptedFrame> = None;
    let mut received = 0;

    eprintln!(
        "[DECRYPT SEGMENT] collecting {} decrypted frames",
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
                    "[DECRYPT SEGMENT] received frame {} (type {:?})",
                    frame.frame_index, frame.frame_type
                );

                // Merge frame telemetry
                stage_times.merge(&frame.stage_times);

                // Categorize frame by type
                match frame.frame_type {
                    FrameType::Data => data_frames.push(frame),
                    FrameType::Digest => {
                        if digest_frame.is_some() {
                            return Err(SegmentWorkerError::InvalidSegment(
                                "Multiple digest frames detected".into(),
                            ));
                        }
                        digest_frame = Some(frame);
                    }
                    FrameType::Terminator => {
                        if terminator_frame.is_some() {
                            return Err(SegmentWorkerError::InvalidSegment(
                                "Multiple terminator frames detected".into(),
                            ));
                        }
                        terminator_frame = Some(frame);
                    }
                }
            }
            Ok(Err(e)) => {
                // Frame worker returned an error
                eprintln!("[DECRYPT SEGMENT] frame worker error: {:?}", e);
                return Err(e.into());
            }
            Err(_) => {
                // Frame output channel closed unexpectedly
                eprintln!("[DECRYPT SEGMENT] frame worker channel disconnected");
                return Err(SegmentWorkerError::FrameWorkerError(
                    FrameWorkerError::WorkerDisconnected,
                ));
            }
        }
    }

    // Validate frame counts (data frames + digest + terminator)
    if (data_frames.len() + 2) != frame_count {
        eprintln!(
            "[DECRYPT SEGMENT] frame count mismatch: data={}, total={}",
            data_frames.len(),
            frame_count
        );
        return Err(SegmentWorkerError::InvalidSegment(
            format!(
                "Expected {} frames (data+digest+terminator), got {}+2",
                frame_count,
                data_frames.len()
            ),
        ));
    }

    // ---- Stage 4: Sort data frames by index ----
    data_frames.sort_unstable_by_key(|f| f.frame_index);
    eprintln!(
        "[DECRYPT SEGMENT] sorted {} data frames",
        data_frames.len()
    );

    let data_frame_count = data_frames.len() as u32;
    let segment_index = data_frames
        .first()
        .map(|f| f.segment_index)
        .unwrap_or(input.header.segment_index());

    // ---- Stage 5: Verify segment digest ----
    let start = Instant::now();

    let digest_frame_data = digest_frame.ok_or(SegmentWorkerError::MissingDigestFrame)?;

    // Validate digest frame is at expected position
    if digest_frame_data.frame_index != data_frame_count {
        eprintln!(
            "[DECRYPT SEGMENT] digest frame index mismatch: expected {}, got {}",
            data_frame_count, digest_frame_data.frame_index
        );
        return Err(SegmentWorkerError::InvalidSegment(
            "Digest frame at incorrect position".into(),
        ));
    }

    // Decode digest payload
    let digest_frame_payload = DigestFrame::decode(&digest_frame_data.plaintext)?;
    eprintln!(
        "[DECRYPT SEGMENT] digest frame decoded, verifying segment {}",
        segment_index
    );

    // Initialize digest verifier
    let mut verifier = SegmentDigestVerifier::new(
        digest_alg.clone(),
        segment_index,
        data_frame_count,
        digest_frame_payload.digest,
    );

    // Update verifier with all frame ciphertexts
    for frame in &data_frames {
        // Track overhead: frame header
        counters.bytes_overhead += FrameHeader::LEN as u64;
        // Track compressed/plaintext size
        counters.bytes_compressed += frame.plaintext.len() as u64;

        // Update digest with frame ciphertext
        verifier.update_frame(frame.frame_index, frame.ciphertext());
    }

    counters.frames_data = data_frame_count as u64;

    // Finalize and verify digest (fails if mismatch)
    verifier.finalize()?;
    counters.add_digest(digest_frame_data.plaintext.len());

    stage_times.add(Stage::Digest, start.elapsed());
    eprintln!(
        "[DECRYPT SEGMENT] digest verified for segment {}",
        segment_index
    );

    // ---- Stage 6: Validate terminator frame ----
    let start = Instant::now();

    let terminator_frame_data =
        terminator_frame.ok_or(SegmentWorkerError::MissingTerminatorFrame)?;

    // Validate terminator frame is at expected position (last frame)
    if terminator_frame_data.frame_index != data_frame_count + 1 {
        eprintln!(
            "[DECRYPT SEGMENT] terminator frame index mismatch: expected {}, got {}",
            data_frame_count + 1,
            terminator_frame_data.frame_index
        );
        return Err(SegmentWorkerError::InvalidSegment(
            "Terminator frame must be the last frame".into(),
        ));
    }

    counters.add_terminator(terminator_frame_data.plaintext.len());
    eprintln!(
        "[DECRYPT SEGMENT] terminator frame validated for segment {}",
        segment_index
    );

    stage_times.add(Stage::Validate, start.elapsed());

    // ---- Stage 7: Reassemble plaintext ----
    let start = Instant::now();

    // Preallocate buffer for all plaintext
    let total_plaintext_len: usize = data_frames.iter().map(|f| f.plaintext.len()).sum();
    let mut plaintext_out = Vec::with_capacity(total_plaintext_len);

    // Concatenate all data frame plaintext in order
    for frame in data_frames {
        plaintext_out.extend_from_slice(&frame.plaintext);
    }

    let bytes = Bytes::from(plaintext_out);

    // Note: We can validate that header.bytes_len == bytes.len()
    // to ensure plaintext length matches header expectation

    stage_times.add(Stage::Write, start.elapsed());

    eprintln!(
        "[DECRYPT SEGMENT] completed segment {} ({} bytes plaintext from {} frames)",
        segment_index,
        bytes.len(),
        data_frame_count
    );

    Ok(DecryptedSegment {
        header: input.header,
        bytes,
        counters,
        stage_times,
    })
}

