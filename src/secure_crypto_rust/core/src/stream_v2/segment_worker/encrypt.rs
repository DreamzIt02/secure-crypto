// # 📂 `src/stream_v2/segment_worker/encrypt.rs`

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use crossbeam::channel::{Receiver, Sender, bounded, unbounded};
use tracing::{debug, error};

use crate::{
    recovery::AsyncLogManager, stream_v2::{
        frame_worker::{EncryptedFrame, FrameInput, FrameWorkerError, encrypt::{EncryptFrameWorker0, EncryptFrameWorker1}},
        segment_worker::{EncryptContext, SegmentWorkerError, enc_helpers::{encrypt_segment_lockfree, process_encrypt_segment_1}},
    }, types::StreamError, utils::tracing_logger
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
        // explicitly set DEBUG level
        tracing_logger(Some(tracing::Level::DEBUG));

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
                    error!("[WORKER] cancelled, exiting early");
                    break;
                }

                debug!("[WORKER] processing segment {}", segment.segment_index);
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
                        if let Err(e) = tx.send(Ok(seg)) {
                            error!("[SEGMENT WORKER] tx send failed, receiver gone");
                            // propagate fatal error so monitor drops channels
                            let _ = fatal_tx.send(StreamError::SegmentWorker(
                                SegmentWorkerError::StateError(e.to_string()
                            )));
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("[SEGMENT WORKER] error: {:?}", e);
                        let _ = fatal_tx.send(StreamError::SegmentWorker(e.clone()));
                        cancelled.store(true, Ordering::Relaxed);
                        let _ = tx.send(Err(e));
                        break;
                    }
                }

            }

            debug!("[WORKER] rx closed, exiting loop");
            drop(frame_tx);
            drop(tx);
            debug!("[WORKER] dropped tx, worker exiting");
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
        // explicitly set DEBUG level
        tracing_logger(Some(tracing::Level::DEBUG));

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
                    error!("[ENCRYPT SEGMENT WORKER] cancelled, exiting early");
                    break;
                }

                // Receive next segment (blocks until available or channel closes)
                let segment = match rx.recv() {
                    Ok(segment) => segment,
                    Err(_) => {
                        // Channel closed normally - all segments processed
                        debug!("[ENCRYPT SEGMENT WORKER] rx closed, exiting loop");
                        break;
                    }
                };

                let segment_idx = segment.segment_index;
                debug!(
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
                        if let Err(e) = tx.send(Ok(encrypted_segment)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            error!(
                                "[ENCRYPT SEGMENT WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = fatal_tx.send(StreamError::SegmentWorker(
                                SegmentWorkerError::StateError(e.to_string()),
                            ));
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                        // Append log for successfully encrypted segment
                        self.log_manager.console(("[ENCRYPT SEGMENT]: ".to_string() + &segment_idx.to_string() + " successfully encrypted").into());
                    }
                    Err(e) => {
                        // Segment processing failed - this is a fatal error
                        error!("[ENCRYPT SEGMENT WORKER] processing error: {:?}", e);

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
            debug!("[ENCRYPT SEGMENT WORKER] dropped channels, thread exiting");
        });
    }

}

#[derive(Debug, Clone)]
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
    pub fn run_v1( // SUCCESS: This is working good code run_v1
        self,
        rx: Receiver<EncryptSegmentInput>,
        tx: Sender<Result<EncryptedSegment, SegmentWorkerError>>,
    ) {
        // explicitly set DEBUG level
        tracing_logger(Some(tracing::Level::DEBUG));

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
                    debug!("[ENCRYPT SEGMENT WORKER] cancelled, exiting early");
                    break;
                }

                // Receive next segment (blocks until available or channel closes)
                let segment = match rx.recv() {
                    Ok(segment) => segment,
                    Err(_) => {
                        // Channel closed normally - all segments processed
                        debug!("[ENCRYPT SEGMENT WORKER] rx closed, exiting loop");
                        break;
                    }
                };

                let segment_idx = segment.segment_index;
                debug!(
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
                        if let Err(e) = tx.send(Ok(encrypted_segment)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            error!(
                                "[ENCRYPT SEGMENT WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = fatal_tx.send(StreamError::SegmentWorker(
                                SegmentWorkerError::StateError(e.to_string()),
                            ));
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                        // Append log for successfully encrypted segment
                        self.log_manager.console(("[ENCRYPT SEGMENT]: ".to_string() + &segment_idx.to_string() + " successfully encrypted").into());
                    }
                    Err(e) => {
                        // Segment processing failed - this is a fatal error
                        error!("[ENCRYPT SEGMENT WORKER] processing error: {:?}", e);

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
            
            debug!("[ENCRYPT SEGMENT WORKER] dropped channels, thread exiting");
        // });

    }

    pub fn run_v2(
        self,
        rx: Receiver<EncryptSegmentInput>,
        tx: Sender<Result<EncryptedSegment, SegmentWorkerError>>,
    ) {
        // explicitly set DEBUG level
        tracing_logger(Some(tracing::Level::DEBUG));

        let crypto = self.crypto.clone();
        let fatal_tx = self.fatal_tx.clone();
        let cancelled = self.cancelled.clone();

        // Remove thread::spawn - we're already spawned in pipeline
        // std::thread::spawn(move || {
            // ---- Initialize frame worker pool ----
            // Frame processing channels
            // let (out_tx, out_rx) = unbounded::<Result<EncryptedFrame, FrameWorkerError>>();

            // ---- Process segments sequentially ----
            loop {
                // Check for cancellation before blocking on receive
                if cancelled.load(Ordering::Relaxed) {
                    error!("[ENCRYPT SEGMENT WORKER] cancelled, exiting early");
                    break;
                }

                // Receive next segment (blocks until available or channel closes)
                let segment = match rx.recv() {
                    Ok(segment) => segment,
                    Err(_) => {
                        // Channel closed normally - all segments processed
                        debug!("[ENCRYPT SEGMENT WORKER] rx closed, exiting loop");
                        break;
                    }
                };

                let segment_idx = segment.segment_index;
                error!(
                    "[ENCRYPT SEGMENT WORKER] processing segment {}",
                    segment_idx
                );

                // Process the segment (splits into frames, encrypts, digests)
                let result = encrypt_segment_lockfree(
                    &crypto,
                    &segment,
                    // &out_tx,
                    // &out_rx,
                    cancelled.clone(),
                );

                match result {
                    Ok(encrypted_segment) => {
                        // Send encrypted segment to output
                        if let Err(e) = tx.send(Ok(encrypted_segment)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            error!(
                                "[ENCRYPT SEGMENT WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = fatal_tx.send(StreamError::SegmentWorker(
                                SegmentWorkerError::StateError(e.to_string()),
                            ));
                            cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                        // Append log for successfully encrypted segment
                        self.log_manager.console(("[ENCRYPT SEGMENT]: ".to_string() + &segment_idx.to_string() + " successfully encrypted").into());
                    }
                    Err(e) => {
                        // Segment processing failed - this is a fatal error
                        error!("[ENCRYPT SEGMENT WORKER] processing error: {:?}", e);

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
            drop(tx);
            
            debug!("[ENCRYPT SEGMENT WORKER] dropped channels, thread exiting");
        // });

    }

}

