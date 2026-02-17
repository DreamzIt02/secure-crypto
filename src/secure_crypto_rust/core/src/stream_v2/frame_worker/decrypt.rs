// # 📂 `src/stream_v2/frame_worker/decrypt.rs`

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender};

use crate::crypto::AadHeader;
use crate::crypto::{
    aad::build_aad,
    aead::AeadImpl,
    nonce::derive_nonce_12_tls_style,
};
use crate::headers::types::HeaderV1;
use crate::stream_v2::framing::{FrameHeader, FrameType};
use crate::stream_v2::framing::decode::decode_frame;
use crate::telemetry::{Stage, StageTimes};
use crate::types::StreamError;
use super::types::{FrameWorkerError, DecryptedFrame};

pub struct DecryptFrameWorker0 {
    header: HeaderV1,
    aead: AeadImpl,
    fatal_tx: Arc<Sender<StreamError>>,   // global error channel
    cancelled: Arc<AtomicBool>,           // global cancellation flag
}

impl DecryptFrameWorker0 {
    /// Creates a new frame decryption worker
    ///
    /// # Arguments
    /// * `header` - Stream header containing decryption parameters
    /// * `session_key` - Session key for AEAD decryption
    /// * `fatal_tx` - Channel to signal fatal errors to the pipeline monitor
    /// * `cancelled` - Shared cancellation flag for graceful shutdown
    pub fn new(
        header: HeaderV1,
        session_key: &[u8],
        fatal_tx: Arc<Sender<StreamError>>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, FrameWorkerError> {
        let aead = AeadImpl::from_header_and_key(&header, session_key)?;
        Ok(Self {
            header,
            aead,
            fatal_tx,
            cancelled,
        })
    }

    /// Decrypts a single encrypted frame from wire format
    ///
    /// # Process
    /// 1. Parses frame header from wire bytes
    /// 2. Validates frame structure and extracts ciphertext range
    /// 3. Reconstructs AAD (Additional Authenticated Data) and nonce
    /// 4. Performs AEAD decryption (or skips for Terminator frames)
    /// 5. Returns decrypted frame with plaintext and metadata
    ///
    /// # Memory efficiency
    /// - `wire` bytes are moved (not copied) into the output frame
    /// - Ciphertext is referenced via range (zero-copy)
    /// - Only plaintext is allocated as new memory (crypto requirement)
    pub fn decrypt_frame(&self, wire: Bytes) -> Result<DecryptedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Frame header parsing ----
        let start = Instant::now();
        let view = decode_frame(&wire)?;
        stage_times.add(Stage::Decode, start.elapsed());

        // ---- Stage 2: Validation and AAD reconstruction ----
        let start = Instant::now();
        
        // Validate ciphertext boundaries
        let ct_start = FrameHeader::LEN;
        let ct_end = ct_start + view.header.ciphertext_len() as usize;
        if ct_end > wire.len() {
            return Err(FrameWorkerError::InvalidInput(
                "Wire length mismatch: ciphertext extends beyond frame boundary".into(),
            ));
        }

        // Reconstruct AAD header from frame metadata
        let aad_header = AadHeader {
            frame_type: view.header.frame_type().try_to_u8()?,
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            plaintext_len: view.header.plaintext_len(),
        };

        // Rebuild AAD to match encryption-time construction
        let aad = build_aad(&self.header, &aad_header)?;

        // Derive frame-specific nonce (must match encryption nonce)
        let nonce = derive_nonce_12_tls_style(
            &self.header.salt,
            view.header.frame_index() as u64,
        )?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 3: AEAD Decryption ----
        let start = Instant::now();
        let plaintext: Vec<u8> = match view.header.frame_type() {
            FrameType::Data | FrameType::Digest => {
                // Normal AEAD decryption for data and digest frames
                self.aead.open(&nonce, &aad, view.ciphertext)?
            }
            FrameType::Terminator => {
                // Terminator frames carry no payload, skip decryption
                Vec::new()
            }
        };
        stage_times.add(Stage::Decrypt, start.elapsed());

        // ---- Stage 4: Construct decrypted frame ----
        Ok(DecryptedFrame {
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            frame_type: view.header.frame_type(),
            wire,                              // Wire bytes moved (zero-copy)
            ct_range: ct_start..ct_end,        // Ciphertext referenced by range
            plaintext: Bytes::from(plaintext), // Plaintext allocated (crypto output)
            stage_times,
        })
    }

    /// Runs the worker loop, processing encrypted frames until channel closes or cancellation
    ///
    /// # Behavior
    /// - Spawns a new thread to process incoming encrypted frames
    /// - Checks cancellation flag before processing each frame
    /// - Sends decrypted frames to output channel
    /// - Propagates errors via fatal_tx to trigger pipeline shutdown
    /// - Exits gracefully when input channel closes or on cancellation
    pub fn run(
        self,
        rx: Receiver<Bytes>,
        tx: Sender<Result<DecryptedFrame, FrameWorkerError>>,
    ) {
        std::thread::spawn(move || {
            loop {
                // Check for cancellation before blocking on receive
                if self.cancelled.load(Ordering::Relaxed) {
                    eprintln!("[DECRYPT FRAME WORKER] cancelled, exiting");
                    break;
                }

                // Receive next encrypted frame (blocks until available or channel closes)
                let wire = match rx.recv() {
                    Ok(wire) => wire,
                    Err(_) => {
                        // Channel closed normally - all frames processed
                        eprintln!("[DECRYPT FRAME WORKER] rx closed, exiting");
                        break;
                    }
                };

                // Process the encrypted frame
                match self.decrypt_frame(wire) {
                    Ok(frame) => {
                        // Send decrypted frame to output
                        if let Err(_) = tx.send(Ok(frame)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            eprintln!(
                                "[DECRYPT FRAME WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = self.fatal_tx.send(StreamError::FrameWorker(
                                FrameWorkerError::WorkerDisconnected,
                            ));
                            self.cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(e) => {
                        // Decryption failed - this is a fatal error
                        eprintln!("[DECRYPT FRAME WORKER] decryption error: {:?}", e);

                        // Try to send error to output (best effort)
                        let _ = tx.send(Err(e.clone()));

                        // Signal fatal error to pipeline monitor
                        let _ = self.fatal_tx.send(StreamError::FrameWorker(e));

                        // Set cancellation flag to stop other workers
                        self.cancelled.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }

            eprintln!("[DECRYPT FRAME WORKER] thread exiting");
        });
    }

}

pub struct DecryptFrameWorker1 {
    header: HeaderV1,
    aead: AeadImpl,
    fatal_tx: Sender<StreamError>,        // global error channel
    cancelled: Arc<AtomicBool>,           // global cancellation flag
}

impl DecryptFrameWorker1 {
    /// Creates a new frame decryption worker
    ///
    /// # Arguments
    /// * `header` - Stream header containing decryption parameters
    /// * `session_key` - Session key for AEAD decryption
    /// * `fatal_tx` - Channel to signal fatal errors to the pipeline monitor
    /// * `cancelled` - Shared cancellation flag for graceful shutdown
    pub fn new(
        header: HeaderV1,
        session_key: &[u8],
        fatal_tx: Sender<StreamError>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, FrameWorkerError> {
        let aead = AeadImpl::from_header_and_key(&header, session_key)?;
        Ok(Self {
            header,
            aead,
            fatal_tx,
            cancelled,
        })
    }

    /// Decrypts a single encrypted frame from wire format
    ///
    /// # Process
    /// 1. Parses frame header from wire bytes
    /// 2. Validates frame structure and extracts ciphertext range
    /// 3. Reconstructs AAD (Additional Authenticated Data) and nonce
    /// 4. Performs AEAD decryption (or skips for Terminator frames)
    /// 5. Returns decrypted frame with plaintext and metadata
    ///
    /// # Memory efficiency
    /// - `wire` bytes are moved (not copied) into the output frame
    /// - Ciphertext is referenced via range (zero-copy)
    /// - Only plaintext is allocated as new memory (crypto requirement)
    pub fn decrypt_frame(&self, wire: Bytes) -> Result<DecryptedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Frame header parsing ----
        let start = Instant::now();
        let view = decode_frame(&wire)?;
        stage_times.add(Stage::Decode, start.elapsed());

        // ---- Stage 2: Validation and AAD reconstruction ----
        let start = Instant::now();
        
        // Validate ciphertext boundaries
        let ct_start = FrameHeader::LEN;
        let ct_end = ct_start + view.header.ciphertext_len() as usize;
        if ct_end > wire.len() {
            return Err(FrameWorkerError::InvalidInput(
                "Wire length mismatch: ciphertext extends beyond frame boundary".into(),
            ));
        }

        // Reconstruct AAD header from frame metadata
        let aad_header = AadHeader {
            frame_type: view.header.frame_type().try_to_u8()?,
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            plaintext_len: view.header.plaintext_len(),
        };

        // Rebuild AAD to match encryption-time construction
        let aad = build_aad(&self.header, &aad_header)?;

        // Derive frame-specific nonce (must match encryption nonce)
        let nonce = derive_nonce_12_tls_style(
            &self.header.salt,
            view.header.frame_index() as u64,
        )?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 3: AEAD Decryption ----
        let start = Instant::now();
        let plaintext: Vec<u8> = match view.header.frame_type() {
            FrameType::Data | FrameType::Digest => {
                // Normal AEAD decryption for data and digest frames
                self.aead.open(&nonce, &aad, view.ciphertext)?
            }
            FrameType::Terminator => {
                // Terminator frames carry no payload, skip decryption
                Vec::new()
            }
        };
        stage_times.add(Stage::Decrypt, start.elapsed());

        // ---- Stage 4: Construct decrypted frame ----
        Ok(DecryptedFrame {
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            frame_type: view.header.frame_type(),
            wire,                              // Wire bytes moved (zero-copy)
            ct_range: ct_start..ct_end,        // Ciphertext referenced by range
            plaintext: Bytes::from(plaintext), // Plaintext allocated (crypto output)
            stage_times,
        })
    }

    /// Runs the worker loop, processing encrypted frames until channel closes or cancellation
    ///
    /// # Behavior
    /// - Spawns a new thread to process incoming encrypted frames
    /// - Checks cancellation flag before processing each frame
    /// - Sends decrypted frames to output channel
    /// - Propagates errors via fatal_tx to trigger pipeline shutdown
    /// - Exits gracefully when input channel closes or on cancellation
    pub fn run(
        self,
        rx: Receiver<Bytes>,
        tx: Sender<Result<DecryptedFrame, FrameWorkerError>>,
    ) {
       // Remove thread::spawn - we're already spawned in run_v2
        // std::thread::spawn(move || {

            loop {
                // Check for cancellation before blocking on receive
                if self.cancelled.load(Ordering::Relaxed) {
                    eprintln!("[DECRYPT FRAME WORKER] cancelled, exiting");
                    break;
                }

                // Receive next encrypted frame (blocks until available or channel closes)
                let wire = match rx.recv() {
                    Ok(wire) => wire,
                    Err(_) => {
                        // Channel closed normally - all frames processed
                        eprintln!("[DECRYPT FRAME WORKER] rx closed, exiting");
                        break;
                    }
                };

                // Process the encrypted frame
                match self.decrypt_frame(wire) {
                    Ok(frame) => {
                        // Send decrypted frame to output
                        if let Err(_) = tx.send(Ok(frame)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            eprintln!(
                                "[DECRYPT FRAME WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = self.fatal_tx.send(StreamError::FrameWorker(
                                FrameWorkerError::WorkerDisconnected,
                            ));
                            self.cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(e) => {
                        // Decryption failed - this is a fatal error
                        eprintln!("[DECRYPT FRAME WORKER] decryption error: {:?}", e);

                        // Try to send error to output (best effort)
                        let _ = tx.send(Err(e.clone()));

                        // Signal fatal error to pipeline monitor
                        let _ = self.fatal_tx.send(StreamError::FrameWorker(e));

                        // Set cancellation flag to stop other workers
                        self.cancelled.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }

            eprintln!("[DECRYPT FRAME WORKER] thread exiting");
        // });
    }

}

