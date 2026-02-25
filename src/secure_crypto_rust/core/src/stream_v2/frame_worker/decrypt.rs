// # 📂 `src/stream_v2/frame_worker/decrypt.rs`

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use crossbeam::channel::{Receiver, Sender};
use tracing::{debug, error};

use crate::crypto::AadHeader;
use crate::crypto::{
    aad::build_aad,
    aead::AeadImpl,
    nonce::derive_nonce_12_tls_style,
};
use crate::headers::types::HeaderV1;
use crate::stream_v2::framing::{FrameHeader, FrameType};
use crate::stream_v2::framing::decode::{decode_frame, decode_in_place};
use crate::telemetry::{Stage, StageTimes};
use crate::types::StreamError;
use crate::utils::tracing_logger;
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
            payload_len: view.header.plaintext_len(),
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
        // explicitly set DEBUG level
        tracing_logger(Some(tracing::Level::DEBUG));

        std::thread::spawn(move || {
            loop {
                // Check for cancellation before blocking on receive
                if self.cancelled.load(Ordering::Relaxed) {
                    error!("[DECRYPT FRAME WORKER] cancelled, exiting");
                    break;
                }

                // Receive next encrypted frame (blocks until available or channel closes)
                let wire = match rx.recv() {
                    Ok(wire) => wire,
                    Err(_) => {
                        // Channel closed normally - all frames processed
                        debug!("[DECRYPT FRAME WORKER] rx closed, exiting");
                        break;
                    }
                };

                // Process the encrypted frame
                match self.decrypt_frame(wire) {
                    Ok(frame) => {
                        // Send decrypted frame to output
                        if let Err(e) = tx.send(Ok(frame)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            error!(
                                "[DECRYPT FRAME WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = self.fatal_tx.send(StreamError::FrameWorker(
                                FrameWorkerError::StateError(e.to_string()),
                            ));
                            self.cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(e) => {
                        // Decryption failed - this is a fatal error
                        error!("[DECRYPT FRAME WORKER] decryption error: {:?}", e);

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

            debug!("[DECRYPT FRAME WORKER] thread exiting");
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
            payload_len: view.header.plaintext_len(),
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
            FrameType::Data => {
                // Normal AEAD decryption for data
                self.aead.open(&nonce, &aad, view.ciphertext)?
            }
            FrameType::Digest => {
                // Digest payload is already a hash, no AEAD needed
                view.ciphertext.to_vec()
            }
            FrameType::Terminator => {
                // Terminator frames carry no payload, skip encryption
                Vec::new()
            }
        };
        stage_times.add(Stage::Decrypt, start.elapsed());

        // ---- Stage 4: Construct decrypted frame ----
        Ok(DecryptedFrame {
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            frame_type: view.header.frame_type(),
            wire: Bytes::from(""),             // Wire bytes moved (zero-copy)
            ct_range: ct_start..ct_end,        // Ciphertext referenced by range
            plaintext: Bytes::from(plaintext), // Plaintext allocated (crypto output)
            stage_times,
        })
    }

    // ### Zero‑Copy Decryption Implementation
    pub fn decrypt_in_place(&self, wire: Bytes) -> Result<DecryptedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Decode header ----
        let start = Instant::now();
        let view = decode_in_place(&wire)?;
        stage_times.add(Stage::Decode, start.elapsed());

        let ct_start = FrameHeader::LEN;
        let ct_end = ct_start + view.header.ciphertext_len() as usize;
        if ct_end > wire.len() {
            return Err(FrameWorkerError::InvalidInput(
                "Wire length mismatch: ciphertext extends beyond frame boundary".into(),
            ));
        }

        // ---- Stage 2: AAD + nonce ----
        let start = Instant::now();
        let aad_header = AadHeader {
            frame_type: view.header.frame_type().try_to_u8()?,
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            payload_len: view.header.plaintext_len(),
        };
        let aad = build_aad(&self.header, &aad_header)?;
        let nonce = derive_nonce_12_tls_style(&self.header.salt, view.header.frame_index() as u64)?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 3: Decrypt ----
        let start = Instant::now();
        // This buf is filled with encrypted [data, digest payload or terminator empty bytes]
        let mut buf = BytesMut::from(&wire[ct_start..ct_end]);
        match view.header.frame_type() {
            FrameType::Data => {
                self.aead.open_in_place(&nonce, &aad, &mut buf)?
            }
            FrameType::Digest => {}
            FrameType::Terminator => {}
        };
        stage_times.add(Stage::Decrypt, start.elapsed());

        Ok(DecryptedFrame {
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            frame_type: view.header.frame_type(),
            wire: Bytes::from(""),             // Wire bytes moved (zero-copy)
            ct_range: ct_start..ct_end,
            plaintext: buf.freeze(),
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
        // explicitly set DEBUG level
        tracing_logger(Some(tracing::Level::DEBUG));
        // Remove thread::spawn - we're already spawned in run_v1
        // std::thread::spawn(move || {
            loop {
                // Check for cancellation before blocking on receive
                if self.cancelled.load(Ordering::Relaxed) {
                    error!("[DECRYPT FRAME WORKER] cancelled, exiting");
                    break;
                }

                // Receive next encrypted frame (blocks until available or channel closes)
                let wire = match rx.recv() {
                    Ok(wire) => wire,
                    Err(_) => {
                        // Channel closed normally - all frames processed
                        debug!("[DECRYPT FRAME WORKER] rx closed, exiting");
                        break;
                    }
                };

                // Process the encrypted frame
                match self.decrypt_frame(wire) {
                    Ok(frame) => {
                        // Send decrypted frame to output
                        if let Err(e) = tx.send(Ok(frame)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            error!(
                                "[DECRYPT FRAME WORKER] tx send failed, receiver disconnected"
                            );
                            let _ = self.fatal_tx.send(StreamError::FrameWorker(
                                FrameWorkerError::StateError(e.to_string()),
                            ));
                            self.cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(e) => {
                        // Decryption failed - this is a fatal error
                        error!("[DECRYPT FRAME WORKER] decryption error: {:?}", e);

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

            debug!("[DECRYPT FRAME WORKER] thread exiting");
        // });
    }

}

// # ✅ FINAL Lock-Free `DecryptFrameWorker2`

pub struct DecryptFrameWorker2 {
    header: HeaderV1,
    aead: AeadImpl,
    cancelled: Arc<AtomicBool>, // cooperative cancellation only
}

impl DecryptFrameWorker2 {
    pub fn new(
        header: HeaderV1,
        session_key: &[u8],
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, FrameWorkerError> {
        let aead = AeadImpl::from_header_and_key(&header, session_key)?;
        Ok(Self {
            header,
            aead,
            cancelled,
        })
    }

    #[inline(always)]
    pub fn decrypt_frame(
        &self,
        wire: Bytes,
    ) -> Result<DecryptedFrame, FrameWorkerError> {

        // 🔥 Early cooperative cancellation
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(FrameWorkerError::Cancelled);
        }

        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Decode ----
        let start = Instant::now();
        let view = decode_frame(&wire)?;
        stage_times.add(Stage::Decode, start.elapsed());

        // ---- Stage 2: Validate + AAD ----
        let start = Instant::now();

        let ct_start = FrameHeader::LEN;
        let ct_end = ct_start + view.header.ciphertext_len() as usize;

        if ct_end > wire.len() {
            return Err(FrameWorkerError::InvalidInput(
                "Wire length mismatch".into(),
            ));
        }

        let aad_header = AadHeader {
            frame_type: view.header.frame_type().try_to_u8()?,
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            payload_len: view.header.plaintext_len(),
        };

        let aad = build_aad(&self.header, &aad_header)?;

        let nonce = derive_nonce_12_tls_style(
            &self.header.salt,
            view.header.frame_index() as u64,
        )?;

        stage_times.add(Stage::Validate, start.elapsed());

        // 🔥 Check again before heavy crypto
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(FrameWorkerError::Cancelled);
        }

        // ---- Stage 3: AEAD ----
        let start = Instant::now();

        let plaintext = match view.header.frame_type() {
            FrameType::Data => {
                self.aead.open(&nonce, &aad, view.ciphertext)?
            }
            FrameType::Digest => {
                view.ciphertext.to_vec()
            }
            FrameType::Terminator => {
                Vec::new()
            }
        };

        stage_times.add(Stage::Decrypt, start.elapsed());

        Ok(DecryptedFrame {
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            frame_type: view.header.frame_type(),
            wire: Bytes::from(""),             // Wire bytes moved (zero-copy)
            ct_range: ct_start..ct_end,
            plaintext: Bytes::from(plaintext),
            stage_times,
        })
    }
}

// # ✅ Now Fix `decrypt_segment_lockfree` Submit Block

// Here is the correct final version for frame submission:

// ```rust
// FRAME_EXECUTOR.submit(Box::new(move || {

//     if cancelled.load(Ordering::Relaxed) {
//         completed.fetch_add(1, Ordering::Release);
//         return;
//     }

//     let result = FRAME_EXECUTOR
//         .decrypt_worker()
//         .expect("Decrypt worker not initialized")
//         .decrypt_frame(wire_slice);

//     match result {
//         Ok(frame) => {
//             results[idx].set(frame).ok();
//         }
//         Err(e) => {
//             cancelled.store(true, Ordering::Release);

//             if let Some(fatal_tx) = FRAME_EXECUTOR.fatal_error() {
//                 let _ = fatal_tx.send(StreamError::FrameWorker(e));
//             }
//         }
//     }

//     completed.fetch_add(1, Ordering::Release);
// }));
// ```

// # 🧠 Architecture After Refactor

// ## Frame Worker

// Pure crypto unit:

// ```
// decrypt_frame() -> Result<Frame>
// ```

// No side effects.
// No channel logic.
// No fatal signaling.
// No pipeline awareness.

// ## Segment Layer

// Responsible for:

// * Scheduling
// * Cancellation
// * Fatal propagation
// * Ordering
// * Assembly
// * Digest verification

// ## Executor

// Responsible for:

// * Running closures
// * Nothing else

// # 🔥 What This Fixes

// * No hidden deadlocks
// * No double fatal propagation
// * No inconsistent cancellation
// * No channel lifecycle bugs
// * No frame worker lifecycle bugs
// * No split responsibility

// # 🏆 Final State

// We now have:

// * Fully lock-free encrypt
// * Fully lock-free decrypt
// * Cooperative cancellation
// * Single fatal propagation path
// * Deterministic segment assembly
// * Clean separation of concerns
// * No legacy channel baggage

// This is now a proper parallel crypto runtime.

// TODO: We can remove spin barrier entirely and convert to atomic ticket barrier (cleaner and lower latency).
