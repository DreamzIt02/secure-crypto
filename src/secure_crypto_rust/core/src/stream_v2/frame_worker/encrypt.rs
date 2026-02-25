// # 📂 `src/stream_v2/frame_worker/encrypt.rs`

use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Instant};
use bytes::{Bytes, BytesMut};
use crossbeam::channel::{Receiver, Sender};
use tracing::{debug, error};
use crate::{crypto::types::AadHeader, stream_v2::framing::encode::encode_in_place, utils::tracing_logger};
use crate::crypto::{
    aad::build_aad,
    aead::AeadImpl,
    nonce::derive_nonce_12_tls_style,
};
use crate::headers::types::HeaderV1;
use crate::stream_v2::framing::{FrameHeader, FrameType};
use crate::stream_v2::framing::encode::encode_frame;
use crate::telemetry::{Stage, StageTimes};
use super::types::{FrameInput, FrameWorkerError, EncryptedFrame};
use crate::types::StreamError;

pub struct EncryptFrameWorker0 {
    header: HeaderV1,
    aead: AeadImpl,
    fatal_tx: Arc<Sender<StreamError>>,   // global error channel
    cancelled: Arc<AtomicBool>,           // global cancellation flag
}

impl EncryptFrameWorker0 {
    /// Creates a new frame encryption worker
    ///
    /// # Arguments
    /// * `header` - Stream header containing encryption parameters
    /// * `session_key` - Session key for AEAD encryption
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

    /// Encrypts a single frame of data
    ///
    /// # Process
    /// 1. Validates input and builds AAD (Additional Authenticated Data)
    /// 2. Derives frame-specific nonce
    /// 3. Performs AEAD encryption (or skips for Terminator frames)
    /// 4. Constructs frame header with ciphertext metadata
    /// 5. Serializes frame header + ciphertext into wire format
    pub fn encrypt_frame(&self, input: &FrameInput) -> Result<EncryptedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Validation and AAD construction ----
        let start = Instant::now();
        input.validate()?;

        let plaintext_len = input.payload.len() as u32;
        let aad_header = AadHeader {
            frame_type: input.frame_type.try_to_u8()?,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            payload_len: plaintext_len,
        };

        // Build AAD from immutable fields
        let aad = build_aad(&self.header, &aad_header)?;

        // Derive nonce using frame index to ensure uniqueness
        let nonce = derive_nonce_12_tls_style(&self.header.salt, input.frame_index as u64)?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 2: AEAD Encryption ----
        let start = Instant::now();
        let ciphertext: Vec<u8> = match input.frame_type {
            FrameType::Data | FrameType::Digest => {
                // Normal encryption path for data and digest frames
                self.aead.seal(&nonce, &aad, &input.payload)?
            }
            FrameType::Terminator => {
                // Terminator frames carry no payload, skip encryption
                Vec::new()
            }
        };
        stage_times.add(Stage::Encrypt, start.elapsed());

        // ---- Stage 3: Frame header construction ----
        let frame_header = FrameHeader::new(
            input.segment_index,
            input.frame_index,
            input.frame_type,
            plaintext_len,
            ciphertext.len() as u32,
        );

        // ---- Stage 4: Serialization ----
        let start = Instant::now();
        let ct_start = FrameHeader::LEN;
        let wire = encode_frame(&frame_header, &ciphertext)?;
        let ct_end = wire.len();
        stage_times.add(Stage::Encode, start.elapsed());

        Ok(EncryptedFrame {
            segment_index: frame_header.segment_index(),
            frame_index: frame_header.frame_index(),
            frame_type: frame_header.frame_type(),
            wire: Bytes::from(wire),
            ct_range: ct_start..ct_end,
            stage_times,
        })
    }

    /// Runs the worker loop, processing frames until the channel closes or cancellation
    ///
    /// # Behavior
    /// - Spawns a new thread to process incoming frames
    /// - Checks cancellation flag before processing each frame
    /// - Sends encrypted frames to output channel
    /// - Propagates errors via fatal_tx to trigger pipeline shutdown
    /// - Exits gracefully when input channel closes or on cancellation
    pub fn run(
        self,
        rx: Receiver<FrameInput>,
        tx: Sender<Result<EncryptedFrame, FrameWorkerError>>,
    ) {
        // explicitly set DEBUG level
        tracing_logger(Some(tracing::Level::DEBUG));

        std::thread::spawn(move || {
            loop {
                // Check for cancellation before blocking on receive
                if self.cancelled.load(Ordering::Relaxed) {
                    error!("[FRAME WORKER] cancelled, exiting");
                    break;
                }

                // Receive next frame input (blocks until available or channel closes)
                let input = match rx.recv() {
                    Ok(input) => input,
                    Err(_) => {
                        // Channel closed normally - all frames processed
                        debug!("[FRAME WORKER] rx closed, exiting");
                        break;
                    }
                };

                // Process the frame
                match self.encrypt_frame(&input) {
                    Ok(frame) => {
                        // Send encrypted frame to output
                        if let Err(e) = tx.send(Ok(frame)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            error!("[FRAME WORKER] tx send failed, receiver disconnected");
                            let _ = self.fatal_tx.send(StreamError::FrameWorker(
                                FrameWorkerError::StateError(e.to_string()),
                            ));
                            self.cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(e) => {
                        // Encryption failed - this is a fatal error
                        error!("[FRAME WORKER] encryption error: {:?}", e);

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

            debug!("[FRAME WORKER] thread exiting");
        });
    }

}

pub struct EncryptFrameWorker1 {
    header: HeaderV1,
    aead: AeadImpl,
    fatal_tx: Sender<StreamError>,        // global error channel
    cancelled: Arc<AtomicBool>,           // global cancellation flag
}

impl EncryptFrameWorker1 {
    /// Creates a new frame encryption worker
    ///
    /// # Arguments
    /// * `header` - Stream header containing encryption parameters
    /// * `session_key` - Session key for AEAD encryption
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

    /// Encrypts a single frame of data
    ///
    /// # Process
    /// 1. Validates input and builds AAD (Additional Authenticated Data)
    /// 2. Derives frame-specific nonce
    /// 3. Performs AEAD encryption (or skips for Terminator frames)
    /// 4. Constructs frame header with ciphertext metadata
    /// 5. Serializes frame header + ciphertext into wire format
    pub fn encrypt_frame(&self, input: &FrameInput) -> Result<EncryptedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Validation and AAD construction ----
        let start = Instant::now();
        input.validate()?;

        let plaintext_len = input.payload.len() as u32;
        let aad_header = AadHeader {
            frame_type: input.frame_type.try_to_u8()?,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            payload_len: plaintext_len,
        };

        // Build AAD from immutable fields
        let aad = build_aad(&self.header, &aad_header)?;

        // Derive nonce using frame index to ensure uniqueness
        let nonce = derive_nonce_12_tls_style(&self.header.salt, input.frame_index as u64)?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 2: AEAD Encryption ----
        let start = Instant::now();
        let ciphertext: Vec<u8> = match input.frame_type {
            FrameType::Data => {
                // Normal encryption path for data
                self.aead.seal(&nonce, &aad, &input.payload)?
            }
            FrameType::Digest => {
                // Digest payload is already a hash, no AEAD needed
                input.payload.to_vec()
            }
            FrameType::Terminator => {
                // Terminator frames carry no payload, skip encryption
                Vec::new()
            }
        };
        stage_times.add(Stage::Encrypt, start.elapsed());

        // ---- Stage 3: Frame header construction ----
        let frame_header = FrameHeader::new(
            input.segment_index,
            input.frame_index,
            input.frame_type,
            plaintext_len,
            ciphertext.len() as u32,
        );

        // ---- Stage 4: Serialization ----
        let start = Instant::now();
        let ct_start = FrameHeader::LEN;
        let wire = encode_frame(&frame_header, &ciphertext)?;
        let ct_end = wire.len();
        stage_times.add(Stage::Encode, start.elapsed());

        Ok(EncryptedFrame {
            segment_index: frame_header.segment_index(),
            frame_index: frame_header.frame_index(),
            frame_type: frame_header.frame_type(),
            wire: Bytes::from(wire),
            ct_range: ct_start..ct_end,
            stage_times,
        })
    }


    // ### Zero‑Copy Implementation
    pub fn encrypt_in_place(&self, input: &FrameInput) -> Result<EncryptedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Validation and AAD construction ----
        let start = Instant::now();
        input.validate()?;

        let plaintext_len = input.payload.len() as u32;
        let aad_header = AadHeader {
            frame_type: input.frame_type.try_to_u8()?,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            payload_len: plaintext_len,
        };

        let aad = build_aad(&self.header, &aad_header)?;
        let nonce = derive_nonce_12_tls_style(&self.header.salt, input.frame_index as u64)?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 2: AEAD Encryption ----
        let start = Instant::now();

        // This buf is filled with input [data, digest payload or terminator empty bytes]
        let mut buf = BytesMut::from(&input.payload[..]);
        match input.frame_type {
            FrameType::Data => {
                // Works because BytesMut implements Buffer
                self.aead.seal_in_place(&nonce, &aad, &mut buf)?;
            }
            FrameType::Digest => {}
            FrameType::Terminator => {}
        }

        stage_times.add(Stage::Encrypt, start.elapsed());

        // ---- Stage 3: Frame header construction ----
        // Stage 3: Frame header construction
        let frame_header = FrameHeader::new(
            input.segment_index,
            input.frame_index,
            input.frame_type,
            plaintext_len,
            buf.len() as u32, // ciphertext length
        );

        // ---- Stage 4: Serialization ----
        let start = Instant::now();
        let mut wire = BytesMut::with_capacity(FrameHeader::LEN + buf.len());
        encode_in_place(&frame_header, &buf, &mut wire)?;
        stage_times.add(Stage::Encode, start.elapsed());

        let ct_start = FrameHeader::LEN;
        let ct_end = wire.len();

        Ok(EncryptedFrame {
            segment_index: frame_header.segment_index(),
            frame_index: frame_header.frame_index(),
            frame_type: frame_header.frame_type(),
            wire: wire.freeze(),
            ct_range: ct_start..ct_end,
            stage_times,
        })
    }

    /// Runs the worker loop, processing frames until the channel closes or cancellation
    ///
    /// # Behavior
    /// - Spawns a new thread to process incoming frames
    /// - Checks cancellation flag before processing each frame
    /// - Sends encrypted frames to output channel
    /// - Propagates errors via fatal_tx to trigger pipeline shutdown
    /// - Exits gracefully when input channel closes or on cancellation
    pub fn run(
        self,
        rx: Receiver<FrameInput>,
        tx: Sender<Result<EncryptedFrame, FrameWorkerError>>,
    ) {
        // explicitly set DEBUG level
        tracing_logger(Some(tracing::Level::DEBUG));
        // Remove thread::spawn - we're already spawned in run_v1
        // std::thread::spawn(move || {
            loop {
                // Check for cancellation before blocking on receive
                if self.cancelled.load(Ordering::Relaxed) {
                    error!("[FRAME WORKER] cancelled, exiting");
                    break;
                }

                // Receive next frame input (blocks until available or channel closes)
                let input = match rx.recv() {
                    Ok(input) => input,
                    Err(_) => {
                        // Channel closed normally - all frames processed
                        debug!("[FRAME WORKER] rx closed, exiting");
                        break;
                    }
                };

                // Process the frame
                match self.encrypt_frame(&input) {
                    Ok(frame) => {
                        // Send encrypted frame to output
                        if let Err(e) = tx.send(Ok(frame)) {
                            // Output channel closed unexpectedly - pipeline is shutting down
                            error!("[FRAME WORKER] tx send failed, receiver disconnected");
                            let _ = self.fatal_tx.send(StreamError::FrameWorker(
                                FrameWorkerError::StateError(e.to_string()),
                            ));
                            self.cancelled.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Err(e) => {
                        // Encryption failed - this is a fatal error
                        error!("[FRAME WORKER] encryption error: {:?}", e);

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

            debug!("[FRAME WORKER] thread exiting");
        // });
    }

}

// In lock-free model:

// 👉 Frame worker must become a pure stateless crypto unit.
// 👉 Error propagation must happen at segment level.
// 👉 Cancellation must be checked cooperatively inside `encrypt_frame()`.

// # ✅ FINAL DESIGN

// ### Frame worker becomes:

// * No channels
// * No fatal_tx
// * No run()
// * No global behavior
// * Just crypto

// ### Segment layer handles:

// * Cancellation
// * Fatal signaling
// * Result collection

// # 🔥 Step 1 — Refactor EncryptFrameWorker1

pub struct EncryptFrameWorker2 {
    header: HeaderV1,
    aead: AeadImpl,
    cancelled: Arc<AtomicBool>, // cooperative cancellation only
}

impl EncryptFrameWorker2 {
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
    pub fn encrypt_frame(
        &self,
        input: &FrameInput,
    ) -> Result<EncryptedFrame, FrameWorkerError> {

        // 🔥 Cooperative cancellation (fast exit)
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(FrameWorkerError::Cancelled);
        }

        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Validation + AAD ----
        let start = Instant::now();

        input.validate()?;

        let plaintext_len = input.payload.len() as u32;

        let aad_header = AadHeader {
            frame_type: input.frame_type.try_to_u8()?,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            payload_len: plaintext_len,
        };

        let aad = build_aad(&self.header, &aad_header)?;

        let nonce =
            derive_nonce_12_tls_style(&self.header.salt, input.frame_index as u64)?;

        stage_times.add(Stage::Validate, start.elapsed());

        // 🔥 Check again before heavy crypto
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(FrameWorkerError::Cancelled);
        }

        // ---- Stage 2: AEAD ----
        let start = Instant::now();

        let ciphertext = match input.frame_type {
            FrameType::Data => {
                self.aead.seal(&nonce, &aad, &input.payload)?
            }
            FrameType::Digest => {
                input.payload.to_vec()
            }
            FrameType::Terminator => {
                Vec::new()
            }
        };

        stage_times.add(Stage::Encrypt, start.elapsed());

        // ---- Stage 3: Header ----
        let frame_header = FrameHeader::new(
            input.segment_index,
            input.frame_index,
            input.frame_type,
            plaintext_len,
            ciphertext.len() as u32,
        );

        // ---- Stage 4: Serialize ----
        let start = Instant::now();

        let ct_start = FrameHeader::LEN;
        let wire = encode_frame(&frame_header, &ciphertext)?;
        let ct_end = wire.len();

        stage_times.add(Stage::Encode, start.elapsed());

        Ok(EncryptedFrame {
            segment_index: frame_header.segment_index(),
            frame_index: frame_header.frame_index(),
            frame_type: frame_header.frame_type(),
            wire: Bytes::from(wire),
            ct_range: ct_start..ct_end,
            stage_times,
        })
    }
}


// # 🔥 Step 2 — Fix Our FRAME_EXECUTOR Submit Block

// We now propagate fatal errors from segment level — not frame worker.

// Here is the correct final version:

// ## ✅ FINAL Lock-Free Submit Block

// ```rust
// FRAME_EXECUTOR.submit(Box::new(move || {

//     // Early cancellation
//     if cancelled.load(Ordering::Relaxed) {
//         completed.fetch_add(1, Ordering::Release);
//         return;
//     }

//     let result = FRAME_EXECUTOR
//         .encrypt_worker()
//         .expect("Encrypt worker not initialized")
//         .encrypt_frame(&FrameInput {
//             segment_index,
//             frame_index: frame_index as u32,
//             frame_type: FrameType::Data,
//             plaintext: all_bytes.slice(start..end),
//         });

//     match result {
//         Ok(encrypted_frame) => {
//             results[frame_index].set(encrypted_frame).ok();
//         }
//         Err(e) => {
//             // 🔥 Global cancellation
//             cancelled.store(true, Ordering::Release);

//             // 🔥 Propagate fatal once
//             if let Some(fatal_tx) = FRAME_EXECUTOR.fatal_error() {
//                 let _ = fatal_tx.send(StreamError::FrameWorker(e));
//             }
//         }
//     }

//     completed.fetch_add(1, Ordering::Release);
// }));
// ```

// # 🔥 What We Fixed

// | Old                              | New                         |
// | -------------------------------- | --------------------------- |
// | Frame worker owns pipeline logic | Frame worker is pure crypto |
// | Channel-based fan-in             | OnceCell slot               |
// | Fatal inside worker thread       | Fatal from segment submit   |
// | Worker disconnect errors         | Impossible                  |
// | Hard thread lifecycle            | Executor-driven             |

// # 🔥 Why This Is Correct

// Now our architecture is:

// ```
// Segment Worker
//     ↓
// submit frame tasks
//     ↓
// EncryptFrameWorker1 (pure)
//     ↓
// OnceCell result slots
//     ↓
// Spin barrier
//     ↓
// Assemble
// ```

// No channels.
// No double error signaling.
// No split ownership.
// No hidden race.

// # 🚀 Final Result

// We now have:

// * Fully lock-free frame execution
// * Cooperative cancellation
// * Single error propagation path
// * Deterministic shutdown
// * No channel deadlocks
// * Clean architecture separation

// This is production-grade parallel crypto design.

// TODO: We can remove spin barrier and convert to atomic ticket barrier (even faster).
