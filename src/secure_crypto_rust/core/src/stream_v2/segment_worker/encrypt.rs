// # 📂 `src/stream_v2/segment_worker/encrypt.rs`

use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, bounded, unbounded};

use crate::{
    crypto::{DigestAlg, DigestFrame, SegmentDigestBuilder}, 
    stream_v2::{
        frame_worker::{EncryptedFrame, FrameInput, FrameWorkerError, encrypt::EncryptFrameWorker},
        framing::types::FrameType, segment_worker::SegmentWorkerError, segmenting::{SegmentHeader, types::SegmentFlags},
    }, telemetry::counters::TelemetryCounters
};
use super::types::{EncryptSegmentInput, EncryptedSegment};

pub struct EncryptSegmentWorker {
    pub crypto: crate::stream_v2::segment_worker::SegmentCryptoContext,
    // Production requirement: Access to the background logger
    pub log_manager: std::sync::Arc<crate::recovery::persist::AsyncLogManager>,
}

impl EncryptSegmentWorker {
    pub fn new(
        crypto: crate::stream_v2::segment_worker::SegmentCryptoContext,
        log_manager: std::sync::Arc<crate::recovery::persist::AsyncLogManager>,
    ) -> Self {
        Self { crypto, log_manager }
    }

    /// Run loop: consumes plaintext segments, emits encrypted segments.
    ///
    /// Segment layout:
    /// [ Data frames (parallel) ]
    /// [ Digest frame ]
    /// [ Terminator frame ]
    /// Run encryption loop - processes plaintext segments and outputs encrypted segments
    pub fn run_v2(
        self,
        rx: Receiver<EncryptSegmentInput>,
        tx: Sender<Result<EncryptedSegment, SegmentWorkerError>>,
    ) {
        let crypto = self.crypto.clone();

        std::thread::spawn(move || {
            // Spawn frame workers
            let worker_count = crypto.worker_count;
            let digest_alg = crypto.digest_alg;
            let frame_size = crypto.frame_size;

            let (frame_tx, frame_rx) = bounded::<FrameInput>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<EncryptedFrame, FrameWorkerError>>();

            for _ in 0..worker_count {
                let fw = EncryptFrameWorker::new(crypto.header.clone(), &crypto.session_key)
                    .expect("EncryptFrameWorker pool init failed");
                fw.run(frame_rx.clone(), out_tx.clone());
            }
            drop(frame_rx);
            drop(out_tx);

            while let Ok(segment) = rx.recv() {
                eprintln!("[WORKER] processing segment {}", segment.segment_index);
                let result = process_encrypt_segment_2(
                    &segment,
                    frame_size,
                    digest_alg,
                    &frame_tx,
                    &out_rx,
                );

                // Send result (Ok or Err) - let caller decide how to handle errors
                if tx.send(result).is_err() {
                    eprintln!("[WORKER] tx send failed, receiver gone");
                    // Receiver dropped, exit cleanly
                    return;
                }
            }
            eprintln!("[WORKER] rx closed, exiting loop");
            drop(frame_tx);
            drop(tx); // critical: close output channel
            eprintln!("[WORKER] dropped tx, worker exiting");
        });
    }
}

/// Process a single plaintext segment into encrypted wire format
fn process_encrypt_segment_2(
    input: &EncryptSegmentInput,
    frame_size: usize,
    digest_alg: DigestAlg,
    frame_tx: &Sender<FrameInput>,
    out_rx: &Receiver<Result<EncryptedFrame, FrameWorkerError>>,
    ) -> Result<EncryptedSegment, SegmentWorkerError> {
    let mut telemetry = TelemetryCounters::default();
    
    // ✅ Empty final segment case
    if input.plaintext.is_empty() && input.flags.contains(SegmentFlags::FINAL_SEGMENT) {
        let header = SegmentHeader::new(
            &Bytes::new(),
            input.segment_index,
            input.compressed_len,
            0, // no frames
            digest_alg as u16,
            input.flags,
        );
        return Ok(EncryptedSegment {
            header,
            wire: Bytes::new(),
            telemetry,
        });
    }

    // 1️⃣ Split plaintext into frame-sized chunks
    let frame_count: usize = (input.plaintext.len() + frame_size - 1) / frame_size;
    if frame_count == 0 {
        return Err(SegmentWorkerError::InvalidSegment("Empty segment".into()));
    }

    // 2️⃣ Initialize digest calculator
    let mut digest_builder = SegmentDigestBuilder::new(digest_alg, input.segment_index, frame_count as u32);

    // 3️⃣ Dispatch plaintext frames for parallel encryption
    // 🔥 zero-copy slicing
    for (frame_index, chunk) in input.plaintext.chunks(frame_size).enumerate() {
        frame_tx.send(FrameInput {
            segment_index: input.segment_index,
            frame_index: frame_index as u32,
            frame_type: FrameType::Data,
            plaintext: Bytes::copy_from_slice(chunk), // unavoidable copy ONCE
        })
        .map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;
        
        // Always update telemetry
        telemetry.bytes_plaintext += chunk.len() as u64;
    }

    // 4️⃣ Collect encrypted frames (unordered) and update digest
    let mut data_frames = Vec::with_capacity(frame_count.saturating_sub(2));
    let mut data_wire_len = 0;
    let mut received = 0;
    
    while received < frame_count {
        match out_rx.recv() {
            Ok(Ok(frame)) => {
                received += 1;
                data_frames.push(frame);
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected)),
        }
    }

    // data_frames
    if data_frames.len() != frame_count as usize {
        return Err(SegmentWorkerError::InvalidSegment("Invalid number of frames received".into()));
    }

    // 5️⃣ Sort frames by index
    data_frames.sort_unstable_by_key(|f| f.frame_index);

    // Phase 1: digest only (cheap loop)
    for frame in &data_frames {
        data_wire_len += frame.wire.len();

        // Always update telemetry
        telemetry.frames_data += 1;
        telemetry.bytes_ciphertext += frame.ciphertext().len() as u64;

        digest_builder.update_frame(frame.frame_index, frame.ciphertext());
    }

    // 6️⃣ Finalize digest and create digest frame
    let digest = digest_builder.finalize();
    let digest_payload = Bytes::from(DigestFrame::new(digest_alg, digest).encode());

    frame_tx.send(FrameInput {
        segment_index: input.segment_index,
        frame_index: frame_count as u32, // Digest frame comes after all data frames
        frame_type: FrameType::Digest,
        plaintext: digest_payload,
    })
        .map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;

    let digest_frame_result = out_rx.recv()
        .map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;
    let digest_frame = digest_frame_result?;
    
    telemetry.frames_digest += 1;
    telemetry.bytes_overhead += digest_frame.ciphertext().len() as u64;

    // 6️⃣ Terminator frame
    frame_tx.send(FrameInput {
        segment_index: input.segment_index,
        frame_index: frame_count as u32 + 1, // terminator frame comes after data_frames + digest_frame
        frame_type: FrameType::Terminator,
        plaintext: Bytes::new(),
    })
        .map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;
    
    let terminator_frame_result = out_rx.recv()
        .map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;
    let terminator_frame = terminator_frame_result?;

    telemetry.frames_terminator += 1;
    telemetry.bytes_overhead += terminator_frame.ciphertext().len() as u64;

    // 7️⃣ Serialize frames to wire format
    // 🔥 Build final wire once
    let total_len = data_wire_len + digest_frame.wire.len() + terminator_frame.wire.len();
    let mut wire_bytes = Vec::with_capacity(total_len);

    for frame in data_frames {
        wire_bytes.extend_from_slice(&frame.wire);
    }
    wire_bytes.extend_from_slice(&digest_frame.wire);
    wire_bytes.extend_from_slice(&terminator_frame.wire);

    let wire = Bytes::from(wire_bytes);
    let header = SegmentHeader::new(
        &wire,
        input.segment_index,
        input.compressed_len, // Calculate in caller after compress, before sending to the worker
        frame_count as u32,
        digest_alg as u16,
        input.flags,
    );

    Ok(EncryptedSegment {
        header,
        wire: wire,
        telemetry: telemetry,
    })
}
