// # 📂 `src/stream_v2/segment_worker/encrypt.rs`

use std::time::Instant;
use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, bounded, unbounded};

use crate::{
    crypto::{DigestAlg, DigestFrame, SegmentDigestBuilder}, 
    stream_v2::{
        frame_worker::{EncryptedFrame, FrameInput, FrameWorkerError, encrypt::EncryptFrameWorker},
        framing::{FrameHeader, types::FrameType}, segment_worker::SegmentWorkerError, segmenting::{SegmentHeader, types::SegmentFlags},
    }, telemetry::{Stage, StageTimes, counters::TelemetryCounters}
};
use super::types::{EncryptSegmentInput, EncryptedSegment};

pub struct EncryptSegmentWorker {
    pub crypto: crate::stream_v2::segment_worker::EncryptContext,
    // Production requirement: Access to the background logger
    pub log_manager: std::sync::Arc<crate::recovery::persist::AsyncLogManager>,
}

impl EncryptSegmentWorker {
    pub fn new(
        crypto: crate::stream_v2::segment_worker::EncryptContext,
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
            let worker_count = crypto.base.profile.cpu_workers();
            let digest_alg = crypto.base.digest_alg;
            let frame_size = crypto.base.frame_size;

            let (frame_tx, frame_rx) = bounded::<FrameInput>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<EncryptedFrame, FrameWorkerError>>();

            for _ in 0..worker_count {
                let fw = EncryptFrameWorker::new(crypto.header.clone(), &crypto.base.session_key)
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
pub fn process_encrypt_segment_2(
    input: &EncryptSegmentInput,
    frame_size: usize,
    digest_alg: DigestAlg,
    frame_tx: &Sender<FrameInput>,
    out_rx: &Receiver<Result<EncryptedFrame, FrameWorkerError>>,
) -> Result<EncryptedSegment, SegmentWorkerError> {
    let mut counters = TelemetryCounters::default();
    let mut stage_times = StageTimes::default();

    eprintln!("[ENCRYPT] Entering process_encrypt_segment_v2 for segment {}", input.segment_index);

    // Validation
    let start = Instant::now();
    // ✅ Empty final segment case
    if input.bytes.is_empty() && input.flags.contains(SegmentFlags::FINAL_SEGMENT) {
        eprintln!("[ENCRYPT] Empty FINAL_SEGMENT detected at index {}", input.segment_index);
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
    // Consider one frame for each segment, the SegmentHeader
    counters.add_header(SegmentHeader::LEN);

    // 1️⃣ Split plaintext into frame-sized chunks
    let bytes_len: usize = input.bytes.len();
    let frame_count: usize = (bytes_len + frame_size - 1) / frame_size;
    if frame_count == 0 {
        return Err(SegmentWorkerError::InvalidSegment("Empty segment".into()));
    }
    stage_times.add(Stage::Validate, start.elapsed());

    // 2️⃣ Dispatch plaintext frames for parallel encryption
    // Read / chunking
    let start_encrypt = Instant::now();
    for (frame_index, chunk) in input.bytes.chunks(frame_size).enumerate() {
        eprintln!("[ENCRYPT] Chunking frames from bytes, len={}", input.bytes.len());
        frame_tx.send(FrameInput {
            segment_index: input.segment_index,
            frame_index: frame_index as u32,
            frame_type: FrameType::Data,
            plaintext: Bytes::copy_from_slice(chunk),
        })
        .map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;
    }
    stage_times.add(Stage::Read, start_encrypt.elapsed());

    // 3️⃣ Collect encrypted frames
    let mut data_frames = Vec::with_capacity(frame_count);
    let mut data_wire_len = 0;
    let mut received = 0;
    eprintln!("[ENCRYPT] Collecting {} encrypted frames", frame_count);

    while received < frame_count {
        match out_rx.recv() {
            Ok(Ok(frame)) => {
                received += 1;
                eprintln!("[ENCRYPT] Received frame type {:?}, index {}", frame.frame_type, frame.frame_index);
                // Encryption
                println!("{}", &frame.stage_times.summary());
                stage_times.merge(&frame.stage_times);

                data_frames.push(frame);
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected)),
        }
    }
    if data_frames.len() != frame_count {
        return Err(SegmentWorkerError::InvalidSegment("Invalid number of frames received".into()));
    }
    data_frames.sort_unstable_by_key(|f| f.frame_index);
    eprintln!("[ENCRYPT] Sorted {} data frames", data_frames.len());

    // 4️⃣ Initialize digest calculator
    // Digesting
    let start = Instant::now();
    let mut digest_builder = SegmentDigestBuilder::new(digest_alg, input.segment_index, frame_count as u32);

    for frame in &data_frames {
        data_wire_len += frame.wire.len();

        // Calculate len of data overhead, the FrameHeader
        counters.bytes_overhead += FrameHeader::LEN as u64;
        // Calculate len of ciphertext
        counters.bytes_ciphertext += frame.ciphertext().len() as u64;

        digest_builder.update_frame(frame.frame_index, frame.ciphertext());
    }
    // Many frames for each segment data
    counters.frames_data = frame_count as u64;

    // 5️⃣ Digest frame
    let digest = digest_builder.finalize();
    let digest_payload = Bytes::from(DigestFrame::new(digest_alg, digest).encode());
    frame_tx.send(FrameInput {
        segment_index: input.segment_index,
        frame_index: frame_count as u32,
        frame_type: FrameType::Digest,
        plaintext: digest_payload,
    }).map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;
    
    let digest_frame_result = out_rx.recv()
        .map_err(|e| SegmentWorkerError::StateError(e.to_string()))?;
    let digest_frame = digest_frame_result?;
    eprintln!("[ENCRYPT] Digest frame encoded, for segment {}", input.segment_index);
    
    counters.add_digest(digest_frame.ciphertext().len());
    stage_times.add(Stage::Digest, start.elapsed());

    // 6️⃣ Terminator frame
    // Finalizing
    let start = Instant::now();
    frame_tx.send(FrameInput {
        segment_index: input.segment_index,
        frame_index: frame_count as u32 + 1,
        frame_type: FrameType::Terminator,
        plaintext: Bytes::new(),
    }).map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;
    
    let terminator_frame_result = out_rx.recv()
        .map_err(|e| SegmentWorkerError::StateError(e.to_string()))?;
    let terminator_frame = terminator_frame_result?;

    eprintln!("[ENCRYPT] Terminator frame encoded for segment {}", input.segment_index);
    counters.add_terminator(terminator_frame.ciphertext().len());
    stage_times.add(Stage::Validate, start.elapsed());

    // 7️⃣ Serialize frames
    // Writing / wiring
    let start = Instant::now();
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
        bytes_len as u32,
        frame_count as u32,
        digest_alg as u16,
        input.flags,
    );
    stage_times.add(Stage::Write, start.elapsed());

    eprintln!("[ENCRYPT] Returning encrypted segment {}", input.segment_index);
    Ok(EncryptedSegment {
        header,
        wire,
        counters,
        stage_times,
    })
}
