// # 📂 `src/stream_v2/segment_worker/decrypt.rs`

use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, bounded, unbounded};
use std::{thread, time::Instant};

use crate::{
    crypto::{DigestAlg, DigestFrame, SegmentDigestVerifier}, 
    stream_v2::{
        frame_worker::{DecryptedFrame, FrameWorkerError, decrypt::DecryptFrameWorker}, 
        framing::{FrameError, FrameHeader, FrameType, decode::parse_frame_header}, 
        segment_worker::{DecryptContext, DecryptedSegment, SegmentWorkerError, types::DecryptSegmentInput}, segmenting::{SegmentHeader, types::SegmentFlags}
    }, telemetry::{Stage, StageTimes, counters::TelemetryCounters}
};

pub struct DecryptSegmentWorker {
    crypto: DecryptContext,
    pub log_manager: std::sync::Arc<crate::recovery::persist::AsyncLogManager>,
}

impl DecryptSegmentWorker {
    pub fn new(
        crypto: crate::stream_v2::segment_worker::DecryptContext,
        log_manager: std::sync::Arc<crate::recovery::persist::AsyncLogManager>,
    ) -> Self {
        Self { crypto, log_manager }
    }

    /// Run decrypt loop.
    ///
    /// Receives segment wire bytes from `rx`, processes frames in parallel,
    /// reorders decrypted frames, verifies Digest, streams out ordered plaintext frames.
    pub fn run_v2(
        self,
        rx: Receiver<DecryptSegmentInput>,
        tx: Sender<Result<DecryptedSegment, SegmentWorkerError>>,
    ) {
        let crypto = self.crypto.clone();

        thread::spawn(move || {
            eprintln!("[WORKER] thread spawned");
            let worker_count = crypto.base.profile.cpu_workers();
            let digest_alg = crypto.base.digest_alg;

            // Frame worker pool channels
            let (frame_tx, frame_rx) = bounded::<Bytes>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<DecryptedFrame, FrameWorkerError>>();

            for _ in 0..worker_count {
                let fw = DecryptFrameWorker::new(crypto.header, &crypto.base.session_key)
                    .expect("DecryptFrameWorker pool init failed");
               
                fw.run(frame_rx.clone(), out_tx.clone());
            }
            drop(frame_rx);
            drop(out_tx);

            // Main loop: process encrypted segments
            while let Ok(segment) = rx.recv() {
                eprintln!("[WORKER] processing segment {}", segment.header.segment_index);
                // verify segment wire
                match segment.header.validate(&segment.wire) {
                    Ok(()) => {
                        let result = process_decrypt_segment_v2(
                            &segment,
                            &digest_alg,
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
                    Err(e) => {
                        if tx.send(Err(SegmentWorkerError::SegmentError(e))).is_err() {
                            eprintln!("[WORKER] tx send failed, receiver gone");
                            // Receiver dropped, exit cleanly
                            return;
                        }
                    }
                }
            }
            eprintln!("[WORKER] rx closed, dropping frame_tx and exiting");
            drop(frame_tx);
            drop(tx);
        });
    }

}

/// Process a single encrypted segment into plaintext
pub fn process_decrypt_segment_v2(
    input: &DecryptSegmentInput,
    digest_alg: &DigestAlg,
    frame_tx: &Sender<Bytes>,
    out_rx: &Receiver<Result<DecryptedFrame, FrameWorkerError>>,
) -> Result<DecryptedSegment, SegmentWorkerError> {
    let mut counters = TelemetryCounters::default();
    let mut stage_times = StageTimes::default();

    eprintln!("[DECRYPT] Entering process_decrypt_segment_v2 for segment {}", input.header.segment_index);

    // Validation
    let start = Instant::now();
    // ✅ Empty final segment case
    if input.wire.is_empty() && input.header.flags.contains(SegmentFlags::FINAL_SEGMENT) {
        eprintln!("[DECRYPT] Empty FINAL_SEGMENT detected at index {}", input.header.segment_index);
        return Ok(DecryptedSegment {
            header: input.header.clone(),
            bytes: Bytes::new(), // no plaintext frames
            counters,
            stage_times,
        });
    }
    // verify crc32 of segment wire
    input.header.validate(&input.wire).map_err(SegmentWorkerError::SegmentError)?;
    stage_times.add(Stage::Validate, start.elapsed());

    // One frame for each segment, the SegmentHeader
    counters.add_header(SegmentHeader::LEN);

    // 1️⃣ Locate frame boundaries (zero-copy)
    // Read / chunking
    let start = Instant::now();
    let mut offset = 0;
    let mut frame_count: usize = 0;
    while offset < input.wire.len() {
        eprintln!("[DECRYPT] Parsing frame headers from wire, len={}", input.wire.len());
        let header = parse_frame_header(&input.wire[offset..])?;
        let frame_len = FrameHeader::LEN + header.ciphertext_len as usize;
        let end = offset + frame_len;

        if end > input.wire.len() {
            eprintln!("[DECRYPT] Frame truncated at offset {}", offset);
            return Err(FrameError::Truncated.into());
        }

        eprintln!("[DECRYPT] Dispatching frame {} (segment {}, len={})",
                  frame_count, input.header.segment_index, frame_len);
        // 2️⃣ Dispatch all frames for parallel decryption
        // 🔥 O(1) slice
        frame_tx.send(input.wire.slice(offset..end))
            .map_err(|_| SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected))?;

        offset = end;
        frame_count += 1;

    }
    stage_times.add(Stage::Read, start.elapsed());

    if frame_count == 0 {
        eprintln!("[DECRYPT] No frames found in non-final segment {}", input.header.segment_index);
        return Err(SegmentWorkerError::InvalidSegment("Empty segment".into()));
    }

    // 3️⃣ Collect decrypted frames (unordered)
    let mut data_frames = Vec::with_capacity(frame_count.saturating_sub(2));
    let mut digest_frame: Option<DecryptedFrame> = None;
    let mut terminator_frame: Option<DecryptedFrame> = None;
    let mut received = 0;
    eprintln!("[DECRYPT] Collecting {} decrypted frames", frame_count);

    while received < frame_count {
        match out_rx.recv() {
            Ok(Ok(frame)) => {
                received += 1;
                eprintln!("[DECRYPT] Received frame type {:?}, index {}", frame.frame_type, frame.frame_index);
                // Decryption
                println!("{}", &frame.stage_times.summary());
                stage_times.merge(&frame.stage_times);

                match frame.frame_type {
                    FrameType::Data => data_frames.push(frame),
                    FrameType::Digest => {
                        if digest_frame.is_some() {
                            return Err(SegmentWorkerError::InvalidSegment("Multiple digest frames".into()));
                        }
                        digest_frame = Some(frame);
                    }
                    FrameType::Terminator => {
                        if terminator_frame.is_some() {
                            return Err(SegmentWorkerError::InvalidSegment("Multiple terminator frames".into()));
                        }
                        terminator_frame = Some(frame);
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("[DECRYPT] Frame worker error: {:?}", e);
                return Err(e.into());
            }
            Err(_) => {
                eprintln!("[DECRYPT] Frame worker channel disconnected");
                return Err(SegmentWorkerError::FrameWorkerError(FrameWorkerError::WorkerDisconnected));
            }
        }
    }

    // Validate frame counts, data_frames + digest_frame + terminator_frame
    if (data_frames.len() + 2) != frame_count as usize {
        eprintln!("[DECRYPT] Invalid frame count: data={} total={}", data_frames.len(), frame_count);
        return Err(SegmentWorkerError::InvalidSegment("Invalid number of frames received".into()));
    }

    // 4️⃣ Sort decrypted DATA frames by frame_index
    data_frames.sort_unstable_by_key(|f| f.frame_index);
    eprintln!("[DECRYPT] Sorted {} data frames", data_frames.len());

    let data_frame_count = data_frames.len() as u32;
    let segment_index = data_frames.first().map(|f| f.segment_index).unwrap_or(0);

    // 5️⃣ Authenticated digest Logic
    // Digesting
    let start = Instant::now();
    let digest_frame_data = digest_frame.ok_or(SegmentWorkerError::MissingDigestFrame)?;
    if digest_frame_data.frame_index != data_frame_count {
        eprintln!("[DECRYPT] Digest frame index mismatch: expected {}, got {}",
                  data_frame_count, digest_frame_data.frame_index);
        return Err(SegmentWorkerError::InvalidSegment("Invalid digest frame index".into()));
    }
    let digest_frame_payload = DigestFrame::decode(&digest_frame_data.plaintext)?;
    eprintln!("[DECRYPT] Digest frame decoded, verifying segment {}", segment_index);

    let mut verifier = SegmentDigestVerifier::new(
        digest_alg.clone(),
        segment_index,
        data_frame_count,
        digest_frame_payload.digest,
    );

    // 6️⃣ Update Verifier   
    for frame in &data_frames {
        // Calculate len of data overhead, the FrameHeader
        counters.bytes_overhead += FrameHeader::LEN as u64;
        // Calculate len of plaintext (may be compressed)
        counters.bytes_compressed += frame.plaintext.len() as u64;
        //
        verifier.update_frame(frame.frame_index, frame.ciphertext());
    }
    // Many frames for each segment data
    counters.frames_data = data_frame_count as u64;

    // 7️⃣ Cryptographic finalization
    verifier.finalize()?; // may fail if digest mismatch
    // One frame for each segment, the SegmentDigest of segment data
    counters.add_digest(digest_frame_data.plaintext.len());

    stage_times.add(Stage::Digest, start.elapsed());
    eprintln!("[DECRYPT] Digest verified for segment {}", segment_index);

    // 8️⃣ Terminator
    let start = Instant::now();
    let terminator_frame_data = terminator_frame.ok_or(SegmentWorkerError::MissingTerminatorFrame)?;
    if terminator_frame_data.frame_index != data_frame_count + 1 {
        eprintln!("[DECRYPT] Terminator frame index mismatch: expected {}, got {}",
                  data_frame_count + 1, terminator_frame_data.frame_index);
        return Err(SegmentWorkerError::InvalidSegment("Terminator frame should be the last frame of a segment".into()));
    }
    // One frame for each segment, the SegmentTerminator
    counters.add_terminator(terminator_frame_data.plaintext.len());

    eprintln!("[DECRYPT] Terminator frame validated for segment {}", segment_index);
    stage_times.add(Stage::Validate, start.elapsed());

    // 9️⃣ collect plaintext
    // Writing / wiring
    let start = Instant::now();
    let mut plaintext_out = Vec::with_capacity(data_frames.iter().map(|f| f.plaintext.len()).sum());

    for frame in data_frames {
        // Append frame plaintext into one contiguous buffer 
        plaintext_out.extend_from_slice(&frame.plaintext);
    }
    let bytes = Bytes::from(plaintext_out); // single Bytes
    let header = input.header;
    // We can compare the header.bytes_len against plaintext.len(), must be equal
    // header.bytes_len == plaintext.len() as u32
    stage_times.add(Stage::Write, start.elapsed());

    // 🔟 Return decrypted segment
    eprintln!("[DECRYPT] Returning decrypted segment {}", segment_index);
    Ok(DecryptedSegment {
        header,
        bytes, // single Bytes
        counters,
        stage_times,
    })
}
