// # 📂 `src/stream_v2/segment_worker/decrypt.rs`

use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, bounded, unbounded};
use std::thread;

use crate::{
    crypto::{DigestAlg, DigestFrame, SegmentDigestVerifier}, 
    stream_v2::{
        frame_worker::{DecryptedFrame, FrameWorkerError, decrypt::DecryptFrameWorker}, 
        framing::{FrameError, FrameHeader, FrameType, decode::parse_frame_header}, 
        segment_worker::{DecryptedSegment, SegmentCryptoContext, SegmentWorkerError, types::DecryptSegmentInput}, segmenting::types::SegmentFlags
    }, telemetry::counters::TelemetryCounters
};

pub struct DecryptSegmentWorker {
    crypto: SegmentCryptoContext,
    pub log_manager: std::sync::Arc<crate::recovery::persist::AsyncLogManager>,
}

impl DecryptSegmentWorker {
    pub fn new(
        crypto: crate::stream_v2::segment_worker::SegmentCryptoContext,
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
            let worker_count = crypto.worker_count;
            let digest_alg = crypto.digest_alg;

            // Frame worker pool channels
            let (frame_tx, frame_rx) = bounded::<Bytes>(worker_count * 4);
            let (out_tx, out_rx) = unbounded::<Result<DecryptedFrame, FrameWorkerError>>();

            for i in 0..worker_count {
                let fw = DecryptFrameWorker::new(crypto.header.clone(), &crypto.session_key)
                    .expect("DecryptFrameWorker pool init failed");
                eprintln!("[FRAME WORKER-{i}] starting");
                fw.run(frame_rx.clone(), out_tx.clone());
            }
            drop(frame_rx);
            drop(out_tx);

            // Main loop: process encrypted segments
            while let Ok(segment) = rx.recv() {
                eprintln!("[WORKER] processing segment {}", segment.header.segment_index);
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
            eprintln!("[WORKER] rx closed, dropping frame_tx and exiting");
            drop(frame_tx);
            drop(tx);
        });
    }

}

/// Process a single encrypted segment into plaintext
fn process_decrypt_segment_v2(
    input: &DecryptSegmentInput,
    digest_alg: &DigestAlg,
    frame_tx: &Sender<Bytes>,
    out_rx: &Receiver<Result<DecryptedFrame, FrameWorkerError>>,
) -> Result<DecryptedSegment, SegmentWorkerError> {
    let mut telemetry = TelemetryCounters::default();
    eprintln!("[DECRYPT] Entering process_decrypt_segment_v2 for segment {}", input.header.segment_index);

    // ✅ Empty final segment case
    if input.wire.is_empty() && input.header.flags.contains(SegmentFlags::FINAL_SEGMENT) {
        eprintln!("[DECRYPT] Empty FINAL_SEGMENT detected at index {}", input.header.segment_index);
        return Ok(DecryptedSegment {
            header: input.header.clone(),
            frames: Vec::new(), // no plaintext frames
            telemetry,
        });
    }

    // 1️⃣ Locate frame boundaries (zero-copy)
    let mut offset = 0;
    let mut frame_count: usize = 0;
    eprintln!("[DECRYPT] Parsing frame headers from wire, len={}", input.wire.len());

    while offset < input.wire.len() {
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
                eprintln!("[DECRYPT] Received frame type {:?}, index {}",
                          frame.frame_type, frame.frame_index);
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

    let digest_frame_data = digest_frame.ok_or(SegmentWorkerError::MissingDigestFrame)?;
    if digest_frame_data.frame_index != data_frame_count {
        eprintln!("[DECRYPT] Digest frame index mismatch: expected {}, got {}",
                  data_frame_count, digest_frame_data.frame_index);
        return Err(SegmentWorkerError::InvalidSegment("Invalid digest frame index".into()));
    }

    let digest_frame_payload = DigestFrame::decode(&digest_frame_data.plaintext)?;
    eprintln!("[DECRYPT] Digest frame decoded, verifying segment {}", segment_index);

    // 5️⃣ Authenticated digest Logic
    let mut verifier = SegmentDigestVerifier::new(
        digest_alg.clone(),
        segment_index,
        data_frame_count,
        digest_frame_payload.digest,
    );

    // 6️⃣ Update Verifier and collect plaintext
    let mut plaintext_out: Vec<Bytes> = Vec::with_capacity(data_frames.len());
   
    for frame in data_frames {
        // Always update telemetry
        telemetry.bytes_ciphertext += frame.ciphertext().len() as u64;
        telemetry.frames_data += 1;
        telemetry.bytes_plaintext += frame.plaintext.len() as u64;

        verifier.update_frame(frame.frame_index, frame.ciphertext());
        plaintext_out.push(frame.plaintext);
    }

    // 7️⃣ Cryptographic finalization
    verifier.finalize()?; // may fail if digest mismatch
    telemetry.frames_digest += 1;
    telemetry.bytes_overhead += digest_frame_data.plaintext.len() as u64;
    eprintln!("[DECRYPT] Digest verified for segment {}", segment_index);

    // 8️⃣ Terminator
    let terminator_frame_data = terminator_frame.ok_or(SegmentWorkerError::MissingTerminatorFrame)?;
    if terminator_frame_data.frame_index != data_frame_count + 1 {
        eprintln!("[DECRYPT] Terminator frame index mismatch: expected {}, got {}",
                  data_frame_count + 1, terminator_frame_data.frame_index);
        return Err(SegmentWorkerError::InvalidSegment("Terminator frame should be the last frame of a segment".into()));
    }
    telemetry.frames_terminator += 1;
    telemetry.bytes_overhead += terminator_frame_data.plaintext.len() as u64;
    eprintln!("[DECRYPT] Terminator frame validated for segment {}", segment_index);

    // 9️⃣ 
    // 🔟 Return decrypted segment
    eprintln!("[DECRYPT] Returning decrypted segment {}", segment_index);
    Ok(DecryptedSegment {
        header: input.header.clone(),
        frames: plaintext_out,
        telemetry,
    })
}
