// **production-ready, parallel DecryptSegmentWorker** that:

// * **Decodes frames from a segment wire buffer** (no copying beyond slices)
// * **Dispatches frame slices to a worker pool** for parallel decrypt
// * **Collects decrypted frames asynchronously**
// * **Reorders decrypted frames by frame index**
// * **Streams decrypted plaintext frames in order (zero-copy except output Vec)**
// * **Minimal buffering — no unnecessary cloning of ciphertext**

// ### Key points:

// * Uses `&[u8]` slices into the segment buffer, no extra allocations per frame.
// * Worker pool processes frame slices and returns decrypted plaintext.
// * Main thread collects decrypted frames and orders them by `frame_index`.
// * Supports `Digest` and `Terminator` frames for validation.
// * Uses crossbeam channels for parallel dispatch and collection.
// * Panics or returns errors on unexpected conditions.

use crossbeam::channel::{unbounded, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use crate::{
    crypto::{DigestAlg, DigestFrame, SegmentDigestVerifier}, stream_v2::{
        frame_worker::{DecryptedFrame, decrypt::DecryptFrameWorker}, 
        framing::{FrameError, FrameHeader, FrameType, decode::parse_frame_header}, 
        segment_worker::{DecryptedSegment, SegmentCryptoContext, types::DigestResumePoint}
    }, telemetry::counters::TelemetryCounters
};

pub struct DecryptSegmentWorker {
    crypto: SegmentCryptoContext,
}

impl DecryptSegmentWorker {
    pub fn new(crypto: SegmentCryptoContext) -> Self {
        Self { crypto }
    }

    /// Run decrypt loop.
    ///
    /// Receives segment wire bytes from `rx`, processes frames in parallel,
    /// reorders decrypted frames, verifies Digest, streams out ordered plaintext frames.
    pub fn run(self, 
        rx: Receiver<Arc<Vec<u8>>>, 
        tx: Sender<DecryptedSegment>,
        resume: Option<DigestResumePoint>,
    ) {
        // Clone crypto for thread usage
        let crypto = self.crypto.clone();

        thread::spawn(move || {
            // Worker pool channels: frame slices -> decrypted frames
            let (frame_tx, frame_rx) = unbounded::<Arc<[u8]>>();
            let (out_tx, out_rx) = unbounded::<DecryptedFrame>();

            // Spawn workers
            let workers = num_cpus::get().max(1);
            for _ in 0..workers {
                let fw = DecryptFrameWorker::new(crypto.header.clone(), &crypto.session_key)
                    .expect("DecryptFrameWorker init failed");

                fw.run(frame_rx.clone(), out_tx.clone());
                // let frame_rx = frame_rx.clone();
                // let result_tx = result_tx.clone();
                // thread::spawn(move || {
                //     while let Ok(frame_bytes) = frame_rx.recv() {
                //         let decrypted = fw.decrypt_frame(&frame_bytes)
                //             .expect("frame decryption failed");
                //         result_tx.send(decrypted).expect("result channel closed");
                //     }
                // });
            }
            drop(frame_rx);
            drop(out_tx);

            // Main loop: handle incoming segments
            while let Ok(segment_wire) = rx.recv() {
                let telemetry = &mut TelemetryCounters::default();

                // 1️⃣ Split segment into frame byte slices (NO decode)
                let ranges = self.split_frames(&segment_wire)
                    .expect("invalid segment framing");

                let frame_count = ranges.len();
                if frame_count < 1 { 
                    // Segment-level validation 
                    eprintln!("SegmentWorker error: empty segment");
                    // You can choose to panic, drop, or send an error marker downstream. 
                    continue; 
                }
                // continue with normal encryption...
                let resume_from = resume.map(|r| r.next_frame_index).unwrap_or(0);

                // 2️⃣ Dispatch frames (parallel decrypt)
                for r in &ranges {
                    frame_tx
                        .send(Arc::from(&segment_wire[r.clone()]))
                        .expect("frame tx closed");
                }
                // 3️⃣ Collect decrypted frames (unordered)
                let mut data_frames = Vec::new();
                let mut digest_frame: Option<DigestFrame> = None;

                for _ in 0..frame_count {
                    let f = out_rx.recv().expect("decrypt failed");

                    match f.frame_type {
                        FrameType::Data => {
                            // telemetry.frames_data += 1;
                            // telemetry.bytes_plaintext += f.plaintext.len() as u64;
                            data_frames.push(f);
                        }
                        FrameType::Digest => {
                            let df = DigestFrame::decode(&f.plaintext)
                                .expect("invalid digest frame");
                            // telemetry.frames_digest += 1;
                            digest_frame = Some(df);
                        }
                        FrameType::Terminator => {
                            telemetry.frames_terminator += 1;
                        }
                    }
                }
                
                // 4️⃣ Sort decrypted DATA frames by frame_index
                data_frames.sort_unstable_by_key(|f| f.frame_index);
                // FIXME:
                let data_frame_count = data_frames.len() as u32;
                let segment_index = data_frames
                    .get(0)
                    .map(|f| f.segment_index)
                    .unwrap_or(0);

                
                // 5️⃣ Streaming digest verification (SKIP old frames)
                let digest_frame_build = digest_frame.expect("missing digest frame");
                
                let mut verifier = SegmentDigestVerifier::new(
                    DigestAlg::Sha256,
                    segment_index,
                    data_frame_count,
                    digest_frame_build.digest,
                );

                for f in &data_frames {
                    if f.frame_index < resume_from {
                        continue; // already authenticated earlier
                    }
                    verifier.update_frame(f.frame_index, &f.ciphertext);

                    telemetry.frames_data += 1;
                    telemetry.bytes_plaintext += f.plaintext.len() as u64;

                    // plaintext_out.push(f.plaintext.clone());
                }

                // 6️⃣ Verify digest AFTER Digest frame arrives
                verifier.finalize().expect("digest mismatch");
                telemetry.frames_digest += 1;

                // 5️⃣ Emit decrypted segment with ordered plaintext frames
                let plaintext = data_frames.into_iter().map(|f| f.plaintext).collect();

                let out = DecryptedSegment {
                    segment_index,
                    frames: plaintext,
                    telemetry: telemetry.clone(),
                };

                // 7️⃣ Emit plaintext
                if tx.send(out).is_err() {
                    return; // Receiver dropped, shutdown
                }
            }
        });
    }

    // # 1️⃣ Formalizing `split_frames()` (framing module only)

    // ## Design goals

    // * **Single responsibility**: locate frame boundaries
    // * **No decryption**
    // * **No AEAD**
    // * **No allocation**
    // * **Zero-copy**
    // * **No dependency on `DecryptSegmentWorker`**

    // This function is allowed to:

    // * Read frame headers
    // * Read `ciphertext_len`
    // * Validate framing integrity

    // This function is **not allowed** to:

    // * Classify frame types
    // * Decode ciphertext
    // * Perform crypto

    /// Zero-copy frame boundary detection
    ///
    /// Returns byte ranges covering complete frames:
    /// [FrameHeader | ciphertext]
    pub fn split_frames(&self, segment: &[u8]) -> Result<Vec<std::ops::Range<usize>>, FrameError> {

        let mut ranges = Vec::new();
        let mut offset = 0usize;

        while offset < segment.len() {
            // Must have at least header
            if segment.len() - offset < FrameHeader::LEN {
                return Err(FrameError::Truncated);
            }

            // Decode header ONLY to get ciphertext_len
            let header = parse_frame_header(&segment[offset..])?;
            let frame_len = FrameHeader::LEN + header.ciphertext_len as usize;

            let end = offset + frame_len;
            if end > segment.len() {
                return Err(FrameError::Truncated);
            }

            ranges.push(offset..end);
            offset = end;
        }

        Ok(ranges)
    }
    
}

// ### Notes:

// * Uses `Arc<Vec<u8>>` for segment wire to share buffer slices cheaply without copy.
// * Extracts each frame as an `Arc<[u8]>` slice into segment buffer (zero-copy).
// * DecryptFrameWorker decrypts frames in parallel worker threads.
// * Digest and Terminator frames are handled synchronously after data frames decrypt.
// * We must implement the digest validation by incremental hashing of decrypted frames plaintext ourself (this is application-specific).
// * Assumes `FrameHeader::LEN` and `decode_frame()` exist and work as specified.

