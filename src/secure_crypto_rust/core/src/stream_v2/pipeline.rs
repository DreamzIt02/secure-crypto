// # 📂 src/stream_v2/pipeline.rs

// ## 📂 File: `src/stream_v2/pipeline.rs`
// ## Pure pipeline wiring (no crypto logic)

use std::io::{Read, Write};
use std::sync::{Arc};
use std::thread;

use bytes::Bytes;
use crossbeam::channel::{bounded};

use crate::stream_v2::{HybridParallelismProfile, io};
use crate::stream_v2::segment_worker::{
    DecryptSegmentInput, DecryptSegmentWorker, DecryptedSegment, EncryptSegmentInput, EncryptSegmentWorker, EncryptedSegment, SegmentCryptoContext, SegmentWorkerError
};
use crate::stream_v2::segmenting::types::SegmentFlags;
use crate::telemetry::{TelemetryCounters, TelemetrySnapshot, TelemetryTimer};
use crate::types::StreamError;
use crate::recovery::persist::AsyncLogManager;

// ============================================================
// Encrypt pipeline
// ============================================================
pub fn run_encrypt_pipeline<R, W>(
    mut reader: R,
    mut writer: W,
    crypto: SegmentCryptoContext,
    profile: HybridParallelismProfile,
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    let telemetry = TelemetryCounters::default();
    let telemetry_timer = TelemetryTimer::new();
    let mut segment_index = 0u64;
    eprintln!("[PIPELINE] Start encrypt pipeline");

    // ---- Write stream header ----
    eprintln!("[PIPELINE] Writing stream header");
    io::write_header(&mut writer, &crypto.header)?;
    eprintln!("[PIPELINE] Header written");

    // ---- Channels ----
    let (seg_tx, seg_rx) = bounded::<EncryptSegmentInput>(profile.inflight_segments);
    let (out_tx, out_rx) = bounded::<Result<EncryptedSegment, SegmentWorkerError>>(profile.inflight_segments);

    // ---- Reader thread (segmenter) ----
    let chunk_size = crypto.segment_size;

    thread::scope(|scope| {
        // ---- Reader thread ----
        scope.spawn(|| -> Result<(), StreamError> {
            loop {
                let buf = io::read_exact_or_eof(&mut reader, chunk_size)?;
                // At EOF, if we’ve already dispatched at least one segment, send a dummy empty segment with `FINAL_SEGMENT` set:
                if buf.is_empty() {
                    eprintln!("[READER] EOF reached, dispatching final empty segment {}", segment_index);
                    if segment_index > 0 {
                        seg_tx.send(EncryptSegmentInput {
                            segment_index,
                            plaintext: Bytes::new(),
                            compressed_len: 0,
                            flags: SegmentFlags::FINAL_SEGMENT,
                        }).map_err(|_| StreamError::PipelineError("encrypt segment channel closed".into()))?;
                    }
                    break;
                }
                eprintln!("[READER] Dispatching segment {}", segment_index);

                seg_tx.send(EncryptSegmentInput {
                    segment_index,
                    plaintext: buf,
                    compressed_len: 0,
                    flags: SegmentFlags::empty(),
                }).map_err(|_| StreamError::PipelineError("encrypt segment channel closed".into()))?;
                
                segment_index += 1;
            }

            eprintln!("[READER] Finished, dropping seg_tx");
            drop(seg_tx); // important: close input channel

            Ok(())
        });

        // ---- Workers ----
        for i in 0..profile.cpu_workers {
            let worker = EncryptSegmentWorker::new(crypto.clone(), log_manager.clone());
            let rx = seg_rx.clone();
            let tx = out_tx.clone();
            scope.spawn(move || {
                eprintln!("[WORKER-{i}] starting");
                worker.run_v2(rx, tx);
                eprintln!("[WORKER-{i}] finished");
            });
        }

        drop(out_tx);
        eprintln!("[PIPELINE] dropped out_tx in main thread");

        // ---- Ordered writer ----
        let mut ordered_writer = io::OrderedEncryptedWriter::new(&mut writer);
        
        for res in out_rx.iter() {
            eprintln!("[WRITER] receiving segment result");
            let encrypted = res.map_err(StreamError::SegmentWorker)?;
            eprintln!("[WRITER] received segment {}", encrypted.header.segment_index);
            ordered_writer.push(encrypted)?;
        }

        eprintln!("[WRITER] out_rx closed, finishing writer");
        ordered_writer.finish()?;

        Ok::<(), StreamError>(())
    })?;

    Ok(TelemetrySnapshot::from(&telemetry, &telemetry_timer, Some(segment_index + 1)))
}

// ============================================================
// Decrypt pipeline
// ============================================================
pub fn run_decrypt_pipeline<R, W>(
    mut reader: R,
    mut writer: W,
    crypto: SegmentCryptoContext,
    profile: HybridParallelismProfile,
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    let telemetry = TelemetryCounters::default();
    let telemetry_timer = TelemetryTimer::new();
    let mut last_segment_index = 0;

    eprintln!("[PIPELINE] Start decrypt pipeline");

    // ---- Read stream header ----
    eprintln!("[PIPELINE] Reading stream header");
    let header = io::read_header(&mut reader)?;
    if header != crypto.header {
        return Err(StreamError::Validation("Header mismatch detected".into()));
    }
    eprintln!("[PIPELINE] Header validated");

    // ---- Channels ----
    let (seg_tx, seg_rx) = bounded::<DecryptSegmentInput>(profile.inflight_segments);
    let (out_tx, out_rx) = bounded::<Result<DecryptedSegment, SegmentWorkerError>>(profile.inflight_segments);

    thread::scope(|scope| {
        // ---- Reader (segmenter) ----
        scope.spawn(|| -> Result<(), StreamError> {
            eprintln!("[READER] Thread started");
            while let Some((header, wire)) = io::read_segment(&mut reader)? {
                eprintln!("[READER] Dispatching segment {}", header.segment_index);
                seg_tx.send(DecryptSegmentInput { header, wire })
                    .map_err(|_| StreamError::PipelineError("decrypt segment channel closed".into()))?;
            }
            eprintln!("[READER] Finished, dropping seg_tx");
            drop(seg_tx);

            Ok(())
        });

        // ---- Workers ----
        for i in 0..profile.cpu_workers {
            let worker = DecryptSegmentWorker::new(crypto.clone(), log_manager.clone());
            let rx = seg_rx.clone();
            let tx = out_tx.clone();

            scope.spawn(move || {
                eprintln!("[WORKER-{i}] starting");
                worker.run_v2(rx, tx);
                eprintln!("[WORKER-{i}] finished");
            });
        }

        drop(out_tx);
        eprintln!("[PIPELINE] dropped out_tx in main thread");

        // ---- Ordered plaintext writer ----
        let mut ordered_writer = io::OrderedPlaintextWriter::new(&mut writer);

        for res in out_rx.iter() {
            let segment = res.map_err(StreamError::SegmentWorker)?;
            eprintln!("[WRITER] receiving segment {}", segment.header.segment_index);

            if segment.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && segment.frames.is_empty() {
                eprintln!("[WRITER] final empty segment {}", segment.header.segment_index);
                last_segment_index = segment.header.segment_index;
                
                // ✅ Push the final marker so OrderedPlaintextWriter sees it
            }

            ordered_writer.push(segment)?;
        }

        eprintln!("[WRITER] out_rx closed, finishing writer");
        ordered_writer.finish()?;

        Ok::<(), StreamError>(())
    })?;

    Ok(TelemetrySnapshot::from(&telemetry, &telemetry_timer, Some(last_segment_index + 1)))
}

