use std::{sync::{Arc, Mutex}, time::Instant};
use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender};

use crate::{stream_v2::{
    compression_worker::{CodecInfo, CompressionBackend, CpuCompressionBackend, GpuCompressionBackend, types::CompressionWorkerError}, 
    parallelism::{Scheduler, WorkerTarget}, segment_worker::{DecryptedSegment, EncryptSegmentInput}, 
    segmenting::types::SegmentFlags
}, telemetry::{Stage, StageTimes}};

/// Factory: choose backend based on codec + target
pub fn make_backend(target: WorkerTarget, codec_info: CodecInfo) -> Box<dyn CompressionBackend> {
    match target {
        WorkerTarget::Cpu(_) => {
            let backend = CpuCompressionBackend::new(codec_info)
                .expect("failed to create CPU compressor/decompressor");
            Box::new(backend)
        }
        WorkerTarget::Gpu(_) => {
            let backend = GpuCompressionBackend::new(codec_info)
                .expect("failed to create GPU compressor/decompressor");
            Box::new(backend)
        }
    }
}


/// Single compression worker loop
pub fn run_compression_worker(
    rx: Receiver<EncryptSegmentInput>,
    tx: Sender<Result<EncryptSegmentInput, CompressionWorkerError>>,
    mut backend: Box<dyn super::CompressionBackend>,
    scheduler: Arc<Mutex<Scheduler>>,
) {

    while let Ok(mut seg) = rx.recv() {
        let mut stage_times = StageTimes::default();
        // Compression / segment
        let start = Instant::now();

        let target = {
            let mut sched = scheduler.lock().unwrap();
            sched.dispatch(seg.bytes.len())
        };

        // ✅ Catch final empty segment before compression
        if seg.flags.contains(SegmentFlags::FINAL_SEGMENT) && seg.bytes.is_empty() {
            eprintln!("[COMPRESSION] final empty segment {} bypassed", seg.segment_index);
            stage_times.add(Stage::Compress, start.elapsed());
            seg.stage_times = stage_times;

            let _ = tx.send(Ok(seg));
            let mut sched = scheduler.lock().unwrap();
            sched.complete(target);
            continue;
        }

        match backend.compress_chunk(&seg.bytes) {
            Ok(buf) => {
                seg.bytes = Bytes::from(buf);
                stage_times.add(Stage::Compress, start.elapsed());
                seg.stage_times = stage_times;

                let _ = tx.send(Ok(seg));
            }
            Err(e) => {
                eprintln!("[COMPRESSION] failed: {e}");
                let _ = tx.send(Err(CompressionWorkerError::Compression(e)));
                break; // exit on error so pipeline can terminate
            }
        }

        let mut sched = scheduler.lock().unwrap();
        sched.complete(target);
    }
}

/// Single decompression worker loop
pub fn run_decompression_worker(
    rx: Receiver<DecryptedSegment>,
    tx: Sender<Result<DecryptedSegment, CompressionWorkerError>>,
    mut backend: Box<dyn super::CompressionBackend>,
    scheduler: Arc<Mutex<Scheduler>>,
) {
    while let Ok(mut seg) = rx.recv() {
        let mut stage_times = StageTimes::default();
        // Decompression / segment
        let start = Instant::now();

        let target = {
            let mut sched = scheduler.lock().unwrap();
            sched.dispatch(seg.bytes.len())
        };

        // ✅ Catch final empty segment before decompression
        if seg.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && seg.bytes.is_empty() {
            eprintln!("[DECOMPRESSION] final empty segment {} bypassed", seg.header.segment_index);
            stage_times.add(Stage::Decompress, start.elapsed());
            seg.stage_times = stage_times;

            let _ = tx.send(Ok(seg));
            let mut sched = scheduler.lock().unwrap();
            sched.complete(target);
            continue;
        }
        
        match backend.decompress_chunk(&seg.bytes) {
            Ok(buf) => {
                seg.bytes = Bytes::from(buf);
                stage_times.add(Stage::Decompress, start.elapsed());
                seg.stage_times = stage_times;

                let _ = tx.send(Ok(seg));
            }
            Err(e) => {
                eprintln!("[DECOMPRESSION] failed: {e}");
                let _ = tx.send(Err(CompressionWorkerError::Compression(e)));
                break; // exit on error so pipeline can terminate
            }
        }

        let mut sched = scheduler.lock().unwrap();
        sched.complete(target);
    }
}
