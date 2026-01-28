use std::sync::{Arc, Mutex};
use crossbeam::channel::{Receiver, Sender};

use crate::stream_v2::{ 
    compression_worker::{CodecInfo, CompressionWorkerError, make_backend, run_compression_worker, run_decompression_worker},
    parallelism::{HybridParallelismProfile, Scheduler, WorkerTarget}, 
    segment_worker::{DecryptedSegment, EncryptSegmentInput}
};

pub fn spawn_compression_workers(
    profile: HybridParallelismProfile,
    codec_info: CodecInfo,
    comp_rx: Receiver<EncryptSegmentInput>,
    out_tx: Sender<Result<EncryptSegmentInput, CompressionWorkerError>>,
) {
    let scheduler = Arc::new(Mutex::new(Scheduler::new(
        profile.cpu_workers(),
        profile.gpu_workers(),
        profile.gpu_threshold(),
    )));

    // spawn CPU workers
    for i in 0..profile.cpu_workers() {
        let backend = make_backend(WorkerTarget::Cpu(i), codec_info.clone());
        let sched = scheduler.clone();
        let rx = comp_rx.clone();
        let tx = out_tx.clone();
        std::thread::spawn(move || run_compression_worker(rx, tx, backend, sched));
    }

    // spawn GPU workers
    for i in 0..profile.gpu_workers() {
        let backend = make_backend(WorkerTarget::Gpu(i), codec_info.clone());
        let sched = scheduler.clone();
        let rx = comp_rx.clone();
        let tx = out_tx.clone();
        std::thread::spawn(move || run_compression_worker(rx, tx, backend, sched));
    }
}

/// Decompression worker entry point
pub fn spawn_decompression_workers(
    profile: HybridParallelismProfile,
    codec_info: CodecInfo,
    decomp_rx: Receiver<DecryptedSegment>,
    out_tx: Sender<Result<DecryptedSegment, CompressionWorkerError>>,
) {
    let scheduler = Arc::new(Mutex::new(Scheduler::new(
        profile.cpu_workers(),
        profile.gpu_workers(),
        profile.gpu_threshold(),
    )));

    // spawn CPU workers
    for i in 0..profile.cpu_workers() {
        let backend = make_backend(WorkerTarget::Cpu(i), codec_info.clone());
        let sched = scheduler.clone();
        let rx = decomp_rx.clone();
        let tx = out_tx.clone();
        std::thread::spawn(move || run_decompression_worker(rx, tx, backend, sched));
    }

    // spawn GPU workers
    for i in 0..profile.gpu_workers() {
        let backend = make_backend(WorkerTarget::Gpu(i), codec_info.clone());
        let sched = scheduler.clone();
        let rx = decomp_rx.clone();
        let tx = out_tx.clone();
        std::thread::spawn(move || run_decompression_worker(rx, tx, backend, sched));
    }
}
