#[cfg(test)]
mod gpu_worker_tests {
    use std::sync::{Arc, Mutex};
    use bytes::Bytes;
    use crossbeam::channel;

    use crypto_core::{compression::{CodecLevel, codec_ids}, 
        stream_v2::{
            compression_worker::{CodecInfo, GpuCompressionBackend, run_compression_worker}, 
            parallelism::Scheduler, segment_worker::EncryptSegmentInput, segmenting::types::SegmentFlags
        }, telemetry::StageTimes
    };

    #[test]
    fn gpu_worker_handles_large_segment() {
        let codec_info = CodecInfo {
            codec_id: codec_ids::AUTO,
            level: CodecLevel::Custom(0),
            dict: None,
            gpu: None,
        };

        let backend = GpuCompressionBackend::new(codec_info).expect("gpu backend init");
        let (tx_in, rx_in) = channel::unbounded();
        let (tx_out, rx_out) = channel::unbounded();

        let scheduler = Arc::new(Mutex::new(Scheduler::new(0, 1, 4 * 1024 * 1024)));

        // spawn worker
        let sched_clone = scheduler.clone();
        std::thread::spawn(move || run_compression_worker(rx_in, tx_out, Box::new(backend), sched_clone));

        // send a large segment (>= 4 MB)
        let big_buf = vec![42u8; 32 * 1024 * 1024]; // 5 MB
        let seg = EncryptSegmentInput {
            segment_index: 0,
            bytes: Bytes::from(big_buf),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        };
        tx_in.send(seg).unwrap();

        // receive result
        let result = rx_out.recv().unwrap();
        assert!(result.is_ok(), "GPU worker should process large segment successfully");
    }
}
