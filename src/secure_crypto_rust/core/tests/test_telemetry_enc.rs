#[cfg(test)]
mod tests {
    use std::time::Duration;
    use bytes::Bytes;
    use crossbeam::channel::{Receiver, Sender, bounded, unbounded};
    use crypto_core::{crypto::DigestAlg, headers::HeaderV1, stream_v2::{frame_worker::{EncryptedFrame, FrameInput, FrameWorkerError, encrypt::EncryptFrameWorker}, segment_worker::{EncryptSegmentInput, encrypt::process_encrypt_segment_2}, segmenting::types::SegmentFlags}, telemetry::{Stage, StageTimes}};

    fn make_channels() -> (
        Sender<FrameInput>,
        Receiver<Result<EncryptedFrame, FrameWorkerError>>,
    ) {
        let (frame_tx, frame_rx) = bounded::<FrameInput>(4);
        let (out_tx, out_rx) = unbounded::<Result<EncryptedFrame, FrameWorkerError>>();

        // Minimal worker stub (replace with real header/session_key in integration tests)
        let header = HeaderV1::test_header();
        let session_key = vec![0u8; 32];
        let fw = EncryptFrameWorker::new(header, &session_key).unwrap();
        fw.run(frame_rx, out_tx);

        (frame_tx, out_rx)
    }

    #[test]
    fn test_empty_final_segment() {
        let (frame_tx, out_rx) = make_channels();
        let input = EncryptSegmentInput {
            segment_index: 0,
            bytes: Bytes::new(),
            flags: SegmentFlags::FINAL_SEGMENT,
            stage_times: StageTimes::default(),
        };

        let result = process_encrypt_segment_2(&input, 1024, DigestAlg::Blake3, &frame_tx, &out_rx)
            .expect("should succeed");

        assert!(result.wire.is_empty());
        assert_eq!(result.counters.frames_data, 0);
        assert_eq!(result.stage_times.total(), Duration::ZERO);
    }

    #[test]
    fn test_single_frame_segment() {
        let (frame_tx, out_rx) = make_channels();
        let input = EncryptSegmentInput {
            segment_index: 1,
            bytes: Bytes::from_static(b"hello world"),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        };

        let result = process_encrypt_segment_2(&input, 64, DigestAlg::Blake3, &frame_tx, &out_rx)
            .expect("encryption should succeed");

        // Telemetry counters
        assert_eq!(result.counters.frames_data, 1);
        assert!(result.counters.bytes_ciphertext > 0);

        // Stage times
        assert!(result.stage_times.get(Stage::Encrypt) > Duration::ZERO);
        assert!(result.stage_times.get(Stage::Digest) > Duration::ZERO);
        assert!(result.stage_times.get(Stage::Write) > Duration::ZERO);
    }

    #[test]
    fn test_multi_frame_segment() {
        let (frame_tx, out_rx) = make_channels();
        let big_payload = vec![42u8; 4096]; // 4 KB
        let input = EncryptSegmentInput {
            segment_index: 2,
            bytes: Bytes::from(big_payload),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        };

        let result = process_encrypt_segment_2(&input, 1024, DigestAlg::Blake3, &frame_tx, &out_rx)
            .expect("encryption should succeed");

        // Expect 4 data frames
        assert_eq!(result.counters.frames_data, 4);
        assert!(result.counters.bytes_ciphertext >= 4096);

        // Stage times should all be non-zero
        // for stage in [Stage::Encrypt, Stage::Encode, Stage::Digest, Stage::Write] {
        //     assert!(result.stage_times.get(stage) > Duration::ZERO);
        // }
        assert!(result.stage_times.get(Stage::Encode) > std::time::Duration::ZERO);
        assert!(result.stage_times.get(Stage::Encrypt) > std::time::Duration::ZERO);
        assert!(result.stage_times.get(Stage::Digest) > std::time::Duration::ZERO);
        assert!(result.stage_times.get(Stage::Write) > std::time::Duration::ZERO);
    }

    #[test]
    fn test_invalid_empty_non_final_segment() {
        let (frame_tx, out_rx) = make_channels();
        let input = EncryptSegmentInput {
            segment_index: 3,
            bytes: Bytes::new(),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        };

        let result = process_encrypt_segment_2(&input, 1024, DigestAlg::Blake3, &frame_tx, &out_rx);
        assert!(result.is_err());
    }
}
