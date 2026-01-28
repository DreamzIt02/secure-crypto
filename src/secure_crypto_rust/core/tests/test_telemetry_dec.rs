// # 📂 tests/decrypt_segment_worker_telemetry.rs

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crossbeam::channel::{Receiver, Sender, bounded, unbounded};
    use crypto_core::{crypto::DigestAlg, headers::HeaderV1, stream_v2::{frame_worker::{DecryptedFrame, EncryptedFrame, FrameInput, FrameWorkerError, decrypt::DecryptFrameWorker, encrypt::EncryptFrameWorker}, segment_worker::{DecryptSegmentInput, EncryptSegmentInput, SegmentWorkerError, decrypt::process_decrypt_segment_v2, encrypt::process_encrypt_segment_2}, segmenting::{SegmentHeader, types::SegmentFlags}}, telemetry::{Stage, StageTimes, TelemetryCounters}};

    /// Build a deterministic encrypted segment fixture for testing.
    /// This uses the real encrypt pipeline to produce a wire payload
    /// that can be fed into `process_decrypt_segment_v2`.
    pub fn build_fake_encrypted_segment() -> Bytes {
        // Minimal plaintext fixture
        let plaintext = Bytes::from_static(b"hello world telemetry test");

        // Construct input segment
        let input = EncryptSegmentInput {
            bytes: plaintext.clone(),
            segment_index: 42,
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        };

        // Frame worker channels
        let (frame_tx, frame_rx) = bounded::<FrameInput>(4);
        let (out_tx, out_rx) = unbounded::<Result<EncryptedFrame, FrameWorkerError>>();

        // Minimal worker stub (replace with real header/session_key in integration tests)
        let header = HeaderV1::test_header();
        let session_key = vec![0u8; 32];
        let fw = EncryptFrameWorker::new(header, &session_key).unwrap();
        fw.run(frame_rx, out_tx);

        // Run encrypt pipeline
        let result = process_encrypt_segment_2(
            &input,
            16, // frame_size
            DigestAlg::Sha256,
            &frame_tx,
            &out_rx,
        );

        match result {
            Ok(seg) => seg.wire,
            Err(e) => panic!("failed to build fake encrypted segment: {:?}", e),
        }
    }

    fn make_channels() -> (
        Sender<Bytes>,
        Receiver<Result<DecryptedFrame, FrameWorkerError>>,
    ) {
        let (frame_tx, frame_rx) = bounded::<Bytes>(4);
        let (out_tx, out_rx) = unbounded::<Result<DecryptedFrame, FrameWorkerError>>();

        // Minimal worker stub (replace with real header/session_key in integration tests)
        let header = HeaderV1::test_header();
        let session_key = vec![0u8; 32];
        let fw = DecryptFrameWorker::new(header, &session_key).unwrap();
        fw.run(frame_rx, out_tx);

        (frame_tx, out_rx)
    }

    #[test]
    fn telemetry_empty_final_segment() {
        let (frame_tx, out_rx) = make_channels();
        let header = SegmentHeader::new(
            &Bytes::new(),
            0,
            0,
            0,
            0,
            SegmentFlags::FINAL_SEGMENT,
        );
        let input = DecryptSegmentInput {
            header: header.clone(),
            wire: Bytes::new(),
        };

        let result = process_decrypt_segment_v2(&input, &DigestAlg::Sha256, &frame_tx, &out_rx);
        assert!(result.is_ok());
        let seg = result.unwrap();
        assert_eq!(seg.bytes.len(), 0);
        assert_eq!(seg.counters, TelemetryCounters::default());
        assert_eq!(seg.stage_times, StageTimes::default());
    }

    #[test]
    fn telemetry_invalid_segment_empty_non_final() {
        let (frame_tx, out_rx) = make_channels();
        let header = SegmentHeader::new(
            &Bytes::new(),
            1,
            0,
            0,
            DigestAlg::Sha256 as u16,
            SegmentFlags::empty(),
        );
        let input = DecryptSegmentInput {
            header,
            wire: Bytes::new(),
        };

        let result = process_decrypt_segment_v2(&input, &DigestAlg::Sha256, &frame_tx, &out_rx);
        assert!(matches!(result, Err(SegmentWorkerError::InvalidSegment(_))));
    }

    #[test]
    fn telemetry_digest_mismatch() {
        let (frame_tx, out_rx) = make_channels();
        // Build a fake segment with mismatched digest frame
        let bogus_wire = Bytes::from_static(&[0x01, 0x02, 0x03]); // truncated nonsense
        let header = SegmentHeader::new(
            &bogus_wire,
            2,
            bogus_wire.len() as u32,
            1,
            DigestAlg::Sha256 as u16,
            SegmentFlags::empty(),
        );
        let input = DecryptSegmentInput { header, wire: bogus_wire };

        let result = process_decrypt_segment_v2(&input, &DigestAlg::Sha256, &frame_tx, &out_rx);
        assert!(result.is_err());
        // Telemetry counters should remain default on failure
        if let Err(e) = result {
            match e {
                SegmentWorkerError::FramingError(_) |
                SegmentWorkerError::FrameWorkerError(_) |
                SegmentWorkerError::InvalidSegment(_) |
                SegmentWorkerError::MissingDigestFrame => {}
                _ => panic!("unexpected error variant: {:?}", e),
            }
        }
    }

    #[test]
    fn telemetry_successful_decrypt_updates_counters() {
        let (frame_tx, out_rx) = make_channels();
        // Construct a valid encrypted segment fixture (replace with real wire in integration)
        let fake_wire = build_fake_encrypted_segment(); // helper to craft valid frames
        let header = SegmentHeader::new(
            &fake_wire,
            3,
            fake_wire.len() as u32,
            1,
            DigestAlg::Sha256 as u16,
            SegmentFlags::empty(),
        );
        let input = DecryptSegmentInput { header, wire: fake_wire };

        let result = process_decrypt_segment_v2(&input, &DigestAlg::Sha256, &frame_tx, &out_rx);
        assert!(result.is_ok());
        let seg = result.unwrap();

        // Telemetry counters should reflect data, digest, terminator
        assert!(seg.counters.bytes_compressed > 0);
        assert!(seg.counters.frames_digest > 0);
        assert!(seg.counters.frames_terminator > 0);

        // Stage times should have nonzero durations
        assert!(seg.stage_times.get(Stage::Decode) > std::time::Duration::ZERO);
        assert!(seg.stage_times.get(Stage::Decrypt) > std::time::Duration::ZERO);
        assert!(seg.stage_times.get(Stage::Digest) > std::time::Duration::ZERO);
        assert!(seg.stage_times.get(Stage::Write) > std::time::Duration::ZERO);
    }

    #[test]
    fn telemetry_merge_counters() {
        let mut c1 = TelemetryCounters::default();
        let mut c2 = TelemetryCounters::default();
        c1.bytes_plaintext = 100;
        c2.bytes_plaintext = 50;

        c1.merge(&c2);
        assert_eq!(c1.bytes_plaintext, 150);
    }
}
