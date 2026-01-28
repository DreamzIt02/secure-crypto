#[cfg(test)]
mod telemetry_encrypt_tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use crypto_core::crypto::{DigestAlg, KEY_LEN_32};
    use crypto_core::headers::HeaderV1;
    use crypto_core::recovery::AsyncLogManager;
    use crypto_core::stream_v2::io::PayloadReader;
    use crypto_core::stream_v2::parallelism::HybridParallelismProfile;
    use crypto_core::stream_v2::pipeline::{PipelineConfig, run_encrypt_pipeline};
    use crypto_core::stream_v2::segment_worker::{EncryptContext};
    use crypto_core::telemetry::TelemetrySnapshot;

    fn setup_enc_context(alg: DigestAlg) -> (EncryptContext, HybridParallelismProfile, Arc<AsyncLogManager>) {
        let header = HeaderV1::test_header(); // Mock header
        let profile = HybridParallelismProfile::dynamic(header.chunk_size as u32, 0.50, 64);
       // Create a Vec of 32 bytes
        let session_key = vec![0x42u8; KEY_LEN_32];
        let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
        
        let context = EncryptContext::new(
            header,
            profile.clone(),
            &session_key,
            alg,
        ).unwrap();
        (context, profile, log_manager)
    }
    
    fn run_pipeline_with_data(data: &[u8]) -> TelemetrySnapshot {
        let mut reader = PayloadReader::new(Cursor::new(data.to_vec()));
        let mut writer = Cursor::new(Vec::new());
        let (mut crypto, profile, log_manager) = setup_enc_context(DigestAlg::Blake3);
        let config_pipe = PipelineConfig::new(profile.clone(), None);

        let mut snapshot = run_encrypt_pipeline(&mut reader, &mut writer, &mut crypto, &config_pipe, log_manager)
            .expect("pipeline should succeed");

        // Attach the buffer contents
        snapshot.attach_output(writer.into_inner());

        snapshot
    }

    #[test]
    fn telemetry_counts_plaintext_bytes() {
        let data = b"hello world this is plaintext";
        let snapshot = run_pipeline_with_data(data);

        assert!(snapshot.bytes_plaintext >= data.len() as u64);
        assert!(snapshot.bytes_overhead > 0);
    }

    // #[test]
    // fn telemetry_records_stage_times() {
    //     let data = b"some test data for timing";
    //     let snapshot = run_pipeline_with_data(data);

    //     // Ensure stage times are non-empty
    //     assert!(!snapshot.stage_times.times.is_empty());
    //     assert!(snapshot.elapsed.as_nanos() > 0);
    // }

    #[test]
    fn telemetry_merges_compression_and_encryption() {
        let data = b"compress me and encrypt me";
        let snapshot = run_pipeline_with_data(data);

        // Compression counters should be populated
        assert!(snapshot.bytes_compressed > 0);

        // Encryption counters should be merged
        assert!(snapshot.bytes_ciphertext > 0);
    }
    #[test]
    fn telemetry_handles_single_segment_then_final() {
        // Provide at least one valid frame
        let data = b"x"; // minimal non-empty input
        let snapshot = run_pipeline_with_data(data);

        // Plaintext bytes should equal input length
        assert_eq!(snapshot.bytes_plaintext, data.len() as u64);

        // Overhead should still exist (header, terminator, etc.)
        assert!(snapshot.bytes_overhead > 0);

        // Segments processed should be >= 2 (one data + final empty segment)
        assert!(snapshot.segments_processed >= 2);
    }

    #[test]
    fn telemetry_fails_on_empty_input() {
        let data = b"";
        let result = std::panic::catch_unwind(|| run_pipeline_with_data(data));

        assert!(result.is_err(), "Empty input should fail validation");
    }

    #[test]
    fn telemetry_reports_segment_count() {
        let data = b"segment test data";
        let snapshot = run_pipeline_with_data(data);

        assert!(snapshot.segments_processed >= 1);
    }

    // 🔧 Extra tests for new fields

    #[test]
    fn telemetry_compression_ratio_is_computed() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // highly compressible
        let snapshot = run_pipeline_with_data(data);

        assert!(snapshot.compression_ratio >= 0.0);
    }

    #[test]
    fn telemetry_throughput_is_nonzero() {
        let data = b"throughput test data repeated repeated repeated repeated";
        let snapshot = run_pipeline_with_data(data);

        assert!(snapshot.throughput_plaintext_bytes_per_sec > 0.0);
    }

    #[test]
    fn telemetry_output_contains_ciphertext() {
        let data = b"check output field";
        let snapshot = run_pipeline_with_data(data);

        assert!(snapshot.output.is_some());
        assert!(!snapshot.output.as_ref().unwrap().is_empty());
    }
}
