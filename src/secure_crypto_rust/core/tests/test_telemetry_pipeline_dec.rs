#[cfg(test)]
mod telemetry_decrypt_tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use crypto_core::constants::MAX_CHUNK_SIZE;
    use crypto_core::crypto::{DigestAlg, KEY_LEN_32};
    use crypto_core::headers::HeaderV1;
    use crypto_core::recovery::AsyncLogManager;
    use crypto_core::stream_v2::io::PayloadReader;
    use crypto_core::stream_v2::parallelism::HybridParallelismProfile;
    use crypto_core::stream_v2::pipeline::{PipelineConfig, run_decrypt_pipeline, run_encrypt_pipeline};
    use crypto_core::stream_v2::segment_worker::{DecryptContext, EncryptContext};
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
    fn setup_dec_context(alg: DigestAlg, header: &HeaderV1) -> (DecryptContext, HybridParallelismProfile, Arc<AsyncLogManager>) {
        let profile = HybridParallelismProfile::dynamic(header.chunk_size as u32, 0.50, 64);
       // Create a Vec of 32 bytes
        let session_key = vec![0x42u8; KEY_LEN_32];
        let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
        
        let context = DecryptContext::from_stream_header(
            header.clone(),
            profile.clone(),
            &session_key,
            alg,
        ).unwrap();
        (context, profile, log_manager)
    }
    
    /// Helper: run decrypt pipeline with given ciphertext produced by encrypt pipeline
    fn run_decrypt_with_data(data: &[u8]) -> TelemetrySnapshot {
        // First encrypt to produce ciphertext
        let mut enc_reader = PayloadReader::new(Cursor::new(data.to_vec()));
        let mut enc_writer = Cursor::new(Vec::new());
        let (mut enc_ctx, enc_profile, log_manager) = setup_enc_context(DigestAlg::Blake3);
        let config_pipe = PipelineConfig::new(enc_profile.clone(), None);

        let _ = run_encrypt_pipeline(
            &mut enc_reader,
            &mut enc_writer,
            &mut enc_ctx,
            &config_pipe,
            log_manager.clone(),
        ).expect("encryption pipeline should succeed");

        // 🔧 The writer now contains ciphertext including the final empty segment
        let ciphertext = enc_writer.into_inner();

        // Consume the 80‑byte stream header first
        let cursor = Cursor::new(ciphertext);
        let (stream_header, reader) = PayloadReader::with_header(cursor)
            .expect("failed to read stream header");

        // Now decrypt the ciphertext
        let mut dec_reader = PayloadReader::new(reader);
        let mut dec_writer = Cursor::new(Vec::new());
        let (mut dec_ctx, dec_profile, log_manager) = setup_dec_context(DigestAlg::Blake3, &stream_header);
        let config_pipe = PipelineConfig::new(dec_profile.clone(), None);

        run_decrypt_pipeline(
            &mut dec_reader,
            &mut dec_writer,
            &mut dec_ctx,
            &config_pipe,
            log_manager,
        ).expect("decryption pipeline should succeed")
    }

    fn run_pipeline_with_data(data: &[u8]) -> (TelemetrySnapshot, Vec<u8>) {
        let mut reader = PayloadReader::new(Cursor::new(data.to_vec()));
        let mut writer = Cursor::new(Vec::new());
        let (mut crypto, profile, log_manager) = setup_enc_context(DigestAlg::Blake3);
        let config_pipe = PipelineConfig::new(profile.clone(), None);

        let snapshot = run_encrypt_pipeline(
            &mut reader,
            &mut writer,
            &mut crypto,
            &config_pipe,
            log_manager,
        ).expect("encrypt pipeline should succeed");

        // 🔧 The writer now contains ciphertext including the final empty segment
        let ciphertext = writer.into_inner();

        (snapshot, ciphertext)
    }

    fn run_decrypt_with_ciphertext(ciphertext: Vec<u8>) -> TelemetrySnapshot {
        // Consume the 80‑byte stream header first
        let cursor = Cursor::new(ciphertext);
        let (stream_header, mut reader) = PayloadReader::with_header(cursor)
            .expect("failed to read stream header");

        eprintln!("[TEST] Parsed stream header: {:?}", stream_header);

        let mut writer = Cursor::new(Vec::new());
        let (mut dec_ctx, profile, log_manager) = setup_dec_context(DigestAlg::Blake3, &stream_header);
        let config_pipe = PipelineConfig::new(profile.clone(), None);

        run_decrypt_pipeline(
            &mut reader,          // reader now positioned after HeaderV1
            &mut writer,
            &mut dec_ctx,
            &config_pipe,
            log_manager,
        ).expect("decrypt pipeline should succeed")
    }

    #[test]
    fn decrypt_pipeline_includes_final_segment() {
        let data = b"hello world";
        let (_, ciphertext) = run_pipeline_with_data(data);

        let snapshot = run_decrypt_with_ciphertext(ciphertext);

        // Expect at least 2 segments: one data + one final empty
        assert!(snapshot.segments_processed >= 2);
    }

    #[test]
    fn telemetry_counts_plaintext_bytes_after_decrypt() {
        let data = b"hello world this is plaintext";
        let snapshot = run_decrypt_with_data(data);

        assert_eq!(snapshot.bytes_plaintext, data.len() as u64);
        assert!(snapshot.bytes_ciphertext > 0);
        assert!(snapshot.bytes_overhead > 0);
    }

    #[test]
    fn telemetry_records_stage_times_in_decrypt() {
        let data = b"some test data for timing";
        let snapshot = run_decrypt_with_data(data);

        assert!(!snapshot.stage_times.times.is_empty());
        assert!(snapshot.elapsed.as_nanos() > 0);
    }

    #[test]
    fn telemetry_merges_decryption_and_decompression() {
        let data = b"compress me and encrypt me";
        let snapshot = run_decrypt_with_data(data);

        // Decompression counters should be populated
        assert!(snapshot.bytes_plaintext > 0);

        // Ciphertext counters should also be merged
        assert!(snapshot.bytes_ciphertext > 0);
    }

    #[test]
    fn telemetry_reports_segment_count_in_decrypt() {
        let data = b"segment test data";
        let snapshot = run_decrypt_with_data(data);

        assert!(snapshot.segments_processed >= 2); // one data + final empty segment
    }

    #[test]
    fn telemetry_sanity_check_passes_for_decrypt() {
        let data = b"sanity check data";
        let snapshot = run_decrypt_with_data(data);

        assert!(snapshot.sanity_check());
    }

    #[test]
    fn telemetry_output_bytes_matches_ciphertext_count() {
        let data = b"check output bytes";
        let snapshot = run_decrypt_with_data(data);

        assert_eq!(snapshot.output_bytes(), snapshot.bytes_ciphertext);
    }

    // 🔧 Negative-path tests

    #[test]
    fn telemetry_fails_on_corrupted_ciphertext() {
        // Provide invalid ciphertext (not produced by encrypt pipeline)
        let bad_ciphertext = vec![0xde, 0xad, 0xbe, 0xef];
        let mut reader = PayloadReader::new(Cursor::new(bad_ciphertext));
        let mut writer = Cursor::new(Vec::new());
        let (mut dec_ctx, profile, log_manager) = setup_dec_context(DigestAlg::Blake3, &HeaderV1::test_header());
        let config_pipe = PipelineConfig::new(profile.clone(), None);

        let result = run_decrypt_pipeline(
            &mut reader,
            &mut writer,
            &mut dec_ctx,
            &config_pipe,
            log_manager,
        );

        assert!(result.is_err(), "Corrupted ciphertext should fail validation");
    }

    #[test]
    fn telemetry_handles_multi_segment_input() {
        // Input larger than one chunk size to force multiple segments
        let data = vec![42u8; MAX_CHUNK_SIZE + 4096]; // adjust to exceed chunk size

        // Step 1: Encrypt plaintext -> ciphertext (includes HeaderV1 + segments)
        let (_, ciphertext) = run_pipeline_with_data(&data);

        // Step 2: Decrypt ciphertext -> snapshot
        let snapshot = run_decrypt_with_ciphertext(ciphertext);

        // Step 3: Assert telemetry
        assert!(snapshot.segments_processed > 2); // multiple data segments + final empty
        assert_eq!(snapshot.bytes_plaintext, data.len() as u64);
    }

}
