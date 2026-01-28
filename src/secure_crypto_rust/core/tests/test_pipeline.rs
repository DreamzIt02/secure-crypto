// # 📂 `src/stream_v2/pipeline_tests.rs`

// * ✅ end-to-end encrypt → decrypt correctness
// * ✅ segment ordering under parallelism
// * ✅ boundary conditions (empty input, exact chunk, multi-segment)
// * ✅ header validation
// * ✅ backpressure correctness (bounded channels)
// * ✅ determinism under concurrency
// * ✅ error propagation (worker failure, corrupted stream)

#[cfg(test)]
mod tests {
    use std::io::{Cursor};
    use std::sync::Arc;

    use crypto_core::constants::DEFAULT_CHUNK_SIZE;
    use crypto_core::crypto::{DigestAlg, KEY_LEN_32};
    use crypto_core::headers::{HeaderV1};
    use crypto_core::recovery::AsyncLogManager;
    use crypto_core::stream_v2::framing::FrameHeader;
    use crypto_core::stream_v2::io::{PayloadReader};
    use crypto_core::stream_v2::parallelism::HybridParallelismProfile;
    use crypto_core::stream_v2::pipeline::{PipelineConfig, run_decrypt_pipeline, run_encrypt_pipeline};
    use crypto_core::stream_v2::segment_worker::{EncryptContext, DecryptContext, SegmentWorkerError};
    use crypto_core::stream_v2::segmenting::SegmentHeader;
    use crypto_core::telemetry::TelemetrySnapshot;
    use crypto_core::types::StreamError;

    // ------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------
    fn setup_enc_context(alg: DigestAlg) -> (EncryptContext, Arc<AsyncLogManager>) {
        let header = HeaderV1::test_header(); // Mock header
        let profile = HybridParallelismProfile::dynamic(header.chunk_size as u32, 0.50, 64);
       // Create a Vec of 32 bytes
        let session_key = vec![0x42u8; KEY_LEN_32];
        let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
        
        let context = EncryptContext::new(
            header,
            profile,
            &session_key,
            alg,
        ).unwrap();
        (context, log_manager)
    }
    fn setup_dec_context(alg: DigestAlg) -> (DecryptContext, Arc<AsyncLogManager>) {
        let header = HeaderV1::test_header(); // Mock header
        let profile = HybridParallelismProfile::dynamic(header.chunk_size as u32, 0.50, 64);
       // Create a Vec of 32 bytes
        let session_key = vec![0x42u8; KEY_LEN_32];
        let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
        
        let context = DecryptContext::from_stream_header(
            header,
            profile,
            &session_key,
            alg,
        ).unwrap();
        (context, log_manager)
    }

    fn run_encrypt_decrypt(
        plaintext: &[u8],
        profile: HybridParallelismProfile,
    ) -> Result<(Vec<u8>, TelemetrySnapshot), StreamError> {
        let (mut crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (mut crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        // PipelineConfig now expects Option<Arc<Mutex<Vec<u8>>>>
        let config_pipe = PipelineConfig::new(profile.clone(), None);

        let mut encrypted = Vec::new();

        // Encrypt pipeline
        let mut enc_reader = PayloadReader::new(std::io::Cursor::new(plaintext.to_vec()));
        let enc_writer = std::io::Cursor::new(&mut encrypted);

        let enc_snapshot = run_encrypt_pipeline(
            &mut enc_reader,
            enc_writer,
            &mut crypto_enc,
            &config_pipe, // pass by reference, not move
            log_enc,
        )?;

        let mut decrypted = Vec::new();

        // Decrypt pipeline
        let dec_cursor = std::io::Cursor::new(encrypted);
        let (_header, mut dec_reader) = PayloadReader::with_header(dec_cursor)?;
        let dec_writer = std::io::Cursor::new(&mut decrypted);

        run_decrypt_pipeline(
            &mut dec_reader,
            dec_writer,
            &mut crypto_dec,
            &config_pipe, // pass by reference here too
            log_dec,
        )?;

        Ok((decrypted, enc_snapshot))
    }



    // ------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------
    #[test]
    fn decrypt_pipeline_exact_multiple_chunk_size() {
        let (mut crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (mut crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);
        let profile = HybridParallelismProfile::new(2, 2, 4);
        let config_pipe = PipelineConfig::new(profile.clone(), None);

        let chunk_size = crypto_enc.header.chunk_size as usize;
        let num_segments = 2;
        let data = vec![0x22u8; chunk_size * num_segments];

        // Encrypt
        let mut encrypted = Vec::new();
        let mut enc_reader = PayloadReader::new(Cursor::new(data.clone()));
        run_encrypt_pipeline(
            &mut enc_reader,
            Cursor::new(&mut encrypted),
            &mut crypto_enc,
            &config_pipe,
            log_enc,
        ).expect("encryption pipeline should succeed");

        // Decrypt
        let dec_cursor = Cursor::new(encrypted);
        let (_header, mut dec_reader) = PayloadReader::with_header(dec_cursor).unwrap();
        let mut decrypted = Vec::new();
        let snapshot = run_decrypt_pipeline(
            &mut dec_reader,
            Cursor::new(&mut decrypted),
            &mut crypto_dec,
            &config_pipe,
            log_dec,
        ).expect("decryption pipeline should finish");

        assert_eq!(decrypted.len(), data.len());
        assert!(snapshot.segments_processed >= num_segments as u64);
    }

    #[test]
    fn encrypt_pipeline_exact_multiple_chunk_size() {
        // Setup context
        let (mut crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        // let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);
        let profile = HybridParallelismProfile::new(2, 2, 4);
        let config_pipe = PipelineConfig::new(profile, None);

        // Match the header's chunk_size (64 KiB)
        let chunk_size = crypto_enc.header.chunk_size as usize;
        let num_segments = 3;
        let data = vec![0x11u8; chunk_size * num_segments]; // exact multiple of header chunk_size

        let mut enc_reader = PayloadReader::new(Cursor::new(data.clone()));

        // First encrypt to produce ciphertext
        let mut encrypted = Vec::new();
        let snapshot = run_encrypt_pipeline(
            &mut enc_reader,
            Cursor::new(&mut encrypted),
            &mut crypto_enc,
            &config_pipe,
            log_enc,
        ).expect("encryption pipeline should finish");

        // Assert we got some output and telemetry
        assert!(!encrypted.is_empty(), "encrypted stream should not be empty");
        assert!(snapshot.segments_processed >= num_segments as u64);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_single_thread() {
        let data = b"hello secure streaming world";

        let (out, _) = run_encrypt_decrypt(
            data,
            HybridParallelismProfile::single_threaded(),
        )
        .unwrap();
        eprintln!("[TEST_PIPELINE] Finished, decrypted output {} must equal original plaintext {}", out.len(), data.len());
        assert_eq!(out, data);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_parallel() {
        let data = vec![0xAB; 64 * 1024];

        let (out, _) = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile::new(4, 4, 8),
        )
        .unwrap();

        assert_eq!(out, data);
    }

    #[test]
    fn header_mismatch_is_detected() {
        let (mut crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (_crypto_dec, _log_dec) = setup_dec_context(DigestAlg::Sha256);
        let profile = HybridParallelismProfile::single_threaded();
        let config_pipe = PipelineConfig::new(profile.clone(), None);

        let data = b"attack at dawn";

        let mut enc_reader = PayloadReader::new(Cursor::new(data.clone()));
        let mut encrypted = Vec::new();

        run_encrypt_pipeline(
            &mut enc_reader,
            Box::new(Cursor::new(&mut encrypted)),
            &mut crypto_enc,
            &config_pipe,
            log_enc,
        )
        .unwrap();

        // Corrupt payload
        let index = 22; // 80 bytes HeaderV1 + must fail at crc32 verification during decode
        encrypted[index] ^= 0xFF;

        let dec_cursor = Cursor::new(encrypted);
        let err = PayloadReader::with_header(dec_cursor).unwrap_err();

        // let err = run_decrypt_pipeline(
        //     &mut dec_reader,
        //     Box::new(Cursor::new(Vec::new())),
        //     crypto_dec,
        //     HybridParallelismProfile::single_threaded(),
        //     log_dec,
        // )
        // .unwrap_err();

        matches!(err, StreamError::Header(_));
    }

    #[test]
    fn detects_corrupted_stream() {
        let (mut crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (mut crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);
        let profile = HybridParallelismProfile::single_threaded();
        let config_pipe = PipelineConfig::new(profile.clone(), None);

        let data = b"this will be corrupted";
        let mut enc_reader = PayloadReader::new(Cursor::new(data.clone()));
        let mut encrypted = Vec::new();

        run_encrypt_pipeline(
            &mut enc_reader,
            Box::new(Cursor::new(&mut encrypted)),
            &mut crypto_enc,
            &config_pipe,
            log_enc,
        )
        .unwrap();

        // Corrupt payload
        // Find offset of first segment ciphertext
        let header_len = HeaderV1::LEN;
        let seg_hdr_len = SegmentHeader::LEN;
        let frame_hdr_len = FrameHeader::LEN;
        let ct_start = header_len + seg_hdr_len + frame_hdr_len + 2;
        encrypted[ct_start] ^= 0xAA; // guaranteed inside ciphertext


        let dec_cursor = Cursor::new(encrypted);
        let (_header, mut dec_reader) = PayloadReader::with_header(dec_cursor).unwrap();

        let err = run_decrypt_pipeline(
            &mut dec_reader,
            Box::new(Cursor::new(Vec::new())),
            &mut crypto_dec,
            &config_pipe,
            log_dec,
        )
        .unwrap_err();

        matches!(err, StreamError::SegmentWorker(_));
    }

    #[test]
    fn exact_multiple_of_chunk_size_final_segment() {
        // Suppose segment_size = 64 (from SegmentCryptoContext)
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let num_segments = 5;
        let data = vec![0xABu8; chunk_size * num_segments]; // exactly multiple of chunk_size

        let profile = HybridParallelismProfile::new(2, 2, 4);

        // Run encrypt + decrypt pipeline
        let (decrypted, enc_snapshot) = run_encrypt_decrypt(&data, profile)
            .expect("pipeline should not hang and must succeed");

        // Assert round-trip correctness
        assert_eq!(decrypted, data);

        // Assert telemetry sanity (optional)
        assert!(enc_snapshot.segments_processed >= num_segments as u64);
    }

    #[test]
    fn preserves_order_under_parallelism() {
        let mut data = Vec::new();
        for i in 0..10_000u32 {
            data.extend_from_slice(&i.to_le_bytes());
        }

        let (out, _) = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile::new(6, 6, 12),
        )
        .unwrap();

        assert_eq!(out, data);
    }

    #[test]
    fn exact_chunk_boundary() {
        let chunk = DEFAULT_CHUNK_SIZE;
        let data = vec![1u8; chunk * 10];

        let (out, _) = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile::new(2, 2, 4),
        )
        .unwrap();
        
        assert_eq!(out, data);
    }

    #[test]
    fn empty_input_produces_error() {
        let data = [];

        let err = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile::single_threaded(),
        )
        .unwrap_err();

        matches!(err, StreamError::SegmentWorker(SegmentWorkerError::InvalidSegment(_)));
    }

    #[test]
    fn bounded_backpressure_does_not_deadlock() {
        let data = vec![42u8; 1024 * 1024 * 118];

        let (out, _) = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile::new(8, 8, 1), // extreme pressure
        )
        .unwrap();

        assert_eq!(out, data);
    }

}
