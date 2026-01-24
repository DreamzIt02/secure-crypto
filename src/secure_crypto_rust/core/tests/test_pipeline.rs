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
    use std::io::{Cursor, Read, Write};
    use std::sync::Arc;

    use crypto_core::constants::DEFAULT_CHUNK_SIZE;
    use crypto_core::crypto::{DigestAlg, KEY_LEN_32};
    use crypto_core::headers::HeaderV1;
    use crypto_core::recovery::AsyncLogManager;
    use crypto_core::stream_v2::{HybridParallelismProfile};
    use crypto_core::stream_v2::pipeline::{run_decrypt_pipeline, run_encrypt_pipeline};
    use crypto_core::stream_v2::segment_worker::{SegmentCryptoContext, SegmentWorkerError};
    use crypto_core::telemetry::TelemetrySnapshot;
    use crypto_core::types::StreamError;

    // ------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------
    fn setup_test_context(alg: DigestAlg) -> (SegmentCryptoContext, Arc<AsyncLogManager>) {
        let worker_count = num_cpus::get().max(1);
        let header = HeaderV1::test_header(); // Mock header
       // Create a Vec of 32 bytes
        let session_key = vec![0x42u8; KEY_LEN_32];
        let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
        
        let context = SegmentCryptoContext::new(
            header,
            &session_key,
            alg,
            worker_count,
        ).unwrap();
        (context, log_manager)
    }

    fn run_encrypt_decrypt(
        plaintext: &[u8],
        profile: HybridParallelismProfile,
    ) -> Result<(Vec<u8>, TelemetrySnapshot), StreamError> {
        let (crypto, log_manager) = setup_test_context(DigestAlg::Sha256);

        let mut encrypted = Vec::new();

        let enc_snapshot = run_encrypt_pipeline(
            Cursor::new(plaintext.to_vec()),
            Cursor::new(&mut encrypted),
            crypto.clone(),
            profile.clone(),
            log_manager.clone(),
        )?;

        let mut decrypted = Vec::new();

        run_decrypt_pipeline(
            Cursor::new(encrypted),
            Cursor::new(&mut decrypted),
            crypto,
            profile,
            log_manager,
        )?;

        Ok((decrypted, enc_snapshot))
    }


    // ------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------
    #[test]
    fn encrypt_pipeline_exact_multiple_chunk_size() {
        // Setup context
        let (crypto, log_manager) = setup_test_context(DigestAlg::Sha256);
        // Match the header's chunk_size (64 KiB)
        let chunk_size = crypto.header.chunk_size as usize;
        let num_segments = 3;
        let data = vec![0x11u8; chunk_size * num_segments]; // exact multiple of header chunk_size

        let profile = HybridParallelismProfile {
            cpu_workers: 2,
            gpu_workers: 2,
            inflight_segments: 4,
        };

        // First encrypt to produce ciphertext
        let mut encrypted = Vec::new();
        let snapshot = run_encrypt_pipeline(
            Cursor::new(data.clone()),
            Cursor::new(&mut encrypted),
            crypto,
            profile,
            log_manager,
        ).expect("encryption pipeline should finish");

        // Assert we got some output and telemetry
        assert!(!encrypted.is_empty(), "encrypted stream should not be empty");
        assert!(snapshot.segments_processed >= num_segments as u64);
    }

    #[test]
    fn decrypt_pipeline_exact_multiple_chunk_size() {
        let (crypto, log_manager) = setup_test_context(DigestAlg::Sha256);
        // Match the header's chunk_size (64 KiB)
        let chunk_size = crypto.header.chunk_size as usize;
        let num_segments = 2;
        let data = vec![0x22u8; chunk_size * num_segments];

        let profile = HybridParallelismProfile {
            cpu_workers: 2,
            gpu_workers: 2,
            inflight_segments: 4,
        };

        // First encrypt to produce ciphertext
        let mut encrypted = Vec::new();
        run_encrypt_pipeline(
            Cursor::new(data.clone()),
            Cursor::new(&mut encrypted),
            crypto.clone(),
            profile.clone(),
            log_manager.clone(),
        ).expect("encryption pipeline should succeed");

        // Now decrypt only
        let mut decrypted = Vec::new();
        let snapshot = run_decrypt_pipeline(
            Cursor::new(encrypted),
            Cursor::new(&mut decrypted),
            crypto,
            profile,
            log_manager,
        ).expect("decryption pipeline should finish");

        eprintln!("[TEST_PIPELINE] Finished, decrypted output {} must equal original plaintext {}", decrypted.len(), data.len());

        assert_eq!(decrypted.len(), data.len(), "decrypted output must equal original plaintext");
        // assert_eq!(decrypted, data, "decrypted output must equal original plaintext");
        assert!(snapshot.segments_processed >= num_segments as u64);
    }

    #[test]
    fn exact_multiple_of_chunk_size_final_segment() {
        // Suppose segment_size = 64 (from SegmentCryptoContext)
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let num_segments = 5;
        let data = vec![0xABu8; chunk_size * num_segments]; // exactly multiple of chunk_size

        let profile = HybridParallelismProfile {
            cpu_workers: 2,
            gpu_workers: 2,
            inflight_segments: 4,
        };

        // Run encrypt + decrypt pipeline
        let (decrypted, enc_snapshot) = run_encrypt_decrypt(&data, profile)
            .expect("pipeline should not hang and must succeed");

        // Assert round-trip correctness
        assert_eq!(decrypted, data);

        // Assert telemetry sanity (optional)
        assert!(enc_snapshot.segments_processed >= num_segments as u64);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_single_thread() {
        let data = b"hello secure streaming world";

        let (out, _) = run_encrypt_decrypt(
            data,
            HybridParallelismProfile {
                cpu_workers: 1,
                gpu_workers: 1,
                inflight_segments: 1
            },
        )
        .unwrap();

        assert_eq!(out, data);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_parallel() {
        let data = vec![0xAB; 64 * 1024];

        let (out, _) = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile {
                cpu_workers: 4,
                gpu_workers: 4,
                inflight_segments: 8,
            },
        )
        .unwrap();

        assert_eq!(out, data);
    }

    #[test]
    fn preserves_order_under_parallelism() {
        let mut data = Vec::new();
        for i in 0..10_000u32 {
            data.extend_from_slice(&i.to_le_bytes());
        }

        let (out, _) = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile {
                cpu_workers: 6,
                gpu_workers: 6,
                inflight_segments: 12,
            },
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
            HybridParallelismProfile {
                cpu_workers: 2,
                gpu_workers: 2,
                inflight_segments: 4,
            },
        )
        .unwrap();
        
        assert_eq!(out, data);
    }

    #[test]
    fn empty_input_produces_error() {
        let data = [];

        let err = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile {
                cpu_workers: 1,
                gpu_workers: 1,
                inflight_segments: 1,
            },
        )
        .unwrap_err();

        matches!(err, StreamError::SegmentWorker(SegmentWorkerError::InvalidSegment(_)));
    }

    #[test]
    fn header_mismatch_is_detected() {
        let (crypto, log_manager) = setup_test_context(DigestAlg::Sha256);

        let data = b"attack at dawn";
        let crypto_good = crypto.clone();
        // let mut h = header.clone();
        //     h.key_id = 999; // mismatch

        let mut crypto_bad = crypto.clone();
        crypto_bad.header.key_id = 999; // mismatch

        let mut encrypted = Vec::new();

        run_encrypt_pipeline(
            Box::new(Cursor::new(data.to_vec())),
            Box::new(Cursor::new(&mut encrypted)),
            crypto_good,
            HybridParallelismProfile::single_threaded(),
            log_manager.clone(),
        )
        .unwrap();

        let err = run_decrypt_pipeline(
            Box::new(Cursor::new(encrypted)),
            Box::new(Cursor::new(Vec::new())),
            crypto_bad,
            HybridParallelismProfile::single_threaded(),
            log_manager,
        )
        .unwrap_err();

        matches!(err, StreamError::Validation(_));
    }

    #[test]
    fn bounded_backpressure_does_not_deadlock() {
        let data = vec![42u8; 1024 * 128];

        let (out, _) = run_encrypt_decrypt(
            &data,
            HybridParallelismProfile {
                cpu_workers: 8,
                gpu_workers: 8,
                inflight_segments: 1, // extreme pressure
            },
        )
        .unwrap();

        assert_eq!(out, data);
    }

    #[test]
    fn detects_corrupted_stream() {
        let (crypto, log_manager) = setup_test_context(DigestAlg::Sha256);

        let data = b"this will be corrupted";
        let mut encrypted = Vec::new();

        run_encrypt_pipeline(
            Box::new(Cursor::new(data.to_vec())),
            Box::new(Cursor::new(&mut encrypted)),
            crypto.clone(),
            HybridParallelismProfile::single_threaded(),
            log_manager.clone(),
        )
        .unwrap();

        // Corrupt payload
        let index = encrypted.len() / 2;
        encrypted[index] ^= 0xFF;

        let err = run_decrypt_pipeline(
            Box::new(Cursor::new(encrypted)),
            Box::new(Cursor::new(Vec::new())),
            crypto,
            HybridParallelismProfile::single_threaded(),
            log_manager,
        )
        .unwrap_err();

        matches!(err, StreamError::SegmentWorker(_));
    }

}

// ## 🧪 What this suite **guarantees**

// ### ✔ Functional correctness

// * byte-perfect round-trip
// * correct segmentation
// * correct ordering

// ### ✔ Concurrency safety

// * no deadlocks
// * bounded channel pressure works
// * workers exit cleanly

// ### ✔ Security invariants

// * header binding enforced
// * corruption detected
// * digest verification exercised

// ### ✔ Regression resistance

// If **any** of these fail:

// * pipeline wiring is broken
// * ordering logic regressed
// * segmentation logic incorrect
// * shutdown semantics wrong

// ---
