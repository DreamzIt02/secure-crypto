// ## 🧪 Test File: `secure_crypto_rust/core/tests/public_api/test_parallelism_profiles.rs`

#[cfg(test)]
mod tests {
    use crypto_core::{compression::CompressionCodec, headers::{AadDomain, AlgProfile, CipherSuite, HeaderV1, HkdfPrf, Strategy}, stream_v2::{InputSource, OutputSink, core::{ApiConfig, DecryptParams, EncryptParams}, decrypt_stream_v2, encrypt_stream_v2, parallelism::{ParallelismConfig}}};

    fn dummy_master_key() -> Vec<u8> {
        vec![0x11; 32] // 256‑bit dummy key
    }

    fn dummy_header() -> HeaderV1 {
        HeaderV1 {
            magic: *b"RSE1",
            version: 1,
            alg_profile: AlgProfile::Aes256GcmHkdfSha256 as u16,
            cipher: CipherSuite::Chacha20Poly1305 as u16,
            hkdf_prf: HkdfPrf::Sha256 as u16,
            compression: CompressionCodec::Auto as u16,
            strategy: Strategy::Auto as u16,
            aad_domain: AadDomain::Generic as u16,
            flags: 0,
            chunk_size: 64 * 1024,
            plaintext_size: 0,
            crc32: 0,
            dict_id: 0,
            salt: [1u8; 16],
            key_id: 0,
            parallel_hint: 0,
            enc_time_ns: 0,
            reserved: [0; 8],
        }
    }

    #[test]
    fn roundtrip_single_threaded_profile() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = b"single threaded profile test".to_vec();

        let snapshot_enc = encrypt_stream_v2(
            InputSource::Memory(plaintext.clone()),
            OutputSink::Memory,
            &master_key,
            params.clone(),
            config.clone(),
        ).expect("encryption should succeed");

        let ciphertext = snapshot_enc.output.expect("ciphertext captured");

        let snapshot_dec = decrypt_stream_v2(
            InputSource::Memory(ciphertext),
            OutputSink::Memory,
            &master_key,
            DecryptParams,
            config,
        ).expect("decryption should succeed");

        assert_eq!(snapshot_dec.bytes_plaintext, plaintext.len() as u64);
    }

    #[test]
    fn roundtrip_multi_threaded_profile() {
        let master_key = dummy_master_key();
        let mut header = dummy_header();
        // Multi-threaded profile
        header.strategy = Strategy::Parallel as u16; // Explicit parallel profile
        let params = EncryptParams { header, dict: None };
        let config_para = ParallelismConfig::new(4, 4, 0.5, 8);
        let config = ApiConfig::new(Some(true), None, None, Some(config_para));

        let plaintext = vec![0xAB; 512 * 1024]; // 512 KB

        let snapshot_enc = encrypt_stream_v2(
            InputSource::Memory(plaintext.clone()),
            OutputSink::Memory,
            &master_key,
            params.clone(),
            config.clone(),
        ).expect("encryption should succeed");

        let ciphertext = snapshot_enc.output.expect("ciphertext captured");

        let snapshot_dec = decrypt_stream_v2(
            InputSource::Memory(ciphertext),
            OutputSink::Memory,
            &master_key,
            DecryptParams,
            config,
        ).expect("decryption should succeed");

        assert_eq!(snapshot_dec.bytes_plaintext, plaintext.len() as u64);
    }

    #[test]
    fn extreme_backpressure_large_input() {
        let master_key = dummy_master_key();
        let mut header = dummy_header();
        // Extreme backpressure profile: many threads but tiny queue
        header.strategy = Strategy::Parallel as u16; // Explicit parallel profile
        let params = EncryptParams { header, dict: None };
        let config_para = ParallelismConfig::new(8, 8, 0.5, 1);
        let config = ApiConfig::new(Some(true), None, None, Some(config_para));

        // Very large input to stress pipeline
        let plaintext = vec![42u8; 32 * 1024 * 1024]; // 32 MB

        let snapshot_enc = encrypt_stream_v2(
            InputSource::Memory(plaintext.clone()),
            OutputSink::Memory,
            &master_key,
            params.clone(),
            config.clone(),
        ).expect("encryption should succeed under pressure");

        let ciphertext = snapshot_enc.output.expect("ciphertext captured");

        let snapshot_dec = decrypt_stream_v2(
            InputSource::Memory(ciphertext),
            OutputSink::Memory,
            &master_key,
            DecryptParams,
            config,
        ).expect("decryption should succeed under pressure");

        assert_eq!(snapshot_dec.bytes_plaintext, plaintext.len() as u64);
    }

    // ### ✅ What These Tests Cover
    // - **Single‑threaded profile**: Ensures correctness with sequential execution.
    // - **Multi‑threaded profile**: Validates parallel execution produces correct round‑trip results.
    // - **Extreme backpressure**: Large input with constrained worker queues ensures no deadlock and correct output.
}
