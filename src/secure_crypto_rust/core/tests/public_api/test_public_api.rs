// ## 🧪 Test File: `secure_crypto_rust/core/tests/public_api/test_public_api.rs`

#[cfg(test)]
mod tests {
    use crypto_core::{compression::CompressionCodec, headers::{AadDomain, AlgProfile, CipherSuite, HeaderV1, HkdfPrf, Strategy}, stream_v2::{InputSource, OutputSink, core::{ApiConfig, DecryptParams, EncryptParams}, decrypt_stream_v2, encrypt_stream_v2}, types::StreamError};

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
    fn roundtrip_memory_output() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = b"hello world".to_vec();

        let snapshot_enc = encrypt_stream_v2(
            InputSource::Memory(plaintext.clone()),
            OutputSink::Memory,
            &master_key,
            params.clone(),
            config.clone(),
        ).expect("encryption should succeed");

        let ciphertext = snapshot_enc.output.expect("ciphertext should be captured");

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
    fn detects_corrupted_ciphertext() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = vec![0xAB; 1024];
        let snapshot_enc = encrypt_stream_v2(
            InputSource::Memory(plaintext),
            OutputSink::Memory,
            &master_key,
            params,
            config.clone(),
        ).unwrap();

        let mut ciphertext = snapshot_enc.output.unwrap();
        ciphertext[HeaderV1::LEN + 10] ^= 0xFF; // flip a byte

        let err = decrypt_stream_v2(
            InputSource::Memory(ciphertext),
            OutputSink::Memory,
            &master_key,
            DecryptParams,
            config,
        ).unwrap_err();

        matches!(err, StreamError::SegmentWorker(_));
    }
}