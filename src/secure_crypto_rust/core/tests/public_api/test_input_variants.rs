// ## 🧪 Test File: `secure_crypto_rust/core/tests/public_api/test_input_variants.rs`

#[cfg(test)]
mod tests {
    use crypto_core::{compression::CompressionCodec, headers::{AadDomain, AlgProfile, CipherSuite, HeaderV1, HkdfPrf, Strategy}, stream_v2::{InputSource, OutputSink, core::{ApiConfig, DecryptParams, EncryptParams}, decrypt_stream_v2, encrypt_stream_v2}};

    use std::fs;
    use std::io::Cursor;
    use tempfile::NamedTempFile;

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
    fn roundtrip_memory_input() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = b"hello from memory".to_vec();

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
    fn roundtrip_file_input() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = b"hello from file".to_vec();

        // Write plaintext to a temp file
        let tmpfile = NamedTempFile::new().unwrap();
        fs::write(tmpfile.path(), &plaintext).unwrap();

        // Encrypt from file input
        let snapshot_enc = encrypt_stream_v2(
            InputSource::File(tmpfile.path().to_path_buf()),
            OutputSink::Memory,
            &master_key,
            params.clone(),
            config.clone(),
        ).unwrap();

        let ciphertext = snapshot_enc.output.unwrap();

        // Decrypt back
        let snapshot_dec = decrypt_stream_v2(
            InputSource::Memory(ciphertext),
            OutputSink::Memory,
            &master_key,
            DecryptParams,
            config,
        ).unwrap();

        assert_eq!(snapshot_dec.bytes_plaintext, plaintext.len() as u64);
    }

    #[test]
    fn roundtrip_reader_input() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = b"hello from reader".to_vec();
        let cursor = Cursor::new(plaintext.clone());

        let snapshot_enc = encrypt_stream_v2(
            InputSource::Reader(Box::new(cursor)),
            OutputSink::Memory,
            &master_key,
            params.clone(),
            config.clone(),
        ).unwrap();

        let ciphertext = snapshot_enc.output.unwrap();

        let snapshot_dec = decrypt_stream_v2(
            InputSource::Memory(ciphertext),
            OutputSink::Memory,
            &master_key,
            DecryptParams,
            config,
        ).unwrap();

        assert_eq!(snapshot_dec.bytes_plaintext, plaintext.len() as u64);
    }
}
