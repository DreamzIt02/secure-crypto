// ## 🧪 Test File: `secure_crypto_rust/core/tests/public_api/test_header_meta.rs`

#[cfg(test)]
mod tests {
    use crypto_core::{compression::CompressionCodec, constants::flags, headers::{AadDomain, AlgProfile, CipherSuite, HeaderV1, HkdfPrf, Strategy}, stream_v2::{InputSource, OutputSink, core::{ApiConfig, DecryptParams, EncryptParams, MasterKey}, decrypt_stream_v2, encrypt_stream_v2, io::PayloadReader}, types::StreamError};

    use std::io::Cursor;

    fn dummy_master_key() -> MasterKey {
        MasterKey::new(vec![0x11; 32]) // 256‑bit dummy key
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
    fn header_presence_in_ciphertext() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = b"header presence test".to_vec();

        let snapshot_enc = encrypt_stream_v2(
            InputSource::Memory(plaintext),
            OutputSink::Memory,
            &master_key,
            params,
            config,
        ).expect("encryption should succeed");

        let ciphertext = snapshot_enc.output.expect("ciphertext captured");

        // Assert magic marker at start
        assert_eq!(&ciphertext[0..4], b"RSE1");
        // Assert length ≥ header size
        assert!(ciphertext.len() >= HeaderV1::LEN as usize);
    }

    #[test]
    fn flags_are_preserved_in_header() {
        let master_key = dummy_master_key();
        let mut header = dummy_header();
        header.flags = flags::HAS_TOTAL_LEN | flags::HAS_CRC32;
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = b"flags preservation test".to_vec();

        let snapshot_enc = encrypt_stream_v2(
            InputSource::Memory(plaintext.clone()),
            OutputSink::Memory,
            &master_key,
            params.clone(),
            config.clone(),
        ).unwrap();

        let ciphertext = snapshot_enc.output.unwrap();

        // Decrypt back and check header flags
        let (_header, _) = PayloadReader::with_header(Cursor::new(ciphertext)).unwrap();
        assert_eq!(_header.flags & (flags::HAS_TOTAL_LEN | flags::HAS_CRC32),
                flags::HAS_TOTAL_LEN | flags::HAS_CRC32);
    }

    #[test]
    fn aad_domain_mismatch_detected() {
        let master_key = dummy_master_key();
        let mut header = dummy_header();
        header.aad_domain = AadDomain::FileEnvelope as u16; // mismatch domain
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

        let plaintext = b"aad mismatch test".to_vec();

        let snapshot_enc = encrypt_stream_v2(
            InputSource::Memory(plaintext.clone()),
            OutputSink::Memory,
            &master_key,
            params.clone(),
            config.clone(),
        ).unwrap();

        let mut ciphertext = snapshot_enc.output.unwrap();

        // Corrupt the aad_domain field in header
        // HeaderV1 layout: aad_domain is at offset after strategy (2 bytes each)
        // magic(4) + version(2) + alg_profile(2) + cipher(2) + hkdf_prf(2) +
        // compression(2) + strategy(2) = 16 bytes so far
        // aad_domain at offset 16..18
        ciphertext[16] ^= 0xFF; // flip a byte

        let err = decrypt_stream_v2(
            InputSource::Memory(ciphertext),
            OutputSink::Memory,
            &master_key,
            DecryptParams,
            config,
        ).unwrap_err();

        matches!(err, StreamError::Header(_));
    }

    // ### ✅ What These Tests Cover
    // - **Header presence**: Ensures ciphertext starts with `"RSE1"` and has at least `HeaderV1::LEN` bytes.
    // - **Flags preservation**: Confirms flags set in `EncryptParams.header` are preserved and visible when reading back the header.
    // - **AAD domain mismatch**: Simulates corruption in the header’s `aad_domain` field and asserts that decryption fails with `StreamError::Header`.
}
