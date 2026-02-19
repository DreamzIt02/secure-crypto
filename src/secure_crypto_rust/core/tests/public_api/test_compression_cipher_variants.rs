// ## 🧪 Test File: `secure_crypto_rust/core/tests/public_api/test_compression_cipher_variants.rs`

#[cfg(test)]
mod tests {
    use crypto_core::{compression::{CompressionCodec, codec_ids}, constants::{cipher_ids, prf_ids}, headers::{AadDomain, AlgProfile, CipherSuite, HeaderV1, HkdfPrf, Strategy}, stream_v2::{InputSource, OutputSink, core::{ApiConfig, DecryptParams, EncryptParams, MasterKey}, decrypt_stream_v2, encrypt_stream_v2}};

    fn dummy_master_key() -> MasterKey {
        MasterKey::new(vec![0x11; 32]) // 256‑bit dummy key
    }

    fn base_header() -> HeaderV1 {
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

    fn run_roundtrip_with_header(header: HeaderV1, plaintext: Vec<u8>) {
        let master_key = dummy_master_key();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None, None, None );

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
    fn compression_disabled_auto() {
        let mut header = base_header();
        header.compression = codec_ids::AUTO;
        run_roundtrip_with_header(header, b"no compression test".to_vec());
    }

    #[test]
    fn compression_enabled_zstd() {
        let mut header = base_header();
        header.compression = codec_ids::ZSTD;
        run_roundtrip_with_header(header, b"zstd compression test".to_vec());
    }

    #[test]
    fn compression_enabled_lz4() {
        let mut header = base_header();
        header.compression = codec_ids::LZ4;
        run_roundtrip_with_header(header, b"lz4 compression test".to_vec());
    }

    #[test]
    fn cipher_aes256_gcm() {
        let mut header = base_header();
        header.cipher = cipher_ids::AES256_GCM;
        run_roundtrip_with_header(header, b"aes256-gcm cipher test".to_vec());
    }

    #[test]
    fn cipher_chacha20_poly1305() {
        let mut header = base_header();
        header.cipher = cipher_ids::CHACHA20_POLY1305;
        run_roundtrip_with_header(header, b"chacha20-poly1305 cipher test".to_vec());
    }

    #[test]
    fn prf_sha256() {
        let mut header = base_header();
        header.hkdf_prf = prf_ids::SHA256;
        run_roundtrip_with_header(header, b"sha256 prf test".to_vec());
    }

    #[test]
    fn prf_blake3k() {
        let mut header = base_header();
        header.hkdf_prf = prf_ids::BLAKE3K;
        run_roundtrip_with_header(header, b"blake3k prf test".to_vec());
    }

    // ### ✅ What These Tests Cover
    // - **Compression**: Disabled (`AUTO`), enabled (`ZSTD`, `LZ4`).
    // - **Cipher suites**: AES‑256‑GCM vs ChaCha20‑Poly1305.
    // - **PRFs**: SHA‑256 vs BLAKE3K.
}
