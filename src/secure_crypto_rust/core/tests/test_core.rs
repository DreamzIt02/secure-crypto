#[cfg(test)]
mod tests {
    use crypto_core::{
        constants::{MAGIC_DICT, MIN_DICT_LEN}, 
        headers::HeaderV1, 
        stream_v2::{
            InputSource, OutputSink, 
            core::{ApiConfig, DecryptParams, EncryptParams, decrypt_stream_v2, encrypt_stream_v2, validate_decrypt_params, validate_dictionary, validate_encrypt_params}, 
    }};

    fn dummy_master_key() -> Vec<u8> {
        vec![0x11u8; 32] // valid 32-byte key
    }

    fn dummy_header() -> HeaderV1 {
        HeaderV1 {
            chunk_size: 64 * 1024,
            // fill in other required fields with defaults or dummy values
            ..HeaderV1::test_header()
        }
    }

    // --- Validation Tests ---

    #[test]
    fn validate_encrypt_params_with_valid_key_and_defaults() {
        let params = EncryptParams {
            header: dummy_header(),
            dict: None,
        };
        let result = validate_encrypt_params(&dummy_master_key(), &params, None, None);
        assert!(result.is_ok(), "Expected valid params to pass");
    }

    #[test]
    fn validate_encrypt_params_with_invalid_key_len() {
        let params = EncryptParams {
            header: dummy_header(),
            dict: None,
        };
        let bad_key = vec![0x22u8; 15]; // invalid length
        let result = validate_encrypt_params(&bad_key, &params, None, None);
        assert!(result.is_err(), "Expected invalid master key length error");
    }

    #[test]
    fn validate_decrypt_params_with_valid_key_and_defaults() {
        let params = DecryptParams;
        let result = validate_decrypt_params(&dummy_master_key(), &params, None, None);
        assert!(result.is_ok(), "Expected valid decrypt params to pass");
    }

    #[test]
    fn validate_dictionary_none_and_empty() {
        assert!(validate_dictionary(None).is_ok());
        assert!(validate_dictionary(Some(&[])).is_ok());
    }

    #[test]
    fn validate_dictionary_invalid_payload() {
        let bad_dict = vec![0x00u8; MIN_DICT_LEN];
        assert!(validate_dictionary(Some(&bad_dict)).is_err());
    }

    #[test]
    fn validate_dictionary_valid_payload() {
        let mut dict = MAGIC_DICT.to_vec();
        dict.resize(MIN_DICT_LEN, 0xAA);
        assert!(validate_dictionary(Some(&dict)).is_ok());
    }

    // --- Encrypt/Decrypt Pipeline Tests ---
    #[test]
    fn encrypt_and_decrypt_roundtrip_minimal() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header: header.clone(), dict: None };
        let config = ApiConfig::new(Some(true), None);

        let plaintext = vec![0x55u8; 1024];
        let input = InputSource::Memory(plaintext.clone());

        // Encrypt
        // let (cursor, _) = open_output_cursor(OutputSink::Memory).unwrap();
        let snapshot_enc = encrypt_stream_v2(
            input, 
            OutputSink::Memory, 
            &master_key, 
            params.clone(), 
            config.clone()
        )
        .expect("encryption should succeed");

        // Recover the buffer from the cursor the pipeline wrote into
        let ciphertext = snapshot_enc.output.unwrap();

        // Assert header is present
        println!("Ciphertext LEN: {}", ciphertext.len());
        assert!(ciphertext.len() >= HeaderV1::LEN, "Ciphertext missing stream header");
        eprintln!(
            "[TEST] Ciphertext length = {}, header prefix = {:?}",
            ciphertext.len(),
            &ciphertext[..HeaderV1::LEN]
        );

        // Decrypt
        let input_dec = InputSource::Memory(ciphertext.clone());
        let snapshot_dec = decrypt_stream_v2(
            input_dec, 
            OutputSink::Memory, 
            &master_key, 
            DecryptParams, 
            config
        )
        .expect("decryption should succeed");

        assert_eq!(snapshot_dec.bytes_plaintext, plaintext.len() as u64);
    }

    #[test]
    fn encrypt_and_decrypt_roundtrip() {
        let master_key = dummy_master_key();
        let header = dummy_header();
        let params = EncryptParams { header: header.clone(), dict: None };
        let config = ApiConfig::new(Some(true), None);

        let plaintext = vec![0x55u8; 1024]; // 1 KiB of data
        let input = InputSource::Memory(plaintext.clone());
        let output = OutputSink::Memory;

        // Encrypt
        let snapshot_enc = encrypt_stream_v2(input, output, &master_key, params.clone(), config.clone())
            .expect("encryption should succeed");

        assert!(snapshot_enc.bytes_plaintext >= 1024);

        // Decrypt
        let input_dec = InputSource::Memory(snapshot_enc.output.clone().unwrap());
        let output_dec = OutputSink::Memory;
        let snapshot_dec = decrypt_stream_v2(input_dec, output_dec, &master_key, DecryptParams, config)
            .expect("decryption should succeed");

        assert_eq!(snapshot_dec.bytes_plaintext, 1024);
    }

    #[test]
    fn encrypt_stream_with_invalid_key_should_fail() {
        let bad_key = vec![0x33u8; 15]; // invalid length
        let header = dummy_header();
        let params = EncryptParams { header, dict: None };
        let config = ApiConfig::new(Some(true), None);

        let plaintext = vec![0x44u8; 512];
        let input = InputSource::Memory(plaintext);
        let output = OutputSink::Memory;

        let result = encrypt_stream_v2(input, output, &bad_key, params, config);
        assert!(result.is_err(), "Expected encryption to fail with invalid key");
    }

    #[test]
    fn decrypt_stream_with_invalid_key_should_fail() {
        let bad_key = vec![0x33u8; 16]; // invalid length
        let input = InputSource::Memory(vec![0x99u8; 128]);
        let output = OutputSink::Memory;
        let config = ApiConfig::new(Some(true), None);

        let result = decrypt_stream_v2(input, output, &bad_key, DecryptParams, config);
        assert!(result.is_err(), "Expected decryption to fail with invalid key");
    }
}
