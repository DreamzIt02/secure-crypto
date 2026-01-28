// ## 📘 Full Test Suite for `HeaderV1`

#[cfg(test)]
mod tests {
    use crypto_core::{constants::{MAX_CHUNK_SIZE, flags}, headers::{HeaderError, HeaderV1, decode_header_le, encode_header_le}};

    // fn make_valid_header() -> HeaderV1 {
    //     HeaderV1 {
    //         magic: MAGIC_RSE1,
    //         version: HEADER_V1,
    //         alg_profile: AlgProfile::Chacha20Poly1305HkdfSha256 as u16,
    //         cipher: CipherSuite::Chacha20Poly1305 as u16,
    //         hkdf_prf: HkdfPrf::Sha256 as u16,
    //         compression: CompressionCodec::Auto as u16,
    //         strategy: Strategy::Sequential as u16,
    //         aad_domain: AadDomain::Generic as u16,
    //         flags: 0,
    //         chunk_size: DEFAULT_CHUNK_SIZE as u32,
    //         plaintext_size: 1234,
    //         crc32: 0, // will be filled by encode
    //         dict_id: 0,
    //         salt: [0xA5; 16],
    //         key_id: 42,
    //         parallel_hint: 0,
    //         enc_time_ns: 987654321,
    //         reserved: [0u8; 8],
    //     }
    // }
    fn make_valid_header() -> HeaderV1 {
        HeaderV1::test_header()
    }

    #[test]
    fn roundtrip_encode_decode() {
        let header = make_valid_header();
        let encoded = encode_header_le(&header).expect("encode ok");
        let decoded = decode_header_le(&encoded).expect("decode ok");
        assert_eq!(header.magic, decoded.magic);
        assert_eq!(header.version, decoded.version);
        assert_eq!(header.alg_profile, decoded.alg_profile);
        assert_eq!(header.cipher, decoded.cipher);
        assert_eq!(header.hkdf_prf, decoded.hkdf_prf);
        assert_eq!(header.compression, decoded.compression);
        assert_eq!(header.strategy, decoded.strategy);
        assert_eq!(header.aad_domain, decoded.aad_domain);
        assert_eq!(header.flags, decoded.flags);
        assert_eq!(header.chunk_size, decoded.chunk_size);
        assert_eq!(header.plaintext_size, decoded.plaintext_size);
        assert_eq!(header.dict_id, decoded.dict_id);
        assert_eq!(header.salt, decoded.salt);
        assert_eq!(header.key_id, decoded.key_id);
        assert_eq!(header.parallel_hint, decoded.parallel_hint);
        assert_eq!(header.enc_time_ns, decoded.enc_time_ns);
        assert_eq!(header.reserved, decoded.reserved);
        // CRC must match
        assert_eq!(decoded.crc32, crc32fast::hash(&encoded[0..32]));
    }

    #[test]
    fn detects_corrupted_crc32() {
        let header = make_valid_header();
        let mut encoded = encode_header_le(&header).unwrap();
        // Flip a byte in the magic field
        encoded[0] ^= 0xFF;
        let err = decode_header_le(&encoded).unwrap_err();
        match err {
            HeaderError::InvalidCrc32 { .. } => {} // expected
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn detects_buffer_too_short() {
        let buf = vec![0u8; HeaderV1::LEN - 1]; // too short
        let err = decode_header_le(&buf).unwrap_err();
        match err {
            HeaderError::BufferTooShort { .. } => {} // expected
            _ => panic!("unexpected error: {err:?}"),
        }
    }
    #[test]
    fn detects_invalid_magic() {
        let mut header = make_valid_header();
        header.magic = *b"BAD!";
        let err = header.validate().unwrap_err();
        match err {
            HeaderError::InvalidMagic { .. } => {} // expected
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn detects_invalid_chunk_size() {
        let mut header = make_valid_header();
        header.chunk_size = 0; // invalid
        let err = header.validate().unwrap_err();
        match err {
            HeaderError::InvalidChunkSizeZero => {} // expected
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn detects_reserved_bytes_nonzero() {
        let mut header = make_valid_header();
        header.reserved = [1u8; 8];
        let err = header.validate().unwrap_err();
        match err {
            HeaderError::ReservedBytesNonZero { .. } => {} // expected
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    // ## ⚖️ Coverage
    // - ✅ Round‑trip encode/decode correctness.
    // - ✅ CRC32 mismatch detection.
    // - ✅ Buffer too short.
    // - ✅ Invalid magic.
    // - ✅ Invalid chunk size.
    // - ✅ Reserved bytes non‑zero.

    // ## 🔧 Additional Tests

    #[test]
    fn detects_invalid_chunk_size_zero() {
        let mut header = make_valid_header();
        header.chunk_size = 0;
        let err = header.validate().unwrap_err();
        match err {
            HeaderError::InvalidChunkSizeZero => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn detects_invalid_chunk_size_too_large() {
        let mut header = make_valid_header();
        header.chunk_size = (MAX_CHUNK_SIZE as u32) + 1;
        let err = header.validate().unwrap_err();
        match err {
            HeaderError::InvalidChunkSizeTooLarge { .. } => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn detects_invalid_salt_all_zero() {
        let mut header = make_valid_header();
        header.salt = [0u8; 16];
        let err = header.validate().unwrap_err();
        match err {
            HeaderError::InvalidSalt { .. } => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn detects_dict_used_but_missing_id() {
        let mut header = make_valid_header();
        header.flags |= flags::DICT_USED;
        header.dict_id = 0;
        let err = header.validate().unwrap_err();
        match err {
            HeaderError::DictUsedButMissingId => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn detects_invalid_version_zero() {
        let mut header = make_valid_header();
        header.version = 0;
        let err = header.validate().unwrap_err();
        match err {
            HeaderError::InvalidVersion { .. } => {}
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    // ## ⚖️ What’s new
    // - **Invalid chunk size too large** (beyond `MAX_CHUNK_SIZE`).
    // - **Salt all zero**.
    // - **Dict flag set but missing dict_id**.
    // - **Version zero**.
    // - All validation paths are now exercised.
}