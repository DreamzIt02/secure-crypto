// It covers round‑trip encoding/decoding, buffer length errors, field integrity, and edge cases. 

#[cfg(test)]
mod tests {

    use crypto_core::{
        constants::{HEADER_V1, MAGIC_RSE1}, 
        headers::{CipherSuite, HEADER_LEN_V1, HeaderError, HeaderV1, HkdfPrf, decode_header_le, encode_header_le}
    };

    #[test]
    fn encode_decode_roundtrip_preserves_fields() {
        let h = HeaderV1::test_header();
        let buf = encode_header_le(&h).expect("encode ok");
        assert_eq!(buf.len(), HEADER_LEN_V1);

        let decoded = decode_header_le(&buf).expect("decode ok");
        assert_eq!(decoded, h);
    }

    #[test]
    fn encode_produces_exact_length() {
        let h = HeaderV1::test_header();
        let buf = encode_header_le(&h).unwrap();
        assert_eq!(buf.len(), HEADER_LEN_V1);
    }

    #[test]
    fn decode_fails_on_short_buffer() {
        let buf = vec![0u8; HEADER_LEN_V1 - 1];
        let err = decode_header_le(&buf).unwrap_err();
        match err {
            HeaderError::BufferTooShort { have, need } => {
                assert_eq!(have, HEADER_LEN_V1 - 1);
                assert_eq!(need, HEADER_LEN_V1);
            }
            _ => panic!("unexpected error: {:?}", err),
        }
    }

    #[test]
    fn decode_succeeds_on_exact_length_buffer() {
        let h = HeaderV1::test_header();
        let buf = encode_header_le(&h).unwrap();
        let decoded = decode_header_le(&buf).unwrap();
        assert_eq!(decoded.magic, MAGIC_RSE1);
        assert_eq!(decoded.version, HEADER_V1);
        assert_eq!(decoded.cipher, CipherSuite::Chacha20Poly1305 as u16);
        assert_eq!(decoded.hkdf_prf, HkdfPrf::Sha256 as u16);
        assert_eq!(decoded.salt, [0xA5; 16]);
        assert_eq!(decoded.reserved, [0u8; 8]);
    }

    #[test]
    fn encode_and_decode_with_zeroed_fields() {
        let h = HeaderV1::default();
        let buf = encode_header_le(&h).unwrap();
        let decoded = decode_header_le(&buf).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn encode_and_decode_with_max_values() {
        let mut h = HeaderV1::default();
        h.magic = [0xFF; 4];
        h.version = u16::MAX;
        h.alg_profile = u16::MAX;
        h.cipher = u16::MAX;
        h.hkdf_prf = u16::MAX;
        h.compression = u16::MAX;
        h.strategy = u16::MAX;
        h.aad_domain = u16::MAX;
        h.flags = u16::MAX;
        h.chunk_size = u32::MAX;
        h.plaintext_size = u64::MAX;
        h.crc32 = u32::MAX;
        h.dict_id = u32::MAX;
        h.salt = [0xFF; 16];
        h.key_id = u32::MAX;
        h.parallel_hint = u32::MAX;
        h.enc_time_ns = u64::MAX;
        h.reserved = [0xFF; 8];

        let buf = encode_header_le(&h).unwrap();
        let decoded = decode_header_le(&buf).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn decode_fails_if_buffer_truncated_mid_field() {
        let h = HeaderV1::test_header();
        let buf = encode_header_le(&h).unwrap();
        let truncated = &buf[..40]; // cut in middle of salt
        let err = decode_header_le(truncated).unwrap_err();
        match err {
            HeaderError::BufferTooShort { have, need } => {
                assert!(have < need);
                assert_eq!(need, HEADER_LEN_V1);
            }
            _ => panic!("unexpected error: {:?}", err),
        }
    }
}

// ### Coverage provided
// - **encode/decode roundtrip**: ensures all fields survive serialization.
// - **length correctness**: buffer size matches `HEADER_LEN_V1`.
// - **short buffer error**: verifies `BufferTooShort` is raised.
// - **field integrity**: checks specific fields decode correctly.
// - **zeroed header**: default values roundtrip.
// - **max values**: stress test with all fields at maximum.
// - **truncated mid‑field**: ensures partial buffers fail.

