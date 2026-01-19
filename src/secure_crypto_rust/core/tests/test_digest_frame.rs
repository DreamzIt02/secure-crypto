

// ## 🧪 Test Suite for Digest Frame Validation

#[cfg(test)]
mod tests {
    use crypto_core::{crypto::{DigestAlg, DigestError, DigestFrame}, stream_v2::{frame_worker::{FrameInput, FrameWorkerError}, framing::FrameType}};

    fn make_digest_frame(alg: DigestAlg, digest: &[u8]) -> FrameInput {
        // let mut buf = Vec::new();
        // buf.extend_from_slice(&(alg as u16).to_le_bytes()); // alg_id
        // buf.extend_from_slice(&(digest.len() as u16).to_le_bytes()); // length
        // buf.extend_from_slice(digest); // digest bytes
        let digest_frame = DigestFrame {
            algorithm: alg,
            digest: digest.to_vec(),
        };

        let digest_plaintext = digest_frame.encode();
        FrameInput {
            frame_type: FrameType::Digest,
            segment_index: 0,
            frame_index: 0,
            plaintext: digest_plaintext,
        }
    }
    #[test]
    fn digest_frame_roundtrip() {
        let digest = vec![0xAA; 32];
        let frame = DigestFrame { algorithm: DigestAlg::Sha256, digest: digest.clone() };

        let encoded = frame.encode();
        let decoded = DigestFrame::decode(&encoded).unwrap();

        assert_eq!(decoded.algorithm, DigestAlg::Sha256);
        assert_eq!(decoded.digest, digest);
    }
    #[test]
    fn digest_frame_valid_sha256() {
        let digest = vec![0xAA; 32];
        let frame = make_digest_frame(DigestAlg::Sha256, &digest);
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn digest_frame_valid_sha512() {
        let digest = vec![0xBB; 64];
        let frame = make_digest_frame(DigestAlg::Sha512, &digest);
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn digest_frame_valid_blake3() {
        let digest = vec![0xCC; 32];
        let frame = make_digest_frame(DigestAlg::Blake3, &digest);
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn digest_frame_too_short_fails() {
        let frame = FrameInput {
            frame_type: FrameType::Digest,
            segment_index: 0,
            frame_index: 0,
            plaintext: vec![0x01, 0x02], // only 2 bytes
        };
        let err = frame.validate().unwrap_err();
        assert!(matches!(err, FrameWorkerError::InvalidInput(msg) if msg.contains("too short")));
    }

    #[test]
    fn digest_frame_invalid_length_field_fails() {
        // Declared length 32, but only 16 bytes provided
        let mut buf = Vec::new();
        buf.extend_from_slice(&(DigestAlg::Sha256 as u16).to_be_bytes());
        buf.extend_from_slice(&(32u16).to_be_bytes());
        buf.extend_from_slice(&vec![0xDD; 16]);
        let frame = FrameInput {
            frame_type: FrameType::Digest,
            segment_index: 0,
            frame_index: 0,
            plaintext: buf,
        };
        let err = DigestFrame::decode(&frame.plaintext).unwrap_err();
        assert!(matches!(
            err,
            DigestError::InvalidLength { .. }
        ));
    }

    #[test]
    fn digest_frame_unknown_algorithm_fails() {
        // alg_id = 0x9999 (unknown)
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x9999u16.to_be_bytes());
        buf.extend_from_slice(&(4u16).to_be_bytes());
        buf.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let frame = FrameInput {
            frame_type: FrameType::Digest,
            segment_index: 0,
            frame_index: 0,
            plaintext: buf,
        };
        let err = DigestFrame::decode(&frame.plaintext).unwrap_err();
         assert!(matches!(
            err,
            DigestError::UnknownAlgorithm { .. }
        ));
    }
}

// ### Coverage

// - ✅ Valid digest frames for **Sha256**, **Sha512**, **Blake3**.
// - ✅ Too short plaintext (less than 4 bytes).
// - ✅ Declared length mismatch.
// - ✅ Unknown algorithm ID.
