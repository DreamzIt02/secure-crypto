#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use crypto_core::{constants::prf_ids, crypto::derive_session_key_32, headers::types::HeaderV1};

    fn dummy_header(prf: u16, salt: [u8; 16]) -> HeaderV1 { 
        let mut header = HeaderV1::test_header();
        header.hkdf_prf = prf;
        header.salt = salt;

        header
    }

    #[test]
    fn test_sha256_derivation_changes_with_salt() {
        let master = b"masterkey";
        let h1 = dummy_header(prf_ids::SHA256, [1; 16]);
        let h2 = dummy_header(prf_ids::SHA256, [2; 16]);

        let k1 = derive_session_key_32(master, &h1).unwrap();
        let k2 = derive_session_key_32(master, &h2).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_blake3_derivation_consistency() {
        let master = b"masterkey";
        let h = dummy_header(prf_ids::BLAKE3K, [9; 16]);

        let k1 = derive_session_key_32(master, &h).unwrap();
        let k2 = derive_session_key_32(master, &h).unwrap();
        assert_eq!(k1, k2);
    }

    // Deterministic reproducibility: same inputs → same key
    #[test]
    fn test_reproducibility_sha256() {
        let master = b"masterkey";
        let header = dummy_header(prf_ids::SHA256, [1; 16]);
        let k1 = derive_session_key_32(master, &header).unwrap();
        let k2 = derive_session_key_32(master, &header).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_uniqueness_different_salts() {
        let master = b"masterkey";
        let h1 = dummy_header(prf_ids::SHA512, [1; 16]);
        let h2 = dummy_header(prf_ids::SHA512, [2; 16]);
        let k1 = derive_session_key_32(master, &h1).unwrap();
        let k2 = derive_session_key_32(master, &h2).unwrap();
        assert_ne!(k1, k2);
    }

    // Property-based fuzzing: arbitrary salts produce deterministic keys
    proptest! {
        #[test]
        fn prop_sha3_256_deterministic(salt in any::<[u8;16]>()) {
            let master = b"masterkey";
            let header = dummy_header(prf_ids::SHA3_256, salt);
            let k1 = derive_session_key_32(master, &header).unwrap();
            let k2 = derive_session_key_32(master, &header).unwrap();
            prop_assert_eq!(k1, k2);
        }

        #[test]
        fn prop_sha3_512_uniqueness(salt1 in any::<[u8;16]>(), salt2 in any::<[u8;16]>()) {
            let master = b"masterkey";
            let h1 = dummy_header(prf_ids::SHA3_512, salt1);
            let h2 = dummy_header(prf_ids::SHA3_512, salt2);
            let k1 = derive_session_key_32(master, &h1).unwrap();
            let k2 = derive_session_key_32(master, &h2).unwrap();
            if salt1 != salt2 {
                prop_assert_ne!(k1, k2);
            }
        }

        #[test]
        fn prop_blake3_deterministic(salt in any::<[u8;16]>()) {
            let master = b"masterkey";
            let header = dummy_header(prf_ids::BLAKE3K, salt);
            let k1 = derive_session_key_32(master, &header).unwrap();
            let k2 = derive_session_key_32(master, &header).unwrap();
            prop_assert_eq!(k1, k2);
        }
    }
}

// ## ✅ What This Suite Confirms

// - **Reproducibility**: Same master key + header → identical derived key.  
// - **Uniqueness**: Different salts → different derived keys.  
// - **Fuzz coverage**: Random salts across SHA3 and Blake3 confirm determinism and uniqueness.  
// - **Cross‑PRF validation**: Tests cover SHA‑256, SHA‑512, SHA3‑256, SHA3‑512, and Blake3.  
