// 📂 File: tests/test_aead_bench.rs

use std::time::Instant;
use crypto_core::{constants::cipher_ids, crypto::{AeadImpl, CryptoError, NONCE_LEN_12}, headers::HeaderV1};
use rand::Rng;

#[test]
fn test_aead_roundtrip() -> Result<(), CryptoError> {
    let key = [0u8; 32]; // 256-bit key
    let nonce = [1u8; NONCE_LEN_12];
    let aad = b"benchmark-aad";
    let plaintext = b"hello world, AEAD test!";

    // AES-GCM
    let header = HeaderV1 { cipher: cipher_ids::AES256_GCM, ..Default::default() };
    let aes = AeadImpl::from_header_and_key(&header, &key)?;
    let ciphertext = aes.seal(&nonce, aad, plaintext)?;
    let recovered = aes.open(&nonce, aad, &ciphertext)?;
    assert_eq!(plaintext.to_vec(), recovered);

    // ChaCha20-Poly1305
    let header = HeaderV1 { cipher: cipher_ids::CHACHA20_POLY1305, ..Default::default() };
    let chacha = AeadImpl::from_header_and_key(&header, &key)?;
    let ciphertext = chacha.seal(&nonce, aad, plaintext)?;
    let recovered = chacha.open(&nonce, aad, &ciphertext)?;
    assert_eq!(plaintext.to_vec(), recovered);

    Ok(())
}

#[test]
fn bench_aead_encrypt_decrypt() -> Result<(), CryptoError> {
    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();
    let nonce: [u8; NONCE_LEN_12] = rng.gen();
    let aad = b"benchmark-aad";
    let plaintext: Vec<u8> = vec![0u8; 32 * 1024 * 1024]; // 32 MB random input

    for &cipher_id in &[cipher_ids::AES256_GCM, cipher_ids::CHACHA20_POLY1305] {
        let header = HeaderV1 { cipher: cipher_id, ..Default::default() };
        let aead = AeadImpl::from_header_and_key(&header, &key)?;

        let start = Instant::now();
        let ciphertext = aead.seal(&nonce, aad, &plaintext)?;
        let enc_time = start.elapsed();

        let start = Instant::now();
        let recovered = aead.open(&nonce, aad, &ciphertext)?;
        let dec_time = start.elapsed();

        assert_eq!(plaintext, recovered);

        println!(
            "Cipher {:?}: encrypt={:?}, decrypt={:?}, throughput={:.2} MB/s",
            cipher_id,
            enc_time,
            dec_time,
            (plaintext.len() as f64 / (enc_time.as_secs_f64() * 1024.0 * 1024.0))
        );
    }

    Ok(())
}

// ### What this does
// - **`test_aead_roundtrip`**: sanity check that both AES‑GCM and ChaCha20‑Poly1305 encrypt/decrypt correctly.
// - **`bench_aead_encrypt_decrypt`**: runs a 32 MB benchmark, prints encryption/decryption times and throughput in MB/s.

// ### Notes
// - Use `cargo test -- --nocapture` to see the printed benchmark results.
// - For more rigorous benchmarking, integrate with `criterion` crate, which gives statistical analysis (mean, median, MAD, R²).
// - If we want to add **XChaCha20‑Poly1305** or experimental **Blake3‑AEAD**, we can extend the `CipherSuite` enum and plug them into the same harness.
