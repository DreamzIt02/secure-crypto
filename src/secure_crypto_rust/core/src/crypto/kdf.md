# **`kdf.rs`**

## 🔑 Why `kdf.rs` is Necessary

- **Session key derivation**: We must never use the master key directly for AEAD or stream encryption. Deriving per‑stream/session keys via HKDF is industry standard (TLS 1.3, QUIC).
- **Salt binding**: Each stream gets a random salt, ensuring uniqueness and forward secrecy.
- **Protocol identity binding**: The `info` string ties the derived key to our protocol configuration (magic, version, cipher, flags, etc.), preventing cross‑protocol misuse.
- **PRF flexibility**: We support multiple PRFs (`SHA256`, `SHA512`, `BLAKE3K`). This allows algorithm agility and future upgrades.

Without `kdf.rs`, our pipeline would be insecure: all streams would share the same master key material, making replay and cross‑stream compromise trivial.

---

## ✅ Benefits of This Refactor

- **Blake3**: Uses official `derive_key` API (domain‑separated, safe).  
- **SHA3**: Adds HKDF with `Sha3_256` and `Sha3_512`.  
- **Error handling**: Clear, per‑PRF error messages.  
- **Compatibility**: Works if all crypto crates (`sha2`, `sha3`, `hkdf`) are pinned to the same `digest = 0.10` line.

---

### ✅ What’s Fixed

- **Digest version mismatch**: All crates (`hkdf`, `sha2`, `sha3`) are now on `digest = 0.11`, so trait bounds are satisfied.
- **Blake3**: Uses official `derive_key` API with a domain separation string.
- **SHA3**: Adds HKDF with `Sha3_256` and `Sha3_512`.
- **Error handling**: Clear, per‑PRF error messages.
- **Salt validation**: Rejects all‑zero salt.

---
