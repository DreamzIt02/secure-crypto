# Advanced fixed-length header for industry-grade streaming encryption

This header is designed for portability, future-proofing, and high-assurance operations. It encodes crypto, strategy, integrity, and key-management signals while remaining parseable cross-language. Fixed length ensures deterministic IO and easy embedding in containers and transports.

---

## Objectives

- **Security:** Bind all critical parameters via AAD; ensure nonce uniqueness; enable key rotation and recovery out-of-band.
- **Streaming correctness:** Self-describe frame structure, strategy, and ordering without relying on totals or footers.
- **Interoperability:** Use explicit enums and IDs; keep fields stable across Rust and future bindings.
- **Observability:** Provide optional telemetry hints without affecting correctness.
- **Future-proofing:** Reserve space and versioning for evolution without breaking old streams.

---

## Field overview

- **Magic:** Format identification and quick rejection of mismatches.
- **Versioning:** Protocol and algorithm profile version to avoid silent incompatibility.
- **Crypto suite:** Cipher and PRF/HKDF identifiers for deterministic key/nonce derivation parity.
- **Compression:** Codec registry ID, dictionary hints.
- **Strategy:** Sequential, parallel, or auto; encoder metadata, decoder may choose parallel execution.
- **Flags:** Presence bits for optional header values; do not infer from zero.
- **Chunk control:** Declares target frame size; last frame may be shorter.
- **Optional metadata:** Plaintext_len and CRC32 if provided by params; otherwise 0.
- **Key management:** Key ID to locate master key; not a secret itself.
- **Nonce base:** Salt for HKDF and per-frame nonce derivation; random per stream.
- **AAD domain:** Short ID to bind header semantics into frame AAD and avoid cross-protocol confusion.
- **Telemetry hints:** Suggested parallelism, encoder wall-clock nanos for benchmarking (optional).
- **Reserved:** Zeroed bytes for future fields like signing, digest types, or policy markers.

---

## 80-byte header layout (recommended)

| Offset | Size | Field | Description |
|-------:|-----:|-------|-------------|
| 0 | 4 | **Magic** | e.g., b"RSE1" |
| 4 | 2 | **Protocol version** | Header/envelope version |
| 6 | 2 | **Algorithm profile** | Bundle ID (cipher + HKDF PRF) |
| 8 | 2 | **Cipher suite** | Enum (AES‑256‑GCM, ChaCha20‑Poly1305) |
| 10 | 2 | **HKDF PRF** | Enum (SHA‑256, SHA‑512, BLAKE3 keyed) |
| 12 | 2 | **Compression type** | Enum (None, Zstd, LZ4, Deflate) |
| 14 | 2 | **Strategy** | Sequential/Parallel/Auto |
| 16 | 2 | **AAD domain** | Small ID to bind AAD context (e.g., 0x0001) |
| 18 | 2 | **Flags** | Bitmask (HAS_TOTAL_LEN, HAS_CRC32, …) |
| 20 | 4 | **Chunk size** | Target plaintext bytes per frame |
| 24 | 8 | **Plaintext size** | 0 if unknown |
| 32 | 4 | **CRC32** | 0 if not provided |
| 36 | 4 | **Dict ID** | Compression dictionary ID |
| 40 | 16 | **Salt (nonce base)** | Random per stream |
| 56 | 4 | **Key ID** | Master key registry reference |
| 60 | 4 | **Parallelism hint** | 0 if none (e.g., worker count) |
| 64 | 8 | **Encoder time ns** | Optional monotonic timestamp |
| 72 | 8 | **Reserved** | Future use; zeroed |
| — | — | **Total: 80 bytes** | Fixed-length |

> Notes
> ---
> The 80‑byte plan buys clarity and future space.

---

## Flag bits

- **HAS_TOTAL_LEN:** 0x0001 — plaintext_size is meaningful.
- **HAS_CRC32:** 0x0002 — crc32 is meaningful.
- **HAS_TERMINATOR:** 0x0004 — stream ends with authenticated terminator frame.
- **HAS_FINAL_DIGEST:** 0x0008 — final authenticated digest frame will follow.
- **DICT_USED:** 0x0010 — compression uses external dictionary.
- **AAD_STRICT:** 0x0020 — decoder must enforce exact AAD domain match.

Keep a single source-of-truth constants module to avoid drift.

---

## Rust struct sketch

```rust
#[repr(C)]
pub struct HeaderV1 {
    pub magic: [u8; 4],        // "RSE1"
    pub version: u16,          // protocol version
    pub alg_profile: u16,      // bundle id (cipher + PRF choice)
    pub cipher: u16,           // cipher enum
    pub hkdf_prf: u16,         // PRF enum
    pub compression: u16,      // compression enum
    pub strategy: u16,         // sequential / parallel / auto
    pub aad_domain: u16,       // binds AAD context
    pub flags: u16,            // bitmask
    pub chunk_size: u32,       // frame size
    pub plaintext_size: u64,   // 0 if unknown
    pub crc32: u32,            // 0 if not provided
    pub dict_id: u32,          // compression dictionary id
    pub salt: [u8; 16],        // nonce base
    pub key_id: u32,           // master key id
    pub parallel_hint: u32,    // suggested worker count (optional)
    pub enc_time_ns: u64,      // optional timestamp for telemetry
    pub reserved: [u8; 8],     // future fields; zeroed
}
```

---

## Decoder behavior

- **Chunk size, strategy, compression:** Read from header; never require external params.
- **Nonce derivation:** HKDF/session key from master_key + salt; per-frame nonce from (salt, frame_index).
- **AAD composition:** Include magic, version, alg_profile, cipher, hkdf_prf, compression, strategy, flags, aad_domain, chunk_size, key_id, and frame_index. This prevents cross-protocol confusion and undetected reordering/truncation.
- **Totals/CRC:** Ignore for correctness; use only if flags indicate presence.
- **Terminator/digest frames:** If enabled by flags, expect and authenticate them; otherwise, EOF after last data frame is valid.

---

## Industry-aligned rationale

- **Key ID and versioning** mirror enterprise/HSM practices for rotation without embedding secrets.
- **Explicit cipher and PRF identifiers** avoid silent incompatibility and allow HKDF upgrades.
- **Per-stream nonce base** ensures uniqueness across streams, matching AEAD best practices.
- **AAD domain** prevents blending streams from different contexts (e.g., file vs pipe vs archive envelope).
- **Strategy and telemetry** support performance engineering and reproducible benchmarking across environments.
- **Fixed-length with reserved space** ensures we can introduce new checks (e.g., signing, attestation, digest types) later with protocol version bumps while staying parseable.

---

## 🧭 Dependency Direction (HEADERS)

```text
constants.rs
   ↑
types.rs
   ↑
headers     →     compression
```
