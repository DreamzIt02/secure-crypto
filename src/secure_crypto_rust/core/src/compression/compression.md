# Plan for compression module

Compression must be locked before core streaming. We’ll design a production-ready module that offers deterministic, streaming-safe compression/decompression with explicit registries, dictionary support, and chunk-size discipline.

---

## Module layout

- src/compression/
  - mod.rs
  - errors.rs
  - constants.rs
  - registry.rs
  - traits.rs
  - codecs/
    - none.rs
    - zstd.rs
    - lz4.rs
    - deflate.rs
  - stream.rs
  - detect.rs (optional later for content-aware decisions)
  - tests.rs

---

## Objectives and invariants

- **Streaming correctness:** Compress/decompress in chunks; no frame-spanning state unless explicitly configured via dictionaries.  
- **Deterministic output:** Same input chunk → same compressed output for a given codec and settings.  
- **Explicit configuration:** Registry resolves codec by header ID; no magic defaults beyond chunk_size and sensible codec presets.  
- **Dictionary parity:** If `DICT_USED` is set, `dict_id` must be non-zero; missing dictionary is a hard error.  
- **Bounded memory:** Buffers respect header.chunk_size; last frame may be shorter; no unbounded accumulation.  
- **Cross-language parity:** Stable codec IDs, compression levels, and dictionary behavior reproducible in Python bindings.

---

## Interfaces

- **Traits (traits.rs):**
  - **Compressor:**
    - `init(codec_id: u16, level: Option<u32>, dict: Option<&[u8]>) -> Result<Self, CompressionError>`
    - `compress_chunk(input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError>`
    - `finish(out: &mut Vec<u8>) -> Result<(), CompressionError>` (flush any pending state)
  - **Decompressor:**
    - `init(codec_id: u16, dict: Option<&[u8]>) -> Result<Self, CompressionError>`
    - `decompress_chunk(input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError>`

- **Registry (registry.rs):**
  - `resolve(codec_id: u16) -> CodecInfo` with name, default level, and capabilities (supports_dict, streaming_safe).
  - `create_compressor(..) -> Box<dyn Compressor>`
  - `create_decompressor(..) -> Box<dyn Decompressor>`

- **Stream helpers (stream.rs):**
  - `compress_stream<R: Read>(r, chunk_size, compressor) -> impl Iterator<Item=Result<Vec<u8>, CompressionError>>`
  - `decompress_stream<R: Read>(r, chunk_size, decompressor) -> impl Iterator<Item=Result<Vec<u8>, CompressionError>>`
  - These helpers produce chunk-aligned outputs suitable for frames.

- **Constants (constants.rs):**
  - Stable codec IDs: None=0x0000, Zstd=0x0001, LZ4=0x0002, Deflate=0x0003.
  - Default compression levels per codec and safe bounds.

- **Errors (errors.rs):**
  - `UnsupportedCodec`, `InvalidDictionary`, `CodecInitFailed`, `CodecProcessFailed`, `ChunkTooLarge`, `StateError`.
  - Clear messages with context (codec, dict_id, chunk_size).

---

## Codecs

- **None (none.rs):**
  - Pass-through; compress_chunk copies input; finish is no-op.
  - Deterministic and trivial; used when header.compression == None.

- **Zstd (zstd.rs):**
  - Streaming encoder/decoder (zstd safe APIs).
  - Supports dictionary; level range (e.g., 1–22), with a conservative default (e.g., 6–10).
  - Deterministic encoding for given `(level, dict)`; avoid content-dependent auto parameters.

- **LZ4 (lz4.rs):**
  - Streaming encoder/decoder (frame or block mode); prefer block streaming for chunk alignment.
  - Dictionary optional; ensure dictionary parity and explicit use.

- **Deflate (deflate.rs):**
  - Streaming via flate2; levels (0–9); prefer fixed strategy variants for determinism.

> Industry notes
> ---
> For reproducibility, avoid codec “auto” modes that vary with environment.
>
> Always document level and dictionary effect; bind them into header and AAD via flags and dict_id.

---

## Dictionary management

- **External dictionary loading:** Caller provides dictionary bytes via `dict: Option<&[u8]>`.  
- **Policy:**
  - **If DICT_USED flag set:** dict must be provided; else error `InvalidDictionary`.  
  - **If DICT_USED not set:** dict must be None; registry rejects mismatched use.  
- **Dict ID parity:** Header.dict_id maps to lookup source (e.g., app-managed store); compression module only consumes bytes.

---

## Chunk-size discipline

- **Encrypt path:** Compress each plaintext chunk independently; record `comp_len_in_frame`.  
- **Decrypt path:** Decompress per frame after AEAD-open; last frame may produce fewer bytes than chunk_size.  
- **No frame-spanning state:** Default policy forbids compression across frames to preserve random access and parallel safety. If future mode permits “streaming across frames,” it must be explicitly signaled via header flags (not enabled here).

---

## Validation rules

- **Codec support:** Reject unknown codec IDs.  
- **Level bounds:** Clamp or reject out-of-range levels for determinism.  
- **Dictionary:** Enforce presence or absence per flag; validate minimal size (> 0).  
- **Chunk bounds:** Input chunk must be ≤ header.chunk_size; output should fit reasonable limits (protect against expansion attacks).

---

## Testing strategy

- **Round-trip per codec:** Compress chunks → Decompress to original for various sizes, including last short chunk.  
- **Dictionary parity:** With dict enabled, ensure compression reduces size and decompression succeeds only with the same dict.  
- **Determinism:** Same input, codec, level, dict → identical compressed output bytes.  
- **Error cases:** Unsupported codec, missing dict when flagged, invalid level, corrupted compressed data.  
- **Performance sanity:** Measure throughput and memory under large inputs to validate streaming behavior.

---

## Integration points with streaming

- **Encrypt:** `compress_chunk` invoked before AEAD seal; output becomes ciphertext input.  
- **Decrypt:** AEAD-open first; `decompress_chunk` invoked to produce plaintext.  
- **Telemetry:** Expose compressed bytes per frame for ratios and performance stats.

---

## Next step (TODO:)

- **Confirm codec set and defaults:**
  - **Zstd default level:** propose 6 (balanced).  
  - **LZ4 mode:** fast block mode, deterministic.  
  - **Deflate level:** default 6.  
  - **No dictionary by default; dictionary only when `DICT_USED` is set and dict provided.**

## 🧭 Dependency Direction (COMPRESSION)

```text
compression/constants.rs
     ↑
compression/types.rs
     ↑
compression (codecs, )
```
