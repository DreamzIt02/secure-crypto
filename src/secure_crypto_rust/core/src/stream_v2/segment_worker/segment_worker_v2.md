# Segment Worker V2

## 🎯 Key Changes

### 1. **Structured Error Types**

- `SegmentWorkerError` - for segment-level failures
- `FrameWorkerError` - for frame-level failures
- Using `thiserror` for clean error definitions with automatic `From` implementations

### 2. **No More Panics in Workers**

- Frame workers **always** return `Result<T, E>` via channels
- Segment workers return `Result<DecryptedSegment, SegmentWorkerError>`
- Errors propagate cleanly with `?` operator

### 3. **Extracted Processing Logic**

- `process_encrypt_segment()` - pure function that returns `Result`
- `process_decrypt_segment()` - pure function that returns `Result`
- This makes the code testable and the control flow clear

### 4. **Clean Error Propagation**

```rust
// Old way (panic gets lost)
let frame = out_rx.recv().expect("Worker hung");

// New way (error propagates to caller)
let frame_result = out_rx.recv()
    .map_err(|_| SegmentWorkerError::FrameWorkerDisconnected)?;
let frame = frame_result
    .map_err(SegmentWorkerError::FrameDecryptionFailed)?;
```

### 5. **Graceful Degradation**

```rust
// Checkpoint persistence doesn't fail the entire segment
if let Err(e) = resume_point.persist(log_manager) {
    eprintln!("Warning: Failed to persist checkpoint: {}", e);
}
```

### 6. **Updated Tests**

- Tests now assert on specific error types
- Can distinguish between AEAD failures and digest mismatches
- Full error context preserved for debugging

## 💡 Benefits

1. **Better Debugging**: Full error chain preserved
2. **Testability**: Can assert on specific error types
3. **Robustness**: No silent failures or lost panics
4. **Flexibility**: Callers can decide how to handle each error
5. **Production Ready**: Can log, retry, or skip bad segments

## 🔄 Migration Path

The API change is minimal:

```rust
// Before
let rx: Receiver<DecryptedSegment>

// After  
let rx: Receiver<Result<DecryptedSegment, SegmentWorkerError>>
```

Callers just need to handle the `Result` wrapper, which gives them much more control over error handling!

## ✅ Problem 1: Fixed `persist()` Return Type

The issue was that `persist()` returns `()`, not `Result`. Since it's designed as fire-and-forget (non-blocking), we just call it directly:

```rust
// Before (incorrect)
if let Err(e) = resume_point.persist(log_manager) {
    eprintln!("Warning: Failed to persist checkpoint: {}", e);
}

// After (correct)
resume_point.persist(log_manager);
```

This matches the design where `AsyncLogManager::append()` handles errors internally and doesn't propagate them.

## ✅ Problem 2: Added Resume Support to Encrypt Worker

Restored full resume/checkpoint support to the encryption path:

### Changes Made

1. **Added `resume` parameter** to `run()` method
2. **Added resume logic** to `process_encrypt_segment()`:
   - Checks if current segment matches resume point
   - Restores digest calculator state from checkpoint
   - Skips digest updates for already-processed frames (optimization)
3. **Added checkpoint persistence** after digest finalization
4. **Added `can_checkpoint` flag** to control when checkpointing is enabled

### How It Works

```rust
// Initialize digest calculator with resume support
let (start_frame, mut digest_calculator) = if can_checkpoint && is_resume_segment {
    // Resume from checkpoint
    (resume_point.next_frame_index, SegmentDigestCalculator::with_state(...))
} else {
    // Normal start
    (0, SegmentDigestCalculator::new(...))
};

// Skip digest for already-processed frames
if frame.frame_index >= start_frame {
    digest_calculator.update_frame(frame.frame_index, &frame.ciphertext);
}

// Save checkpoint after finalization
resume_point.persist(log_manager);
```

This makes the encrypt and decrypt workers **symmetric** in their resume/checkpoint support! Both now support:

- ✅ Resuming from checkpoints
- ✅ Skipping already-processed frames
- ✅ Persisting checkpoints after each segment
- ✅ Proper error handling throughout

---

## Fix 1: Segment Index Input Design

**Best option: Use a dedicated input struct with `u32` for segment_index**

```rust
// For Encryption
pub struct EncryptSegmentInput {
    pub segment_index: u64,  // u64 matches our frame header type
    pub plaintext: Vec<u8>,   // Single plaintext blob, not pre-framed
}

// For Decryption  
pub struct DecryptSegmentInput {
    pub segment_index: u64,
    pub wire: Arc<Vec<u8>>,  // Encrypted wire bytes (zero-copy via Arc)
}
```

**Why this is best:**

- ✅ Explicit segment_index eliminates ambiguity
- ✅ `u64` matches `FrameHeader::segment_index` type
- ✅ `Arc<Vec<u8>>` for wire bytes enables zero-copy sharing
- ✅ `Vec<u8>` for plaintext is fine (it's moved, not shared)
- ✅ Worker does the framing internally (single responsibility)

**Update signatures:**

```rust
// Encrypt
pub fn run(
    self,
    rx: Receiver<EncryptSegmentInput>,
    tx: Sender<Result<EncryptedSegment, SegmentWorkerError>>,
    resume: Option<SegmentResumePoint>,
)

// Decrypt
pub fn run(
    self,
    rx: Receiver<DecryptSegmentInput>,
    tx: Sender<Result<DecryptedSegment, SegmentWorkerError>>,
    resume: Option<SegmentResumePoint>,
)
```

**Why NOT `Vec<Vec<u8>>` for frames:**

- ❌ Framing is an internal implementation detail
- ❌ Caller shouldn't need to know frame_size
- ❌ More complex API

---

**Key principle:**

- ✅ **Telemetry = what we processed THIS run** (always count everything)
- ✅ **Digest skip = cryptographic optimization** (skip already-verified work)
- These are independent concerns!

---

## Summary

**Best Design:**

```rust
// Input structs
pub struct EncryptSegmentInput {
    pub segment_index: u32,
    pub plaintext: Vec<u8>,
}

pub struct DecryptSegmentInput {
    pub segment_index: u32,
    pub wire: Arc<Vec<u8>>,
}

// Usage in pipeline.rs
let input = EncryptSegmentInput {
    segment_index: current_segment,
    plaintext: data_chunk,
};
encrypt_tx.send(input)?;
```

This gives us:

- ✅ Explicit control over segment numbering
- ✅ Clean API boundaries
- ✅ Zero-copy where beneficial
- ✅ Accurate telemetry always
- ✅ Cryptographic optimization via resume

---

## Industry Standards

### Segment Sizes (Our "Chunk Size")

Our current values are **excellent** and align with industry standards:

```rust
// Our current segment sizes are good ✅
pub const ALLOWED_CHUNK_SIZES: &[usize] = &[
    16 * 1024,    // 16 KiB  - IoT/embedded, constrained memory
    32 * 1024,    // 32 KiB  - Mobile devices, network packets
    64 * 1024,    // 64 KiB  - Default (good balance) ✅ RECOMMENDED
    128 * 1024,   // 128 KiB - Desktop apps
    256 * 1024,   // 256 KiB - Server applications
    1024 * 1024,  // 1 MiB   - Bulk data processing
    2048 * 1024,  // 2 MiB   - Large file transfers
    4096 * 1024,  // 4 MiB   - High-throughput systems
];
```

**Industry References:**

- **TLS 1.3**: Max record size 16 KiB (but can send multiple records)
- **HTTP/2**: Default frame size 16 KiB
- **AWS S3 Multipart**: Recommends 5-100 MiB parts
- **Google Cloud Storage**: Recommends 8-32 MiB chunks
- **Azure Blob**: Recommends 4-100 MiB blocks
- **Tarsnap/Restic**: Use 1-4 MiB chunks

### Frame Sizes (Within Segments)

Frame sizes should be **smaller** than segment sizes for parallelization:

```rust
/// Industry-standard frame sizes for parallel processing
pub const ALLOWED_FRAME_SIZES: &[usize] = &[
    4 * 1024,    // 4 KiB   - Maximum parallelization
    8 * 1024,    // 8 KiB   - Good balance
    16 * 1024,   // 16 KiB  - TLS record size (common) ✅ RECOMMENDED
    32 * 1024,   // 32 KiB  - Network packet friendly
    64 * 1024,   // 64 KiB  - Larger frames, less overhead
];

pub const DEFAULT_FRAME_SIZE: usize = 16 * 1024; // 16 KiB
pub const MIN_FRAME_SIZE: usize = 4 * 1024;      // 4 KiB
pub const MAX_FRAME_SIZE: usize = 64 * 1024;     // 64 KiB
```

## Recommended Approach: **Dynamic Frame Sizing**

**Best practice: Adjust frame size based on segment size** for optimal performance:

```rust
/// Calculate optimal frame size for a given segment size
pub fn optimal_frame_size(segment_size: usize) -> usize {
    ...
}

/// Frame size mapping table (precomputed for common segment sizes)
pub const FRAME_SIZE_TABLE: &[(usize, usize)] = &[
    // (segment_size, optimal_frame_size)
    (16 * 1024,    4 * 1024),   // 16 KiB segment → 4 KiB frames (4 frames)
    (32 * 1024,    8 * 1024),   // 32 KiB segment → 8 KiB frames (4 frames)
    (64 * 1024,    16 * 1024),  // 64 KiB segment → 16 KiB frames (4 frames)
    (128 * 1024,   16 * 1024),  // 128 KiB segment → 16 KiB frames (8 frames)
    (256 * 1024,   16 * 1024),  // 256 KiB segment → 16 KiB frames (16 frames)
    (1024 * 1024,  32 * 1024),  // 1 MiB segment → 32 KiB frames (32 frames)
    (2048 * 1024,  64 * 1024),  // 2 MiB segment → 64 KiB frames (32 frames)
    (4096 * 1024,  64 * 1024),  // 4 MiB segment → 64 KiB frames (64 frames)
];

/// Get optimal frame size from lookup table
pub fn get_frame_size(segment_size: usize) -> usize {
    FRAME_SIZE_TABLE
        .iter()
        .find(|(seg_size, _)| *seg_size == segment_size)
        .map(|(_, frame_size)| *frame_size)
        .unwrap_or_else(|| optimal_frame_size(segment_size))
}
```

## Implementation in SegmentCryptoContext

```rust

```

## Performance Characteristics

### Why Dynamic Frame Sizing?

| Segment Size | Fixed 16 KiB Frames | Dynamic Frames | Benefit |
|--------------|---------------------|----------------|---------|
| 16 KiB | 1 frame (no parallelization) | 4 KiB × 4 frames | 4× parallelization ✅ |
| 64 KiB | 16 KiB × 4 frames | 16 KiB × 4 frames | Optimal ✅ |
| 4 MiB | 16 KiB × 256 frames | 64 KiB × 64 frames | Less overhead ✅ |

**Dynamic sizing gives:**

- ✅ Better parallelization for small segments
- ✅ Lower overhead for large segments
- ✅ Consistent ~4-64 frames per segment
- ✅ Adaptive to workload

## Recommendation

```rust
// config.rs - Add frame size configuration
pub const DEFAULT_FRAME_SIZE: Option<usize> = None; // Auto-calculate

// Update constants
pub const MIN_FRAME_SIZE: usize = 4 * 1024;
pub const MAX_FRAME_SIZE: usize = 64 * 1024;
pub const DEFAULT_FRAME_SIZE_EXPLICIT: usize = 16 * 1024; // When user specifies

/// Frame size recommendations for different use cases
pub mod frame_size_profiles {
    use super::*;
    
    /// Maximum parallelization (many small frames)
    pub const HIGH_PARALLELIZATION: usize = 4 * 1024;
    
    /// Balanced (recommended default)
    pub const BALANCED: usize = 16 * 1024;
    
    /// Network-optimized (align with network MTU)
    pub const NETWORK_FRIENDLY: usize = 32 * 1024;
    
    /// Minimum overhead (fewer larger frames)
    pub const LOW_OVERHEAD: usize = 64 * 1024;
}
```

## Final Recommendation

**Use dynamic frame sizing by default** with the ability to override:

```rust
// Option 1: Auto (recommended) ✅
let ctx = SegmentCryptoContext::new(
    header,
    key,
    DigestAlg::Sha256,
    None,       // frame_size = auto-calculate
)?;

// Option 2: Explicit
let ctx = SegmentCryptoContext::new(
    header,
    key,
    DigestAlg::Sha256,
    Some(16 * 1024), // frame_size = explicit
)?;
```

This gives us:

- ✅ Optimal defaults
- ✅ User control when needed
- ✅ Industry-standard sizes
- ✅ Adaptive performance

---

### Encrypt side

```rust
use bytes::Bytes;

/// Input from reader stage (plaintext)
#[derive(Debug, Clone)]
pub struct EncryptSegmentInput {
    pub segment_index: u64,
    pub plaintext: Bytes, // 🔥 zero-copy shared
}

/// Output of encryption
#[derive(Debug)]
pub struct EncryptedSegment {
    pub segment_index: u64,
    pub wire: Bytes, // 🔥 contiguous encoded frames
    pub telemetry: TelemetryCounters,
}
```

### Decrypt side

```rust
use bytes::Bytes;

#[derive(Debug)]
pub struct DecryptSegmentInput {
    pub segment_index: u64,
    pub wire: Bytes, // 🔥 shared, sliceable
}

#[derive(Debug)]
pub struct DecryptedSegment {
    pub segment_index: u64,
    pub frames: Vec<Bytes>, // plaintext frames
    pub telemetry: TelemetryCounters,
}
```

✅ **Arc<Vec<u8>> is gone forever**
✅ **Vec<u8> only appears at AEAD boundary**

---

## 2️⃣ Encrypt side – precise fixes

### 2.1 FrameInput (already correct)

```rust
#[derive(Debug, Clone)]
pub struct FrameInput {
    pub segment_index: u64,
    pub frame_index: u32,
    pub frame_type: FrameType,
    pub plaintext: Bytes, // 🔥 instead of Arc<[u8]>
}
```

### 2.2 EncryptSegmentWorker → no logic change, only Bytes

## 3️⃣ Decrypt side – precise fixes

### 3.1 Frame worker channel

```rust
let (frame_tx, frame_rx) = bounded::<Bytes>(worker_count * 4);
```

### 3.2 Dispatch frames (zero-copy slicing)

```rust
while offset < segment_wire.len() {
    let header = parse_frame_header(&segment_wire[offset..])?;
    let frame_len = FrameHeader::LEN + header.ciphertext_len as usize;

    let end = offset + frame_len;
    if end > segment_wire.len() {
        return Err(FrameError::Truncated.into());
    }

    // 🔥 O(1) slice
    frame_tx.send(segment_wire.slice(offset..end))?;
    offset = end;
    frame_count += 1;
}
```

### 3.3 DecryptedFrame (final form)

```rust
#[derive(Debug)]
pub struct DecryptedFrame {
    pub segment_index: u64,
    pub frame_index: u32,
    pub frame_type: FrameType,
    pub wire: Bytes,
    pub ct_range: std::ops::Range<usize>,
    pub plaintext: Bytes,
}

impl DecryptedFrame {
    #[inline]
    pub fn ciphertext(&self) -> Bytes {
        self.wire.slice(self.ct_range.clone())
    }
}
```

### 3.4 Digest verification (unchanged logic, zero-copy input)

```rust
verifier.update_frame(
    frame.frame_index,
    &frame.ciphertext(), // Bytes deref to &[u8]
);
```

No allocation, no borrow issues.

---

## 4️⃣ Subtle wins we just unlocked (important)

### ✅ No cross-segment frame mixing

Because:

- **each segment owns its `Bytes`**
- **slices keep refcount to correct backing buffer**
- **no shared `out_rx` confusion beyond ordering logic**

### ✅ Digest verification is now fully zero-copy

Ciphertext is *never* cloned on decrypt.

### ✅ Resume / persistence becomes trivial

We can persist:

```rust
(segment_index, wire.clone())
```

and replay later with zero reparse cost.

### ✅ S3 / file sinks become trivial

We can write `Bytes` directly.

---

## 5️⃣ Final migration checklist (do not skip)

- **[ ] Remove **all** `Arc<Vec<u8>>`**
- **[ ] Remove **all** `Arc<[u8]>`**
- **[ ] `EncryptedFrame.wire: Bytes`**
- **[ ] `DecryptFrameWorker::run(rx: Receiver<Bytes>)`**
- **[ ] `SegmentInput / Output use Bytes`**
- **[ ] Only AEAD produces `Vec<u8>`**

---

## 🧠 Final verdict

We now have:

- **Zero-copy framing**
- **Deterministic segment atomicity**
- **Digest without duplication**
- **Resume-safe wire format**
- **Tokio / async ready buffers**
