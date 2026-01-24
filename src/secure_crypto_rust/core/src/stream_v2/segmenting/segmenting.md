# Segmenting

## 2️⃣ Absolute minimum required fields

### ✅ Required fields (non-negotiable)

| Field           | Why                                                     |
| --------------- | ------------------------------------------------------- |
| `segment_index` | ordering, resume, validation                            |
| `wire_len`      | **Hard segment boundary** (decrypt pipeline needs this) |
| `frame_count`   | Detect truncation / replay                              |
| `digest_alg`    | Resume safety                                           |

---

Without `wire_len`, decrypt **cannot stream**.
Without `segment_index`, ordered writer becomes fragile.
Without `frame_count`, we can’t detect truncated segments early.

---

## 3️⃣ Additional fields that are worth adding (but still minimal)

These are **high ROI** fields — not bloat.

### ✅ Recommended fields

| Field                 | Why                                          |
| --------------------- | -------------------------------------------- |
| `plaintext_len`       | progress, resume, telemetry                  |
| `compressed_len`      | progress, resume, telemetry                  |
| `crc32` or `xxhash64` | detect segment corruption *before decrypt*   |
| `flags`               | future behaviors (compressed? last segment?) |
| `reserved`            | forward compatibility                        |

### Why this is *exactly right*

* **32-bit wire_len** → segments capped at 4 GiB (good)
* **plaintext_len** → resume + progress
* **flags** → no format churn later
* **crc32** → cheap, optional, effective

---

## 4️⃣ Final `SegmentHeader` (locked proposal)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    /// Monotonic segment number starting at 0
    pub segment_index: u64,

    /// Total plaintext bytes represented by this segment
    pub plaintext_len: u64, // Not required, this is exact slice of HeaderV1::chunk_size

    /// Total plaintext bytes represented by this segment
    /// Calculate in caller after compress, before sending to the encrypt worker
    pub compressed_len: u32,

    /// Total encoded bytes following this header (frames only)
    pub wire_len: u32,

    /// Optional integrity check of the segment wire (0 if unused)
    pub wire_crc32: u32,

    /// Number of frames in this segment (data + digest + terminator)
    pub frame_count: u32,

    /// Digest algorithm used (binds verifier)
    pub digest_alg: u16,

    /// Segment-level flags (LAST, CHECKPOINT, etc.)
    pub flags: u16,

    /// Reserved for future use; must be zero
    pub reserved: u16,

}

impl SegmentHeader {
    pub const LEN: usize = 8  // segment_index
        + 4                  // compressed_len
        + 4                  // wire_len
        + 4                  // wire_crc32
        + 4                  // frame_count
        + 2                  // digest_alg
        + 2                  // flags
        + 2;                 // reserved
}
```

## 5️⃣ How this affects EncryptSegmentWorker

### ✅ Encryption output (corrected)

```rust
#[derive(Debug)]
pub struct EncryptedSegment {
    pub header: SegmentHeader,
    pub wire: Bytes, // contiguous encoded frames
    pub telemetry: TelemetryCounters,
}
```

### Responsibilities of `EncryptSegmentWorker`

* build frames
* encode frames into `wire`
* compute:

  * `wire_len`
  * `frame_count`
  * `plaintext_len`
  * optional `crc32`
* **prepend or emit header separately** (our choice)

👉 **Important**:
`SegmentHeader` is **not encrypted**. It is part of the wire protocol, like a record boundary.

---

## 🔧 EncryptSegmentWorker changes (precise)

### What stays the same

* Frame parallelism
* Digest computation
* Zero-copy ciphertext handling
* Telemetry

### What changes

1. **After building `wire`**, compute:

   * `wire_len`
   * `crc32(wire)`
   * frame counts

2. Emit:

```rust
Ok(EncryptedSegment {
    segment_index,
    header: SegmentHeader { ... },
    wire,
    telemetry,
})
```

⚠️ **Important invariant**

> `SegmentHeader` is NOT encrypted
> It is written *verbatim* before the segment wire

---

## 6️⃣ How this affects DecryptSegmentWorker

### ✅ Decrypt input model (correct)

Decrypt workers should receive **exact segment slices**, not raw stream bytes.

```rust
struct DecryptSegmentInput {
    pub header: SegmentHeader,
    pub wire: Bytes,
}
```

### New validation steps (cheap but critical)

Before frame parsing:

1. `header.wire_len == wire.len()`
2. `crc32(wire) == header.wire_crc32`
3. `frame_count >= 3`
4. `digest_alg` matches crypto context

Only *then* decrypt frames.

---
