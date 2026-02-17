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
| `bytes_len`           | progress, resume, telemetry                  |
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
    segment_index: u32,

    /// Total plaintext (or maybe compressed) bytes represented by this segment before encrypt, and after decrypt
    bytes_len: u32,

    /// Total encrypted+encoded bytes following this header (frames only), and before decrypt
    wire_len: u32,

    /// Optional integrity check of the segment wire (0 if unused)
    wire_crc32: u32,

    /// Number of frames in this segment (data + digest + terminator)
    frame_count: u32,

    /// Digest algorithm used (binds verifier)
    digest_alg: u16,

    /// Segment-level flags (LAST, CHECKPOINT, etc.)
    flags: SegmentFlags, // ✅ NOT u16

    /// CRC32 of the entire SegmentHeader (all fields above, including wire_len and wire_crc32) 
    header_crc32: u32,
}

impl SegmentHeader {
    /// Total serialized length of the header in bytes (28)
    pub const LEN: usize = 4  // segment_index
        + 4                  // bytes_len
        + 4                  // wire_len
        + 4                  // wire_crc32
        + 4                  // frame_count
        + 2                  // digest_alg
        + 2                  // flags
        + 4;                 // header_crc32
}
```

## 5️⃣ How this affects EncryptSegmentWorker

### ✅ Encryption output (corrected)

```rust
#[derive(Debug)]
pub struct EncryptedSegment {
    pub header: SegmentHeader,
    pub wire: Bytes, // 🔥 contiguous encoded frames
    pub counters: TelemetryCounters,
    pub stage_times: StageTimes,
}
```

### Responsibilities of `EncryptSegmentWorker`

* build frames
* encode frames into `wire`
* compute:

  * `wire_len`
  * `frame_count`
  * `bytes_len`
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
