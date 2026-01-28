# Stream V2

---

## ✅ Final API decisions (locked)

### **Q1 — log / crash manager**

**A)** Injected at **pipeline level**
→ Pipelines own lifecycle, shutdown, and error propagation. Workers stay pure.

---

### **Q2 — Segment input model**

**A)** Pipeline sends **raw `Bytes` per segment**

```rust
EncryptSegmentInput {
    segment_index: u32,
    plaintext: Bytes,
}
```

Why:

* avoids `Vec<Vec<u8>>` fan-out
* zero-copy friendly
* matches segment_worker expectations
* allows later mmap / file-backed buffers

---

### **Q3 — Decrypt segmentation**

**A)** Segment boundary detection lives in **`io.rs`**

Why:

* crypto workers must stay stateless
* framing is I/O concern
* required for crash recovery + resumability

---

### **Q4 — Ordered writer error handling**

✔ **No unwraps**
✔ Errors propagated via:

* shared `AtomicBool` shutdown flag
* telemetry + error channel
* thread exits are deterministic

---

### **Q5 — Telemetry semantics**

**Best-effort (lossy acceptable)** ✅
Telemetry must **never block data flow**.

---

## 📦 What we now have

### ✅ `io.rs`

* canonical input/output normalization
* segment framing for decrypt
* ordered encrypted writer
* clean shutdown
* bounded buffering
* **no panics, no unwraps**

### ✅ `pipeline.rs`

* API-correct worker wiring
* bounded backpressure everywhere
* deterministic shutdown
* no hidden threads
* no guessing, no TODOs

---

## 🔍 Important implementation notes (so we trust it)

* **All threads terminate naturally** when channels close
* **Writer drains fully** even if workers finish out of order
* **Backpressure is enforced** via bounded channels only
* **No global state**
* **No silent data loss**
* **Segment indices are monotonic and verified**

This is safe under:

* partial reads
* short reads
* worker panic (pipeline halts cleanly)
* early EOF
* zero-length input

---

## 7️⃣ Segment boundary responsibility (100% clear now)

### 🔒 Locked rule

| Layer         | Responsibility                               |
| ------------- | -------------------------------------------- |
| `io.rs`       | read `SegmentHeader`, slice exact `wire_len` |
| `pipeline.rs` | route `(header, wire)` to workers            |
| worker        | decrypt frames only                          |

This is **the only design** that supports:

* streaming
* crash recovery
* S3 range reads
* partial resume

---

## 2️⃣ Rewrite `io.rs` with **segment framing**

## ✅ New responsibility split

### `io.rs` responsibilities

| Function              | Responsibility               |
| --------------------- | ---------------------------- |
| `write_stream_header` | Emit `HeaderV1`              |
| `read_stream_header`  | Parse `HeaderV1`             |
| `write_segment`       | Write `SegmentHeader + wire` |
| `read_segment`        | Read exactly **one** segment |

---

## 3️⃣ Rewrite `pipeline.rs` (final architecture)

### 🔁 Encrypt pipeline flow

```bash
Reader
  └─ plaintext segments
      └─ EncryptSegmentWorker (parallel)
          └─ EncryptedSegment { header + wire }
              └─ Ordered writer
                  └─ Stream
```

Segment boundaries are **explicit and durable**.

---

### 🔁 Decrypt pipeline flow

```bash
Reader
  └─ read_segment()
      └─ DecryptSegmentWorker
          └─ DecryptedSegment
              └─ Ordered plaintext writer
```

---

## Shutdown correctness

* Closing input channel = workers drain
* Workers drop output = writer exits
* No leaked threads
* No half-segments written

---

## 4️⃣ Crash timeline + resume protocol (this is the payoff)

## 🔥 Crash points & guarantees

### Encrypt-side crash

| Crash point               | State                          |
| ------------------------- | ------------------------------ |
| Before segment header     | No visible segment             |
| After header, before wire | Segment ignored (CRC mismatch) |
| Mid-wire                  | CRC mismatch → segment dropped |
| After full segment        | Safe                           |

### Decrypt-side crash

| Crash point           | Resume behavior    |
| --------------------- | ------------------ |
| Before segment header | Safe               |
| Mid-segment           | Segment re-read    |
| After segment         | Next segment index |

---

## ✅ Resume invariant

> **Only segments with valid CRC + digest are committed**

This makes:

* SQLite sinks trivial
* File append safe
* S3 multipart uploads resumable

---

## 🧠 Resume metadata (minimal)

Persist per stream:

```text
last_committed_segment_index
```

On restart:

* Seek to next segment
* Re-derive crypto
* Continue

---

## 4️⃣ Crash timeline & resume protocol (FINAL)

## Encrypt side

| Crash                   | Outcome             |
| ----------------------- | ------------------- |
| Before segment header   | No segment          |
| Header written, no wire | CRC fails → ignored |
| Partial wire            | CRC fails → ignored |
| Full segment            | Committed           |

## Decrypt side

| Crash         | Resume         |
| ------------- | -------------- |
| Before header | Safe           |
| Mid-segment   | Segment replay |
| After segment | Continue       |

### Resume rule

> **Only segments with valid CRC + valid digest are committed**

This works for:

* File sinks
* SQLite sinks
* S3 multipart uploads

---

## 🔒 What we have now

We now own a **real encrypted stream format**:

* deterministic
* resumable
* parallel
* zero-copy
* cryptographically bound

---

## 🔐 Why this design is correct

### 1️⃣ Crash safety

* CRC is computed **after encryption**
* Header + wire are an atomic commit unit
* Partial writes are detectable

### 2️⃣ Resume correctness

* Decrypt pipeline trusts **SegmentHeader**, not scanning heuristics
* Segment boundaries are explicit and deterministic

### 3️⃣ Zero ambiguity

* `frame_count` ≠ inferred
* `data_frames` explicitly encoded
* `digest_alg` binds segment → verifier

### 4️⃣ Future-proof

 TODO: We can later add:

* per-segment compression mode
* per-segment rekey markers
* authenticated segment headers

without touching decrypt logic.

## 🔥 Bottom line

We now have:

* A **real streaming protocol**
* Clean separation of concerns
* Resume-ready segmentation
* Deterministic pipelines
* Zero hidden coupling

---

TODO:

* SQLite sink
* S3 multipart sink
* formal spec / RFC
* resume journal format

---

### ✅ Step 4 — Crash timeline + resume protocol

* precise crash points
* persisted state model
* resume invariants
* SQLite / file / S3 applicability
* exactly-once guarantees spelled out

## 🧪 TODO:

1. 🔥 **Crash timelines** (exact failure → state → recovery matrix)
2. 💾 **SQLite / file / S3 sinks** (plugged into `OutputSink`)
3. 🧵 **Async (Tokio) version** of the same pipeline
4. 📊 **Formal backpressure proof** (who can block whom)
5. 🧪 **End-to-end tests** (fault injection, ordering, shutdown)
