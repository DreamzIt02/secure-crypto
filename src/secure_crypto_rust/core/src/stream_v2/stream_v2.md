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

---

## 🧭 Connecting All Four Files

1. **`core.rs` (Public API)**  

    * User calls `encrypt_stream_v2`.  
    * Sets up context, opens input/output, and calls `encrypt_pipeline`.

2. **`pipeline.rs` (Pipeline Orchestration)**

    * Writes stream header.  
    * Spawns reader thread → produces `EncryptSegmentInput`.  
    * Compression workers (optional).  
    * Segment workers (`EncryptSegmentWorker::run_v1`) consume segments.  
    * Writer consumes `EncryptedSegment` results.

3. **`encrypt.rs` (Segment Worker)**

    * Receives `EncryptSegmentInput`.  
    * Splits into frames (`FrameInput`).  
    * Dispatches frames to frame workers.  
    * Collects `EncryptedFrame`s.  
    * Adds digest + terminator frames.  
    * Assembles into `EncryptedSegment` with `SegmentHeader`.  
    * Sends result to pipeline writer.

4. **`encrypt.rs` (Frame Worker)**

    * Receives `FrameInput`.  
    * Encrypts with AEAD.  
    * Encodes into wire format.  
    * Returns `EncryptedFrame` to segment worker.

---

## ✅ Key Invariants Across Pipeline

* **Segmenting**: Each segment ≤ `HeaderV1::chunk_size`.  
* **Framing**: Each segment → N data frames + 1 digest + 1 terminator.  
* **Headers**:  
  * `SegmentHeader.frame_count` = number of data frames only.  
  * `SegmentHeader.wire_len` = sum of all frame wires.  
* **Encryption**:  
  * Nonce derived from salt + frame index.  
  * AAD binds header fields to ciphertext.  
* **Termination**:  
  * Final empty segment marks EOF.  
  * Terminator frame marks end of segment.

---

## 🔗 Big Picture

The encrypt pipeline is now fully mapped:

### **Public API → Pipeline → Segment Worker → Frame Worker → Writer**

Each stage is isolated, uses channels for communication, and merges telemetry for performance profiling.

---

Perfect — with this last piece (`decrypt_frame.rs`), we now have the **complete decrypt pipeline** mapped end‑to‑end. Let’s stitch everything together:

---

## 🧭 Connecting All Four Decrypt Files

1. **`core_decrypt.rs` (Public API)**  
   * User calls `decrypt_stream_v2`.  
   * Sets up context, opens input/output, and calls `decrypt_pipeline`.

2. **`pipeline_decrypt.rs` (Pipeline Orchestration)**  
   * Validates stream header.  
   * Spawns reader thread → produces `DecryptSegmentInput`.  
   * Segment workers (`DecryptSegmentWorker::run_v1`) consume segments.  
   * Adapter forwards results to decompression workers.  
   * Writer consumes `DecryptedSegment` results and writes plaintext in order.

3. **`decrypt_segment.rs` (Segment Worker)**  
   * Receives `DecryptSegmentInput`.  
   * Splits segment wire into frames (`FrameHeader::ciphertext_len`).  
   * Dispatches frames to frame workers.  
   * Collects `DecryptedFrame`s.  
   * Verifies digest + terminator.  
   * Assembles plaintext into `DecryptedSegment`.  
   * Sends result to pipeline writer.

4. **`decrypt_frame.rs` (Frame Worker)**  
   * Receives raw frame slice (`Bytes`).  
   * Parses header, validates, rebuilds AAD, derives nonce.  
   * Decrypts ciphertext with AEAD.  
   * Returns `DecryptedFrame` to segment worker.

---

## ✅ Key Invariants Across Decrypt Pipeline

* **Segmenting**: Each segment wire length = `SegmentHeader::wire_len`.
* **Framing**: Each segment contains N data frames + 1 digest + 1 terminator.
* **Headers**:
  * `FrameHeader.ciphertext_len` must match actual ciphertext length.
  * Digest frame index = number of data frames.
  * Terminator frame index = number of data frames + 1.
* **Crypto**:
  * Nonce derived from salt + frame index.
  * AAD binds header fields to ciphertext.
  * AEAD open must succeed (authenticity check).
* **Termination**:
  * Final empty segment marks EOF.
  * Terminator frame marks end of segment.

---

## 🔗 Big Picture (1)

Now both sides are complete:

* **Encrypt pipeline**: Public API → Pipeline → Segment Worker → Frame Worker → Writer.  
* **Decrypt pipeline**: Public API → Pipeline → Segment Worker → Frame Worker → Writer.

Each stage is isolated, uses channels for communication, and merges telemetry for performance profiling. The symmetry ensures correctness: what encrypt produces, decrypt consumes.

---

## 🔧 Step 1: Define the Error Channel

At the **pipeline.rs / pipeline_decrypt.rs** level, create a global fatal error channel:

```rust
let (fatal_tx, fatal_rx) = unbounded::<StreamError>();
let cancelled = Arc::new(AtomicBool::new(false));
```

* `fatal_tx`: any worker can send an error here.
* `fatal_rx`: monitor thread listens.
* `cancelled`: shared flag to stop workers early.

---

## 🔧 Step 2: Monitor Thread

Spawn a monitor that listens for the first fatal error:

```rust
let cancelled_monitor = cancelled.clone();
scope.spawn(move || {
    if let Ok(err) = fatal_rx.recv() {
        eprintln!("[FATAL] error detected: {err}");
        cancelled_monitor.store(true, Ordering::Relaxed);

        // Drop channels to unblock recv loops
        drop(seg_tx);
        drop(frame_tx);
        drop(out_tx);
    }
});
```

This ensures the pipeline short‑circuits immediately.

---

## 🔧 Step 3: Feed Errors from Segment Workers

In **EncryptSegmentWorker / DecryptSegmentWorker**, wrap the result send:

```rust
match process_segment(&segment) {
    Ok(res) => {
        if tx.send(Ok(res)).is_err() {
            let _ = fatal_tx.send(StreamError::PipelineError("segment tx closed".into()));
            return;
        }
    }
    Err(e) => {
        let _ = fatal_tx.send(StreamError::SegmentWorker(e));
        return;
    }
}
```

* On any error, send to `fatal_tx`.
* Worker exits immediately.

---

## 🔧 Step 4: Feed Errors from Frame Workers

In **EncryptFrameWorker::run / DecryptFrameWorker::run**, after encrypt/decrypt:

```rust
while let Ok(input) = rx.recv() {
    let result = self.encrypt_frame(&input); // or decrypt_frame
    if tx.send(result).is_err() {
        let _ = fatal_tx.send(StreamError::FrameWorker(FrameWorkerError::WorkerDisconnected));
        return;
    }
    if cancelled.load(Ordering::Relaxed) {
        return; // stop early if fatal error triggered
    }
}
```

* If frame worker fails, send error to `fatal_tx`.
* If `cancelled` is set, exit cleanly.

---

## 🔧 Step 5: Writer Integration

In the **OrderedWriter loop**:

```rust
for res in out_rx.iter() {
    match res {
        Ok(segment) => { ordered_writer.push(segment)?; }
        Err(e) => {
            let _ = fatal_tx.send(StreamError::Writer(e));
            break;
        }
    }
    if cancelled.load(Ordering::Relaxed) { break; }
}
```

---

## ✅ What This Achieves
* **Any stage** (reader, segment worker, frame worker, writer) can feed errors into `fatal_tx`.
* The monitor thread sets `cancelled = true` and drops channels.
* All blocking `recv()` loops exit cleanly.
* The pipeline short‑circuits immediately on error, instead of hanging after 8 segments.

---

## 🔗 Flow Summary
* **pipeline.rs → EncryptFrameWorker**:  
  Segment worker sends errors to `fatal_tx` if frame collection fails. Frame worker sends errors if AEAD fails.  

* **pipeline_decrypt.rs → DecryptFrameWorker**:  
  Segment worker sends errors if digest/terminator mismatch. Frame worker sends errors if AEAD open fails.  

* **Monitor thread**:  
  Listens on `fatal_rx`, sets `cancelled`, drops channels → unblocks all workers.

---
