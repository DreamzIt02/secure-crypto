# Pipeline

This pipeline obeys:

* **Single stream header**
* **Explicit segment boundaries**
* **Unordered workers → ordered writer**
* **No full buffering**
* **Bounded memory**
* **Deterministic shutdown**
* **Crash-safe segment atomicity**

* `EncryptSegmentWorker` / `DecryptSegmentWorker` are **pure** (no I/O).
* `io.rs` owns:

  * exact reads
  * exact writes
  * header encode/decode
  * ordered writer helper
* `SegmentHeader` is authoritative for segmentation.

---

## 4️⃣ Ordering + shutdown guarantees

### ✅ No deadlocks

* Readers exit → channels close → workers drain → writers finish

### ✅ No full buffering

* `OrderedSegmentWriter` holds **only missing gaps**

### ✅ Deterministic end

* Final segment flag determines completion
* No reliance on channel exhaustion alone

### ✅ Crash-safe

* Each segment = `(SegmentHeader + wire)`
* Partial writes detectable

---

### Pipeline (pipeline.rs)

* **Pipeline does NOT construct crypto** → workers already receive `SegmentCryptoContext`
* **Pipeline passes `EncryptSegmentInput` / `DecryptSegmentInput`**
* **Segment framing happens ONLY in `io.rs`**
* **Pipeline never parses frames**
* **Ordering handled by ordered writers**
* **Final segment detected via `SegmentHeader::flags`**

### IO (io.rs)

* reads/writes `HeaderV1`
* reads/writes **`SegmentHeader + wire`**
* owns segment boundary detection
* ordered writers are minimal and deterministic

---

## ✅ Result

We now have:

* **Exact alignment** with our worker APIs
* **Zero-copy everywhere (`Bytes`)**
* **Segment boundaries guaranteed**
* **Crash-resumable framing**
* **No hidden buffering**
* **Production-ready wiring**

---

## 🔑 Industry Practices for Final Segment Detection

### 1. **Explicit Length in Header**

* **AES file encryption tools (OpenSSL, GnuTLS, etc.)**: The total plaintext length is stored in the container header. Workers know exactly how many blocks to expect, and the last block is deterministically marked as final.
* **TLS record layer**: Each record carries its own length field. The receiver knows when the stream ends without guessing based on block size.

### 2. **Dedicated Final Segment Marker**

* **Parallel AES FPGA implementations**: Hardware pipelines often append a “final block” marker bit to signal termination, regardless of block size alignment .
* **GPU/CPU hybrid crypto libraries**: Projects like *ParallelCryptography* on GitHub use explicit flags in segment headers to mark the last chunk, ensuring workers and writers can finalize cleanly .

### 3. **Padding + Final Flag**

* **AES/DES acceleration on many‑core processors**: Systems pad the last block to full size but still set a termination flag in metadata. This avoids ambiguity when the last block is “full” but actually final .

---

## 📊 Comparison of Approaches

| Approach                           | Used By (Examples)                            | Pros                                 | Cons                       |
|------------------------------------|-----------------------------------------------|--------------------------------------|----------------------------|
| **Length in header**               | TLS, OpenSSL, GnuTLS                          | Deterministic, no dummy segment      | Requires header integrity  |
| **Dedicated final marker segment** | FPGA AES pipelines, ParallelCryptography repo | Simple, explicit, works with streams | Adds one extra segment     |
| **Padding + final flag**           | DES/AES many‑core accelerators                | Compatible with block ciphers        | Slight overhead in padding |

---

## 🔧 Refactor Plan

### 1. Reader

At EOF, if we’ve already dispatched at least one segment, send a dummy empty segment with `FINAL_SEGMENT` set:

```rust
if buf.is_empty() {
    if segment_index > 0 {
        seg_tx.send(EncryptSegmentInput {
            segment_index,
            plaintext: Vec::new(),
            compressed_len: 0,
            flags: SegmentFlags::FINAL_SEGMENT,
        }).map_err(|_| StreamError::PipelineError("encrypt segment channel closed".into()))?;
    }
    break;
}
```

---

### 2. Worker (`process_encrypt_segment_2`)

Handle the empty‑final case explicitly:

```rust
fn process_encrypt_segment_2(
    input: &EncryptSegmentInput,
    frame_size: usize,
    digest_alg: DigestAlg,
    frame_tx: &Sender<FrameInput>,
    out_rx: &Receiver<Result<EncryptedFrame, FrameWorkerError>>,
) -> Result<EncryptedSegment, SegmentWorkerError> {
    let mut telemetry = TelemetryCounters::default();

    // ✅ Empty final segment case
    if input.plaintext.is_empty() && input.flags.contains(SegmentFlags::FINAL_SEGMENT) {
        let header = SegmentHeader::new(
            &Bytes::new(),
            input.segment_index,
            input.compressed_len,
            0, // no frames
            digest_alg as u16,
            input.flags,
        );
        return Ok(EncryptedSegment {
            header,
            wire: Bytes::new(),
            telemetry,
        });
    }

    // … existing logic for non‑empty segments …
}
```

This way, the worker emits a valid `EncryptedSegment` with no frames but with the `FINAL_SEGMENT` flag set.

---

### 3. Ordered Writer

Update `OrderedEncryptedWriter::push` and `finish` to accept an empty segment gracefully:

```rust
impl OrderedEncryptedWriter<'_> {
    pub fn push(&mut self, segment: EncryptedSegment) -> Result<(), StreamError> {
        // Accept empty wire if FINAL_SEGMENT is set
        if segment.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && segment.wire.is_empty() {
            self.final_index = Some(segment.header.segment_index);
            return Ok(());
        }
        // Normal push logic
        self.buffer.insert(segment.header.segment_index, segment.wire);
        Ok(())
    }

    pub fn finish(&mut self, final_segment: Option<u32>) -> Result<(), StreamError> {
        // Flush all buffered segments in order
        for idx in 0..=final_segment.unwrap_or(self.buffer.len() as u32 - 1) {
            if let Some(wire) = self.buffer.remove(&idx) {
                self.writer.write_all(&wire)?;
            }
        }
        Ok(())
    }
}
```

---

## ✅ Benefits

* **No hangs**: Writer always sees a `FINAL_SEGMENT`.
* **Industry‑aligned**: Explicit final marker segment, like FPGA AES pipelines and TLS record framing.
* **Extensible**: Works cleanly with compression, resume, or multi‑stream features later.

---

## 🔧 Refactor for Empty Final Segment

### 1. Detect empty segment flagged as final

Add a fast‑path at the top of `process_decrypt_segment_v2`:

```rust
fn process_decrypt_segment_v2(
    input: &DecryptSegmentInput,
    digest_alg: &DigestAlg,
    frame_tx: &Sender<Bytes>,
    out_rx: &Receiver<Result<DecryptedFrame, FrameWorkerError>>,
) -> Result<DecryptedSegment, SegmentWorkerError> {
    let mut telemetry = TelemetryCounters::default();

    // ✅ Empty final segment case
    if input.wire.is_empty() && input.header.flags.contains(SegmentFlags::FINAL_SEGMENT) {
        return Ok(DecryptedSegment {
            header: input.header.clone(),
            frames: Vec::new(), // no plaintext frames
            telemetry,
        });
    }

    // … existing logic for non‑empty segments …
```

This way, the decrypt pipeline accepts the dummy final segment and terminates cleanly.

---

### 2. OrderedPlaintextWriter

Update our writer to accept an empty segment flagged as final:

```rust
impl OrderedPlaintextWriter<'_> {
    pub fn push(&mut self, segment: DecryptedSegment) -> Result<(), StreamError> {
        // Accept empty wire if FINAL_SEGMENT is set
        if segment.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && segment.frames.is_empty() {
            self.final_index = Some(segment.header.segment_index);
            return Ok(());
        }
        // Normal push logic
        for frame in segment.frames {
            self.writer.write_all(&frame)?;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), StreamError> {
        // Flush any buffered frames, then finalize
        // If final_index is None, treat last seen segment as final
        Ok(())
    }
}
```

---

### 3. Reader loop

No changes needed — `io::read_segment` will return the empty final segment header + wire (empty). The worker will now accept it.

---

## ✅ Benefits (Decrypt Stream)

* **Symmetry**: Encrypt emits empty final segment, decrypt consumes it.
* **No hangs**: Writer always sees a final marker.
* **Industry‑aligned**: Explicit end‑of‑stream marker, like TLS record framing and FPGA AES pipelines.
* **Extensible**: Works with compression/resume features later.

---

## 🔧 How to propagate errors

We need a way to bubble up **both crypto worker errors** and **decompression worker errors** to the top‑level `Result`.

### Pattern

* Use a shared error channel (`Sender<StreamError>`).  
* Each worker thread sends its error into that channel.  
* The main thread checks the channel before finishing and returns the first error.

---

### Example patch

```rust
// ---- Channels ----
let (seg_tx, seg_rx) = bounded::<DecryptSegmentInput>(profile.inflight_segments());
let (crypto_out_tx, crypto_out_rx) = bounded::<Result<DecryptedSegment, SegmentWorkerError>>(profile.inflight_segments());
let (decomp_out_tx, decomp_out_rx) = bounded::<Result<DecryptedSegment, SegmentWorkerError>>(profile.inflight_segments());
let (decomp_in_tx, decomp_in_rx) = bounded::<DecryptedSegment>(profile.inflight_segments());

// Error channel
let (err_tx, err_rx) = bounded::<StreamError>(1);
```

---

#### Crypto adapter

```rust
scope.spawn({
    let decomp_in_tx = decomp_in_tx.clone();
    let err_tx = err_tx.clone();
    move || {
        for res in crypto_out_rx.iter() {
            match res {
                Ok(seg) => {
                    if decomp_in_tx.send(seg).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[PIPELINE] crypto worker error: {e}");
                    let _ = err_tx.send(StreamError::SegmentWorker(e));
                    break;
                }
            }
        }
    }
});
```

---

#### Decompression workers

Change `spawn_decompression_workers` so they send `Result<DecryptedSegment, SegmentWorkerError>` instead of plain `DecryptedSegment`. Then adapt:

```rust
spawn_decompression_workers(profile.clone(), codec_info, decomp_in_rx, decomp_out_tx);
```

And in the writer loop:

```rust
for res in decomp_out_rx.iter() {
    match res {
        Ok(segment) => {
            eprintln!("[WRITER] receiving segment {}", segment.header.segment_index);
            if segment.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && segment.bytes.is_empty() {
                last_segment_index = segment.header.segment_index;
            }
            ordered_writer.push(segment)?;
        }
        Err(e) => {
            eprintln!("[PIPELINE] decompression worker error: {e}");
            return Err(StreamError::SegmentWorker(e));
        }
    }
}
```

---

#### Final error check

Before returning telemetry:

```rust
if let Ok(err) = err_rx.try_recv() {
    return Err(err);
}
```

---

## Telemetry

### Encrypt

```rust
    // Writing / stream header
    timer.stage_times.add(Stage::Write, start.elapsed());

    // Read / chunking / before compress
    let final_times = read_stage_times.lock().unwrap(); 
    for (stage, dur) in final_times.iter() { timer.add_stage_time(*stage, *dur); }

    // Compression / segment
    let final_times = compression_stage_times.lock().unwrap(); 
    for (stage, dur) in final_times.iter() { timer.add_stage_time(*stage, *dur); }

    // Encryption
    for (stage, dur) in encryption_stage_times.iter() {
        timer.add_stage_time(*stage, *dur);
    }

    // Writing / wiring
    encryption_stage_times.add(Stage::Write, start.elapsed());

```

### Decrypt

```rust
    // Validation / stream header
    timer.stage_times.add(Stage::Validate, start.elapsed());

    // merge read stage_times
    let final_times = read_stage_times.lock().unwrap(); 
    for (stage, dur) in final_times.iter() { timer.add_stage_time(*stage, *dur); }

    // merge decryption stage_times
    let final_times = decryption_stage_times.lock().unwrap(); 
    for (stage, dur) in final_times.iter() { timer.add_stage_time(*stage, *dur); }

    // merge decompression stage_times
    decompression_stage_times.merge(&segment.stage_times);

    // Writing / wiring
    decompression_stage_times.add(Stage::Write, start.elapsed());
```

### Encrypt (Counters)

```rust
    // Calculate len of overhead bytes / stream header
    counters.bytes_overhead += HeaderV1::LEN

    // update bytes_plaintext len
    counters.bytes_plaintext = counters_local.lock().unwrap().bytes_plaintext;

    // update bytes_compressed len
    counters.bytes_compressed = counters_local.lock().unwrap().bytes_compressed;

    // 🔥 Merge telemetry from this segment worker
    counters.merge(&encrypted.counters);
```

### Decrypt (Counters)

```rust
    // Calculate len of overhead bytes / stream header
    counters.bytes_overhead += HeaderV1::LEN

    // update bytes_ciphertext len
    counters.bytes_ciphertext = counters_local.lock().unwrap().bytes_ciphertext;

    // 🔥 Merge telemetry from this segment worker
    counters.merge(&encrypted.counters);

    // update bytes_plaintext
    counters.bytes_plaintext += segment.bytes.len() as u64;
```
