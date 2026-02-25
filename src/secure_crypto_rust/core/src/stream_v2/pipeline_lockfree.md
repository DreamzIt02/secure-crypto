# Pipeline lock-free

## ✅ Correct Unified Architecture

Both encrypt and decrypt must follow:

```bash
Reader
  ↓
[ Optional: Compression Stage ]
  ↓
SegmentWorker<T>   (frame split → frame crypto → reassemble)
  ↓
OrderedWriter
```

And both must be powered by:

```bash
process_stream_lockfree<T>()
```

Not custom channel wiring in one side.

---

## 🏗 The Real Symmetry

## Encrypt Pipeline (Correct Model)

```bash
read segment (segment_size)
    ↓
compress(segment)
    ↓
process_stream_lockfree<EncryptOp>()
    ↓
ordered_writer.push(segment)
```

---

## Decrypt Pipeline (True Mirror)

```bash
read encrypted segment
    ↓
process_stream_lockfree<DecryptOp>()
    ↓
decompress(segment)
    ↓
ordered_writer.push(segment)
```

---

## 🎯 Key Insight

Compression/decompression is NOT part of StreamRuntime.

It is part of the SegmentProcessor.

That is the symmetry we were pointing at.

So the true generic structure is:

```rust
process_stream_lockfree<SegmentOp>(
    reader,
    writer,
    processor,
)
```

Where:

### EncryptOp

```bash
compress → frame-split → encrypt → assemble
```

### DecryptOp

```bash
frame-verify → decrypt → assemble → decompress
```

That keeps symmetry perfect.

---

## 🧱 The Correct Design

## 1️⃣ Unified Trait

```rust
pub trait SegmentProcessor {
    type Input;
    type Output;

    fn process(
        &self,
        segment_index: u32,
        input: Self::Input,
    ) -> Result<Self::Output, StreamError>;
}
```

---

## 2️⃣ Generic Streaming Runtime

```rust
pub fn process_stream_lockfree<P, R, W>(
    mut reader: R,
    mut writer: W,
    processor: Arc<P>,
    config: &PipelineConfig,
) -> Result<(), StreamError>
where
    P: SegmentProcessor + Send + Sync + 'static,
    R: Read + Send,
    W: Write + Send,
{
    let inflight = config.profile.inflight_segments();

    let (tx, rx) = bounded(inflight);
    let cancelled = Arc::new(AtomicBool::new(false));

    thread::scope(|scope| {

        // Reader
        {
            let tx = tx.clone();
            scope.spawn(move || {
                let mut index = 0;
                while let Some(segment) = read_segment(&mut reader)? {
                    tx.send((index, segment))?;
                    index += 1;
                }
                Ok::<_, StreamError>(())
            });
        }

        drop(tx);

        // Workers
        for _ in 0..config.profile.cpu_workers() {
            let rx = rx.clone();
            let processor = processor.clone();
            let cancel = cancelled.clone();

            scope.spawn(move || {
                while let Ok((index, segment)) = rx.recv() {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }

                    if let Err(e) = processor.process(index, segment) {
                        cancel.store(true, Ordering::Relaxed);
                        return Err(e);
                    }
                }
                Ok::<_, StreamError>(())
            });
        }

        Ok::<_, StreamError>(())
    })?;

    Ok(())
}
```

Now BOTH encrypt and decrypt use this.

---

## 🔁 Now the real symmetry is this

| Stage        | Encrypt    | Decrypt    |
| ------------ | ---------- | ---------- |
| Reader       | Plaintext  | Ciphertext |
| Pre-process  | Compress   | —          |
| Frame stage  | Encrypt    | Decrypt    |
| Post-process | —          | Decompress |
| Writer       | Ciphertext | Plaintext  |

Compression/decompression are symmetric mirrors.

Frame crypto is symmetric.

Ordered writer is identical.

Segment runtime is identical.

---

## 💎 What We Are Actually Building

Not torrent.

Not pipeline.

We are building a:

> Deterministic, bounded, ordered, multi-segment, lock-free streaming crypto engine.

Torrent uses peer scheduling and piece availability maps.
We don’t.

So we must commit in-order.

That’s correct.

---

## ⚠️ The Only Acceptable Asymmetry

The only allowed asymmetry is:

* Encrypt writes header
* Decrypt validates header

Everything else must mirror.

---

## 🎯 Final Verdict

If once symmetry is broken:

* Bugs become asymmetric
* Telemetry becomes asymmetric
* Deadlocks become asymmetric
* Performance tuning becomes asymmetric
* Future refactor becomes painful

We are thinking at system architecture level.

That’s the correct engineering thinking.

---

What we want is:

* ✅ One single `process_stream_lockfree<T>()`
* ✅ Compression / decompression inside processor
* ✅ True streaming (bounded by `segment_size`)
* ✅ Lock-free (no `Mutex`)
* ✅ Ordered commit
* ✅ Perfect encrypt/decrypt symmetry

This is the correct architecture.

---

## 🧠 Final Architecture

```bash
Reader (segment_size bounded)
        ↓
process_stream_lockfree<T>
        ↓
OrderedWriter
```

Where:

* `EncryptProcessor` = compress → frame-split → encrypt → assemble
* `DecryptProcessor` = frame-verify → decrypt → assemble → decompress

The runtime knows NOTHING about compression or crypto.

It only schedules segments.

---

## 1️⃣ Core Trait — Symmetric Processor

```rust
pub trait SegmentProcessor: Send + Sync + 'static {
    type Input;
    type Output;

    fn process(
        &self,
        segment_index: u32,
        input: Self::Input,
    ) -> Result<Self::Output, StreamError>;
}
```

No telemetry locking.
Telemetry lives inside `Output`.

---

## 2️⃣ The True Streaming Runtime (Lock-Free)

This is the single runtime both encrypt & decrypt use.

```rust
pub fn process_stream_lockfree<P, R, W>(
    mut reader: R,
    mut writer: W,
    processor: Arc<P>,
    config: &PipelineConfig,
) -> Result<TelemetrySnapshot, StreamError>
where
    P: SegmentProcessor<Input = Bytes, Output = ProcessedSegment>,
    R: Read + Send,
    W: Write + Send,
{
    let inflight = config.profile.inflight_segments();

    let (seg_tx, seg_rx) = bounded::<(u32, Bytes)>(inflight);
    let (out_tx, out_rx) = bounded::<ProcessedSegment>(inflight);

    let cancelled = Arc::new(AtomicBool::new(false));

    thread::scope(|scope| {

        // ============================================================
        // Reader (bounded streaming)
        // ============================================================
        {
            let seg_tx = seg_tx.clone();
            let cancel = cancelled.clone();
            let segment_size = processor.segment_size();

            scope.spawn(move || -> Result<(), StreamError> {
                let mut index = 0u32;

                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }

                    let buf = io::read_exact_or_eof(&mut reader, segment_size)?;

                    if buf.is_empty() {
                        break;
                    }

                    seg_tx.send((index, Bytes::from(buf)))
                        .map_err(|_| StreamError::PipelineError("seg channel closed".into()))?;

                    index += 1;
                }

                drop(seg_tx);
                Ok(())
            });
        }

        drop(seg_tx);

        // ============================================================
        // Workers
        // ============================================================
        for _ in 0..config.profile.cpu_workers() {
            let rx = seg_rx.clone();
            let tx = out_tx.clone();
            let processor = processor.clone();
            let cancel = cancelled.clone();

            scope.spawn(move || {
                while let Ok((index, segment)) = rx.recv() {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }

                    match processor.process(index, segment) {
                        Ok(out) => {
                            if tx.send(out).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            cancel.store(true, Ordering::Relaxed);
                            let _ = tx.send(ProcessedSegment::fatal(e));
                            break;
                        }
                    }
                }
            });
        }

        drop(out_tx);
        drop(seg_rx);

        // ============================================================
        // Ordered writer (single commit authority)
        // ============================================================
        let mut ordered = OrderedCommit::new(&mut writer);
        let mut telemetry = TelemetryAggregator::default();

        for seg in out_rx.iter() {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }

            if seg.is_fatal() {
                cancelled.store(true, Ordering::Relaxed);
                return Err(seg.unwrap_err());
            }

            telemetry.merge(&seg.telemetry);

            ordered.push(seg)?;
        }

        ordered.finish()?;

        Ok::<_, StreamError>(())
    })?;

    Ok(TelemetrySnapshot::from_aggregator())
}
```

---

## 3️⃣ Encrypt Processor (Symmetric Layer)

```rust
pub struct EncryptProcessor {
    crypto: Arc<EncryptContext>,
    compressor: Compressor,
}

impl SegmentProcessor for EncryptProcessor {
    type Input = Bytes;
    type Output = ProcessedSegment;

    fn process(
        &self,
        index: u32,
        segment: Bytes,
    ) -> Result<ProcessedSegment, StreamError> {

        // 1️⃣ Compress
        let compressed = self.compressor.compress(&segment)?;

        // 2️⃣ Split into frames
        let frames = split_into_frames(compressed, self.crypto.base.frame_size);

        // 3️⃣ Frame crypto
        let encrypted_frames = encrypt_frames(&self.crypto, index, frames)?;

        // 4️⃣ Reassemble
        Ok(ProcessedSegment::from_frames(index, encrypted_frames))
    }
}
```

---

## 4️⃣ Decrypt Processor (Perfect Mirror)

```rust
pub struct DecryptProcessor {
    crypto: Arc<DecryptContext>,
    decompressor: Decompressor,
}

impl SegmentProcessor for DecryptProcessor {
    type Input = Bytes;
    type Output = ProcessedSegment;

    fn process(
        &self,
        index: u32,
        segment: Bytes,
    ) -> Result<ProcessedSegment, StreamError> {

        // 1️⃣ Split encrypted frames
        let frames = parse_frames(segment)?;

        // 2️⃣ Decrypt frames
        let decrypted = decrypt_frames(&self.crypto, index, frames)?;

        // 3️⃣ Reassemble
        let assembled = assemble_frames(decrypted)?;

        // 4️⃣ Decompress
        let plaintext = self.decompressor.decompress(&assembled)?;

        Ok(ProcessedSegment::from_plaintext(index, plaintext))
    }
}
```

---

## 5️⃣ Encrypt Pipeline (Now Tiny)

```rust
pub fn encrypt_pipeline<R, W>(
    reader: R,
    writer: W,
    crypto: Arc<EncryptContext>,
    config: &PipelineConfig,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    let processor = Arc::new(EncryptProcessor::new(crypto));

    process_stream_lockfree(reader, writer, processor, config)
}
```

---

## 6️⃣ Decrypt Pipeline (Same Runtime)

```rust
pub fn decrypt_pipeline<R, W>(
    reader: R,
    writer: W,
    crypto: Arc<DecryptContext>,
    config: &PipelineConfig,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    let processor = Arc::new(DecryptProcessor::new(crypto));

    process_stream_lockfree(reader, writer, processor, config)
}
```

---

## 🔥 What We Now Have

### True Symmetry

| Layer     | Encrypt                 | Decrypt                 |
| --------- | ----------------------- | ----------------------- |
| Runtime   | process_stream_lockfree | process_stream_lockfree |
| Processor | EncryptProcessor        | DecryptProcessor        |
| Pre-step  | Compress                | —                       |
| Frame     | Encrypt                 | Decrypt                 |
| Post-step | —                       | Decompress              |
| Commit    | OrderedCommit           | OrderedCommit           |

---

### Guarantees

* Lock-free hot path
* Bounded memory (segment_size × inflight)
* No preloading entire stream
* No mutex
* Deterministic ordering
* Backpressure via bounded channel
* Identical runtime code for both paths
* Compression fully symmetric

---

## 🧠 This Is No Longer Half-Baked Torrent

It is:

> A deterministic ordered streaming crypto runtime with pluggable segment processor.

Torrent uses piece scheduler.

We don’t.

We are a streaming transform engine.

Sequential commit is correct.

---

## 🔷 1️⃣ Frame Model

We assume:

```rust
pub struct FrameHeader {
    pub segment_index: u32,
    pub frame_index: u16,
    pub is_last: bool,
}

pub struct Frame {
    pub header: FrameHeader,
    pub payload: Bytes,
}
```

Encrypted frame = header + ciphertext.

---

## 🔷 2️⃣ FrameProcessor Trait (Crypto Layer Only)

This handles **single frame crypto**.

```rust
pub trait FrameProcessor: Send + Sync {
    fn process_frame(
        &self,
        header: &FrameHeader,
        payload: &[u8],
    ) -> Result<Vec<u8>, StreamError>;
}
```

Encrypt and decrypt both implement this.

---

## 🔷 3️⃣ EncryptFrameProcessor

```rust
pub struct EncryptFrameProcessor {
    crypto: Arc<EncryptContext>,
}

impl EncryptFrameProcessor {
    pub fn new(crypto: Arc<EncryptContext>) -> Self {
        Self { crypto }
    }
}

impl FrameProcessor for EncryptFrameProcessor {
    fn process_frame(
        &self,
        header: &FrameHeader,
        payload: &[u8],
    ) -> Result<Vec<u8>, StreamError> {

        // Derive nonce from segment + frame index
        let nonce = self.crypto.derive_nonce(
            header.segment_index,
            header.frame_index,
        );

        let ciphertext = self.crypto
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| StreamError::CryptoError("encrypt failed".into()))?;

        Ok(ciphertext)
    }
}
```

---

## 🔷 4️⃣ DecryptFrameProcessor (Mirror)

```rust
pub struct DecryptFrameProcessor {
    crypto: Arc<DecryptContext>,
}

impl DecryptFrameProcessor {
    pub fn new(crypto: Arc<DecryptContext>) -> Self {
        Self { crypto }
    }
}

impl FrameProcessor for DecryptFrameProcessor {
    fn process_frame(
        &self,
        header: &FrameHeader,
        payload: &[u8],
    ) -> Result<Vec<u8>, StreamError> {

        let nonce = self.crypto.derive_nonce(
            header.segment_index,
            header.frame_index,
        );

        let plaintext = self.crypto
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_| StreamError::CryptoError("decrypt failed".into()))?;

        Ok(plaintext)
    }
}
```

Perfect symmetry.

---

## 🔷 5️⃣ Frame Splitting

```rust
pub fn split_into_frames(
    segment: Vec<u8>,
    frame_size: usize,
    segment_index: u32,
) -> Vec<Frame> {

    let mut frames = Vec::new();
    let mut offset = 0;
    let mut frame_index = 0u16;

    while offset < segment.len() {
        let end = (offset + frame_size).min(segment.len());

        let header = FrameHeader {
            segment_index,
            frame_index,
            is_last: end == segment.len(),
        };

        frames.push(Frame {
            header,
            payload: Bytes::copy_from_slice(&segment[offset..end]),
        });

        offset = end;
        frame_index += 1;
    }

    frames
}
```

---

## 🔷 6️⃣ Frame Assembly

```rust
pub fn assemble_frames(frames: Vec<Frame>) -> Result<Vec<u8>, StreamError> {

    let mut output = Vec::new();

    for frame in frames {
        output.extend_from_slice(&frame.payload);
    }

    Ok(output)
}
```

---

## 🔷 7️⃣ EncryptProcessor (Segment Layer)

```rust
pub struct EncryptProcessor {
    crypto: Arc<EncryptContext>,
    compressor: Compressor,
    frame_processor: Arc<EncryptFrameProcessor>,
}

impl EncryptProcessor {
    pub fn new(crypto: Arc<EncryptContext>) -> Self {
        let frame_processor =
            Arc::new(EncryptFrameProcessor::new(crypto.clone()));

        Self {
            crypto,
            compressor: Compressor::new(),
            frame_processor,
        }
    }
}

impl SegmentProcessor for EncryptProcessor {
    type Input = Bytes;
    type Output = ProcessedSegment;

    fn process(
        &self,
        index: u32,
        segment: Bytes,
    ) -> Result<ProcessedSegment, StreamError> {

        // 1️⃣ Compress
        let compressed = self.compressor.compress(&segment)?;

        // 2️⃣ Split into frames
        let frames = split_into_frames(
            compressed,
            self.crypto.base.frame_size,
            index,
        );

        // 3️⃣ Frame crypto
        let mut encrypted_frames = Vec::with_capacity(frames.len());

        for frame in frames {
            let ciphertext = self.frame_processor.process_frame(
                &frame.header,
                &frame.payload,
            )?;

            encrypted_frames.push(Frame {
                header: frame.header,
                payload: Bytes::from(ciphertext),
            });
        }

        // 4️⃣ Reassemble (serialize)
        let serialized = serialize_frames(encrypted_frames)?;

        Ok(ProcessedSegment::new(index, Bytes::from(serialized)))
    }
}
```

---

## 🔷 8️⃣ DecryptProcessor (Mirror)

```rust
pub struct DecryptProcessor {
    crypto: Arc<DecryptContext>,
    decompressor: Decompressor,
    frame_processor: Arc<DecryptFrameProcessor>,
}

impl DecryptProcessor {
    pub fn new(crypto: Arc<DecryptContext>) -> Self {
        let frame_processor =
            Arc::new(DecryptFrameProcessor::new(crypto.clone()));

        Self {
            crypto,
            decompressor: Decompressor::new(),
            frame_processor,
        }
    }
}

impl SegmentProcessor for DecryptProcessor {
    type Input = Bytes;
    type Output = ProcessedSegment;

    fn process(
        &self,
        index: u32,
        segment: Bytes,
    ) -> Result<ProcessedSegment, StreamError> {

        // 1️⃣ Parse frames
        let frames = parse_frames(segment)?;

        // 2️⃣ Frame decrypt
        let mut decrypted_frames = Vec::with_capacity(frames.len());

        for frame in frames {
            let plaintext = self.frame_processor.process_frame(
                &frame.header,
                &frame.payload,
            )?;

            decrypted_frames.push(Frame {
                header: frame.header,
                payload: Bytes::from(plaintext),
            });
        }

        // 3️⃣ Reassemble
        let assembled = assemble_frames(decrypted_frames)?;

        // 4️⃣ Decompress
        let plaintext = self.decompressor.decompress(&assembled)?;

        Ok(ProcessedSegment::new(index, Bytes::from(plaintext)))
    }
}
```

---

## 🔥 Now Our Architecture Is Fully Layered

```bash
process_stream_lockfree
        ↓
SegmentProcessor
        ↓
FrameProcessor
        ↓
Cipher
```

---

## 💎 Properties Achieved

* Lock-free hot path
* Streaming bounded
* Perfect encrypt/decrypt symmetry
* Compression isolated
* Frame crypto isolated
* Ordered commit guaranteed
* Deterministic segment index usage
* No shared mutable state
* No global telemetry lock

---

## ⚠️ One Important Note

Right now frame crypto is sequential inside segment.

If We want:

* Intra-segment parallel frame crypto

We can easily:

* Spawn rayon parallel iterator inside `process`
* Or use small thread pool
* Without breaking outer streaming pipeline

---

## 🧠 Part 1 — Rayon vs Small Thread Pool

We already have:

```bash
process_stream_lockfree
    → N segment workers (cpu_workers)
        → processor.process(segment)
```

So we already have **inter-segment parallelism**.

If we now also parallelize frames *inside* a segment:

We create **nested parallelism**.

---

## Option 1 — Rayon inside `process()`

Pros:

* Extremely simple
* Good work stealing
* Automatic load balancing

Cons:

* Global thread pool
* Nested parallelism oversubscription
* Harder to bound CPU usage
* Breaks strict control over inflight concurrency

We could easily get:

```bash
cpu_workers × rayon_threads
```

** on a 4-core machine (quad core), this will oversubscribe.

---

## Option 2 — Small Dedicated Thread Pool (Bounded)

Pros:

* Fully bounded
* No oversubscription
* Deterministic CPU usage
* Clean separation from outer runtime
* Better for high-throughput streaming engine

Cons:

* Slightly more implementation work

---

## ✅ Correct Choice

**Use a small dedicated frame thread pool.**

Because:

* Our outer runtime already parallelizes segments.
* We want deterministic bounded concurrency.
* We want predictable latency.
* We want backpressure control.

Rayon is better for pure compute tasks.
We are building a streaming engine.

So we choose:

> Small fixed-size frame pool per processor (or global bounded pool).

---

## 🧠 Part 2 — Zero-Copy Frame Crypto

Right now we do:

```rust
Vec<u8> allocations
Bytes::from(...)
Vec::extend(...)
```

That causes:

* Heap allocation per frame
* Copy from input to Vec
* Copy to Bytes

We can eliminate almost all of this.

---

## 🔥 Design: Zero-Copy Frame Processing

We switch from:

```bash
Vec<Frame>
Vec<u8>
```

To:

```bash
BytesMut (single buffer)
slice references
in-place AEAD
```

The idea:

1. Pre-allocate output buffer per segment.
2. Write encrypted frames directly into it.
3. Avoid intermediate Vec.

---

## 🧱 Implementation

---

## 1️⃣ Frame Processor Trait (Zero-Copy)

```rust
pub trait FrameProcessor: Send + Sync {
    fn process_in_place(
        &self,
        header: &FrameHeader,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, StreamError>;
}
```

It writes ciphertext directly into provided buffer.

No allocation.

Returns number of bytes written.

---

## 2️⃣ EncryptFrameProcessor (Zero-Copy)

Assuming AEAD produces `input.len() + TAG_SIZE`.

```rust
impl FrameProcessor for EncryptFrameProcessor {
    fn process_in_place(
        &self,
        header: &FrameHeader,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, StreamError> {

        let nonce = self.crypto.derive_nonce(
            header.segment_index,
            header.frame_index,
        );

        let written = self.crypto
            .cipher
            .encrypt_in_place(&nonce, input, output)
            .map_err(|_| StreamError::CryptoError("encrypt failed".into()))?;

        Ok(written)
    }
}
```

No Vec.

---

## 3️⃣ DecryptFrameProcessor (Zero-Copy)

```rust
impl FrameProcessor for DecryptFrameProcessor {
    fn process_in_place(
        &self,
        header: &FrameHeader,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, StreamError> {

        let nonce = self.crypto.derive_nonce(
            header.segment_index,
            header.frame_index,
        );

        let written = self.crypto
            .cipher
            .decrypt_in_place(&nonce, input, output)
            .map_err(|_| StreamError::CryptoError("decrypt failed".into()))?;

        Ok(written)
    }
}
```

---

## 4️⃣ Segment-Level Parallel Frame Execution (Bounded Pool)

We create a small pool once:

```rust
pub struct FramePool {
    sender: crossbeam::channel::Sender<FrameTask>,
}
```

Workers run forever.

Inside `EncryptProcessor::process()`:

---

## Zero-Copy + Parallel Segment Execution

```rust
fn process_in_place(
    &self,
    index: u32,
    segment: Bytes,
) -> Result<ProcessedSegment, StreamError> {

    // 1️⃣ Compress
    let compressed = self.compressor.compress(&segment)?;

    let frame_size = self.crypto.base.frame_size;
    let total_len = compressed.len();

    // Pre-allocate output buffer (worst case: +tag per frame)
    let mut output = BytesMut::with_capacity(
        total_len + self.crypto.tag_overhead_estimate(total_len),
    );

    let frames = split_ranges(total_len, frame_size);

    // Channel to collect results
    let (tx, rx) = bounded(frames.len());

    for (frame_index, range) in frames.iter().enumerate() {

        let header = FrameHeader {
            segment_index: index,
            frame_index: frame_index as u16,
            is_last: range.end == total_len,
        };

        let input_slice = &compressed[range.clone()];
        let mut output_slice = unsafe {
            output.chunk_mut()
        };

        let processor = self.frame_processor.clone();
        let tx = tx.clone();

        self.frame_pool.submit(move || {
            let written = processor.process_in_place(
                &header,
                input_slice,
                &mut output_slice,
            )?;

            tx.send((frame_index, written))?;
            Ok::<_, StreamError>(())
        });
    }

    drop(tx);

    // Commit frames in order
    for _ in 0..frames.len() {
        let (_frame_index, written) = rx.recv()?;
        unsafe { output.advance_mut(written); }
    }

    Ok(ProcessedSegment::new(index, output.freeze()))
}
```

---

## 🔥 What This Achieves

### Zero-copy

* No Vec per frame
* No Bytes clone
* Single allocation per segment

### Parallel frame crypto

* Bounded pool
* No oversubscription
* No global Rayon interference

### Streaming intact

* Outer pipeline unchanged
* Segment-level bounded inflight still applies
* Memory bounded by:

  ```bash
  inflight_segments × segment_size
  ```

---

## 🧠 Why This Is Superior to Rayon

| Feature                | Rayon    | Small Pool    |
| ---------------------- | -------- | ------------- |
| CPU bounded            | ❌ maybe | ✅ guaranteed |
| Nested parallel safety | ❌       | ✅            |
| Deterministic          | ❌       | ✅            |
| Streaming friendly     | ⚠️       | ✅            |
| Control                | Low      | High          |

For a crypto streaming engine:

Determinism > Convenience.

---

## 🚀 Final Architecture (Fully Optimized)

```bash
process_stream_lockfree
    → segment workers (N)
        → compress
        → parallel frame crypto (bounded pool)
        → reassemble zero-copy
    → ordered writer
```

No locks.
No Vec churn.
No nested uncontrolled parallelism.
Fully bounded.
Fully streaming safe.

---
