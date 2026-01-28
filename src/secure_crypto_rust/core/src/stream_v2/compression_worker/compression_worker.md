# 🔧 Compression Worker

## 🔧 Step 1: Trait abstraction

We’ll wrap our existing compressor/decompressor objects behind a trait so the scheduler can treat CPU and GPU uniformly:

```rust
pub trait CompressionBackend: Send {
    fn compress_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError>;
    fn decompress_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError>;
}
```

---

## 🔧 Step 2: CPU backend using our registry

```rust
pub struct CpuCompressionBackend {
    compressor: Box<dyn Compressor + Send>,
    decompressor: Box<dyn Decompressor + Send>,
}

impl CpuCompressionBackend {
    
}

impl CompressionBackend for CpuCompressionBackend {
    
}
```

---

## 🔧 Step 3: GPU backend placeholder

Later we can implement GPU kernels (CUDA/OpenCL/wgpu). For now, we can stub it:

```rust
pub struct GpuCompressionBackend {
    // GPU context, pipelines, etc.
}

impl GpuCompressionBackend {
    pub fn new() -> Self {
        Self { /* init GPU context */ }
    }
}

impl CompressionBackend for GpuCompressionBackend {
    fn compress_chunk(&self, input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // TODO: GPU kernel launch
        Ok(input.to_vec()) // placeholder: no-op
    }

    fn decompress_chunk(&self, input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // TODO: GPU kernel launch
        Ok(input.to_vec()) // placeholder: no-op
    }
}
```

---

## 🔧 Step 4: Scheduler integration

Use the `Scheduler` we already wrote:

```rust
pub fn run_compression_worker(
    rx: Receiver<EncryptSegmentInput>,
    tx: Sender<EncryptSegmentInput>,
    mut backend: Box<dyn CompressionBackend>, // owned by this worker
    scheduler: Arc<Mutex<Scheduler>>,
) {
    ...
}
```

---

## 🔧 Step 5: Pipeline wiring

In `run_encrypt_pipeline`:

```rust
let scheduler = Arc::new(Mutex::new(Scheduler::new(
    profile.cpu_workers(),
    profile.gpu_workers(),
    8 * 1024 * 1024, // threshold
)));

let (comp_tx, comp_rx) = bounded::<EncryptSegmentInput>(profile.inflight_segments());
let (seg_tx, seg_rx) = bounded::<EncryptSegmentInput>(profile.inflight_segments());

// spawn CPU compression workers
for _ in 0..profile.cpu_workers() {
    let backend = Arc::new(CpuCompressionBackend::new(codec_id, level, dict)?);
    let sched = scheduler.clone();
    let rx = comp_rx.clone();
    let tx = seg_tx.clone();
    scope.spawn(move || run_compression_worker(rx, tx, backend, sched));
}

// spawn GPU compression workers
for _ in 0..profile.gpu_workers() {
    let backend = Arc::new(GpuCompressionBackend::new());
    let sched = scheduler.clone();
    let rx = comp_rx.clone();
    let tx = seg_tx.clone();
    scope.spawn(move || run_compression_worker(rx, tx, backend, sched));
}

// reader sends raw segments into comp_tx
```

---

## 🔧 Decompression Worker

This worker runs **after crypto** in the decrypt pipeline:

```rust
pub fn run_decompression_worker(
    rx: Receiver<DecryptSegmentOutput>, // segments after crypto
    tx: Sender<DecryptSegmentOutput>,       // forward to writer
    mut backend: Box<dyn CompressionBackend>,
    scheduler: Arc<Mutex<Scheduler>>,
) {
    ...
}
```

---

## ⚖️ Pipeline Flow (Decrypt Side)

1. Reader → encrypted segments.  
2. Crypto workers → decrypted but still compressed segments.  
3. Decompression workers → decompress plaintext.  
4. Ordered writer → writes final plaintext stream.

---

## 🏁 Bottom line

- Our existing `create_compressor` / `create_decompressor` APIs plug directly into a `CpuCompressionBackend`.
- The scheduler decides CPU vs GPU per segment.
- Compression workers forward compressed segments into the crypto workers.
- GPU backend can be filled in later with Metal/CUDA kernels.

- Decompression mirrors compression: each worker owns its backend (`Box<dyn CompressionBackend>`).  
- Scheduler decides CPU vs GPU per segment.  
- Workers call `backend.decompress_chunk()` to expand data before writing.

---

## ✅ Example structure

```bash
src/
 ├─ stream_v2/
 │   ├─ parallelism.rs          // HybridParallelismProfile
 │   ├─ compression_worker/
 │   │   └─ worker.rs           // run_compression_worker, run_decompression_worker
 │   └─ compression_pipeline.rs // spawn_compression_workers(), spawn_decompression_workers()
```

---

### `compression_worker/worker.rs`

```rust
pub fn run_compression_worker(
    rx: Receiver<EncryptSegmentInput>,
    tx: Sender<EncryptSegmentInput>,
    mut backend: Box<dyn CompressionBackend>,
    scheduler: Arc<Mutex<Scheduler>>,
) { ... }

pub fn run_decompression_worker(
    rx: Receiver<DecryptedSegment>,
    tx: Sender<DecryptedSegment>,
    mut backend: Box<dyn CompressionBackend>,
    scheduler: Arc<Mutex<Scheduler>>,
) { ... }
```

---

## 🔧 Integration Plan

1. **Encrypt pipeline wiring**  
   - Reader → raw segments → **compression workers** → compressed segments → crypto workers → writer.  
   - So instead of sending directly into `seg_tx`, we introduce a compression stage.

Crypto workers then consume from `seg_rx` as before.

---

1. **Decrypt pipeline wiring**  
   - Reader → encrypted segments → crypto workers → **decompression workers** → writer.  
   - So instead of sending directly into `out_tx`, crypto workers send into a decompression stage.

---

## ⚖️ Benefits

- **Encapsulation**: `pipeline.rs` only calls `spawn_compression_workers` / `spawn_decompression_workers`. It doesn’t care about backend choice.  
- **Symmetry**: Encrypt pipeline has compression before crypto; decrypt pipeline has decompression after crypto.  
- **Future‑proof**: GPU acceleration is handled inside `compression_pipeline.rs`, not in pipeline logic.  

---
