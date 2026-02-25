# 🖥️ Dynamic Parallelism

Instead of hard‑coding `worker_count` and `inflight_segments`, we can derive them at runtime:

* **CPU cores**:  
  Use `num_cpus::get_physical()` to set `worker_count`. For example, `worker_count = num_cpus::get_physical() / 2` if we want to leave headroom for other tasks.
  
* **Memory capacity**:  
  Use `sysinfo` crate (`System::new_all()`) to query total RAM. Then set `inflight_segments` based on `total_memory / max_segment_size`.  
  Example: if we have 16 GB RAM and `max_segment_size = 32 MB`, we could allow up to 512 segments in flight, but cap it lower (e.g. 16–64) to avoid starving the OS.

* **GPU presence**:  
  If we detect a CUDA/OpenCL device, we could increase `worker_count` or offload frame operations to GPU kernels.

```rust
fn dynamic_profile(max_segment_size: usize) -> ParallelismProfile {
    // Hyperthreads do not double AES throughput.
    // Physical cores matter.
    let cores = num_cpus::get().saturation_sub(1);
    let mut sys = sysinfo::System::new_all();
    sys.refresh_memory();
    let total_mem = sys.total_memory(); // in KB

    let max_segments = (total_mem * 1024) / max_segment_size;
    ParallelismProfile {
        worker_count: cores,
        inflight_segments: max_segments.min(64), // cap to avoid runaway
    }
}
```

---

## 🖥️ Dynamic ParallelismProfile Design

### 1. CPU Awareness

* Hyperthreads do not double AES throughput.
* Physical cores matter.
* Detect total cores with `num_cpus::get_physical()` instead of `num_cpus::get()`.
* Use `cores.saturating_sub(1)` to leave one free for OS/system tasks.
* Optionally, scale down further if we want to reserve capacity for other services.

### 2. Memory Awareness

* Use `sysinfo` to query **available memory** (not total).
* Decide on a percentage budget (e.g. 50% of available RAM).
* Divide that budget by `max_segment_size` to compute maximum inflight segments.
* Apply a hard cap (e.g. 64) to avoid runaway allocations.

---

## ⚖️ Example Usage

* On a machine with 16 cores and 16 GB free RAM:
  * `worker_count = 15`
  * `budget = 8 GB` (50% of 16 GB)
  * `max_segment_size = 32 MB`
  * `max_segments = 8192 MB / 32 MB = 256`
  * With `hard_cap = 64`, we get `inflight_segments = 64`.

---

## 🚀 Benefits

* **Adaptive**: scales up on big servers, scales down on constrained machines.
* **Safe**: memory usage capped by percentage × hard cap.
* **Configurable**: we can tune `mem_fraction` (e.g. 0.25, 0.5, 0.75) and `hard_cap` per deployment.

---

👉 With this design, our pipeline will stream multi‑GB workloads efficiently, without waiting for the final marker, and memory usage will stay bounded.  

---

## 🖥️ + ⚡ Hybrid ParallelismProfile

### 1. Detect GPU presence

Rust doesn’t have GPU detection in the standard library, but we can use crates like:

* [`cust`](https://crates.io/crates/cust) for CUDA
* [`ocl`](https://crates.io/crates/ocl) for OpenCL
* [`wgpu`](https://crates.io/crates/wgpu) for Vulkan/DirectX/Metal

Each of these can query available devices. For example, with `ocl`:

```rust
let platforms = ocl::Platform::list();
let gpu_available = platforms.iter().any(|p| {
    ocl::Device::list_all(p).unwrap().iter().any(|d| d.device_type().unwrap().contains("GPU"))
});
```

### 2. Hybrid profile struct

Extend our profile to include both CPU and GPU worker counts:

```rust
#[derive(Clone)]
pub struct HybridParallelismProfile {
    pub cpu_workers: usize,
    pub gpu_workers: usize,
    pub inflight_segments: usize,
}
```

---

### 🔧 `HybridParallelismProfile::dynamic`

```rust
#[derive(Clone)]
pub struct HybridParallelismProfile {
    pub cpu_workers: usize,
    pub gpu_workers: usize,
    pub inflight_segments: usize,
}

impl HybridParallelismProfile {
    pub fn dynamic(max_segment_size: u32, mem_fraction: f64, hard_cap: usize) -> Self {
        ...
    }
}
```

---

### ⚖️ Behavior

* On a machine with 2 CUDA devices → `gpu_workers = 2`.
* On a machine with 1 OpenCL GPU → `gpu_workers = 1`.
* On a machine with multiple Vulkan adapters → `gpu_workers = adapters.len()`.
* If no GPU → `gpu_workers = 0`.

---

## 2. Enabling the CUDA feature

Our Cargo.toml:

```toml
[features]
default = []
cuda = ["cust"]

[dependencies]
cust = { version = "0.3.2", optional = true }
```

### How it works

* By default, `cust` is **not compiled** (because it’s optional).
* If we want CUDA support, we enable the `cuda` feature when building:

  ```bash
  cargo build --features cuda
  ```

* This tells Cargo to include `cust` in the build, and our `#[cfg(feature = "cuda")]` blocks will compile.

### Important

It is **not automatically enabled** just because the machine has CUDA installed. Cargo features are compile‑time switches, not runtime detection. We must explicitly enable the `cuda` feature in our build command or in our project’s default features.

---

## 🎯 Dispatch Policy Goals

* **CPU workers**: handle small/medium segments, or segments where GPU acceleration doesn’t help (e.g. hashing).
* **GPU workers**: handle large segments or compute‑heavy frames (AES, SHA, compression) where parallelism pays off.
* **Fairness**: avoid starving either pool; balance based on segment size and current load.
* **Scalability**: support multiple GPUs by distributing work across them.

* * We can dispatch based on segment size:

  ```rust
  if segment.len() > gpu_threshold && profile.gpu_workers > 0 {
      send_to_gpu(segment);
  } else {
      send_to_cpu(segment);
  }
  ```

---

## ⚖️ Benefits

* **Adaptive**: scales across machines with or without GPUs.
* **Balanced**: CPU threads keep throughput steady, GPU accelerates heavy workloads.
* **Safe**: inflight segments still bounded by memory budget.

---

## 🔧 Policy Sketch

```rust
pub enum WorkerTarget {
    Cpu(usize), // index of CPU worker
    Gpu(usize), // index of GPU device
}

/// Decide where to dispatch a segment based on size and load.
pub fn dispatch_segment(
    segment_size: usize,
    cpu_workers: usize,
    gpu_workers: usize,
    gpu_threshold: usize, // e.g. 8 MB
    cpu_load: &[usize],   // queue depth per CPU worker
    gpu_load: &[usize],   // queue depth per GPU device
) -> WorkerTarget {
    ...
}
```

---

## ⚖️ Dispatch Strategy

1. **Threshold‑based**:  
   * Segments ≥ `gpu_threshold` (e.g. 8–16 MB) → GPU.  
   * Segments < `gpu_threshold` → CPU.
2. **Load‑aware**:  
   * Within each pool, pick the worker/device with the lowest queue depth.  
   * This balances load across multiple GPUs and CPU threads.
3. **Fallback**:  
   * If no GPU available, all segments go to CPU.  
   * If CPU pool is saturated but GPU idle, small segments can spill over to GPU.

---

## 🚀 Example

* Machine: 15 CPU workers, 2 GPUs.
* Threshold: 8 MB.
* Segment sizes:
  * 2 MB → CPU worker with lowest load.
  * 32 MB → GPU device with lowest load.
* If GPU0 has 10 queued segments and GPU1 has 2, the 32 MB segment goes to GPU1.

---

## 🏁 Benefits

* **Efficiency**: large segments leverage GPU parallelism, small ones avoid GPU overhead.
* **Balance**: load spreads across CPU and GPU pools.
* **Scalability**: multiple GPUs are used fairly, not just the first one.

---

## 🔧 Scheduler Loop Sketch

```rust
pub struct Scheduler {
    cpu_load: Vec<usize>, // queue depth per CPU worker
    gpu_load: Vec<usize>, // queue depth per GPU device
    gpu_threshold: usize, // segment size threshold for GPU dispatch
}

impl Scheduler {
    pub fn new(cpu_workers: usize, gpu_workers: usize, gpu_threshold: usize) -> Self {
        Scheduler {
            cpu_load: vec![0; cpu_workers],
            gpu_load: vec![0; gpu_workers],
            gpu_threshold,
        }
    }

    /// Dispatch a segment to CPU or GPU based on size and current load
    pub fn dispatch(&mut self, segment_size: usize) -> WorkerTarget {
        ...
    }

    /// Mark a worker as finished with a segment
    pub fn complete(&mut self, target: WorkerTarget) {
        ...
    }
}
```

---

## ⚖️ How it works

* **Initialization**: Scheduler starts with `cpu_load` and `gpu_load` vectors, each entry representing queue depth for that worker/device.
* **Dispatch**: For each incoming segment:
  * If segment size ≥ `gpu_threshold` → send to GPU with lowest load.
  * Otherwise → send to CPU with lowest load.
* **Completion**: When a worker finishes a segment, call `complete()` to decrement its load counter.
* **Dynamic balancing**: The scheduler always picks the least loaded worker/device, so load spreads evenly.

---

## 🚀 Example Flow

* Machine: 15 CPU workers, 2 GPUs.
* Threshold: 8 MB.
* Segments arrive: [2 MB, 32 MB, 16 MB, 4 MB].
  * 2 MB → CPU worker with lowest load.
  * 32 MB → GPU device with lowest load.
  * 16 MB → GPU device with lowest load (balances across GPUs).
  * 4 MB → CPU worker with lowest load.

---

## 🏁 Benefits (scheduling)

* **Streaming**: Segments are dispatched immediately, no waiting for final marker.
* **Balanced**: Both CPU and GPU pools are used fairly.
* **Adaptive**: Large segments leverage GPU parallelism, small ones avoid GPU overhead.
* **Scalable**: Multiple GPUs are supported, load spread across them.

---

## 🔧 Integrating Scheduler into Pipeline

### 1. Extend our pipeline signature

Add the scheduler as part of the pipeline state:

```rust
pub fn encrypt_pipeline<R, W>(
    mut reader: R,
    mut writer: W,
    crypto: SegmentCryptoContext,
    profile: HybridParallelismProfile,   // use hybrid profile
    log_manager: Arc<AsyncLogManager>,
) -> Result<TelemetrySnapshot, StreamError>
where
    R: Read + Send,
    W: Write + Send,
{
    let mut scheduler = Scheduler::new(
        profile.cpu_workers,
        profile.gpu_workers,
        8 * 1024 * 1024, // gpu_threshold = 8 MB
    );

    // Channels for CPU and GPU segment workers
    let (cpu_seg_tx, cpu_seg_rx) = bounded::<EncryptSegmentInput>(profile.inflight_segments);
    let (gpu_seg_tx, gpu_seg_rx) = bounded::<EncryptSegmentInput>(profile.inflight_segments);

    // ...
}
```

---

### 2. Reader loop dispatch

When the reader produces a segment:

```rust
for segment in read_segments(&mut reader)? {
    let target = scheduler.dispatch(segment.len());

    match target {
        WorkerTarget::Cpu(idx) => {
            cpu_seg_tx.send(segment)?;
        }
        WorkerTarget::Gpu(idx) => {
            gpu_seg_tx.send(segment)?;
        }
    }
}
```

---

### 3. Worker completion

When a worker finishes a segment, notify the scheduler:

```rust
match result {
    Ok(seg) => {
        scheduler.complete(target); // decrement load
        out_tx.send(Ok(seg))?;
    }
    Err(e) => {
        scheduler.complete(target);
        out_tx.send(Err(e))?;
    }
}
```

---

### 4. Decrypt pipeline

Same pattern: reader dispatches to CPU/GPU pools via scheduler, workers notify completion.

---

## ⚖️ Dispatch Flow

1. Reader reads segment.
2. Scheduler decides CPU vs GPU based on size and current load.
3. Segment enqueued into the chosen pool.
4. Worker processes segment.
5. Worker signals completion → scheduler decrements load.
6. Writer flushes segments in order.

---

## 🚀 Benefits (pipeline scheduling)

* **Streaming**: segments are dispatched immediately, not delayed until final marker.
* **Balanced**: load spreads across CPU and GPU pools.
* **Adaptive**: large segments leverage GPU, small ones stay on CPU.
* **Scalable**: multiple GPUs are used fairly.

---
