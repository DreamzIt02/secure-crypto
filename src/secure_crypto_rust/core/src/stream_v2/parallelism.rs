
fn detect_opencl_count() -> usize {

    let mut cl_count = 0;
    let platforms = ocl::Platform::list(); // returns Vec<Platform>
    for p in platforms {
        // Device::list_all returns Result<Vec<Device>, OclError>
        if let Ok(devices) = ocl::Device::list_all(p) {
            cl_count += devices.len();
        }
    }
    if cl_count > 0 {
        eprintln!("[GPU DETECT] OpenCL devices found: {}", cl_count);
    }
    cl_count
}

async fn detect_wgpu_count() -> usize {
    let instance = wgpu::Instance::default();
    let adapters = instance.enumerate_adapters(wgpu::Backends::all()).await;
    if !adapters.is_empty() {
        eprintln!("[GPU DETECT] wgpu adapters found: {}", adapters.len());
        return adapters.len();
    }
    0
}


/// Return the number of GPU devices detected across CUDA, OpenCL, and wgpu backends.
pub fn detect_gpu_count() -> usize {
    // CUDA
    #[cfg(feature = "cuda")]
    {
        if let Ok(count) = cust::device::Device::num_devices() {
            if count > 0 {
                eprintln!("[GPU DETECT] CUDA devices found: {}", count);
                return count as usize;
            }
        }
    }
    
    // OpenCL
    let cl_count = detect_opencl_count();
    if cl_count > 0 {
        return cl_count;
    }

    // Vulkan/Metal/DX via wgpu
    let cl_count = pollster::block_on(detect_wgpu_count());
    if cl_count > 0 {
        return cl_count;
    }

    eprintln!("[GPU DETECT] No GPU devices found");
    0
}

/// Parallelism configuration
#[derive(Debug, Clone)]
pub struct ParallelismProfile {
    pub worker_count: usize,
    pub inflight_segments: usize,
}

impl ParallelismProfile {
    pub fn single_threaded() -> Self {
        Self {
            worker_count: 1,
            inflight_segments: 1,
        }
    }
    pub fn dynamic(max_segment_size: u64, mem_fraction: f64, hard_cap: usize) -> Self {
        let cores = num_cpus::get();
        let worker_count = cores.saturating_sub(1); // leave one core free

        let mut sys = sysinfo::System::new_all();
        sys.refresh_memory();

        let avail_mem_kb = sys.available_memory(); // in KB
        let avail_bytes = avail_mem_kb * 1024;

        // Budget = fraction of available memory
        let budget = (avail_bytes as f64 * mem_fraction) as u64;

        let max_segments = budget / max_segment_size;

        Self {
            worker_count,
            inflight_segments: max_segments.min(hard_cap as u64) as usize,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HybridParallelismProfile {
    pub cpu_workers: usize,
    pub gpu_workers: usize,
    pub inflight_segments: usize,
}

impl HybridParallelismProfile {
    pub fn single_threaded() -> Self {
        Self {
            cpu_workers: 1,
            gpu_workers: 1,
            inflight_segments: 1,
        }
    }
    pub fn dynamic(max_segment_size: u64, mem_fraction: f64, hard_cap: usize) -> Self {
        let cores = num_cpus::get();
        let cpu_workers = cores.saturating_sub(1);

        let mut sys = sysinfo::System::new_all();
        sys.refresh_memory();
        let avail_bytes = sys.available_memory() * 1024;
        let budget = (avail_bytes as f64 * mem_fraction) as u64;
        let max_segments = budget / max_segment_size;

        let gpu_workers = detect_gpu_count();

        eprintln!(
            "[PROFILE] cpu_workers={}, gpu_workers={}, inflight_segments={}",
            cpu_workers,
            gpu_workers,
            max_segments.min(hard_cap as u64)
        );

        Self {
            cpu_workers,
            gpu_workers,
            inflight_segments: max_segments.min(hard_cap as u64) as usize,
        }
    }
}

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
    if gpu_workers > 0 && segment_size >= gpu_threshold {
        // Choose GPU with lowest load
        let (idx, _) = gpu_load
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| *load)
            .unwrap();
        WorkerTarget::Gpu(idx)
    } else {
        // Choose CPU with lowest load
        let (idx, _) = cpu_load
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| *load)
            .unwrap();
        WorkerTarget::Cpu(idx)
    }
}

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
        if !self.gpu_load.is_empty() && segment_size >= self.gpu_threshold {
            // Choose GPU with lowest load
            let (idx, _) = self.gpu_load
                .iter()
                .enumerate()
                .min_by_key(|(_, load)| *load)
                .unwrap();
            self.gpu_load[idx] += 1; // increment load
            WorkerTarget::Gpu(idx)
        } else {
            // Choose CPU with lowest load
            let (idx, _) = self.cpu_load
                .iter()
                .enumerate()
                .min_by_key(|(_, load)| *load)
                .unwrap();
            self.cpu_load[idx] += 1; // increment load
            WorkerTarget::Cpu(idx)
        }
    }

    /// Mark a worker as finished with a segment
    pub fn complete(&mut self, target: WorkerTarget) {
        match target {
            WorkerTarget::Cpu(idx) => {
                if self.cpu_load[idx] > 0 {
                    self.cpu_load[idx] -= 1;
                }
            }
            WorkerTarget::Gpu(idx) => {
                if self.gpu_load[idx] > 0 {
                    self.gpu_load[idx] -= 1;
                }
            }
        }
    }
}
