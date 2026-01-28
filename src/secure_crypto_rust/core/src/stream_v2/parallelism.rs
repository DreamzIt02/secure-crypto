
pub const GPU_THRESHOLD: usize = 4 * 1024 * 1024; // 4 MB

#[derive(Debug, Copy, Clone)]
pub enum GpuBackend {
    None,
    Cuda,
    Wgpu,
    OpenCL,
}

#[derive(Debug, Clone)]
pub struct GpuInfo {
    pub count: usize,
    pub backend: GpuBackend,
    pub device_names: Vec<String>,
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

// fn detect_opencl_count() -> usize {

//     let mut cl_count = 0;
//     let platforms = ocl::Platform::list(); // returns Vec<Platform>
//     for p in platforms {
//         // Device::list_all returns Result<Vec<Device>, OclError>
//         if let Ok(devices) = ocl::Device::list_all(p) {
//             cl_count += devices.len();
//         }
//     }
//     if cl_count > 0 {
//         eprintln!("[GPU DETECT] OpenCL devices found: {}", cl_count);
//     }
//     cl_count
// }


pub fn detect_gpu_info() -> GpuInfo {
    // CUDA
    #[cfg(feature = "cuda")]
    {
        if let Ok(count) = cust::device::Device::num_devices() {
            if count > 0 {
                eprintln!("[GPU DETECT] CUDA devices found: {}", count);
                let names = (0..count)
                    .filter_map(|i| cust::device::Device::get(i).ok())
                    .map(|d| d.name().unwrap_or_else(|_| "Unknown CUDA device".into()))
                    .collect();
                return GpuInfo {
                    count: count as usize,
                    backend: GpuBackend::Cuda,
                    device_names: names,
                };
            }
        }
    }

    // OpenCL
    let mut names = Vec::new();
    let cl_count = {
        let mut cl_count = 0;
        let platforms = ocl::Platform::list();
        for p in platforms {
            if let Ok(devices) = ocl::Device::list_all(p) {
                cl_count += devices.len();
                names.extend(devices.iter().map(|d| d.name().unwrap_or("Unknown OpenCL device".into())));
            }
        }
        cl_count
    };
    if cl_count > 0 {
        eprintln!("[GPU DETECT] OpenCL devices found: {}", cl_count);
        return GpuInfo {
            count: cl_count,
            backend: GpuBackend::OpenCL,
            device_names: names,
        };
    }

    // Vulkan/Metal/DX via wgpu
    let adapters = pollster::block_on(detect_wgpu_count());
    if adapters > 0 {
        eprintln!("[GPU DETECT] wgpu adapters found: {}", adapters);
        // wgpu::Adapter doesn’t expose names directly without async device creation,
        // so we can leave names empty or fill with placeholders.
        return GpuInfo {
            count: adapters,
            backend: GpuBackend::Wgpu,
            device_names: Vec::new(),
        };
    }

    eprintln!("[GPU DETECT] No GPU devices found");
    GpuInfo {
        count: 0,
        backend: GpuBackend::None,
        device_names: Vec::new(),
    }
}

/// Return the number of GPU devices detected across CUDA, OpenCL, and wgpu backends.
// pub fn detect_gpu_count() -> usize {
//     // CUDA
//     #[cfg(feature = "cuda")]
//     {
//         if let Ok(count) = cust::device::Device::num_devices() {
//             if count > 0 {
//                 eprintln!("[GPU DETECT] CUDA devices found: {}", count);
//                 return count as usize;
//             }
//         }
//     }
    
//     // Vulkan/Metal/DX via wgpu
//     let cl_count = pollster::block_on(detect_wgpu_count());
//     if cl_count > 0 {
//         return cl_count;
//     }

//     // OpenCL
//     let cl_count = detect_opencl_count();
//     if cl_count > 0 {
//         return cl_count;
//     }

//     eprintln!("[GPU DETECT] No GPU devices found");
//     0
// }

/// Parallelism configuration
#[derive(Debug, Clone)]
pub struct HybridParallelismProfile {
    cpu_workers: usize,
    gpu_workers: usize,
    inflight_segments: usize,
    gpu_threshold: usize,
    gpu: Option<GpuInfo>,
}

impl HybridParallelismProfile {
    /// Controlled constructor
    pub fn new(cpu_workers: usize, gpu_workers: usize, inflight_segments: usize) -> Self {
        let gpu = detect_gpu_info();
        // enforce sane limits
        let cpu_workers = cpu_workers.clamp(1, num_cpus::get().saturating_sub(1));
        let gpu_workers = gpu_workers.clamp(0, gpu.count); // arbitrary cap, adjust as needed
        let inflight_segments = inflight_segments.clamp(1, 64);

        Self {
            cpu_workers,
            gpu_workers,
            inflight_segments,
            gpu_threshold: GPU_THRESHOLD,
            gpu: Some(gpu),
        }
    }

    /// Read-only accessors
    pub fn cpu_workers(&self) -> usize {
        self.cpu_workers
    }

    pub fn gpu_workers(&self) -> usize {
        self.gpu_workers
    }

    pub fn inflight_segments(&self) -> usize {
        self.inflight_segments
    }

    pub fn gpu_threshold(&self) -> usize {
        self.gpu_threshold
    }

    pub fn gpu(&self) -> Option<GpuInfo> {
        self.gpu.clone()
    }
    
    pub fn single_threaded() -> Self {
        let gpu = detect_gpu_info();
        Self {
            cpu_workers: 1,
            gpu_workers: 1.clamp(0, gpu.count),
            inflight_segments: 1,
            gpu_threshold: GPU_THRESHOLD,
            gpu: Some(gpu),
        }
    }
    // * On a machine with 16 cores and 16 GB free RAM:
    // * `worker_count = 15`
    // * `budget = 8 GB` (50% of 16 GB)
    // * `max_segment_size = 32 MB`
    // * `max_segments = 8192 MB / 32 MB = 256`
    // * With `hard_cap = 64`, we get `inflight_segments = 64`.
    pub fn dynamic(max_segment_size: u32, mem_fraction: f64, hard_cap: usize) -> Self {
        let cores = num_cpus::get();
        let cpu_workers = cores.saturating_sub(1);

        let mut sys = sysinfo::System::new_all();
        sys.refresh_memory();
        let avail_bytes = sys.available_memory() * 1024;
        let budget = (avail_bytes as f64 * mem_fraction) as u32;
        let max_segments = budget / max_segment_size;

        let gpu = detect_gpu_info();
        let gpu_workers = gpu.count;

        eprintln!(
            "[PROFILE] cpu_workers={}, gpu_workers={}, inflight_segments={}",
            cpu_workers,
            gpu_workers,
            max_segments.min(hard_cap as u32)
        );

        Self {
            cpu_workers,
            gpu_workers,
            inflight_segments: max_segments.min(hard_cap as u32) as usize,
            gpu_threshold: GPU_THRESHOLD,
            gpu: Some(gpu),
        }
    }

}


#[derive(Debug, Clone, PartialEq)]
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
) -> Option<WorkerTarget> {
    if gpu_workers > 0 && segment_size >= gpu_threshold {
        // Choose GPU with lowest load
        let (idx, _) = gpu_load
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| *load)
            .unwrap();
       Some(WorkerTarget::Gpu(idx))
    } 
    else if cpu_workers > 0 {
        // Choose CPU with lowest load
        let (idx, _) = cpu_load
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| *load)
            .unwrap();
        Some(WorkerTarget::Cpu(idx))
    }
    else {
        None
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
