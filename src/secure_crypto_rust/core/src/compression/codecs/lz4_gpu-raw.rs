// ## 🔧 GPU LZ4 Compressor/Decompressor (Sketch)

use bincode::serde::encode_to_vec;
use bincode::config::standard;
use wgpu::{util::DeviceExt, wgt::PollType};
use bytemuck::{cast_slice, Pod, Zeroable};

use crate::compression::types::{Compressor, CompressionError};

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Word(u32);

pub struct Lz4GpuCompressor {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
}

impl Lz4GpuCompressor {
    pub async fn new() -> Result<Self, CompressionError> {
        let instance = wgpu::Instance::default();
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::LowPower,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .map_err(|e| CompressionError::CodecInitFailed {
                codec: "lz4_gpu".into(),
                msg: format!("Adapter request failed: {e:?}"),
            })?;
        
        let info = adapter.get_info();
        println!("Adapter info: {:?}", info);

        let features = adapter.features();
        let limits = adapter.limits();
        println!("Features: {:?}, Limits: {:?}", features, limits);

        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("lz4-gpu-device"),
                    required_features: adapter.features(), // not empty, not more than supported
                    required_limits: adapter.limits(),     // exactly what adapter supports
                    memory_hints: wgpu::MemoryHints::default(),
                    trace: wgpu::Trace::Off,
                    experimental_features: wgpu::ExperimentalFeatures::default(),
                },
            )
            .await
            .map_err(|e| CompressionError::CodecInitFailed {
                codec: "lz4_gpu".into(),
                msg: e.to_string(),
            })?;
         // trace: wgpu::Trace::Enabled {
            //     directory: std::path::PathBuf::from("trace_output"),
            // },

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("LZ4 GPU Compressor Shader"),
            source: wgpu::ShaderSource::Wgsl(include_str!("lz4_hash.wgsl").into()),
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("LZ4 GPU Pipeline"),
            layout: None,
            module: &shader,
            entry_point: Some("main"),
            cache: None, // no pipeline cache
            compilation_options: wgpu::PipelineCompilationOptions::default(), // default options
        });

        Ok(Self { device, queue, pipeline })
    }
}

impl Compressor for Lz4GpuCompressor {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        if input.is_empty() {
            return Ok(());
        }

        // Convert input to u32 words
        let words: Vec<Word> = input
            .chunks_exact(4)
            .map(|c| Word(u32::from_le_bytes(c.try_into().unwrap())))
            .collect();

        let input_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Input Buffer"),
            contents: cast_slice(&words),
            usage: wgpu::BufferUsages::STORAGE,
        });

        let output_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("Output Buffer"),
            size: (words.len() * 4) as u64,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        let bind_group_layout = self.pipeline.get_bind_group_layout(0);
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Bind Group"),
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: input_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 1, resource: output_buf.as_entire_binding() },
            ],
        });

        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        {
            let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: None,
                timestamp_writes: None, // no timestamp queries
            });

            cpass.set_pipeline(&self.pipeline);
            cpass.set_bind_group(0, &bind_group, &[]);
            cpass.dispatch_workgroups(((words.len() as u32) + 63) / 64, 1, 1);
        }
        self.queue.submit(Some(encoder.finish()));

        // Map and read back
        let slice = output_buf.slice(..);
        slice.map_async(wgpu::MapMode::Read, |_| {});
        // Block until ready
        // If we want to wait for all submissions (the common case when mapping a buffer):
        self.device
            .poll(PollType::Wait {
                submission_index: None,   // wait for all GPU work
                timeout: None,            // block indefinitely
            })
            .map_err(|e| CompressionError::CodecProcessFailed {
                codec: "lz4_gpu".into(),
                msg: format!("Device poll failed: {e:?}"),
            })?;
        // If we want to wait until a specific submission index:
        // self.device.poll(PollType::Wait {
        //     submission_index: Some(SubmissionIndex::from(42)), // example index
        //     timeout: Some(Duration::from_millis(500)),         // half‑second timeout
        // })?;

        let data = slice.get_mapped_range();
        let hashes: Vec<u32> = bytemuck::cast_slice(&data).to_vec();
        drop(data);
        output_buf.unmap();

        let encoded: Vec<u8> = encode_to_vec(&hashes, standard()).unwrap();
        out.extend_from_slice(&encoded);

        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CompressionError> {
        Ok(())
    }
}


// ## 🔧 GPU LZ4 Compressor/Decompressor (OpenCL version)

use ocl::{flags, Buffer, Context, Device, Kernel, Platform, Program, Queue};

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Word(u32);

pub struct Lz4OclCompressor {
    context: Context,
    queue: Queue,
    program: Program,
    kernel: Kernel,
}

impl Lz4OclCompressor {
    pub fn new() -> Result<Self, CompressionError> {
        // Pick the first available platform and GPU device
        let platform = Platform::default();
        let device = Device::first(platform)
            .map_err(|e| CompressionError::CodecInitFailed {
                codec: "lz4_ocl".into(),
                msg: format!("Failed to get OpenCL device: {e:?}"),
            })?;

        println!("OpenCL Device: {:?}", device.name().unwrap());

        // Create context and queue
        let context = Context::builder()
            .platform(platform)
            .devices(device.clone())
            .build()
            .map_err(|e| CompressionError::CodecInitFailed {
                codec: "lz4_ocl".into(),
                msg: format!("Failed to create OpenCL context: {e:?}"),
            })?;

        let queue = Queue::new(&context, device, None)
            .map_err(|e| CompressionError::CodecInitFailed {
                codec: "lz4_ocl".into(),
                msg: format!("Failed to create OpenCL queue: {e:?}"),
            })?;

        // Load kernel source (replace with the actual LZ4 kernel)
        let src = r#"
            __kernel void lz4_hash(__global const uint* input, __global uint* output) {
                int gid = get_global_id(0);
                output[gid] = input[gid] ^ 0x9e3779b9; // placeholder hash
            }
        "#;

        let program = Program::builder()
            .src(src)
            .devices(device)
            .build(&context)
            .map_err(|e| CompressionError::CodecInitFailed {
                codec: "lz4_ocl".into(),
                msg: format!("Failed to build OpenCL program: {e:?}"),
            })?;

        // Create kernel
        let kernel = Kernel::builder()
            .program(&program)
            .name("lz4_hash")
            .queue(queue.clone())
            .global_work_size(1) // will be overridden per dispatch
            .build()
            .map_err(|e| CompressionError::CodecInitFailed {
                codec: "lz4_ocl".into(),
                msg: format!("Failed to create OpenCL kernel: {e:?}"),
            })?;

        Ok(Self {
            context,
            queue,
            program,
            kernel,
        })
    }
}

impl Compressor for Lz4OclCompressor {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError> {
        if input.is_empty() {
            return Ok(());
        }

        // Convert input to u32 words
        let words: Vec<Word> = input
            .chunks_exact(4)
            .map(|c| Word(u32::from_le_bytes(c.try_into().unwrap())))
            .collect();

        // Create input/output buffers
        let input_buf: Buffer<Word> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(flags::MEM_READ_ONLY)
            .len(words.len())
            .copy_host_slice(&words)
            .build()
            .map_err(|e| CompressionError::CodecProcessFailed {
                codec: "lz4_ocl".into(),
                msg: format!("Failed to create input buffer: {e:?}"),
            })?;

        let output_buf: Buffer<u32> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(flags::MEM_WRITE_ONLY)
            .len(words.len())
            .build()
            .map_err(|e| CompressionError::CodecProcessFailed {
                codec: "lz4_ocl".into(),
                msg: format!("Failed to create output buffer: {e:?}"),
            })?;

        // Set kernel args
        self.kernel.set_arg("input", &input_buf).unwrap();
        self.kernel.set_arg("output", &output_buf).unwrap();

        // Dispatch kernel
        unsafe {
            self.kernel.set_default_global_work_size(words.len());
            self.kernel.enq().map_err(|e| CompressionError::CodecProcessFailed {
                codec: "lz4_ocl".into(),
                msg: format!("Kernel enqueue failed: {e:?}"),
            })?;
        }

        // Read back results
        let mut hashes = vec![0u32; words.len()];
        output_buf.read(&mut hashes).enq().unwrap();

        let encoded: Vec<u8> = encode_to_vec(&hashes, standard()).unwrap();
        out.extend_from_slice(&encoded);

        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CompressionError> {
        Ok(())
    }
}

// ### 📝 Notes
// - This uses `ocl = "0.19.7"`.
// - The kernel is a **placeholder** (`output[gid] = input[gid] ^ 0x9e3779b9`). Replace it with actual LZ4 compression logic.
// - Struct fields mirror the `wgpu` version: `context`, `queue`, `program`, `kernel`.
// - Implements the same `Compressor` trait.
