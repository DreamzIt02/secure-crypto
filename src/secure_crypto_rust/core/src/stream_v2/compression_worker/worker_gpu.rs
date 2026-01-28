use crate::{
    compression::{CodecOptions, CompressionError, Compressor, Decompressor, create_compressor, create_decompressor},
    stream_v2::{compression_worker::CodecInfo, parallelism::GpuInfo}
};

/// GPU compression backend.
/// Wraps codec compressors/decompressors but carries GPU context information.
/// In a real deployment, we would initialize CUDA/OpenCL/WGPU kernels here.
/// For now, we rely on codec implementations and attach GPU metadata.
pub struct GpuCompressionBackend {
    compressor: Box<dyn Compressor + Send>,
    decompressor: Box<dyn Decompressor + Send>,
    _gpu: Option<GpuInfo>,
}

impl GpuCompressionBackend {
    /// Initialize a GPU backend for compression/decompression.
    /// Uses codec registry to create compressor/decompressor, and attaches GPU info.
    pub fn new(codec_info: CodecInfo) -> Result<Self, CompressionError> {
        Ok(Self {
            compressor: create_compressor(codec_info.codec_id, Some(CodecOptions::resolve(codec_info.level, codec_info.dict)))?,
            decompressor: create_decompressor(codec_info.codec_id, Some(CodecOptions::resolve(codec_info.level, codec_info.dict)))?,
            _gpu: codec_info.gpu,
        })
    }
}

impl super::types::CompressionBackend for GpuCompressionBackend {
    fn compress_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // ✅ Catch empty final segment early
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        // let mut compressor = pollster::block_on(Lz4GpuCompressor::new())?;
        self.compressor.compress_chunk(input, &mut out)?;

        Ok(out)
    }

    fn decompress_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        // ✅ Catch empty final segment early
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        self.decompressor.decompress_chunk(input, &mut out)?;
        
        Ok(out)
    }
}
