use crate::{
    compression::{CodecOptions, CompressionError, Compressor, Decompressor, create_compressor, create_decompressor},
    stream_v2::compression_worker::CodecInfo
};

pub struct CpuCompressionBackend {
    compressor: Box<dyn Compressor + Send>,
    decompressor: Box<dyn Decompressor + Send>,
}

impl CpuCompressionBackend {
    pub fn new(codec_info: CodecInfo) -> Result<Self, CompressionError> {
        Ok(Self {
            compressor: create_compressor(codec_info.codec_id, Some(CodecOptions::resolve(codec_info.level, codec_info.dict)))?,
            decompressor: create_decompressor(codec_info.codec_id, Some(CodecOptions::resolve(codec_info.level, codec_info.dict)))?,
        })
    }
}

impl super::types::CompressionBackend for CpuCompressionBackend {
    fn compress_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut out = Vec::new();
        self.compressor.compress_chunk(input, &mut out)?;
        Ok(out)
    }

    fn decompress_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut out = Vec::new();
        self.decompressor.decompress_chunk(input, &mut out)?;
        Ok(out)
    }
}
