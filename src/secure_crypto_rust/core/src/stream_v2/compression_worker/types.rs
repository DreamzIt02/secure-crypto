use std::fmt;

use crate::{compression::{CodecLevel, CompressionError}, headers::HeaderV1, stream_v2::parallelism::GpuInfo};

#[derive(Debug, Clone)]
pub struct CodecInfo<'a> {
    pub codec_id: u16,
    pub level: CodecLevel,     // now uses enum instead of raw i32
    pub dict: Option<&'a [u8]>,
    pub gpu: Option<GpuInfo>,
}

impl<'a> CodecInfo<'a> {
    pub fn from_header(
        header: &HeaderV1,
        dict_registry: Option<&'a std::collections::HashMap<u32, Vec<u8>>>,
    ) -> Self {
        // Resolve dictionary only if registry is provided and dict_id != 0
        let dict = dict_registry
            .and_then(|registry| {
                header
                    .dict_id
                    .checked_sub(1) // treat 0 as "no dict"
                    .and_then(|id| registry.get(&id))
            })
            .map(|buf| buf.as_slice());

        let level = CodecLevel::auto_select(
            header.compression, 
            header.chunk_size as usize, 
            dict,
        );

        Self {
            codec_id: header.compression,
            level: level,
            dict,
            gpu: None, // detect at runtime
        }
    }
}

// ## 📝 Example Usage

// ```rust
// let info1 = CodecInfo {
//     codec_id: 1, // e.g. Zstd
//     level: Some(CodecLevel::ZstdFast),
//     dict: None,
//     gpu: None,
// };

// let info2 = CodecInfo {
//     codec_id: 2, // e.g. LZ4
//     level: Some(CodecLevel::Lz4HighAccel),
//     dict: None,
//     gpu: None,
// };

// let info3 = CodecInfo {
//     codec_id: 3, // e.g. Flate2
//     level: Some(CodecLevel::FlateBest),
//     dict: None,
//     gpu: None,
// };
// ```

pub trait CompressionBackend: Send {
    fn compress_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError>;
    fn decompress_chunk(&mut self, input: &[u8]) -> Result<Vec<u8>, CompressionError>;
}


#[derive(Debug)]
pub enum CompressionWorkerError {
    Compression(CompressionError),
    StateError(String),
}

impl From<std::io::Error> for CompressionWorkerError {
    fn from(e: std::io::Error) -> Self {
        CompressionWorkerError::StateError(e.to_string())
    }
}
impl From<CompressionError> for CompressionWorkerError {
    fn from(e: CompressionError) -> Self {
        CompressionWorkerError::Compression(e)
    }
}

impl fmt::Display for CompressionWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CompressionWorkerError::*;
        match self {
            CompressionWorkerError::Compression(e) => write!(f, "compression error: {}", e),
            StateError(msg) => write!(f, "compression worker error: {}", msg),
        }
    }
}

impl std::error::Error for CompressionWorkerError {}