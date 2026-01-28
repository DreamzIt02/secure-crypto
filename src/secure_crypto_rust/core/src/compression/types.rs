//! compression/constants.rs
//! Stable codec IDs and defaults, plus FFI-safe enum mapping.
use std::fmt;
use std::net::{TcpStream};
use std::time::{Instant, Duration};
use num_enum::TryFromPrimitive;

/// Stable codec IDs (u16) for headers and wire format.
pub mod codec_ids {
    pub const AUTO: u16    = 0x0000;
    pub const ZSTD: u16    = 0x0001;
    pub const LZ4: u16     = 0x0002;
    pub const DEFLATE: u16 = 0x0003;
}

/// Default compression levels (balanced).
pub const DEFAULT_LEVEL_ZSTD: i32 = 6;
pub const DEFAULT_LEVEL_LZ4: i32 = 0; // fast mode
pub const DEFAULT_LEVEL_DEFLATE: i32 = 6;

// Max chunk size sanity bound (32 MiB).
// pub const MAX_CHUNK_SIZE: usize = 32 * 1024 * 1024;

/// FFI-safe enum for compression codec identifiers.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum CompressionCodec {
    Auto    = codec_ids::AUTO,
    Zstd    = codec_ids::ZSTD,
    Lz4     = codec_ids::LZ4,
    Deflate = codec_ids::DEFLATE,
}

impl CompressionCodec {
    pub fn from(raw: u16) -> Result<Self, CodecError> {
        match raw {
            x if x == codec_ids::AUTO as u16    => Ok(CompressionCodec::Auto),
            x if x == codec_ids::ZSTD as u16    => Ok(CompressionCodec::Zstd),
            x if x == codec_ids::LZ4 as u16     => Ok(CompressionCodec::Lz4),
            x if x == codec_ids::DEFLATE as u16 => Ok(CompressionCodec::Deflate),
            _ => Err(CodecError::UnknownCompression { raw }),
        }
    }
    pub fn verify(raw: u16) -> Result<(), CodecError> {
        match raw {
            x if x == CompressionCodec::Auto as u16    => Ok(()),
            x if x == CompressionCodec::Zstd as u16    => Ok(()),
            x if x == CompressionCodec::Lz4 as u16     => Ok(()),
            x if x == CompressionCodec::Deflate as u16 => Ok(()),
            _ => Err(CodecError::UnknownCompression { raw }),
        }
    }
}

// ## 🎯 Enum for Codec Levels
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum CodecLevel {
    // Zstd presets (zstd = "0.13")
    ZstdFast,        // level 1
    ZstdBalanced,    // level 3
    ZstdMax,         // level 19

    // LZ4 presets (lz4_flex = "0.12")
    Lz4Fast,         // acceleration 1
    Lz4DecSpeed,     // favor decompression speed
    Lz4HighAccel,    // acceleration 4

    // Flate2 presets (flate2 = "1.0")
    FlateFast,       // Compression::fast()
    FlateDefault,    // Compression::default()
    FlateBest,       // Compression::best()

    // Custom numeric level (for fine‑grained control)
    Custom(i32),
}

impl<'a> CodecLevel {
    /// Automatically select optimal CodecLevel based on codec type and multiple inferred factors.
    pub fn auto_select(codec_id: u16, stream_size: usize, dict: Option<&'a [u8]>) -> CodecLevel {
        let codec: CompressionCodec = CompressionCodec::from(codec_id).unwrap_or(CompressionCodec::Auto);

        // 1. Dictionary presence
        let has_dict = dict.is_some();

        // 2. GPU availability (simple probe using wgpu)
        let gpu_available = {
            // TODO:
            // Try to create a wgpu instance and request an adapter
            // let instance = wgpu::Instance::default();
            // let adapter = futures::executor::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            //     power_preference: wgpu::PowerPreference::HighPerformance,
            //     compatible_surface: None,
            //     force_fallback_adapter: false,
            // }));
            // adapter.is_some()
            false
        };

        // 3. Favor decompression (inferred)
        let favor_decompression = match codec {
            CompressionCodec::Lz4 => true, // LZ4 is decompression‑friendly
            CompressionCodec::Zstd => stream_size < 1_000_000, // small payloads → favor decompression
            CompressionCodec::Deflate => false,
            CompressionCodec::Auto => false,
        };

        // 4. Archival (inferred from very large streams)
        let archival = stream_size > 1_000_000_000; // >1 GB considered archival

        // 5. Network bandwidth measurement (simple probe)
        let network_bandwidth_mbps = {
            // crude estimation: attempt to connect to a fast host and measure RTT
            let start = Instant::now();
            let result = TcpStream::connect_timeout(
                &"1.1.1.1:53".parse().unwrap(), // Cloudflare DNS
                Duration::from_millis(200),
            );
            if result.is_ok() {
                let elapsed = start.elapsed().as_millis() as u32;
                if elapsed < 20 {
                    100 // assume high bandwidth
                } else if elapsed < 100 {
                    50
                } else {
                    5 // low bandwidth
                }
            } else {
                10 // fallback default
            }
        };

        // Decision logic
        match codec {
            CompressionCodec::Zstd => {
                if archival || network_bandwidth_mbps < 10 {
                    CodecLevel::ZstdMax
                } else if favor_decompression || has_dict {
                    CodecLevel::ZstdFast
                } else if stream_size < 100_000_000 {
                    CodecLevel::ZstdBalanced
                } else {
                    if gpu_available {
                        CodecLevel::ZstdBalanced
                    } else {
                        CodecLevel::ZstdMax
                    }
                }
            }
            CompressionCodec::Lz4 => {
                if favor_decompression {
                    CodecLevel::Lz4DecSpeed
                } else if network_bandwidth_mbps < 10 {
                    CodecLevel::Lz4HighAccel
                } else if stream_size < 1_000_000 {
                    CodecLevel::Lz4Fast
                } else if stream_size < 100_000_000 {
                    CodecLevel::Lz4DecSpeed
                } else {
                    CodecLevel::Lz4HighAccel
                }
            }
            CompressionCodec::Deflate => {
                if archival || network_bandwidth_mbps < 10 {
                    CodecLevel::FlateBest
                } else if stream_size < 1_000_000 {
                    CodecLevel::FlateFast
                } else if stream_size < 100_000_000 {
                    CodecLevel::FlateDefault
                } else {
                    CodecLevel::FlateBest
                }
            }
            CompressionCodec::Auto => {
                if stream_size < 1_000_000 {
                    CodecLevel::Lz4Fast
                } else if network_bandwidth_mbps < 10 {
                    CodecLevel::ZstdMax
                } else {
                    CodecLevel::ZstdBalanced
                }
            }
        }

        // ## 🧩 What’s Automatic Here
        // - **`dict.is_some()`** → checked directly.  
        // - **`gpu_available`** → probed via `wgpu::Instance::request_adapter`.  
        // - **`favor_decompression`** → inferred from codec type and stream size.  
        // - **`archival`** → inferred if stream size > 1 GB.  
        // - **`network_bandwidth_mbps`** → measured at runtime using a quick TCP probe.  

        // ## 🚀 Example Usage

        // ```rust
        // fn main() {
        //     let codec = CompressionCodec::Zstd;
        //     let stream_size = 200_000_000; // 200 MB
        //     let dict: Option<&[u8]> = None;

        //     let level = CodecInfo::auto_select(codec, stream_size, dict);
        //     println!("Selected level: {:?}", level);
        // }
        // ```

        // Output (example):
        // ```
        // Selected level: ZstdBalanced
        // ```
    }

}

#[derive(Debug, Clone)]
pub struct CodecOptions<'a> {
    /// Compression level (algorithm‑specific meaning).
    pub level: Option<i32>,

    /// Optional dictionary buffer.
    pub dict: Option<&'a [u8]>,

    /// Whether to favor decompression speed over compression ratio (LZ4).
    pub favor_dec_speed: bool,

    /// Whether to use fast acceleration mode (LZ4).
    pub acceleration: Option<u32>,

    /// Window size (Zstd).
    pub window_log: Option<u32>,

    /// Number of worker threads (Zstd).
    pub threads: Option<u32>,

    /// Whether to enable long distance matching (Zstd).
    pub long_distance_matching: bool,

    /// Whether to enable checksum (Zstd).
    pub checksum: bool,
}

impl<'a> CodecOptions<'a> {
    pub fn resolve_auto(codec_id: u16, stream_size: usize, dict: Option<&'a [u8]>) -> Self {
        // 1. Dictionary presence
        // let has_dict = dict.is_some();

        let level: CodecLevel = CodecLevel::auto_select(codec_id, stream_size, dict);
        Self::resolve(level, dict)
    }
    pub fn resolve(level: CodecLevel, dict: Option<&'a [u8]>) -> Self {
        match level {
            // ---------------------------
            // Zstd presets
            // ---------------------------
            CodecLevel::ZstdFast => Self::zstd_fast(dict),
            CodecLevel::ZstdBalanced => Self::zstd_balanced(dict),
            CodecLevel::ZstdMax => Self::zstd_max(dict),

            // ---------------------------
            // LZ4 presets
            // ---------------------------
            CodecLevel::Lz4Fast => Self::lz4_fast(dict),
            CodecLevel::Lz4DecSpeed => Self::lz4_dec_speed(dict),
            CodecLevel::Lz4HighAccel => Self::lz4_high_accel(dict),

            // ---------------------------
            // Flate2 presets
            // ---------------------------
            CodecLevel::FlateFast => Self::flate_fast(dict),
            CodecLevel::FlateDefault => Self::flate_default(dict),
            CodecLevel::FlateBest => Self::flate_best(dict),

            // ---------------------------
            // Custom numeric level
            // ---------------------------
            CodecLevel::Custom(val) => Self {
                level: Some(val),
                dict,
                favor_dec_speed: false,
                acceleration: None,
                window_log: None,
                threads: None,
                long_distance_matching: false,
                checksum: false,
            },

            // ### 🔧 Usage Example

            // ```rust
            // let info = CodecInfo {
            //     codec_id: 1,
            //     level: Some(CodecLevel::ZstdBalanced),
            //     dict: None,
            //     gpu: None,
            // };

            // let opts = CodecOptions::resolve(info.level.unwrap(), info.dict);
            // println!("Resolved options: {:?}", opts);
            // ```
            // ✨ This resolver ensures:
            // - Every `CodecLevel` maps to a valid `CodecOptions`.
            // - We can pass a dictionary (`dict`) through `CodecInfo` and have it applied automatically.
            // - Compatibility with external crates (`zstd`, `lz4_flex`, `flate2`) by using their standard presets.
        }
    }

    /// Default options (no tuning).
    pub fn default(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: None,
            dict: dict,
            favor_dec_speed: false,
            acceleration: None,
            window_log: None,
            threads: None,
            long_distance_matching: false,
            checksum: false,
        }
    }

    // ---------------------------
    // Zstd presets (zstd = "0.13")
    // ---------------------------

    /// Fastest compression (low ratio, high speed).
    pub fn zstd_fast(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: Some(1), // zstd::fast
            dict: dict,
            favor_dec_speed: false,
            acceleration: None,
            window_log: Some(20), // typical default
            threads: Some(1),
            long_distance_matching: false,
            checksum: false,
        }
    }

    /// Balanced compression (good trade‑off).
    pub fn zstd_balanced(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: Some(3), // common balanced level
            dict: dict,
            favor_dec_speed: false,
            acceleration: None,
            window_log: Some(22),
            threads: Some(2),
            long_distance_matching: false,
            checksum: true,
        }
    }

    /// Maximum compression (slow, best ratio).
    pub fn zstd_max(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: Some(19), // zstd max level
            dict: dict,
            favor_dec_speed: false,
            acceleration: None,
            window_log: Some(30),
            threads: Some(4),
            long_distance_matching: true,
            checksum: true,
        }
    }

    // ---------------------------
    // LZ4 presets (lz4_flex = "0.12")
    // ---------------------------

    /// Fast LZ4 compression (favor speed).
    pub fn lz4_fast(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: None,
            dict: dict,
            favor_dec_speed: false,
            acceleration: Some(1), // acceleration factor
            window_log: None,
            threads: None,
            long_distance_matching: false,
            checksum: false,
        }
    }

    /// LZ4 tuned for decompression speed.
    pub fn lz4_dec_speed(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: None,
            dict: dict,
            favor_dec_speed: true,
            acceleration: None,
            window_log: None,
            threads: None,
            long_distance_matching: false,
            checksum: false,
        }
    }

    /// LZ4 with higher acceleration (lower ratio).
    pub fn lz4_high_accel(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: None,
            dict: dict,
            favor_dec_speed: false,
            acceleration: Some(4),
            window_log: None,
            threads: None,
            long_distance_matching: false,
            checksum: false,
        }
    }

    // ---------------------------
    // Flate2 presets (flate2 = "1.0")
    // ---------------------------

    /// Fastest DEFLATE (gzip/zlib).
    pub fn flate_fast(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: Some(flate2::Compression::fast().level() as i32),
            dict: dict,
            favor_dec_speed: false,
            acceleration: None,
            window_log: None,
            threads: None,
            long_distance_matching: false,
            checksum: false,
        }
    }

    /// Balanced DEFLATE.
    pub fn flate_default(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: Some(flate2::Compression::default().level() as i32),
            dict: dict,
            favor_dec_speed: false,
            acceleration: None,
            window_log: None,
            threads: None,
            long_distance_matching: false,
            checksum: false,
        }
    }

    /// Maximum DEFLATE compression.
    pub fn flate_best(dict: Option<&'a [u8]>) -> Self {
        Self {
            level: Some(flate2::Compression::best().level() as i32),
            dict: dict,
            favor_dec_speed: false,
            acceleration: None,
            window_log: None,
            threads: None,
            long_distance_matching: false,
            checksum: true,
        }
    }

    // ### 📌 Usage Examples
    // ```rust
    // let opt1 = CodecOptions::zstd_fast();
    // let opt2 = CodecOptions::lz4_dec_speed();
    // let opt3 = CodecOptions::flate_best();
    // ```
    // ⚠️ **Notes:**
    // - Zstd levels range from **1 (fastest)** to **19 (max compression)**.  
    // - LZ4 (`lz4_flex`) exposes **acceleration** and **favor decompression speed** flags.  
    // - Flate2 (`flate2::Compression`) provides **fast, default, best** presets.  

    // TODO: **add dictionary‑aware variants** (e.g. `zstd_with_dict(dict: &[u8])`) so we can easily plug in training dictionaries for Zstd/LZ4? That’s common in production systems.
}

pub fn enum_name_or_hex<T>(raw: T::Primitive) -> String
where
    T: TryFromPrimitive + fmt::Debug,
    T::Primitive: fmt::LowerHex,
{
    match T::try_from_primitive(raw) {
        Ok(variant) => format!("{:?}", variant),
        Err(_) => format!("0x{:x}", raw),
    }
}

#[derive(Debug)]
pub enum CodecError {
    UnknownCompression { raw: u16 },
}

#[derive(Debug)]
pub enum CompressionError {
    UnsupportedCodec { codec_id: u16 },
    InvalidDictionary { dict_id: u32 },
    CodecInitFailed { codec: String, msg: String },
    CodecProcessFailed { codec: String, msg: String },
    ChunkTooLarge { have: usize, max: usize },
    StateError(String),
}

impl From<std::io::Error> for CompressionError {
    fn from(e: std::io::Error) -> Self {
        CompressionError::StateError(e.to_string())
    }
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CompressionError::*;
        match self {
            UnsupportedCodec { codec_id } => write!(f, "unsupported compression codec: {}", enum_name_or_hex::<CompressionCodec>(*codec_id)),
            InvalidDictionary { dict_id } => write!(f, "invalid dictionary id: {}", dict_id),
            CodecInitFailed { codec, msg } => write!(f, "codec {} init failed: {}", codec, msg),
            CodecProcessFailed { codec, msg } => write!(f, "codec {} process failed: {}", codec, msg),
            ChunkTooLarge { have, max } => write!(f, "chunk too large: {} > {}", have, max),
            StateError(msg) => write!(f, "compression state error: {}", msg),
        }
    }
}

impl std::error::Error for CompressionError {}

#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum ChecksumAlg {
    Crc32   = 0x0001,
    Blake3   = 0x0201, // UN-KEYED Blake3
}
pub fn compute_checksum(data: &[u8], alg: Option<ChecksumAlg>) -> u32 {
    match alg {
        Some(ChecksumAlg::Crc32)  => compute_crc32(data),
        // Some(ChecksumAlg::Blake3) => compute_blake3(data), // Its return 32-bytes
        _                         => compute_crc32(data)
    }
}

pub fn verify_checksum(expected_crc: u32, actual_crc: u32, codec: String) -> Result<(), CompressionError> {
    if actual_crc != expected_crc {
        return Err(CompressionError::CodecProcessFailed {
            codec: codec.into(),
            msg: "checksum mismatch".into(),
        });
    }
    Ok(())
}

fn compute_crc32(data: &[u8]) -> u32 {
    use crc32fast::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

// fn compute_blake3(data: &[u8]) -> [u8; 32] {
//     use blake3::Hasher;
//     let mut hasher = Hasher::new();
//     hasher.update(data);
//     *hasher.finalize().as_bytes()
// }

// Require Send so trait objects can cross thread boundaries.
pub trait Compressor: Send {
    /// Compress a single chunk into out buffer.
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError>;
    /// Flush any pending state.
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), CompressionError>;
}

pub trait Decompressor: Send {
    /// Decompress a single chunk into out buffer.
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CompressionError>;
}
