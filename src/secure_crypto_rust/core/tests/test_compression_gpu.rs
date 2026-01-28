
#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crypto_core::{
        compression::{CodecLevel, CompressionError, codec_ids}, 
        stream_v2::{compression_worker::{CodecInfo, CompressionBackend, GpuCompressionBackend}, 
        segment_worker::EncryptSegmentInput, segmenting::types::SegmentFlags}, telemetry::StageTimes};

    fn make_codec_info() -> CodecInfo<'static> {
        CodecInfo {
            codec_id: codec_ids::ZSTD, // or ZSTD_ID depending on what we want to test
            level: CodecLevel::ZstdBalanced,
            dict: None,
            gpu: None,
        }
    }

    #[test]
    fn gpu_compression_roundtrip_nonempty() {
        let codec_info = make_codec_info();
        let mut backend = GpuCompressionBackend::new(codec_info).expect("gpu backend init");

        let input = b"Hello GPU compression backend!";
        let compressed = backend.compress_chunk(input).expect("compression ok");
        assert!(!compressed.is_empty(), "compressed buffer should not be empty");

        let decompressed = backend.decompress_chunk(&compressed).expect("decompression ok");
        assert_eq!(decompressed, input, "decompressed data should equal original");
    }

    #[test]
    fn gpu_compression_handles_final_segment_empty() {
        let codec_info = make_codec_info();
        let mut backend = GpuCompressionBackend::new(codec_info).expect("gpu backend init");

        // Simulate final empty segment
        let seg = EncryptSegmentInput {
            segment_index: 42,
            bytes: Bytes::new(),
            flags: SegmentFlags::FINAL_SEGMENT,
            stage_times: StageTimes::default(),
        };

        // Compression should bypass and return empty Vec
        let compressed = backend.compress_chunk(&seg.bytes).expect("compression ok");
        assert!(compressed.is_empty(), "final empty segment should compress to empty buffer");

        // Decompression should also bypass
        let decompressed = backend.decompress_chunk(&compressed).expect("decompression ok");
        assert!(decompressed.is_empty(), "final empty segment should decompress to empty buffer");
    }

    #[test]
    fn gpu_compression_error_propagation() {
        let codec_info = make_codec_info();
        let mut backend = GpuCompressionBackend::new(codec_info).expect("gpu backend init");

        // Feed invalid compressed data to decompressor
        let bogus = vec![0x00, 0x01, 0x02, 0x03];
        let result = backend.decompress_chunk(&bogus);

        assert!(matches!(result, Err(CompressionError::CodecProcessFailed { .. })), 
            "bogus input should yield a codec error");
    }
}
