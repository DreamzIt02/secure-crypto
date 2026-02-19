// ## 📖 `bench_v2_encrypt_reader.rs`

use std::time::Instant;
use std::path::PathBuf;
use std::io::Cursor;

use crate::{
    benchmarks::{
        bench_results::{BenchmarkResult, make_result_v2},
        bench_utils::{dummy_master_key, measure_memory_mb},
    },
    compression::CompressionCodec,
    headers::HeaderV1,
    stream_v2::{
        ApiConfig, EncryptParams, InputSource, OutputSink, encrypt_stream_v2,
        parallelism::ParallelismConfig,
    },
    utils::enum_name_or_hex,
};

fn dummy_header(chunk_size: usize, compression: CompressionCodec) -> HeaderV1 {
    HeaderV1 {
        chunk_size: chunk_size as u32,
        compression: compression as u16,
        // fill in other required fields with defaults or dummy values
        ..HeaderV1::test_header()
    }
}

// ### 📖 Reader Input Encrypt Macro
macro_rules! bench_v2_encrypt_reader {
    ($out_variant:ident, $out_expr:expr) => {
        paste::paste! {
            pub fn [<bench_v2_encrypt_reader_2_ $out_variant:lower _sync>](
                reader: Cursor<Vec<u8>>,
                chunk_size: usize,
                compression: CompressionCodec,
                parallelism: ParallelismConfig,
            ) -> (BenchmarkResult, Option<Vec<u8>>, Option<PathBuf>) {
                let comp_name = &enum_name_or_hex::<CompressionCodec>(compression as u16);
                let scenario = &format!("reader_2_{}_{}_sync",
                    stringify!($out_variant).to_lowercase(),
                    comp_name
                );

                let master_key = &dummy_master_key();
                let params_enc = EncryptParams { header: dummy_header(chunk_size, compression), dict: None };
                let api_config = ApiConfig::new(Some(true), None, None, Some(parallelism));

                let mem_before = measure_memory_mb();
                let start = Instant::now();
                let snapshot_enc = encrypt_stream_v2(
                    InputSource::Reader(Box::new(reader.clone())),
                    $out_expr,
                    master_key,
                    params_enc,
                    api_config,
                ).unwrap();

                let plaintext_size = reader.get_ref().len();
                let result = make_result_v2(
                    scenario, "encrypt", "sync", plaintext_size, comp_name,
                    chunk_size, start, mem_before,
                    snapshot_enc.output.as_ref().map(|v| v.len()), None
                );

                match &$out_expr {
                    OutputSink::Memory => (result, snapshot_enc.output.clone(), None),
                    OutputSink::File(path) => (result, None, Some(path.clone())),
                    OutputSink::Writer(_) => (result, snapshot_enc.output.clone(), None),
                }
            }
        }
    };
}

// ### 📖 Reader Input Macro Calls

// Encrypt from Reader → Memory
bench_v2_encrypt_reader!(Memory, OutputSink::Memory);

// Encrypt from Reader → File
bench_v2_encrypt_reader!(File, OutputSink::File(PathBuf::from("encrypted_reader.dat")));

// Encrypt from Reader → Writer
bench_v2_encrypt_reader!(Writer, OutputSink::Writer(Box::new(Vec::new())));

// ### 📖 Expanded Functions
// This generates three functions:

// - `bench_v2_encrypt_reader_2_memory_sync`
// - `bench_v2_encrypt_reader_2_file_sync`
// - `bench_v2_encrypt_reader_2_writer_sync`

// ### 📖 Usage Example

// ```rust
// fn main() {
//     let payload_size = 1024 * 1024; // 1 MB
//     let chunk_size = 4096;
//     let compression = CompressionCodec::None;
//     let parallelism = ParallelismConfig::default();

//     // Encrypt from Reader → Memory
//     let (res_mem, ciphertext_mem, _) = bench_v2_encrypt_reader_2_memory_sync(
//         payload_size, chunk_size, compression, parallelism
//     );
//     println!("Reader→Memory result: {:?}", res_mem);
//     println!("Ciphertext length: {:?}", ciphertext_mem.as_ref().map(|v| v.len()));

//     // Encrypt from Reader → File
//     let (res_file, _, file_path) = bench_v2_encrypt_reader_2_file_sync(
//         payload_size, chunk_size, compression, parallelism
//     );
//     println!("Reader→File result: {:?}", res_file);
//     println!("Ciphertext written to: {:?}", file_path);

//     // Encrypt from Reader → Writer
//     let (res_writer, ciphertext_writer, _) = bench_v2_encrypt_reader_2_writer_sync(
//         payload_size, chunk_size, compression, parallelism
//     );
//     println!("Reader→Writer result: {:?}", res_writer);
//     println!("Ciphertext length: {:?}", ciphertext_writer.as_ref().map(|v| v.len()));
// }
// ```
