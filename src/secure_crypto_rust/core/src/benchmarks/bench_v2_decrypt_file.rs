// ## 📂 `bench_v2_decrypt_file.rs`

use std::time::Instant;
use std::path::PathBuf;

use crate::{
    benchmarks::{
        bench_results::{BenchmarkResult, make_result_v2},
        bench_utils::{dummy_master_key, measure_memory_mb},
    },
    compression::CompressionCodec,
    stream_v2::{
        ApiConfig, DecryptParams, InputSource, OutputSink, decrypt_stream_v2,
        parallelism::ParallelismConfig,
    },
    utils::enum_name_or_hex,
};

// ### 📂 File Input Decrypt Macro
// ### 📂 File Input Decrypt Macro
macro_rules! bench_v2_decrypt_file {
    ($out_variant:ident, $out_expr:expr) => {
        paste::paste! {
            pub fn [<bench_v2_decrypt_file_2_ $out_variant:lower _sync>](
                ciphertext_path: PathBuf,            // ciphertext file path
                chunk_size: usize,
                compression: CompressionCodec,
                parallelism: ParallelismConfig,
            ) -> (BenchmarkResult, Option<Vec<u8>>, Option<PathBuf>) {
                let comp_name = &enum_name_or_hex::<CompressionCodec>(compression as u16);
                let scenario = &format!("file_2_{}_{}_sync",
                    stringify!($out_variant).to_lowercase(),
                    comp_name
                );

                let master_key = &dummy_master_key();
                let params_dec = DecryptParams { };
                let api_config = ApiConfig::new(Some(true), None, None, Some(parallelism));

                let mem_before = measure_memory_mb();
                let start = Instant::now();
                let snapshot_dec = decrypt_stream_v2(
                    InputSource::File(ciphertext_path.clone()),   // <-- File input
                    $out_expr,
                    master_key,
                    params_dec,
                    api_config,
                ).unwrap();

                // Use output length if available, otherwise fallback to ciphertext size
                let plaintext_size = snapshot_dec.output
                    .as_ref()
                    .map(|v| v.len())
                    .unwrap_or_else(|| std::fs::metadata(&ciphertext_path).map(|m| m.len() as usize).unwrap_or(0));

                let result = make_result_v2(
                    scenario, "decrypt", "sync",
                    plaintext_size,
                    comp_name, chunk_size, start, mem_before,
                    snapshot_dec.output.as_ref().map(|v| v.len()), None
                );

                match &$out_expr {
                    OutputSink::Memory => (result, snapshot_dec.output.clone(), None),
                    OutputSink::File(path) => (result, None, Some(path.clone())),
                    OutputSink::Writer(_) => (result, snapshot_dec.output.clone(), None),
                }
            }
        }
    };
}

// ### 📂 File Input Macro Calls

// Decrypt from File → Memory
bench_v2_decrypt_file!(Memory, OutputSink::Memory);

// Decrypt from File → File
bench_v2_decrypt_file!(File, OutputSink::File(PathBuf::from("decrypted_file.dat")));

// Decrypt from File → Writer
bench_v2_decrypt_file!(Writer, OutputSink::Writer(Box::new(Vec::new())));

// ### 📂 Expanded Functions
// This generates three functions:

// - `bench_v2_decrypt_file_2_memory_sync`
// - `bench_v2_decrypt_file_2_file_sync`
// - `bench_v2_decrypt_file_2_writer_sync`

// ### 📂 Usage Example

// ```rust
// fn main() {
//     let chunk_size = 4096;
//     let compression = CompressionCodec::None;
//     let parallelism = ParallelismConfig::default();

//     // Encrypt from File → File
//     let (enc_result, _, file_path) = bench_v2_encrypt_file_2_file_sync(
//         chunk_size, compression, parallelism
//     );
//     println!("Encrypt File→File result: {:?}", enc_result);

//     // Decrypt from that file → Memory
//     let (dec_result, plaintext, _) = bench_v2_decrypt_file_2_memory_sync(
//         file_path.unwrap(), chunk_size, compression, parallelism
//     );
//     println!("Decrypt File→Memory result: {:?}", dec_result);
//     println!("Plaintext length: {:?}", plaintext.as_ref().map(|v| v.len()));
// }
// ```
