use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::{benchmarks::{bench_v2_encrypt_memory::bench_v2_encrypt_memory_2_memory_sync, bench_utils::{random_bytes}}, compression::CompressionCodec, stream_v2::parallelism::ParallelismConfig}; // adjust path

fn bench_memory(c: &mut Criterion) {
    c.bench_function("bench_v2_memory_2_memory_sync", |b| {
        b.iter(|| {
            let payload = random_bytes(50 * 1024 * 1024);
            let chunk_size = 2 * 1024 * 1024;
            bench_v2_encrypt_memory_2_memory_sync(
                payload, // plaintext
                chunk_size,        // chunk size
                CompressionCodec::Auto,
                ParallelismConfig::new(4, 0, 0.5, 64),
            )
        });
    });
}

criterion_group!(benches, bench_memory);
criterion_main!(benches);
