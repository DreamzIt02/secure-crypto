// lz4_hash.wgsl
@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, write> hashes: array<u32>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if (idx < arrayLength(&input)) {
        let val = input[idx];
        // Simple rolling hash for LZ4 match finding
        hashes[idx] = (val * 2654435761u) >> 16u;
    }
}