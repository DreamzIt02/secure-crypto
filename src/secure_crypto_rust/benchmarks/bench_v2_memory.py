# ✅ Python Benchmark Version (Memory Input → Memory Outputs)

# bench_v2_memory.py

import os
import time
from typing import List, Tuple
from pathlib import Path

# import our FFI module here
import rust_crypto as scp

from secure_crypto_rust.benchmarks.bench_v2_utils import BenchmarkParams, choose_input, choose_output, dummy_master_key, make_header, make_result_v2, measure_memory_mb, print_cipher

# ---------------------------------------------------------
# Core Benchmark Function
# ---------------------------------------------------------
scenario = 'memory_2_memory_sync'

def bench_v2_encrypt_memory(
    payload: bytes,
    chunk_size: int,
    compression: int,
    cipher: int,
    output_variant: str,
):
    """
    output_variant:
        "memory"
        "file"
        "writer"
    """

    scenario = f"memory_2_{output_variant}_sync"

    master_key = dummy_master_key()
    header = make_header(chunk_size, compression, cipher=cipher)

    params_enc: scp.PyEncryptParams = scp.PyEncryptParams(master_key=master_key, header=header, dict=None)

    api_config: scp.PyApiConfig = scp.PyApiConfig(with_buf=True, collect_metrics=None)

    # -------------------------------------------------
    # Choose Output
    # -------------------------------------------------
    output = choose_output(output_variant=output_variant)

    # -------------------------------------------------
    # Benchmark
    # -------------------------------------------------
    mem_before = measure_memory_mb()
    start = time.perf_counter()

    snapshot: scp.PyTelemetrySnapshot = scp.py_encrypt_stream_v2(
        payload,
        output,
        params_enc,
        api_config,
    )

    input_size = len(payload)

    output_size = None
    if output_variant == "memory":
        output_size = len(snapshot.output) if snapshot.output else None
    elif output_variant == "writer":
        output_size = output_size = len(snapshot.output) if snapshot.output else None

    result = make_result_v2(
        scenario=scenario,
        operation="encrypt",
        mode="sync",
        input_size=input_size,
        compression=str(compression),
        chunk_size=chunk_size,
        start_time=start,
        mem_before=mem_before,
        output_size=output_size,
        snapshot=snapshot
    )

    # Return consistent with Rust version
    if output_variant == "memory":
        return result, snapshot.output, None
    elif output_variant == "file":
        return result, None, Path("encrypted_memory.dat")
    else:
        return result, snapshot.output, None

def bench_v2_decrypt_memory(
    ciphertext: bytes,
    chunk_size: int,
    compression: int,
    input_variant: str,
    output_variant: str,
):
    """
    input_variant:
        "memory"
        "file"
        "reader"
    """

    scenario = f"{input_variant}_2_memory_sync"

    master_key = dummy_master_key()

    params_dec: scp.PyDecryptParams = scp.PyDecryptParams(master_key=master_key)

    api_config: scp.PyApiConfig = scp.PyApiConfig(with_buf=True, collect_metrics=None)

    # -------------------------------------------------
    # Choose Input
    # -------------------------------------------------
    input_data = choose_input(input_variant, ciphertext)

    # -------------------------------------------------
    # Choose Output
    # -------------------------------------------------
    output = choose_output(output_variant=output_variant)

    # -------------------------------------------------
    # Benchmark
    # -------------------------------------------------
    mem_before = measure_memory_mb()
    start = time.perf_counter()

    snapshot: scp.PyTelemetrySnapshot = scp.py_decrypt_stream_v2(
        input_data,
        output,
        params_dec,
        api_config,
    )

    output_size = len(snapshot.output) if snapshot.output else None

    result = make_result_v2(
        scenario=scenario,
        operation="decrypt",
        mode="sync",
        input_size=output_size,
        compression=str(compression),
        chunk_size=chunk_size,
        start_time=start,
        mem_before=mem_before,
        output_size=output_size,
        snapshot=snapshot
    )

    # Return consistent with Rust version
    return result, snapshot.output

# ---------------------------------------------------------
# Example Usage
# ---------------------------------------------------------

if __name__ == "__main__":
    sizes = [256 * 1024 * 1024]
    chunk_sizes_lower = [64 * 1024, 1 * 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024]
    chunk_sizes_upper = [8 * 1024 * 1024, 16 * 1024 * 1024, 32 * 1024 * 1024]
    compressions = [0]
    ciphers = [1, 2]

    for size in sizes:
        payload = os.urandom(size)
        encrypted_results: List[Tuple[int, int, int, bytes | None]] = []

        for chunk_size in chunk_sizes_lower + chunk_sizes_upper:
            for cipher in ciphers:
                print("-" * 160)
                print(BenchmarkParams(scenario=scenario, operation='encrypt', mode='sync', input_size=size, compression='0', chunk_size=chunk_size, cipher=print_cipher(cipher)))
                result, out, path = bench_v2_encrypt_memory(
                    payload=payload,
                    chunk_size=chunk_size,
                    compression=0,
                    cipher=cipher,
                    output_variant="memory",
                )
                encrypted_results.append((chunk_size, cipher, result.input_size, out))
                print(result)

        for chunk_size, cipher, input_size, encrypted in encrypted_results:
            print("-" * 160)
            print(BenchmarkParams(scenario=scenario, operation='decrypt', mode='sync', input_size=input_size, compression='0', chunk_size=chunk_size, cipher=print_cipher(cipher)))
            result, decrypted = bench_v2_decrypt_memory(
                ciphertext=encrypted or b"",
                compression=0,
                chunk_size=chunk_size,
                input_variant="memory",
                output_variant="memory",
            )
            print(result)
            
            assert decrypted == payload  # sanity check


# python -m src.secure_crypto_rust.benchmarks.bench_v2_memory

# # 🔥 Why This Mirrors Rust Properly

# | Rust                               | Python Equivalent        |
# | ---------------------------------- | ------------------------ |
# | `Instant::now()`                   | `time.perf_counter()`    |
# | `measure_memory_mb()`              | `psutil.Process().rss`   |
# | `InputSource::Memory(payload)`     | `payload`                |
# | `OutputSink::Memory`               | `b""`                    |
# | `OutputSink::File(PathBuf)`        | `str(Path)`              |
# | `OutputSink::Writer(Box<Vec<u8>>)` | custom `.write()` object |

# 🚀 How To Use This For Proper FFI Benchmarking

# To isolate FFI overhead:

# ### 1️⃣ Warm up first

# ```python
# for _ in range(3):
#     scp.encrypt_stream_v2(...)
# ```

### 2️⃣ Run multiple iterations

# ```python
# runs = []
# for _ in range(10):
#     result, _, _ = bench_v2_encrypt_memory(...)
#     runs.append(result.elapsed_sec)

# print("avg:", sum(runs) / len(runs))
# ```

# ⚡ If We Want Ultra Accurate FFI Cost

# Benchmark:

# 1. Pure Rust internal call
# 2. Rust FFI call from Python
# 3. Python wrapper only

# Then compute:

# ```
# FFI overhead = (Python call time) - (pure Rust time)
# ```

# 🧠 Important Note

# If our Rust API returns a Python `bytes` object:

# ```rust
# PyBytes::new(py, &vec)
# ```

# Then Python memory measurement will include that allocation.

# If we want *true* Rust-only measurement:

# * Measure inside Rust
# * Return metrics separately
