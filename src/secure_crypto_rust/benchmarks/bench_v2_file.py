# bench_v2_file.py

import os
import time
from pathlib import Path
from typing import List, Tuple

import rust_crypto as scp
from secure_crypto_rust.benchmarks.bench_v2_utils import (
    BenchmarkParams,
    cleanup_temp_files,
    dummy_master_key,
    make_header,
    make_result_v2,
    measure_memory_mb,
    prepare_demo_input_file,
    prepare_input_file,
    prepare_large_demo_input_file,
    print_cipher,
)

# ---------------------------------------------------------
# Core Benchmark Functions
# ---------------------------------------------------------
scenario = "file_2_file_sync"

def bench_v2_encrypt_file(
    input_path: Path,
    chunk_size: int,
    compression: int,
    cipher: int,
):
    master_key = dummy_master_key()
    header = make_header(chunk_size, compression, cipher=cipher)

    params_enc: scp.PyEncryptParams = scp.PyEncryptParams(master_key=master_key, header=header, dict=None)
    api_config: scp.PyApiConfig = scp.PyApiConfig(with_buf=True, collect_metrics=None)

    # Output path
    output_path = Path(f"encrypted_{chunk_size}_{cipher}.dat")
    output = str(output_path)

    mem_before = measure_memory_mb()
    start = time.perf_counter()

    snapshot: scp.PyTelemetrySnapshot = scp.py_encrypt_stream_v2(
        str(input_path),
        output,
        params_enc,
        api_config,
    )

    result = make_result_v2(
        scenario=scenario,
        operation="encrypt",
        mode="sync",
        input_size=input_path.stat().st_size if input_path.exists() else None,
        compression=str(compression),
        chunk_size=chunk_size,
        start_time=start,
        mem_before=mem_before,
        output_size=output_path.stat().st_size if output_path.exists() else None,
        snapshot=snapshot
    )

    return result, output_path


def bench_v2_decrypt_file(
    encrypted_path: Path,
    chunk_size: int,
    compression: int,
    cipher: int,
):
    master_key = dummy_master_key()
    params_dec: scp.PyDecryptParams = scp.PyDecryptParams(master_key=master_key)
    api_config: scp.PyApiConfig = scp.PyApiConfig(with_buf=True, collect_metrics=None)

    # Output path for decrypted file
    output_path = Path(f"decrypted_{chunk_size}_{cipher}.dat")
    output = str(output_path)

    mem_before = measure_memory_mb()
    start = time.perf_counter()

    snapshot: scp.PyTelemetrySnapshot = scp.py_decrypt_stream_v2(
        str(encrypted_path),
        output,
        params_dec,
        api_config,
    )

    result = make_result_v2(
        scenario=scenario,
        operation="decrypt",
        mode="sync",
        input_size=encrypted_path.stat().st_size if encrypted_path.exists() else None,
        compression=str(compression),
        chunk_size=chunk_size,
        start_time=start,
        mem_before=mem_before,
        output_size=output_path.stat().st_size if output_path.exists() else None,
        snapshot=snapshot
    )

    return result, output_path

# ---------------------------------------------------------
# Example Usage
# ---------------------------------------------------------

if __name__ == "__main__":
    chunk_sizes_lower = [64 * 1024, 1 * 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024]
    chunk_sizes_upper = [32 * 1024 * 1024, 16 * 1024 * 1024, 8 * 1024 * 1024]
    compressions = [0]
    ciphers = [1, 2]

    input_path = prepare_large_demo_input_file(target_size=1 * 1024 * 1024 * 1024)
    print(f"Demo input file created at {input_path}, size={input_path.stat().st_size} bytes")

    sizes = [input_path.stat().st_size if input_path.exists() else 0, 256 * 1024 * 1024]
    # Run our encrypt/decrypt benchmarks on this file
    file_paths = [input_path]
    encrypted_results: List[Tuple[int, int, int, Path]] = []

    # Encrypt to file
    for chunk_size in chunk_sizes_upper: # chunk_sizes_lower + chunk_sizes_upper:
        for cipher in ciphers:
            print("-" * 160)
            print(BenchmarkParams(scenario=scenario, operation='encrypt', mode='sync', input_size=sizes[0], compression='0', chunk_size=chunk_size, cipher=print_cipher(cipher)))
            result, enc_path = bench_v2_encrypt_file(
                input_path=input_path,
                chunk_size=chunk_size,
                compression=0,
                cipher=cipher,
            )
            encrypted_results.append((chunk_size, cipher, result.input_size, enc_path))
            file_paths.append(enc_path)

            print(result)

    # Decrypt from file
    for chunk_size, cipher, input_size, enc_path in encrypted_results:
        print("-" * 160)
        print(BenchmarkParams(scenario=scenario, operation='decrypt', mode='sync', input_size=input_size, compression='0', chunk_size=chunk_size, cipher=print_cipher(cipher)))
        result, dec_path = bench_v2_decrypt_file(
            encrypted_path=enc_path,
            chunk_size=chunk_size,
            compression=0,
            cipher=cipher,
        )
        file_paths.append(dec_path)

        print(result)

        # Sanity check
        assert dec_path.read_bytes() == input_path.read_bytes()

        # clean un on-time
        cleanup_temp_files(file_paths=[enc_path, dec_path])


    # Remove temp file explicitly
    cleanup_temp_files(file_paths=file_paths)

# python -m src.secure_crypto_rust.benchmarks.bench_v2_file
