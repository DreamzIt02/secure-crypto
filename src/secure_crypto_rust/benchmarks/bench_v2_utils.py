from dataclasses import dataclass
import io
import os
from pathlib import Path
import random
import time
from typing import NamedTuple

import psutil

# import our FFI module here
import rust_crypto as scp

class BenchmarkParams(NamedTuple):
    scenario: str = 'memory_2_memory_sync'
    operation: str = 'encrypt'
    mode: str = 'sync'
    input_size: int = 0
    compression: str = '0'
    chunk_size: int = 0
    cipher: str = '0'
    
@dataclass
class BenchmarkResult:
    scenario: str
    operation: str
    mode: str
    input_size: int
    compression: str
    chunk_size: int
    elapsed_sec: float
    memory_delta_mb: float
    output_size: int | None
    snapshot: scp.PyTelemetrySnapshot | None

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def dummy_master_key():
    return b"\x00" * 32

def dummy_salt():
    return b"\x01"*16

def measure_memory_mb():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def choose_input(input_variant: str, ciphertext: bytes):
    if input_variant == "memory":
        input_data = ciphertext

    elif input_variant == "file":
        input_path = Path("encrypted_memory.dat")
        input_path.write_bytes(ciphertext)
        input_data = str(input_path)

    elif input_variant == "reader":
        class Reader:
            def __init__(self, data: bytes):
                self.buffer = io.BytesIO(data)

            def read(self, size=-1):
                return self.buffer.read(size)

        input_data = Reader(ciphertext)

    else:
        raise ValueError("Invalid input_variant")
    
    return input_data
    
def choose_output(output_variant: str,):
    if output_variant == "memory":
        output = b""  # let Rust treat as memory sink

    elif output_variant == "file":
        output_path = Path("encrypted_memory.dat")
        output = str(output_path)

    elif output_variant == "writer":
        class Writer:
            def __init__(self):
                self.buffer = bytearray()

            def write(self, data):
                self.buffer.extend(data)
                return len(data)

        output = Writer()

    else:
        raise ValueError("Invalid output_variant")
    
    return output

def choose_content():
    content1 = (
        "Demo payload for encryption/decryption benchmarks.\n"
        "Quick brown fox jumps over the lazy dog.\n"
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"
        "1234567890 repeated sequence.\n"
        "End of demo block.\n"
    ).encode("utf-8")

    content2 = (
        "Secondary demo payload for crypto benchmarks.\n"
        "Frame and segment orchestration test data.\n"
        "Predictable sequence for validation purposes.\n"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ repeated sequence.\n"
        "End of secondary demo block.\n"
    ).encode("utf-8")

    return random.choice([
        content1,
        content2,
        content1 + content2,
        content2 + content1
    ])


def prepare_demo_input_file(filename: str = "input_payload.dat", target_size: int = 1 * 1024 * 1024) -> Path:
    """
    Create a demo input file with structured, human-readable content (~1 MB).
    """
    path = Path(filename)
    payload = bytearray()

    while len(payload) < target_size:
        block = choose_content()
        remaining = target_size - len(payload)
        if len(block) > remaining:
            block = block[:remaining]
        payload.extend(block)

    path.write_bytes(payload)
    return path


def prepare_large_demo_input_file(filename: str = "input_payload.dat", target_size: int = 256 * 1024 * 1024) -> Path:
    """
    Create a demo input file with human-readable content scaled up to ~256 MB.
    """
    path = Path(filename)
    payload = bytearray()

    while len(payload) < target_size:
        block = choose_content()
        remaining = target_size - len(payload)
        if len(block) > remaining:
            block = block[:remaining]
        payload.extend(block)

    path.write_bytes(payload)
    return path


def prepare_input_file(payload: bytes, filename: str = "input_payload.dat") -> Path:
    """Write payload to a temp file for file→file benchmarks."""
    path = Path(filename)
    path.write_bytes(payload)
    return path

def cleanup_temp_files(file_paths):
    """Explicitly remove temp files after benchmarks."""
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)

def make_result_v2(
    scenario,
    operation,
    mode,
    input_size,
    compression,
    chunk_size,
    start_time,
    mem_before,
    output_size,
    snapshot
):
    elapsed = time.perf_counter() - start_time
    mem_after = measure_memory_mb()

    return BenchmarkResult(
        scenario=scenario,
        operation=operation,
        mode=mode,
        input_size=input_size,
        compression=compression,
        chunk_size=chunk_size,
        elapsed_sec=elapsed,
        memory_delta_mb=mem_after - mem_before,
        output_size=output_size,
        snapshot=snapshot
    )

# ---------------------------------------------------------
# Dummy Header Builder (mirror Rust)
# ---------------------------------------------------------

def make_header(chunk_size: int, compression: int, cipher: int): 
    header = scp.PyHeaderV1(
        magic=b"RSE1", version=1, alg_profile=257, cipher=cipher,
        hkdf_prf=1, compression=compression, strategy=0, aad_domain=1,
        flags=0, chunk_size=chunk_size, plaintext_size=0, crc32=0,
        dict_id=0, salt=dummy_salt(), key_id=42,
        parallel_hint=0, enc_time_ns=0, reserved=b"\x00"*8,
    )
    return header

def print_cipher(cipher: int):
    match cipher:
        case 1:
            return "AES-GCM"
        
        case 2:
            return "ChaCha20-Poly1305"
        
        case default:
            return "Unknown"