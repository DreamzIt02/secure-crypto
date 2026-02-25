## 📄 `secure_crypto_python.pyi`

# Stubs for secure_crypto_python extension module

from typing import Any, Dict, Optional, List

__all__ = [
    # Header and Params
    "PyHeaderV1",
    "PyEncryptParams",
    "PyDecryptParams",
    "PyApiConfig",

    # Telemetry
    "PyTelemetrySnapshot",
    # Error Types
    "PyCryptoError",

    # Streaming functions
    "py_encrypt_stream_v2",
    "py_decrypt_stream_v2",
]

class PyEncryptParams:
    header: PyHeaderV1
    dict: Optional[bytes]
    master_key: bytes
    def __init__(self, master_key: bytes, header: PyHeaderV1, dict: Optional[bytes]) -> None: ...

class PyDecryptParams:
    master_key: bytes
    def __init__(self, master_key: bytes) -> None: ...


class PyHeaderV1:
    magic: bytes  # length 4
    version: int
    alg_profile: int
    cipher: int
    hkdf_prf: int
    compression: int
    strategy: int
    aad_domain: int
    flags: int
    chunk_size: int
    plaintext_size: int
    crc32: int
    dict_id: int
    salt: bytes  # length 16
    key_id: int
    parallel_hint: int
    enc_time_ns: int
    reserved: bytes  # length 8

    def __init__(
        self,
        magic: bytes,  # length 4
        version: int,
        alg_profile: int,
        cipher: int,
        hkdf_prf: int,
        compression: int,
        strategy: int,
        aad_domain: int,
        flags: int,
        chunk_size: int,
        plaintext_size: int,
        crc32: int,
        dict_id: int,
        salt: bytes,  # length 16
        key_id: int,
        parallel_hint: int,
        enc_time_ns: int,
        reserved: bytes,  # length 8
    ) -> None: ...


class PyApiConfig:
    with_buf: Optional[bool]
    collect_metrics: Optional[bool]

    def __init__(
        self,
        with_buf: Optional[bool] = None,
        collect_metrics: Optional[bool] = None,
    ) -> None: ...

from dataclasses import dataclass
from typing import Optional


@dataclass
class PyTelemetrySnapshot:
    segments_processed: int
    frames_data: int
    frames_terminator: int
    frames_digest: int
    bytes_plaintext: int
    bytes_compressed: int
    bytes_ciphertext: int
    bytes_overhead: int
    compression_ratio: float
    throughput_plaintext_bytes_per_sec: float
    elapsed_sec: float
    stage_times: Dict[str, float]
    output: Optional[bytes]

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...
    def to_dict(self) -> Dict[str, Any]: ...

class PyCryptoError:
    code: str
    message: str

    def __init__(self, code: str, message: str) -> None: ...

def py_encrypt_stream_v2(
    input: bytes | str | object, # bytes, str path, or file-like
    output: bytes | str | object,
    params: PyEncryptParams,
    config: PyApiConfig,
) -> PyTelemetrySnapshot: ...

def py_decrypt_stream_v2(
    input: bytes | str | object,  # bytes, str path, or file-like
    output: bytes | str | object,
    params: PyDecryptParams,
    config: PyApiConfig,
) -> PyTelemetrySnapshot: ...

## ✅ Notes
# - `input` and `output` are typed as `bytes | str | object` because they can be memory buffers, file paths, or file‑like objects.
# - `output` in `PyTelemetrySnapshot` is declared as `Optional[bytes]` (instead of `List[int]`) since Python users will see a `bytes` buffer.
# - This stub file should be placed in the same directory as our extension module (`secure_crypto_python.pyi`) so IDEs and type checkers pick it up.
