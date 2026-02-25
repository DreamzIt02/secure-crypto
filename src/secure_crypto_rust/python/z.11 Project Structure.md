# Project Structure

we’ve got a clean separation between **core Rust logic** and **Python bindings**. Let’s walk through how to expose our `encrypt_stream_v2` and `decrypt_stream_v2` APIs to Python via **PyO3**, while keeping the FFI layer ergonomic and safe.

---

## 🔑 Key Design Principles

- **Minimal FFI surface**: Expose only what Python needs (inputs, outputs, error).
- **Error unification**: Map `StreamError` → one Python exception type (`CryptoError`) with `(code, message)`.
- **Memory-safe bridging**: Handle `InputSource`/`OutputSink` variants explicitly, since Python will often pass `bytes`, `str` (file path), or file-like objects.
- **Telemetry snapshot**: Return structured telemetry as a Python class/dict, including optional `output` buffer.

---

## 🔨 Full Implementation Plan

### 1. Core Rust (already done)

Our `core` crate is the pure Rust implementation. We’ll keep it untouched.

### 2. Python Crate (`python/`)

This crate will:

- Depend on `core` via `Cargo.toml`.
- Use **PyO3** to expose functions, types, and errors.
- Provide ergonomic Python APIs (`encrypt_stream_v2`, `decrypt_stream_v2`).
- Map Rust enums/structs into Python classes.

---

## 📂 Project Layout

```bash
python/
├── Cargo.toml
└── src/
    ├── lib.rs          # PyO3 entrypoint
    ├── ffi/
    │   ├── mod.rs      # glue functions
    │   ├── constants.rs
    │   ├── types.rs
    │   └── errors.rs
```

---

## 🦀 `Cargo.toml` (python crate)

```bash
[package]
name = "rust_crypto"
version = "0.1.0"
edition = "2021"

[dependencies]
pyo3 = { version = "0.22", features = ["extension-module"] }
secure_crypto_core = { path = "../core" }

[lib]
name = "rust_crypto"
crate-type = ["cdylib"]
```

---

## 🦀 `src/lib.rs`

```rust
use pyo3::prelude::*;

mod ffi;

#[pymodule]
fn rust_crypto(_py: Python, m: &PyModule) -> PyResult<()> {
    ffi::register(m)?;
    Ok(())
}
```

---

## ✅ Python Usage

```py
import rust_crypto as scp

header = scp.PyHeaderV1(
    magic=b"RSE1",
    version=2,
    alg_profile=1,
    cipher=1,
    hkdf_prf=1,
    compression=0,
    strategy=0,
    aad_domain=0,
    flags=0,
    chunk_size=1024,
    plaintext_size=0,
    crc32=0,
    dict_id=0,
    salt=b"\x00"*16,
    key_id=42,
    parallel_hint=0,
    enc_time_ns=0,
    reserved=b"\x00"*8,
)

config = scp.PyApiConfig(with_buf=True, collect_metrics=False)

snap = scp.py_encrypt_stream_v2(b"hello world", b"supersecretkey", header, config)
print("Ciphertext:", snap.output)
print("Telemetry:", snap.segments_processed, snap.bytes_ciphertext)
```

---

### 1. Accepting File Paths

- If Python passes a `str`, treat it as a filesystem path.
- Map to `InputSource::File(PathBuf)` or `OutputSink::File(PathBuf)`.

### 2. Accepting File‑like Objects

- If Python passes an object with `.read()` or `.write()`, wrap it in a custom adapter implementing `Read`/`Write`.
- Use `PyAny` to call back into Python methods safely.

---

## ✅ Python Usage Examples (Encrypt)

### Memory → Memory

```python
snap = scp.py_encrypt_stream_v2(b"hello", None, b"key", header, config)
print(snap.output)
```

### File → File

```python
snap = scp.py_encrypt_stream_v2("input.txt", "output.enc", b"key", header, config)
```

### File‑like Objects

```python
import io
inp = io.BytesIO(b"hello world")
out = io.BytesIO()

snap = scp.py_encrypt_stream_v2(inp, out, b"key", header, config)
print("Ciphertext:", out.getvalue())
```

---

## 🚀 Production‑Ready Notes

- **Adapters** ensure Python file‑like objects integrate seamlessly.
- **File paths** are supported natively.
- **Memory buffers** remain the default for testing/benchmarks.
- Errors are unified into `CryptoError`.

---

## ✅ Python Usage Examples (Decrypt)

### Memory → Memory (1)

```python
snap = scp.py_decrypt_stream_v2(snap.output, None, b"key", config)
print("Plaintext:", snap.output)
```

### File → File (1)

```python
snap = scp.py_decrypt_stream_v2("output.enc", "decrypted.txt", b"key", config)
```

### File‑like Objects (1)

```python
import io
inp = io.BytesIO(snap.output)
out = io.BytesIO()

snap = scp.py_decrypt_stream_v2(inp, out, b"key", config)
print("Decrypted:", out.getvalue())
```

---

## 🚀 Production‑Ready Symmetry

- Both `encrypt_stream_v2` and `decrypt_stream_v2` now accept:
  - **bytes** (memory buffer)
  - **str path** (file path)
  - **file‑like objects** (`io.BytesIO`, `open()` handles)
- Output can be captured in memory, written to a file, or streamed into a Python writer.
- Errors are unified into `CryptoError`.

---

## ✅ Correct Way to Build

### 1. Make sure `python` sub‑project has its own `Cargo.toml`

Inside `src/secure_crypto_rust/python/` we should have:

```bash
Cargo.toml
pyproject.toml
src/
   lib.rs
   ffi/
```

If `Cargo.toml` is missing, maturin will fail with the error.

---

### 2. Run maturin with the correct manifest path

From the **root of our repo**:

```bash
maturin develop --release -m src/secure_crypto_rust/python/Cargo.toml
```

or if we’re already inside the `python` folder:

```bash
maturin develop -m Cargo.toml
```

The `-m` flag must point to the **Cargo.toml file**, not just the directory.

---

### 3. Verify with cargo

Before running maturin, check that the Rust crate compiles:

```bash
cd src/secure_crypto_rust/python
cargo build --release
```

If this fails, maturin will also fail. We need to fix any Rust compilation errors first.

---

### 4. Install into Python

Once `maturin develop` succeeds, we can import the module:

```python
import rust_crypto
```

---

## 🚀 Production Workflow

- **Local dev**: `maturin develop -m src/secure_crypto_rust/python/Cargo.toml`
- **Wheel build**: `maturin build -m src/secure_crypto_rust/python/Cargo.toml --release`
- **Publish to PyPI**: `maturin publish -m src/secure_crypto_rust/python/Cargo.toml`

---

- TODO: add **automatic detection of plaintext size** in the Python binding (so users don’t need to set `plaintext_size` manually in `HeaderV1` when passing a memory buffer). That would make the API even smoother.
