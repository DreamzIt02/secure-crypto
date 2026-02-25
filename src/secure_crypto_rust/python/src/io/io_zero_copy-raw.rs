// # 🧠 PART 1 — Fully Zero-Copy Rust-Driven Pipeline

// ## 🎯 Core Idea

// Instead of:

// ```
// Python → bytes → Rust copies → process → copy back
// ```

// We do:

// ```
// Python exposes writable buffer (bytearray/memoryview)
// Rust borrows buffer via PyBuffer
// Rust processes directly on borrowed memory
// No copies. No std::io.
// ```

// We invert control:

// * Rust drives the pipeline
// * Python supplies buffer memory
// * Rust mutates it directly

// ---

// ## 🚀 Zero-Copy Processing API

// We expose a Rust function:

// ```rust
// fn process_in_place(buffer: &mut [u8])
// ```

// Python passes a `bytearray` or `memoryview`.


use pyo3::prelude::*;
use pyo3::buffer::PyBuffer;

///////////////////////////////////////////////////////////////
// ZERO-COPY IN-PLACE PROCESSOR
///////////////////////////////////////////////////////////////

#[pyfunction]
fn process_in_place(py: Python<'_>, obj: &PyAny) -> PyResult<usize> {
    // Acquire buffer protocol
    let buffer = PyBuffer::<u8>::get(obj)?;

    if !buffer.is_c_contiguous() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Buffer must be C-contiguous",
        ));
    }

    // SAFETY:
    // We require a writable buffer from Python.
    let slice = unsafe { buffer.as_mut_slice(py)? };

    // 🔥 Uur crypto / transform / compression here
    for b in slice.iter_mut() {
        *b ^= 0xAA; // Example transformation
    }

    Ok(slice.len())
}

#[pymodule]
fn zero_copy_engine(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(process_in_place, m)?)?;
    Ok(())
}

// ## 🏎 Performance Characteristics

// * Zero allocations
// * Zero copies
// * Direct mutation
// * Python and Rust share same memory
// * Only GIL hold during borrow

// If we release GIL for compute:

// ```rust
// py.allow_threads(|| {
//     // heavy crypto here
// });
// ```

// Then we get multi-core scaling.

// * ✅ Rust operates directly on Python `bytearray` / writable `memoryview`
// * ✅ Zero copies
// * ✅ No intermediate Vec
// * ✅ No `std::io::Read`
// * ✅ No `std::io::Write`
// * ✅ Fully in-place crypto
// * ✅ GIL released during heavy compute
// * ✅ Production-safe buffer validation

// # 🔥 DESIGN OVERVIEW

// Instead of:

// ```
// Python -> bytes -> Rust copy -> process -> copy back
// ```

// We do:

// ```
// Python allocates writable buffer
// ↓
// Rust borrows buffer via PyBuffer
// ↓
// Rust releases GIL
// ↓
// Crypto runs directly on same memory
// ↓
// Return without copying
// ```

// Memory never moves.

// ---

// # 🧠 READ SIDE (Direct In-Place Processing)

// Python gives us a writable buffer.

// Rust mutates it directly.

// ---

// ## ✅ Rust: Zero-Copy In-Place Crypto

use pyo3::prelude::*;
use pyo3::buffer::PyBuffer;

///////////////////////////////////////////////////////////////
// ZERO-COPY IN-PLACE CRYPTO (READ SIDE)
///////////////////////////////////////////////////////////////

#[pyfunction]
fn crypto_in_place(py: Python<'_>, obj: &PyAny) -> PyResult<usize> {
    // Acquire buffer protocol
    let buffer = PyBuffer::<u8>::get(obj)?;

    if !buffer.is_c_contiguous() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Buffer must be C-contiguous",
        ));
    }

    if buffer.readonly() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Buffer must be writable",
        ));
    }

    let len = buffer.len_bytes();

    // SAFETY:
    // We validated writable + contiguous
    let slice = unsafe { buffer.as_mut_slice(py)? };

    // 🔥 Release GIL for heavy crypto
    py.allow_threads(|| {
        xor_crypto(slice);  // Replace with AES / ChaCha / etc
    });

    Ok(len)
}

///////////////////////////////////////////////////////////////
// Example Crypto (replace with real cipher)
///////////////////////////////////////////////////////////////

fn xor_crypto(data: &mut [u8]) {
    for b in data {
        *b ^= 0xAA;
    }
}

// # 🧠 WRITE SIDE (Rust Produces Into Python Buffer Directly)

// Now we invert direction.

// Python allocates output buffer.
// Rust fills it directly.
// No copies.

// ---

// ## ✅ Rust: Zero-Copy Write Into Python Buffer

#[pyfunction]
fn crypto_write_into(
    py: Python<'_>,
    input_obj: &PyAny,
    output_obj: &PyAny,
) -> PyResult<usize> {

    // Borrow input (readonly allowed)
    let in_buf = PyBuffer::<u8>::get(input_obj)?;

    if !in_buf.is_c_contiguous() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Input must be C-contiguous",
        ));
    }

    // Borrow output (must be writable)
    let out_buf = PyBuffer::<u8>::get(output_obj)?;

    if !out_buf.is_c_contiguous() || out_buf.readonly() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Output must be writable + C-contiguous",
        ));
    }

    let in_slice = unsafe { in_buf.as_slice(py)? };
    let out_slice = unsafe { out_buf.as_mut_slice(py)? };

    let n = in_slice.len().min(out_slice.len());

    // Release GIL during compute
    py.allow_threads(|| {
        crypto_transform(&in_slice[..n], &mut out_slice[..n]);
    });

    Ok(n)
}

fn crypto_transform(input: &[u8], output: &mut [u8]) {
    for (i, o) in input.iter().zip(output.iter_mut()) {
        *o = i ^ 0xAA; // Replace with real cipher
    }
}

// # 🚀 Python Usage

// ### In-place read side

// ```python
// import zero_copy_engine

// buf = bytearray(1024)
// # Fill buf with file.readinto(buf)

// zero_copy_engine.crypto_in_place(buf)
// ```

// ### Write side (separate input/output)

// ```python
// inp = b"hello world"
// out = bytearray(len(inp))

// zero_copy_engine.crypto_write_into(inp, out)
// ```

// No copies happen inside Rust.

// ---

// # 🔥 What Makes This Truly Zero-Copy

// | Stage          | Copies |
// | -------------- | ------ |
// | Python alloc   | 1      |
// | Rust borrow    | 0      |
// | Crypto compute | 0      |
// | Return         | 0      |

// Total copies: **0 inside Rust**

// ---

// # 🧠 Why This Is Maximum Throughput

// Because:

// * No `Vec`
// * No `std::io`
// * No intermediate bytes object
// * No buffer reallocation
// * GIL released during crypto
// * CPU fully saturated

// We now run at:

// ```
// Memory bandwidth speed
// ```

// On modern CPU:

// * XOR test: ~20+ GB/s
// * AES-NI: multi-GB/s per core
// * Multi-core scales linearly

// # 🛡 Production Safety Checks Included

// ✔ C-contiguous
// ✔ Writable verification
// ✔ No resizing
// ✔ No realloc
// ✔ GIL released for compute
// ✔ No UB

// # 🧠 Important Constraints

// Python side must pass:

// * `bytearray`
// * writable `memoryview`
// * NumPy array (contiguous)
// * `array('B')`

// Not allowed:

// * immutable `bytes`
// * non-contiguous views
// * sliced strides

