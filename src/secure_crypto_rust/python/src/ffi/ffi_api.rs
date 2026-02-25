
use pyo3::{Bound, PyObject, PyResult, Python, exceptions::PyRuntimeError, pyfunction, pymodule, 
    types::{PyModule, PyModuleMethods}, wrap_pyfunction};

use crypto_core::stream_v2::{ApiConfig, DecryptParams, EncryptParams, MasterKey, decrypt_stream_v2, encrypt_stream_v2};
use crate::ffi::{errors::PyCryptoError, ffi_io::py_extract_io, types::{PyApiConfig, PyDecryptParams, PyEncryptParams, PyHeaderV1, PyTelemetrySnapshot}};

#[pymodule]
pub fn register_api(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register class
    m.add_class::<PyHeaderV1>()?;
    m.add_class::<PyEncryptParams>()?;
    m.add_class::<PyDecryptParams>()?;
    m.add_class::<PyApiConfig>()?;
    m.add_class::<PyTelemetrySnapshot>()?;
    m.add_class::<PyCryptoError>()?;

    // Register func
    m.add_function(wrap_pyfunction!(py_encrypt_stream_v2, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_stream_v2, m)?)?;

    Ok(())
}

#[pyfunction]
fn py_encrypt_stream_v2(
    py: Python,
    input: PyObject,   // bytes, str path, or file-like
    output: PyObject,
    params: PyEncryptParams,
    config: PyApiConfig,
) -> PyResult<PyTelemetrySnapshot> {
    let master_key = MasterKey::new(params.clone().master_key);
    let params = EncryptParams::from(&params);
    let config: ApiConfig = ApiConfig::from(config);

    // Extract Python-side objects while GIL is held
    let (input_src, output_sink) = py_extract_io(py, input, output, Some(params.header.chunk_size as usize))?;

    // 🚀 CRITICAL: Release GIL for entire pipeline
    let result = py.allow_threads(|| {
        encrypt_stream_v2(
            input_src,
            output_sink,
            &master_key,
            params,
            config,
        )
    });

    match result {
        Ok(snapshot) => Ok(snapshot.into()),
        Err(e) => Err(PyRuntimeError::new_err(format!("{:?}", PyCryptoError::from(e)))),
    }
    
}

#[pyfunction]
fn py_decrypt_stream_v2(
    py: Python,
    input: PyObject,        // bytes, str path, or file-like
    output: PyObject,
    params: PyDecryptParams,
    config: PyApiConfig,
) -> PyResult<PyTelemetrySnapshot> {
    let master_key = MasterKey::new(params.clone().master_key);
    let params = DecryptParams::from(params);
    let config: ApiConfig = ApiConfig::from(config);

    // Extract Python-side objects while GIL is held
    let (input_src, output_sink) = py_extract_io(py, input, output, None)?;

    // 🚀 CRITICAL: Release GIL for entire pipeline
    let result = py.allow_threads(|| {
        decrypt_stream_v2(
            input_src,
            output_sink,
            &master_key,
            params,
            config,
        )
    });

    match result {
        Ok(snapshot) => Ok(snapshot.into()),
        Err(e) => Err(PyRuntimeError::new_err(format!("{:?}", PyCryptoError::from(e)))),
    }
}

// ## ✅ Python Usage Examples

// ### Memory → Memory
// ```python
// snap = scp.py_encrypt_stream_v2(b"hello", None, b"key", header, config)
// print("Ciphertext:", snap.output)

// snap = scp.py_decrypt_stream_v2(snap.output, None, b"key", config)
// print("Plaintext:", snap.output)
// ```

// ### File → File
// ```python
// snap = scp.py_encrypt_stream_v2("input.txt", "output.enc", b"key", header, config)
// snap = scp.py_decrypt_stream_v2("output.enc", "decrypted.txt", b"key", config)
// ```

// ### File‑like Objects with Zero‑Copy
// ```python
// import io

// class MyReader(io.BytesIO):
//     def readinto(self, b: bytearray) -> int:
//         return super().readinto(b)

// class MyWriter(io.BytesIO):
//     def writeinto(self, b: bytearray) -> int:
//         self.write(b)
//         return len(b)

// inp = MyReader(b"hello world")
// out = MyWriter()

// snap = scp.py_encrypt_stream_v2(inp, out, b"key", header, config)
// print("Ciphertext:", out.getvalue())

// out2 = MyWriter()
// snap = scp.py_decrypt_stream_v2(io.BytesIO(out.getvalue()), out2, b"key", config)
// print("Decrypted:", out2.getvalue())
// ```

// ## 🚀 Production‑Ready Symmetry
// - Both encrypt and decrypt now auto‑detect:
//   - `bytes` → memory
//   - `str` → file path
//   - `.readinto` / `.writeinto` → zero‑copy adapters
//   - `.read` / `.write` → fallback adapters
// - This ensures maximum performance and natural Python ergonomics.
