//! crypto-python
//!
//! Python bindings for crypto-core (PyO3).

use pyo3::prelude::*;

mod ffi;

/// Python module entry point
#[pymodule]
fn rust_crypto(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    ffi::register(py, m)?;
    Ok(())
}
