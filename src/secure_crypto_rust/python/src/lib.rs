//! crypto-python
//!
//! Python bindings for crypto-core (PyO3).

use pyo3::prelude::*;

mod ffi;
mod io;

/// Python module entry point
#[pymodule]
fn rust_crypto(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    ffi::register(py, m)?;
    Ok(())
}

// #[pymodule]
// fn secure_crypto_python(_py: Python, m: &PyModule) -> PyResult<()> {
//     ffi::register(m)?;
//     Ok(())
// }
