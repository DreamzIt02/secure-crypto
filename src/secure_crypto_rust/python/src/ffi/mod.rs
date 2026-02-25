
use pyo3::prelude::*;


mod types;
mod errors;
mod ffi_io;
mod ffi_api;

use ffi_api::*;

#[pymodule]
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {

    // Register public api
    let _ = register_api(py, m);

    Ok(())
}
