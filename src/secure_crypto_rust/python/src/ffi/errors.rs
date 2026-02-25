use pyo3::prelude::*;
use crypto_core::types::StreamError;

#[pyclass]
#[derive(Debug)]
pub struct PyCryptoError {
    #[pyo3(get)]
    pub code: String,
    #[pyo3(get)]
    pub message: String,
}

impl From<StreamError> for PyCryptoError {
    fn from(err: StreamError) -> Self {
        match err {
            StreamError::Io(msg) => Self { code: "Io".into(), message: msg },
            StreamError::Validation(msg) => Self { code: "Validation".into(), message: msg },
            _ => Self { code: "Generic".into(), message: format!("{}", err) },
        }
    }
}
