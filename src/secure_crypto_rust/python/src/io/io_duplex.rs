// io_duplex.rs
// # 🔥 2) Bidirectional Duplex Stream Adapter

// Now we combine both into a full duplex type:

// * Implements `Read`
// * Implements `Write`
// * Optional flush
// * Bound once
// * Panic safe

use std::io::{Read, Write, Result};

use pyo3::{Py, PyAny, PyResult};

use crate::ffi::io_ht::{PyReaderHT, PyWriterHT};

pub struct PyDuplexHT {
    reader: PyReaderHT,
    writer: PyWriterHT,
}

impl PyDuplexHT {
    pub fn new(obj: Py<PyAny>) -> PyResult<Self> {
        let reader = pyo3::Python::with_gil(|py| {
            PyReaderHT::new(obj.clone_ref(py))
        })?;
        let writer = PyWriterHT::new(obj)?;
        Ok(Self {
            reader,
            writer,
        })
    }
}

impl Read for PyDuplexHT {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for PyDuplexHT {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.writer.write_all(buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

// # 🧠 When To Use Duplex

// Perfect for:

// * Encrypted tunnel
// * Rust TLS wrapper exposed to Python
// * Streaming compression
// * Framed protocols
// * Custom transport layer

// We can plug it directly into:

// ```rust
// std::io::copy(&mut duplex, &mut duplex);
// ```

// Or our encrypt/decrypt pipeline.

// # 🧨 Performance Notes

// If we want **even more throughput**, the next level is:

// * Pre-allocate reusable Python `bytearray`
// * Use `.readinto()` instead of `.read()`
// * Eliminate the extra Rust copy entirely
// * Reuse write buffer objects
// * Release GIL during crypto compute (`py.allow_threads()`)

// That gives us **true near-C extension performance**.
