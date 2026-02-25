
// io_ht.rs
// ## ✅ High-Throughput Reader/Writer

// * 🚀 Minimize GIL acquisitions
// * 🚀 Reduce Python method dispatch overhead
// * 🚀 Avoid per-chunk attribute lookups
// * 🚀 Keep FFI boundary panic-safe
// * 🚀 Production-safe for crypto/stream pipelines

// # 🔥 1) GIL-Minimized High-Throughput Version

// ## 🎯 Key Optimizations

// Instead of:

// * Acquiring GIL
// * Looking up `.read`
// * Calling `.read`
// * Extracting

// on every call…

// We:

// 1. Pre-bind `read`, `write`, and `flush` once.
// 2. Store bound callables.
// 3. Minimize attribute lookup.
// 4. Keep GIL hold duration short.
// 5. Catch panics at FFI boundary.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyByteArray};
use pyo3::buffer::PyBuffer;
use std::io::{Read, Write};
use std::io::{Error, ErrorKind, Result};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[inline]
fn pyerr_to_io(err: PyErr) -> Error {
    Error::new(ErrorKind::Other, err.to_string())
}

#[inline]
fn panic_to_io() -> Error {
    Error::new(ErrorKind::Other, "Rust panic across FFI boundary")
}

///////////////////////////////////////////////////////////////
// HIGH-THROUGHPUT READER
///////////////////////////////////////////////////////////////

pub struct PyReaderHT {
    read_fn: Py<PyAny>, // bound once
}

impl PyReaderHT {
    pub fn new(obj: Py<PyAny>) -> PyResult<Self> {
        Python::with_gil(|py| {
            let read_fn = obj.getattr(py, "read")?;
            Ok(Self {
                read_fn: read_fn.into(),
            })
        })
    }
}

impl Read for PyReaderHT {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        catch_unwind(AssertUnwindSafe(|| {
            Python::with_gil(|py| {
                let result = (|| -> PyResult<usize> {
                    let any = self.read_fn.call1(py, (buf.len(),))?;

                    // Fast path: bytes
                    if let Ok(b) = any.downcast_bound::<PyBytes>(py) {
                        let src = b.as_bytes();
                        let n = src.len().min(buf.len());
                        buf[..n].copy_from_slice(&src[..n]);
                        return Ok(n);
                    }

                    // Fast path: bytearray
                    if let Ok(b) = any.downcast_bound::<PyByteArray>(py) {
                        let src = unsafe { b.as_bytes() };
                        let n = src.len().min(buf.len());
                        buf[..n].copy_from_slice(&src[..n]);
                        return Ok(n);
                    }

                    // Buffer protocol
                    if let Ok(buffer) = PyBuffer::<u8>::get_bound(any.bind(py)) {
                        if !buffer.is_c_contiguous() {
                            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                                "Non-contiguous buffer",
                            ));
                        }

                        let slice = { buffer.as_slice(py) }.ok_or_else(|| {
                            PyErr::new::<pyo3::exceptions::PyValueError, _>(
                                "Failed to get buffer slice",
                            )
                        })?;
                        let n = slice.len().min(buf.len());
                        for (dst, src) in buf.iter_mut().zip(slice.iter()) {
                            *dst = src.get();
                        }
                        return Ok(n);
                    }

                    Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                        "read() must return bytes-like",
                    ))
                })();

                result.map_err(pyerr_to_io)
            })
        }))
        .unwrap_or_else(|_| Err(panic_to_io()))
    }
}

///////////////////////////////////////////////////////////////
// HIGH-THROUGHPUT WRITER
///////////////////////////////////////////////////////////////

pub struct PyWriterHT {
    write_fn: Py<PyAny>,
    flush_fn: Option<Py<PyAny>>,
}

impl PyWriterHT {
    pub fn new(obj: Py<PyAny>) -> PyResult<Self> {
        Python::with_gil(|py| {
            let write_fn = obj.getattr(py, "write")?.into();

            let flush_fn = match obj.getattr(py, "flush") {
                Ok(f) => Some(f.into()),
                Err(_) => None,
            };

            Ok(Self { write_fn, flush_fn })
        })
    }
}

impl Write for PyWriterHT {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        catch_unwind(AssertUnwindSafe(|| {
            Python::with_gil(|py| {
                let result = (|| -> PyResult<usize> {
                    let py_bytes = PyBytes::new_bound(py, buf);
                    let any = self.write_fn.call1(py, (py_bytes,))?;
                    any.extract::<usize>(py)
                })();

                result.map_err(pyerr_to_io)
            })
        }))
        .unwrap_or_else(|_| Err(panic_to_io()))
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(ref flush_fn) = self.flush_fn {
            catch_unwind(AssertUnwindSafe(|| {
                Python::with_gil(|py| {
                    let result = (|| -> PyResult<()> {
                        flush_fn.call0(py)?;
                        Ok(())
                    })();

                    result.map_err(pyerr_to_io)
                })
            }))
            .unwrap_or_else(|_| Err(panic_to_io()))
        } else {
            Ok(())
        }
    }
}

// ## 🚀 Why This Is Faster

// | Optimization            | Benefit                         |
// | ----------------------- | ------------------------------- |
// | Bound method caching    | Avoid attribute lookup per call |
// | Fast-path type checks   | Avoid slow extraction           |
// | Buffer protocol support | Works with memoryview/NumPy     |
// | Short GIL sections      | Max parallel Rust compute       |
// | Panic boundary          | FFI safe                        |

// This is ideal for **high-throughput crypto streams**.
