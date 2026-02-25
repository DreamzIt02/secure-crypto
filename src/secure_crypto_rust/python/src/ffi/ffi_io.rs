
// The fix is to make our classifiers **strict and symmetric**:  
// - `bytes`/`bytearray`/`memoryview` → always `Memory`  
// - `str` → always `File` (never mis‑classified as raw bytes)  
// - everything else → treated as file‑like `Reader`/`Writer`  

use std::{io::{Read, Write}, path::PathBuf};

use crypto_core::stream_v2::{InputSource, OutputSink};
use pyo3::{PyObject, PyResult, Python, types::{PyByteArray, PyBytes, PyMemoryView, PyString}};
use pyo3::types::PyAnyMethods; // ✅ bring both traits into scope

use crate::io::{PyReader, PyReaderHT, PyReaderReadInto, PyWriter, PyWriterHT, PyWriterWriteInto};

// fn classify_input_0(
//     py: Python<'_>,
//     input: PyObject,
//     chunk_size: Option<usize>,
// ) -> PyResult<InputSource> {
//     let obj = input.bind(py);

//     // -------------------------------------------------
//     // 1️⃣ Fast path: exact bytes / bytearray (zero copy extract)
//     // -------------------------------------------------
//     if obj.is_instance_of::<PyBytes>() || obj.is_instance_of::<PyByteArray>() {
//         let bytes: Vec<u8> = obj.extract()?;
//         return Ok(InputSource::Memory(bytes));
//     }

//     // -------------------------------------------------
//     // 2️⃣ Generic buffer-like (memoryview, etc.)
//     // -------------------------------------------------
//     if let Ok(bytes) = obj.extract::<Vec<u8>>() {
//         return Ok(InputSource::Memory(bytes));
//     }

//     // -------------------------------------------------
//     // 3️⃣ File path (string)
//     // -------------------------------------------------
//     if let Ok(path) = obj.extract::<String>() {
//         return Ok(InputSource::File(path.into()));
//     }

//     // -------------------------------------------------
//     // 4️⃣ Fallback: Reader object
//     // -------------------------------------------------
//     let reader: Box<dyn Read + Send> =
//         if let Ok(r) = PyReaderReadInto::new(input.clone_ref(py), chunk_size) {
//             Box::new(r)
//         } else if let Ok(r) = PyReaderHT::new(input.clone_ref(py)) {
//             Box::new(r)
//         } else {
//             Box::new(PyReader::new(input.clone_ref(py)))
//         };

//     Ok(InputSource::Reader(reader))
// }

fn classify_input(
    py: Python<'_>,
    input: PyObject,
    chunk_size: Option<usize>,
    debug: Option<bool>
) -> PyResult<InputSource> {
    let obj = input.bind(py);

    // 1️⃣ Exact memory types
    if obj.is_instance_of::<PyBytes>() || obj.is_instance_of::<PyByteArray>() {
        let bytes: Vec<u8> = obj.extract()?;
        if let Some(true) = debug {
            println!("1. Input source detected: {:?}", "memory");
        }
        return Ok(InputSource::Memory(bytes));
    }

    // 2️⃣ Buffer-like (memoryview, etc.)
    if obj.is_instance_of::<PyMemoryView>() {
        let bytes: Vec<u8> = obj.extract()?;
        if let Some(true) = debug {
            println!("2. Input source detected: {:?}", "memory");
        }
        return Ok(InputSource::Memory(bytes));
    }

    // 3️⃣ File path (string only)
    if obj.is_instance_of::<PyString>() {
        let path: String = obj.extract()?;
        if let Some(true) = debug {
            println!("3. Input source detected: {:?}", "file");
        }
        return Ok(InputSource::File(PathBuf::from(path)));
    }

    // 4️⃣ Fallback: file-like reader
    let reader: Box<dyn Read + Send> =
        if let Ok(r) = PyReaderReadInto::new(input.clone_ref(py), chunk_size) {
            if let Some(true) = debug {
                println!("4. Input source detected: {:?}", "reader");
            }
            Box::new(r)
        } else if let Ok(r) = PyReaderHT::new(input.clone_ref(py)) {
            if let Some(true) = debug {
                println!("5. Input source detected: {:?}", "reader");
            }
            Box::new(r)
        } else {
            if let Some(true) = debug {
                println!("6. Input source detected: {:?}", "reader");
            }
            Box::new(PyReader::new(input.clone_ref(py)))
        };

    Ok(InputSource::Reader(reader))
}

// fn classify_output_0(
//     py: Python<'_>,
//     output: PyObject,
// ) -> PyResult<OutputSink> {
//     let obj = output.bind(py);

//     // -------------------------------------------------
//     // 1️⃣ Memory sink (bytes / bytearray)
//     // -------------------------------------------------
//     if obj.is_instance_of::<PyBytes>() || obj.is_instance_of::<PyByteArray>() {
//         return Ok(OutputSink::Memory);
//     }

//     if obj.extract::<Vec<u8>>().is_ok() {
//         return Ok(OutputSink::Memory);
//     }

//     // -------------------------------------------------
//     // 2️⃣ File path
//     // -------------------------------------------------
//     if let Ok(path) = obj.extract::<String>() {
//         return Ok(OutputSink::File(path.into()));
//     }

//     // -------------------------------------------------
//     // 3️⃣ Fallback: Writer object
//     // -------------------------------------------------
//     let writer: Box<dyn Write + Send> =
//         if let Ok(w) = PyWriterWriteInto::new(output.clone_ref(py)) {
//             Box::new(w)
//         } else if let Ok(w) = PyWriterHT::new(output.clone_ref(py)) {
//             Box::new(w)
//         } else {
//             Box::new(PyWriter::new(output.clone_ref(py)))
//         };

//     Ok(OutputSink::Writer(writer))
// }

fn classify_output(
    py: Python<'_>,
    output: PyObject,
    debug: Option<bool>
) -> PyResult<OutputSink> {
    let obj = output.bind(py);

    // 1️⃣ Memory sink
    if obj.is_instance_of::<PyBytes>() || obj.is_instance_of::<PyByteArray>() {
        if let Some(true) = debug {
            println!("1. Output source detected: {:?}", "memory");
        }
        return Ok(OutputSink::Memory);
    }
    if obj.is_instance_of::<PyMemoryView>() {
        if let Some(true) = debug {
            println!("2. Output source detected: {:?}", "memory");
        }
        return Ok(OutputSink::Memory);
    }

    // 2️⃣ File path (string only)
    if obj.is_instance_of::<PyString>() {
        let path: String = obj.extract()?;
        if let Some(true) = debug {
            println!("3. Output source detected: {:?}", "file");
        }
        return Ok(OutputSink::File(PathBuf::from(path)));
    }

    // 3️⃣ Fallback: file-like writer
    let writer: Box<dyn Write + Send> =
        if let Ok(w) = PyWriterWriteInto::new(output.clone_ref(py)) {
            if let Some(true) = debug {
                println!("4. Output source detected: {:?}", "writer");
            }
            Box::new(w)
        } else if let Ok(w) = PyWriterHT::new(output.clone_ref(py)) {
            if let Some(true) = debug {
                println!("5. Output source detected: {:?}", "writer");
            }
            Box::new(w)
        } else {
            if let Some(true) = debug {
                println!("6. Output source detected: {:?}", "writer");
            }
            Box::new(PyWriter::new(output.clone_ref(py)))
        };

    Ok(OutputSink::Writer(writer))
}

// - **InputSource::Memory** → `bytes`, `bytearray`, `memoryview`  
// - **InputSource::File** → `str` path  
// - **InputSource::Reader** → `BytesIO`, file‑like objects, custom readers  

// This way, our API behaves symmetrically:  
// - Passing `bytes`/`bytearray` gives us snapshot buffers.  
// - Passing `BytesIO` gives us streaming behavior.  
pub fn py_extract_io(
    py: Python,
    input: PyObject,  // bytes, str path, or file-like
    output: PyObject,
    chunk_size: Option<usize>,
) -> PyResult<(InputSource, OutputSink)> {
    // ------------------- INPUT -------------------
    let input_src = classify_input(py, input, chunk_size, Some(true))?;

    // ------------------- OUTPUT -------------------
    let output_sink = classify_output(py, output, Some(true))?;

    Ok((input_src, output_sink))
}

// ### Key changes
// - **No generic `extract::<Vec<u8>>()` fallback** — that was too permissive and allowed `str` to be mis‑extracted as bytes.  
// - **Explicit `PyString` check** — ensures only actual Python strings become `File` paths.  
// - **Symmetry** — memory types are always memory, strings are always files, everything else is treated as file‑like.
