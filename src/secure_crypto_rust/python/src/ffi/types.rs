use pyo3::{prelude::*, types::{PyBytes, PyDict}};
use crypto_core::{headers::HeaderV1, stream_v2::{ApiConfig, DecryptParams, EncryptParams}, telemetry::TelemetrySnapshot};

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyHeaderV1 {
    #[pyo3(get, set)]
    pub magic: [u8; 4],
    #[pyo3(get, set)]
    pub version: u16,
    #[pyo3(get, set)]
    pub alg_profile: u16,
    #[pyo3(get, set)]
    pub cipher: u16,
    #[pyo3(get, set)]
    pub hkdf_prf: u16,
    #[pyo3(get, set)]
    pub compression: u16,
    #[pyo3(get, set)]
    pub strategy: u16,
    #[pyo3(get, set)]
    pub aad_domain: u16,
    #[pyo3(get, set)]
    pub flags: u16,
    #[pyo3(get, set)]
    pub chunk_size: u32,
    #[pyo3(get, set)]
    pub plaintext_size: u64,
    #[pyo3(get, set)]
    pub crc32: u32,
    #[pyo3(get, set)]
    pub dict_id: u32,
    #[pyo3(get, set)]
    pub salt: [u8; 16],
    #[pyo3(get, set)]
    pub key_id: u32,
    #[pyo3(get, set)]
    pub parallel_hint: u32,
    #[pyo3(get, set)]
    pub enc_time_ns: u64,
    #[pyo3(get, set)]
    pub reserved: [u8; 8],
}

#[pymethods]
impl PyHeaderV1 {
    #[new]
    pub fn new(
        magic: [u8; 4],
        version: u16,
        alg_profile: u16,
        cipher: u16,
        hkdf_prf: u16,
        compression: u16,
        strategy: u16,
        aad_domain: u16,
        flags: u16,
        chunk_size: u32,
        plaintext_size: u64,
        crc32: u32,
        dict_id: u32,
        salt: [u8; 16],
        key_id: u32,
        parallel_hint: u32,
        enc_time_ns: u64,
        reserved: [u8; 8],
    ) -> Self {
        Self {
            magic,
            version,
            alg_profile,
            cipher,
            hkdf_prf,
            compression,
            strategy,
            aad_domain,
            flags,
            chunk_size,
            plaintext_size,
            crc32,
            dict_id,
            salt,
            key_id,
            parallel_hint,
            enc_time_ns,
            reserved,
        }
    }
}

impl From<PyHeaderV1> for HeaderV1 {
    fn from(h: PyHeaderV1) -> Self {
        HeaderV1 {
            magic: h.magic,
            version: h.version,
            alg_profile: h.alg_profile,
            cipher: h.cipher,
            hkdf_prf: h.hkdf_prf,
            compression: h.compression,
            strategy: h.strategy,
            aad_domain: h.aad_domain,
            flags: h.flags,
            chunk_size: h.chunk_size,
            plaintext_size: h.plaintext_size,
            crc32: h.crc32,
            dict_id: h.dict_id,
            salt: h.salt,
            key_id: h.key_id,
            parallel_hint: h.parallel_hint,
            enc_time_ns: h.enc_time_ns,
            reserved: h.reserved,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyEncryptParams {
    #[pyo3(get, set)]
    pub header: PyHeaderV1,
    #[pyo3(get, set)]
    pub dict: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub master_key: Vec<u8>,
}

#[pymethods]
impl PyEncryptParams {
    #[new]
    #[pyo3(signature = (master_key, header, dict=None))]
    fn new(master_key: Vec<u8>, header: PyHeaderV1, dict: Option<Vec<u8>>) -> Self {
        Self { header, dict, master_key }
    }
}

impl<'a> From<&'a PyEncryptParams> for EncryptParams<'a> {
    fn from(c: &'a PyEncryptParams) -> Self {
        EncryptParams {
            header: c.header.clone().into(),
            dict: c.dict.as_deref(),
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyDecryptParams {
    #[pyo3(get, set)]
    pub master_key: Vec<u8>,
}

#[pymethods]
impl PyDecryptParams {
    #[new]
    fn new(master_key: Vec<u8>) -> Self {
        Self { master_key }
    }
}

impl From<PyDecryptParams> for DecryptParams {
    fn from(_c: PyDecryptParams) -> Self {
        DecryptParams {
        }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyApiConfig {
    #[pyo3(get, set)]
    pub with_buf: Option<bool>,
    #[pyo3(get, set)]
    pub collect_metrics: Option<bool>,
}

#[pymethods]
impl PyApiConfig {
    #[new]
    #[pyo3(signature = (with_buf=None, collect_metrics=None))]
    pub fn new(
        with_buf: Option<bool>,
        collect_metrics: Option<bool>,
    ) -> Self {
        Self {
            with_buf,
            collect_metrics,
        }
    }
}

impl From<PyApiConfig> for ApiConfig {
    fn from(c: PyApiConfig) -> Self {
        ApiConfig {
            with_buf: c.with_buf,
            collect_metrics: c.collect_metrics,
            // TODO: Accept params from ffi bound, such from python
            alg: None,
            // TODO: Accept params from ffi bound, such from python
            parallelism: None,
        }
    }
}

// # ✅ FULL Production-Ready Rust (Complete Mapping)

// * ✅ Full Rust → Python mapping
// * ✅ All fields exposed
// * ✅ Proper `Duration` conversion
// * ✅ `StageTimes` exposed cleanly
// * ✅ Proper `__repr__`
// * ✅ Proper `.pyi` stub
// * ✅ Production quality

// Assumptions:

// * `StageTimes` = `HashMap<Stage, Duration>`
// * `Stage` implements `ToString` or `Display`

// We expose:

// * `elapsed` → seconds (f64)
// * `stage_times` → `Dict[str, float]`
// * `output` → `bytes | None`
#[pyclass]
pub struct PyTelemetrySnapshot {
    #[pyo3(get)]
    pub segments_processed: u64,

    #[pyo3(get)]
    pub frames_data: u64,

    #[pyo3(get)]
    pub frames_terminator: u64,

    #[pyo3(get)]
    pub frames_digest: u64,

    #[pyo3(get)]
    pub bytes_plaintext: u64,

    #[pyo3(get)]
    pub bytes_compressed: u64,

    #[pyo3(get)]
    pub bytes_ciphertext: u64,

    #[pyo3(get)]
    pub bytes_overhead: u64,

    #[pyo3(get)]
    pub compression_ratio: f64,

    #[pyo3(get)]
    pub throughput_plaintext_bytes_per_sec: f64,

    /// elapsed seconds (Duration converted)
    #[pyo3(get)]
    pub elapsed_sec: f64,

    /// stage_times as Python dict[str, float]
    #[pyo3(get)]
    pub stage_times: PyObject,

    #[pyo3(get)]
    pub output: Option<Py<PyBytes>>,
}

impl From<TelemetrySnapshot> for PyTelemetrySnapshot {
    fn from(snap: TelemetrySnapshot) -> Self {
        Python::with_gil(|py| {
            // Convert stage times -> Dict[str, float]
            let stage_dict = PyDict::new_bound(py);

            for (stage, duration) in snap.stage_times.iter() {
                let seconds = duration.as_secs_f64();
                stage_dict
                    .set_item(stage.to_string(), seconds)
                    .expect("stage_times insert failed");
            }

            let py_output = snap.output.map(|v| {
                PyBytes::new_bound(py, &v).into()
            });

            Self {
                segments_processed: snap.segments_processed,
                frames_data: snap.frames_data,
                frames_terminator: snap.frames_terminator,
                frames_digest: snap.frames_digest,
                bytes_plaintext: snap.bytes_plaintext,
                bytes_compressed: snap.bytes_compressed,
                bytes_ciphertext: snap.bytes_ciphertext,
                bytes_overhead: snap.bytes_overhead,
                compression_ratio: snap.compression_ratio,
                throughput_plaintext_bytes_per_sec: snap
                    .throughput_plaintext_bytes_per_sec,
                elapsed_sec: snap.elapsed.as_secs_f64(),
                stage_times: stage_dict.into(),
                output: py_output,
            }
        })
    }
}

#[pymethods]
impl PyTelemetrySnapshot {
    fn __repr__(&self, py: Python) -> PyResult<String> {
        let output_len = match &self.output {
            Some(obj) => obj.bind(py).len()?,
            None => 0,
        };

        Ok(format!(
            "PyTelemetrySnapshot(segments_processed={}, bytes_plaintext={}, bytes_ciphertext={}, compression_ratio={:.6}, throughput={:.2} B/s, elapsed_sec={:.6}, output_len={})",
            self.segments_processed,
            self.bytes_plaintext,
            self.bytes_ciphertext,
            self.compression_ratio,
            self.throughput_plaintext_bytes_per_sec,
            self.elapsed_sec,
            output_len
        ))
    }

    fn __str__(&self, py: Python) -> PyResult<String> {
        self.__repr__(py)
    }

    fn to_dict(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new_bound(py);

        dict.set_item("segments_processed", self.segments_processed)?;
        dict.set_item("frames_data", self.frames_data)?;
        dict.set_item("frames_terminator", self.frames_terminator)?;
        dict.set_item("frames_digest", self.frames_digest)?;
        dict.set_item("bytes_plaintext", self.bytes_plaintext)?;
        dict.set_item("bytes_compressed", self.bytes_compressed)?;
        dict.set_item("bytes_ciphertext", self.bytes_ciphertext)?;
        dict.set_item("bytes_overhead", self.bytes_overhead)?;
        dict.set_item("compression_ratio", self.compression_ratio)?;
        dict.set_item(
            "throughput_plaintext_bytes_per_sec",
            self.throughput_plaintext_bytes_per_sec,
        )?;
        dict.set_item("elapsed_sec", self.elapsed_sec)?;
        dict.set_item("stage_times", &self.stage_times)?;

        if let Some(ref output) = self.output {
            dict.set_item("output_len", output.bind(py).len()?)?;
        } else {
            dict.set_item("output_len", 0)?;
        }

        Ok(dict.into())
    }
}

