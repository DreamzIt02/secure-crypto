
// ## 2️⃣ `core.rs` — stable public API

use std::sync::Arc;

use crate::{
    constants::{DEFAULT_QUEUE_CAP, DEFAULT_WORKERS, MAGIC_DICT, MASTER_KEY_LENGTHS, MAX_DICT_LEN, MIN_DICT_LEN, QUEUE_CAPS, WORKERS_COUNT}, 
    crypto::{CryptoError, DigestAlg, derive_session_key_32}, 
    headers::HeaderV1, recovery::AsyncLogManager, 
    stream_v2::{io::{InputSource, OutputSink, PayloadReader, open_input, open_output}, 
    parallelism::HybridParallelismProfile, pipeline::{PipelineConfig, run_decrypt_pipeline, run_encrypt_pipeline}, 
    segment_worker::{DecryptContext, EncryptContext}}, 
    telemetry::TelemetrySnapshot, 
    types::StreamError
};

#[derive(Clone, Debug)]
pub struct EncryptParams<'a> {
    pub header: HeaderV1,
    pub dict: Option<&'a [u8]>,
}
impl<'a> EncryptParams<'a> {
    pub fn validate(&self) -> Result<(), StreamError> {
        validate_dictionary(self.dict.as_deref())?;
        // If HeaderV1 has validation logic, we can enable it here:
        // self.header.validate_header()?;
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct DecryptParams;
impl DecryptParams {
    pub fn validate(&self) -> Result<(), StreamError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Whether to capture the output buffer in memory.
    /// - `None` or `Some(false)` → no buffer capture (production default).
    /// - `Some(true)` → capture buffer for tests/benchmarks.
    pub with_buf: Option<bool>,

    /// Whether to collect detailed metrics during pipeline execution.
    /// Currently unused, reserved for future expansion.
    pub collect_metrics: Option<bool>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            with_buf: Some(false),      // default: no buffer
            collect_metrics: Some(false), // default: no metrics
        }
    }
}

impl ApiConfig {
    pub fn new(with_buf: Option<bool>, collect_metrics: Option<bool>) -> Self {
        Self {
            with_buf: with_buf.or(Some(false)),
            collect_metrics: collect_metrics.or(Some(false)),
        }
    }

    pub fn with_buf_enabled() -> Self {
        Self { with_buf: Some(true), collect_metrics: Some(false) }
    }
}

fn setup_enc_context(master_key: &[u8], header: &HeaderV1, alg: DigestAlg)
    -> Result<(EncryptContext, HybridParallelismProfile, Arc<AsyncLogManager>), StreamError> 
{
    let session_key = derive_session_key_32(master_key, header).map_err(StreamError::Crypto)?;
    let profile = HybridParallelismProfile::dynamic(header.chunk_size as u32, 0.50, 64);
    let context = EncryptContext::new(header.clone(), profile.clone(), &session_key, alg)
        .map_err(StreamError::SegmentWorker)?;
    let log_manager = Arc::new(AsyncLogManager::new("stream_v2_enc.log", 100)?);

    Ok((context, profile, log_manager))
}

fn setup_dec_context(master_key: &[u8], header: &HeaderV1, alg: DigestAlg)
    -> Result<(DecryptContext, HybridParallelismProfile, Arc<AsyncLogManager>), StreamError> 
{
    let session_key = derive_session_key_32(master_key, header).map_err(StreamError::Crypto)?;
    let profile = HybridParallelismProfile::dynamic(header.chunk_size as u32, 0.50, 64);
    let context = DecryptContext::from_stream_header(header.clone(), profile.clone(), &session_key, alg)
        .map_err(StreamError::SegmentWorker)?;
    let log_manager = Arc::new(AsyncLogManager::new("stream_v2_dec.log", 100)?);

    Ok((context, profile, log_manager))
}

/// 🔐 Encrypt stream (v2)
pub fn encrypt_stream_v2(
    input: InputSource,
    output: OutputSink,
    master_key: &[u8],
    params: EncryptParams,
    config: ApiConfig, // new param
) -> Result<TelemetrySnapshot, StreamError> {
    validate_encrypt_params(master_key, &params, None, None)?;

    let reader = open_input(input)?;
    let (writer, maybe_buf) = open_output(output, config.with_buf)?;

    // ---- Read stream header ----
    let mut payload_reader = PayloadReader::new(reader);

    let (mut crypto, profile, log_manager) = setup_enc_context(master_key, &params.header, DigestAlg::Blake3)?;
    let config_pipe = PipelineConfig::new(profile, maybe_buf.clone());

    let mut snapshot = run_encrypt_pipeline(
        &mut payload_reader,
        writer,
        &mut crypto,
        &config_pipe,
        log_manager,
    )?;

    // --- Telemetry buffer extraction for tests --- 
    if let Some(ref arc_buf) = maybe_buf { 
        let buf = arc_buf.lock().unwrap(); 
        snapshot.attach_output(buf.clone()); 
        // clone Vec<u8> into snapshot.output 
    }

    Ok(snapshot)
}

/// 🔓 Decrypt stream (v2)
pub fn decrypt_stream_v2(
    input: InputSource,
    output: OutputSink,
    master_key: &[u8],
    params: DecryptParams,
    config: ApiConfig, // new param
) -> Result<TelemetrySnapshot, StreamError> {
    //
    validate_decrypt_params(master_key, &params, None, None)?;

    let reader = open_input(input)?;
    let (writer, maybe_buf) = open_output(output, config.with_buf)?;

    // ---- Read stream header ----
    // Assert reader is positioned correctly
    let (header, mut payload_reader) = PayloadReader::with_header(reader)?;

    let (mut crypto, profile, log_manager) = setup_dec_context(master_key, &header, DigestAlg::Blake3)?;
    let config_pipe = PipelineConfig::new(profile, maybe_buf.clone());

    let mut snapshot = run_decrypt_pipeline(
        &mut payload_reader,
        writer,
        &mut crypto,
        &config_pipe,
        log_manager,
    )?;

    // --- Telemetry buffer extraction for tests --- 
    if let Some(ref arc_buf) = maybe_buf { 
        let buf = arc_buf.lock().unwrap(); 
        snapshot.attach_output(buf.clone()); 
        // clone Vec<u8> into snapshot.output 
    }

    Ok(snapshot)
}


pub fn validate_encrypt_params(
    master_key: &[u8],
    params: &EncryptParams,
    workers: Option<usize>,
    queue_cap: Option<usize>,

) -> Result<(), StreamError> {
    // --- Master key length ---
    if !MASTER_KEY_LENGTHS.contains(&master_key.len()) {
        return Err(StreamError::Crypto(CryptoError::InvalidKeyLen {
            expected: 32,
            actual: master_key.len(),
        }));
    }

    // --- Resolve defaults ---
    let w  = workers.unwrap_or(DEFAULT_WORKERS);
    let q  = queue_cap.unwrap_or(DEFAULT_QUEUE_CAP);

    if !WORKERS_COUNT.contains(&w) {
        return Err(StreamError::Validation(format!(
            "invalid workers count: {w}, must be one of {:?}",
            WORKERS_COUNT
        )));
    }
    if !QUEUE_CAPS.contains(&q) {
        return Err(StreamError::Validation(format!(
            "invalid queue capacity: {q}, must be one of {:?}",
            QUEUE_CAPS
        )));
    }

    params.validate()?;
    Ok(())
}

pub fn validate_decrypt_params(
    master_key: &[u8],
    params: &DecryptParams,
    workers: Option<usize>,
    queue_cap: Option<usize>,
) -> Result<(), StreamError> {
    if !MASTER_KEY_LENGTHS.contains(&master_key.len()) {
        return Err(StreamError::Crypto(CryptoError::InvalidKeyLen {
            expected: 32,
            actual: master_key.len(),
        }));
    }

    // --- Resolve defaults ---
    let w  = workers.unwrap_or(DEFAULT_WORKERS);
    let q  = queue_cap.unwrap_or(DEFAULT_QUEUE_CAP);

    if !WORKERS_COUNT.contains(&w) {
        return Err(StreamError::Validation(format!(
            "invalid workers count: {w}, must be one of {:?}",
            WORKERS_COUNT
        )));
    }
    if !QUEUE_CAPS.contains(&q) {
        return Err(StreamError::Validation(format!(
            "invalid queue capacity: {q}, must be one of {:?}",
            QUEUE_CAPS
        )));
    }

    params.validate()?;
    Ok(())
}

pub fn validate_dictionary(dict: Option<&[u8]>) -> Result<(), StreamError> {
    match dict {
        None => Ok(()), // no dictionary supplied
        Some(d) if d.is_empty() => Ok(()), // empty Vec also means "no dictionary"
        Some(d) => {
            // Non-empty dictionary must pass validation
            if !is_valid_dictionary(d) {
                Err(StreamError::Validation("invalid dictionary payload".into()))
            } else {
                Ok(())
            }
        }
    }
}

pub fn is_valid_dictionary(dict: &[u8]) -> bool {
    // Replace with the actual validation logic:
    // e.g. check header bytes, length constraints, codec id, etc.
    if dict.len() < MIN_DICT_LEN || dict.len() > MAX_DICT_LEN {
        return false;
    }

    // First 4 bytes to be a magic number
    let magic = MAGIC_DICT;
    dict.len() >= magic.len() && &dict[..magic.len()] == magic
}
