
// ## 2️⃣ `core.rs` — stable public API

use std::sync::Arc;
use std::ops::Deref;

use crate::{
    constants::{DEFAULT_QUEUE_CAP, DEFAULT_WORKERS, MAGIC_DICT, MASTER_KEY_LENGTHS, MAX_DICT_LEN, MIN_DICT_LEN, QUEUE_CAPS, WORKERS_COUNT}, 
    crypto::{CryptoError, DigestAlg, derive_session_key_32}, 
    headers::HeaderV1, recovery::AsyncLogManager, 
    stream_v2::{io::{InputSource, OutputSink, PayloadReader, open_input, open_output}, 
    parallelism::{HybridParallelismProfile, ParallelismConfig}, pipeline::{PipelineConfig, run_decrypt_pipeline, run_encrypt_pipeline}, 
    segment_worker::{DecryptContext, EncryptContext}}, 
    telemetry::TelemetrySnapshot, 
    types::StreamError
};

#[derive(Clone)]
pub struct MasterKey(Vec<u8>);

impl Deref for MasterKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl MasterKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        // let len = bytes.len();

        // if MASTER_KEY_LENGTHS.contains(&len) {
        //     Ok(Self(bytes))
        // } else {
        //     Err(StreamError::Crypto(
        //         CryptoError::InvalidKeyLen {
        //             expected: &MASTER_KEY_LENGTHS,
        //             actual: len,
        //         },
        //     ))
        // }
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Validate that the provided bytes match one of the allowed key lengths.
    pub fn validate(bytes: &[u8]) -> Result<(), StreamError> {
        let len = bytes.len();

        if MASTER_KEY_LENGTHS.contains(&len) {
            Ok(())
        } else {
            Err(StreamError::Crypto(
                CryptoError::InvalidKeyLen {
                    expected: &MASTER_KEY_LENGTHS,
                    actual: len,
                },
            ))
        }
    }
}


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

    /// 
    /// Supported digest algorithms (extensible).
    pub alg: Option<DigestAlg>,

    /// 
    /// Parallelism configuration.
    pub parallelism: Option<ParallelismConfig>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            with_buf: Some(false),      // default: no buffer
            collect_metrics: Some(false), // default: no metrics
            alg: Some(DigestAlg::Blake3), // default: Blake3
            parallelism: Some(ParallelismConfig::default()),
        }
    }
}

impl ApiConfig {
    pub fn new(with_buf: Option<bool>, collect_metrics: Option<bool>, alg: Option<DigestAlg>, parallelism: Option<ParallelismConfig>) -> Self {
        Self {
            with_buf: with_buf.or(Some(false)),
            collect_metrics: collect_metrics.or(Some(false)),
            alg: alg.or(Some(DigestAlg::Blake3)),
            parallelism: Some(parallelism.unwrap_or_default()),
        }
    }
    /// Merge user-provided values with defaults 
    pub fn with_defaults(self) -> Self { 
        let defaults = ApiConfig::default(); 
        
        Self { 
            with_buf: self.with_buf.or(defaults.with_buf), 
            collect_metrics: self.collect_metrics.or(defaults.collect_metrics), 
            alg: self.alg.or(defaults.alg), 
            parallelism: self.parallelism.or(defaults.parallelism), 
        } 
    }
}

fn setup_enc_context(master_key: &MasterKey, header: &HeaderV1, config: ApiConfig)
    -> Result<(EncryptContext, HybridParallelismProfile, Arc<AsyncLogManager>), StreamError> 
{
    let session_key = derive_session_key_32(&master_key, header).map_err(StreamError::Crypto)?;

    let profile = HybridParallelismProfile::from_stream_header(header.clone(), config.parallelism)?;
    let context = EncryptContext::new(header.clone(), profile.clone(), &session_key, config.alg.unwrap())
        .map_err(StreamError::SegmentWorker)?;
    let log_manager = Arc::new(AsyncLogManager::new("stream_v2_enc.log", 100)?);

    Ok((context, profile, log_manager))
}

fn setup_dec_context(master_key: &MasterKey, header: &HeaderV1, config: ApiConfig)
    -> Result<(DecryptContext, HybridParallelismProfile, Arc<AsyncLogManager>), StreamError> 
{
    let session_key = derive_session_key_32(&master_key, header).map_err(StreamError::Crypto)?;

    let profile = HybridParallelismProfile::from_stream_header(header.clone(), config.parallelism)?;
    let context = DecryptContext::from_stream_header(header.clone(), profile.clone(), &session_key, config.alg.unwrap())
        .map_err(StreamError::SegmentWorker)?;
    let log_manager = Arc::new(AsyncLogManager::new("stream_v2_dec.log", 100)?);

    Ok((context, profile, log_manager))
}

/// 🔐 Encrypt stream (v2)
pub fn encrypt_stream_v2(
    input: InputSource,
    output: OutputSink,
    master_key: &MasterKey,
    params: EncryptParams,
    config: ApiConfig,
) -> Result<TelemetrySnapshot, StreamError> {
    validate_encrypt_params(&master_key, &params, None, None)?;

    // Normalize with defaults 
    let final_config = config.with_defaults();

    let reader = open_input(input)?;
    let (writer, maybe_buf) = open_output(output, final_config.with_buf)?;

    // ---- Read stream header ----
    let mut payload_reader = PayloadReader::new(reader);

    let (crypto, profile, log_manager) = setup_enc_context(&master_key, &params.header, final_config)?;
    let config_pipe = PipelineConfig::new(profile, maybe_buf.clone());

    // Wrap in Arc before passing into pipeline
    let crypto = Arc::new(crypto);

    // Call pipeline
    let mut snapshot = run_encrypt_pipeline(
        &mut payload_reader,
        writer,
        crypto,
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
    master_key: &MasterKey,
    params: DecryptParams,
    config: ApiConfig,
) -> Result<TelemetrySnapshot, StreamError> {
    //
    validate_decrypt_params(&master_key, &params, None, None)?;

    // Normalize with defaults 
    let final_config = config.with_defaults();

    let reader = open_input(input)?;
    let (writer, maybe_buf) = open_output(output, final_config.with_buf)?;

    // ---- Read stream header ----
    // Assert reader is positioned correctly
    let (header, mut payload_reader) = PayloadReader::with_header(reader)?;

    let (crypto, profile, log_manager) = setup_dec_context(&master_key, &header, final_config)?;
    let config_pipe = PipelineConfig::new(profile, maybe_buf.clone());
    
    // Wrap in Arc before passing into pipeline
    let crypto = Arc::new(crypto);

    // Call pipeline
    let mut snapshot = run_decrypt_pipeline(
        &mut payload_reader,
        writer,
        crypto,
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
    master_key: &MasterKey,
    params: &EncryptParams,
    workers: Option<usize>,
    queue_cap: Option<usize>,

) -> Result<(), StreamError> {
    // --- Master key length ---
    MasterKey::validate(&master_key)?;

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
    master_key: &MasterKey,
    params: &DecryptParams,
    workers: Option<usize>,
    queue_cap: Option<usize>,
) -> Result<(), StreamError> {
    if !MASTER_KEY_LENGTHS.contains(&master_key.len()) {
        return Err(StreamError::Crypto(CryptoError::InvalidKeyLen {
            expected: &MASTER_KEY_LENGTHS,
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
