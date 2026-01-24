
// ## 2️⃣ `core.rs` — stable public API

use std::sync::{Arc, Mutex};

use crate::types::{EncryptParams, DecryptParams, StreamError};
use crate::types::{validate_encrypt_params, validate_decrypt_params};

use crate::crypto::derive_session_key_32;
use crate::telemetry::{TelemetryCounters, TelemetrySnapshot, TelemetryTimer};

use crate::stream_v2::io::*;
use crate::stream_v2::pipeline::*;
use crate::stream_v2::segment_worker::SegmentCryptoContext;


/// 🔐 Encrypt stream (v2)
pub fn encrypt_stream_v2(
    input: InputSource,
    output: OutputSink,
    master_key: &[u8],
    params: EncryptParams,
    parallelism: ParallelismProfile,
) -> Result<TelemetrySnapshot, StreamError> {
    validate_encrypt_params(master_key, &params, None, None)?;

    let mut timer = TelemetryTimer::new();
    let telemetry = Arc::new(Mutex::new(TelemetryCounters::default()));

    let reader = open_input(input)?;
    let (writer, maybe_buf) = open_output(output)?;

    let header = params.header.clone();
    let session_key = derive_session_key_32(master_key, &header)?;

    let crypto = SegmentCryptoContext {
        header,
        session_key,
    };

    run_encrypt_pipeline(
        reader,
        writer,
        crypto,
        params.header.chunk_size as usize,
        parallelism,
        telemetry.clone(),
    )?;

    timer.finish();

    let snapshot = TelemetrySnapshot::from(
        &telemetry.lock().unwrap(),
        &timer,
    );

    if let Some(buf) = maybe_buf {
        snapshot.attach_output(buf);
    }

    Ok(snapshot)
}

/// 🔓 Decrypt stream (v2)
pub fn decrypt_stream_v2(
    input: InputSource,
    output: OutputSink,
    master_key: &[u8],
    params: DecryptParams,
    parallelism: ParallelismProfile,
) -> Result<TelemetrySnapshot, StreamError> {
    validate_decrypt_params(master_key, &params, None, None)?;

    let mut timer = TelemetryTimer::new();
    let telemetry = Arc::new(Mutex::new(TelemetryCounters::default()));

    let reader = open_input(input)?;
    let (writer, maybe_buf) = open_output(output)?;

    let header = params.header.clone();
    let session_key = derive_session_key_32(master_key, &header)?;

    let crypto = SegmentCryptoContext {
        header,
        session_key,
    };

    run_decrypt_pipeline(
        reader,
        writer,
        crypto,
        parallelism,
        telemetry.clone(),
    )?;

    timer.finish();

    let snapshot = TelemetrySnapshot::from(
        &telemetry.lock().unwrap(),
        &timer,
    );

    if let Some(buf) = maybe_buf {
        snapshot.attach_output(buf);
    }

    Ok(snapshot)
}
