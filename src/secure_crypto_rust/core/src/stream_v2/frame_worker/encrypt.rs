// # 📂 `src/stream_v2/frame_worker/encrypt.rs`

use std::time::Instant;

use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender};
use crate::crypto::types::AadHeader;
use crate::crypto::{
    aad::{build_aad},
    aead::AeadImpl,
    nonce::derive_nonce_12_tls_style,
};
use crate::headers::types::{HeaderV1};
use crate::stream_v2::framing::{FrameHeader, FrameType};
use crate::stream_v2::framing::encode::encode_frame;
use crate::telemetry::{Stage, StageTimes};
use super::types::{FrameInput, FrameWorkerError, EncryptedFrame};

pub struct EncryptFrameWorker {
    header: HeaderV1,
    aead: AeadImpl,
}

impl EncryptFrameWorker {
    pub fn new(header: HeaderV1, session_key: &[u8]) -> Result<Self, FrameWorkerError> {
        let aead = AeadImpl::from_header_and_key(&header, session_key)?;
        Ok(Self { header, aead })
    }

    pub fn encrypt_frame(
        &self,
        input: &FrameInput,
    ) -> Result<EncryptedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();
        
        // Validation
        let start = Instant::now();
        input.validate()?;

        let plaintext_len = input.plaintext.len() as u32;
        let aad_header = AadHeader {
            frame_type: input.frame_type.try_to_u8()?,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            plaintext_len: plaintext_len,
        };

        // 1️⃣ Build AAD from immutable fields only
        let aad = build_aad(&self.header, &aad_header)?;

        // 2️⃣ Derive nonce (frame_index-based)
        let nonce = derive_nonce_12_tls_style(
            &self.header.salt,
            input.frame_index as u64,
        )?;
        stage_times.add(Stage::Validate, start.elapsed());

        // 3️⃣ Encrypt
        // Encryption
        let start = Instant::now();
        let ciphertext: Vec<u8> = match input.frame_type {
            FrameType::Data | FrameType::Digest => {
                // normal encryption path
                self.aead.seal(&nonce, &aad, &input.plaintext)?
                // build frame with ciphertext
            }
            FrameType::Terminator => {
                // Terminator must be empty, so skip AEAD seal
                Vec::new()
                // build frame with empty ciphertext
            }
        };
        stage_times.add(Stage::Encrypt, start.elapsed());

        let frame_header = FrameHeader {
            frame_type: input.frame_type,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            plaintext_len: plaintext_len,
            // 4️⃣ Fill mutable fields
            ciphertext_len: ciphertext.len() as u32,
        };

        // Encoding
        let start = Instant::now();
        let ct_start = FrameHeader::LEN;
        // 5️⃣ Serialize frame header + ciphertext
        let wire = encode_frame(&frame_header, &ciphertext)?;
        let ct_end = wire.len();
        stage_times.add(Stage::Encode, start.elapsed());

        Ok(EncryptedFrame {
            segment_index: frame_header.segment_index,
            frame_index: frame_header.frame_index,
            frame_type: frame_header.frame_type,
            wire: Bytes::from(wire),
            ct_range: ct_start..ct_end,
            stage_times: stage_times,
        })
        // ✔ ciphertext exists **only once**
        // ✔ ownership ends at encoding
        // ✔ single allocation
        // ✔ ciphertext embedded
        // ✔ range tracked
    }

    /// ## Step 1: Turn `EncryptFrameWorker` into a real worker
    /// ### 1. **Frame Workers**: Return Results (No Panics)
    /// Frame workers should **never panic** - they should always return `Result`:
    pub fn run(
        self,
        rx: Receiver<FrameInput>,
        tx: Sender<Result<EncryptedFrame, FrameWorkerError>>,
    ) {
        std::thread::spawn(move || {
            while let Ok(input) = rx.recv() {
                let result = self.encrypt_frame(&input);
            
                // Always send the result (Ok or Err)
                if tx.send(result).is_err() {
                    // Segment worker dropped rx, exit cleanly
                    return;
                }
                
                // When rx is closed, exit gracefully
                // Continue processing even if encryption failed
                // (the segment worker will handle the error)
            }
        });
    }

}
