// # 📂 `src/stream_v2/frame_worker/decrypt.rs`

use std::time::Instant;

use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender};

use crate::crypto::AadHeader;
use crate::crypto::{
    aad::build_aad,
    aead::AeadImpl,
    nonce::derive_nonce_12_tls_style,
};
use crate::headers::types::HeaderV1;
use crate::stream_v2::framing::{FrameHeader, FrameType};
use crate::stream_v2::framing::decode::{decode_frame};
use crate::telemetry::{Stage, StageTimes};
use super::types::{FrameWorkerError, DecryptedFrame};

pub struct DecryptFrameWorker {
    header: HeaderV1,
    aead: AeadImpl,
}

impl DecryptFrameWorker {
    pub fn new(header: HeaderV1, session_key: &[u8]) -> Result<Self, FrameWorkerError> {
        let aead = AeadImpl::from_header_and_key(&header, session_key)?;
        Ok(Self { header, aead })
    }
    pub fn decrypt_frame(
        &self,
        wire: Bytes,
    ) -> Result<DecryptedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();
        
        // 1️⃣ Parse header
        let start = Instant::now();
        let view = decode_frame(&wire)?;
        // Decoding
        stage_times.add(Stage::Decode, start.elapsed());

        // Validation
        let start = Instant::now();
        let ct_start = FrameHeader::LEN;
        let ct_end = ct_start + view.header.ciphertext_len as usize;

        if ct_end > wire.len() {
            return Err(FrameWorkerError::InvalidInput("Wire length mismatch detected".into()));
        }

        let aad_header = AadHeader {
            frame_type: view.header.frame_type.try_to_u8()?,
            segment_index: view.header.segment_index,
            frame_index: view.header.frame_index,
            plaintext_len: view.header.plaintext_len,
        };
        // rebuild AAD
        let aad = build_aad(&self.header, &aad_header)?;

        // derive nonce
        let nonce = derive_nonce_12_tls_style(
            &self.header.salt,
            view.header.frame_index as u64,
        )?;
        stage_times.add(Stage::Validate, start.elapsed());

        // 2️⃣ Decrypt: AEAD open
        // Decryption
        let start = Instant::now();
        let plaintext: Vec<u8> = match view.header.frame_type {
            FrameType::Data | FrameType::Digest => {
                // Normal AEAD decryption
                self.aead.open(&nonce, &aad, view.ciphertext)?
                // return FrameOutput with plaintext
            }
            FrameType::Terminator => {
                // Terminator must be empty, skip AEAD
                Vec::new()
                // return FrameOutput with empty plaintext
            }
        };
        stage_times.add(Stage::Decrypt, start.elapsed());

        Ok(DecryptedFrame {
            segment_index: view.header.segment_index,
            frame_index: view.header.frame_index,
            frame_type: view.header.frame_type,

            wire, // Bytes cloned, not copied
            ct_range: ct_start..ct_end,

            plaintext: Bytes::from(plaintext),
            stage_times,
        })
        // 💡 Notice:
        // * `wire` is **moved into the frame**
        // * ciphertext is **never copied**
        // * plaintext **must be owned** (crypto output)
    }

    /// ## Step 1: Turn `DecryptFrameWorker` into a real worker
    /// ### 1. **Frame Workers**: Return Results (No Panics)
    /// Frame workers should **never panic** - they should always return `Result`:
    pub fn run(
        self,
        rx: Receiver<Bytes>,
        tx: Sender<Result<DecryptedFrame, FrameWorkerError>>,
    ) {
        std::thread::spawn(move || {
            // We use a reference to the sender 'tx' inside the loop 
            // to ensure it's only dropped when this thread exits.
            while let Ok(input) = rx.recv() {
                let result = self.decrypt_frame(input);
                // Always send result (Ok or Err)
                if tx.send(result).is_err() {
                    // Segment worker dropped rx, exit cleanly
                    return; 
                }
            }
            // When rx is closed, exit gracefully
        });
    }

}
