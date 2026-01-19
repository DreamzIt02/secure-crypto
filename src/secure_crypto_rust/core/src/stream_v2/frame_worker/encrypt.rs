use crossbeam::channel::{Receiver, Sender};
use crate::crypto::types::AadHeader;
use crate::crypto::{
    aad::{build_aad},
    aead::AeadImpl,
    nonce::derive_nonce_12_tls_style,
};
use crate::headers::types::{HeaderV1};
use crate::stream_v2::framing::{FrameHeader, FrameType};
use crate::stream_v2::framing::types::{
    FrameRecord
};
use crate::stream_v2::framing::encode::encode_frame;
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
        input: FrameInput,
    ) -> Result<EncryptedFrame, FrameWorkerError> {
        // validate input
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

        // 3️⃣ Encrypt
        let ciphertext: Vec<u8>;
        match input.frame_type {
            FrameType::Data | FrameType::Digest => {
                // normal encryption path
                ciphertext = self.aead.seal(&nonce, &aad, &input.plaintext)?;
                // build frame with ciphertext
            }
            FrameType::Terminator => {
                // Terminator must be empty, so skip AEAD seal
                ciphertext = Vec::new();
                // build frame with empty ciphertext
            }
        }

        let frame_header = FrameHeader {
            frame_type: input.frame_type,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            plaintext_len: plaintext_len,
            compressed_len: 0,
            // 4️⃣ Fill mutable fields
            ciphertext_len: ciphertext.len() as u32,
        };

        let record = FrameRecord {
            header: frame_header,
            ciphertext: ciphertext,
        };

        // 5️⃣ Serialize frame header + ciphertext
        let wire = encode_frame(&record)?;

        Ok(EncryptedFrame {
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            frame_type: input.frame_type,
            ciphertext: record.ciphertext,
            wire,
        })
    }

    // ## Step 1: Turn `EncryptFrameWorker` into a real worker

    pub fn run(
        self,
        rx: Receiver<FrameInput>,
        tx: Sender<EncryptedFrame>,
    ) {
        std::thread::spawn(move || {
            while let Ok(input) = rx.recv() {
                match self.encrypt_frame(input) {
                    Ok(out) => {
                        if tx.send(out).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }

}
