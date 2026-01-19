use crossbeam::channel::{Receiver, Sender};
use std::sync::Arc;

use crate::crypto::AadHeader;
use crate::crypto::{
    aad::build_aad,
    aead::AeadImpl,
    nonce::derive_nonce_12_tls_style,
};
use crate::headers::types::HeaderV1;
use crate::stream_v2::framing::FrameType;
use crate::stream_v2::framing::decode::{decode_frame};
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
        wire: &[u8],
    ) -> Result<DecryptedFrame, FrameWorkerError> {
        // parse frame header + ciphertext
        let record = decode_frame(wire)?;
        
        let aad_header = AadHeader {
            frame_type: record.header.frame_type.try_to_u8()?,
            segment_index: record.header.segment_index,
            frame_index: record.header.frame_index,
            plaintext_len: record.header.plaintext_len,
        };
        // rebuild AAD
        let aad = build_aad(&self.header, &aad_header)?;

        // derive nonce
        let nonce = derive_nonce_12_tls_style(
            &self.header.salt,
            record.header.frame_index as u64,
        )?;

        // AEAD open
        let plaintext: Vec<u8>;
        match record.header.frame_type {
            FrameType::Data | FrameType::Digest => {
                // Normal AEAD decryption
                plaintext = self.aead.open(&nonce, &aad, &record.ciphertext)?;
                // return FrameOutput with plaintext
            }
            FrameType::Terminator => {
                // Terminator must be empty, skip AEAD
                plaintext = Vec::new();
                // return FrameOutput with empty plaintext
            }
        }

        Ok(DecryptedFrame {
            segment_index: record.header.segment_index,
            frame_index: record.header.frame_index,
            frame_type: record.header.frame_type,
            ciphertext: record.ciphertext,
            plaintext,
        })
    }

    // ## Step 1: Turn `DecryptFrameWorker` into a real worker

    pub fn run(
        self,
        rx: Receiver<Arc<[u8]>>,
        tx: Sender<DecryptedFrame>,
    ) {
        std::thread::spawn(move || {
            while let Ok(input) = rx.recv() {
                match self.decrypt_frame(&input) {
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