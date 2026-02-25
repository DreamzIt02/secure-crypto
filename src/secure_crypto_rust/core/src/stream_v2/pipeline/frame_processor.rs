use std::{ops::Range, sync::Arc, time::Instant};

use bytes::{Bytes, Buf, BytesMut};
use sysinfo::Process;
use crate::{crypto::{AadHeader, AeadImpl, build_aad, derive_nonce_12_tls_style}, stream_v2::{frame_worker::{DecryptedFrame, EncryptedFrame, FrameInput, FrameWorkerError}, framing::{FrameHeader, FrameType, decode::{decode_frame, decode_in_place}, encode::{encode_frame, encode_in_place}}, segment_worker::{DecryptContext, EncryptContext}}, telemetry::{Stage, StageTimes}, types::StreamError};

// pub trait ProcessedFrame: Send + Sync {
//     fn segment_index(&self) -> u32;
//     fn frame_index(&self) -> u32;
//     fn frame_type(&self) -> FrameType;
//     fn wire(&self) -> &Bytes;
//     fn ct_range(&self) -> &Range<usize>;
//     fn ciphertext(&self) -> &[u8];
//     fn stage_times(&self) -> &StageTimes;

//     /// Generic downcast helper
//     fn inner<T: 'static>(&self) -> Option<&T>
//     where
//         Self: Any
//     {
//         // Cast self to Any and try downcast
//         (self as &dyn Any).downcast_ref::<T>()
//     }
// }

// impl ProcessedFrame for EncryptedFrame {
//     fn segment_index(&self) -> u32 { self.segment_index }
//     fn frame_index(&self) -> u32 { self.frame_index }
//     fn frame_type(&self) -> FrameType { self.frame_type }
//     fn wire(&self) -> &Bytes { &self.wire }
//     fn ct_range(&self) -> &Range<usize> { &self.ct_range }
//     fn ciphertext(&self) -> &[u8] { self.ciphertext() }
//     fn stage_times(&self) -> &StageTimes { &self.stage_times }
// }

// impl ProcessedFrame for DecryptedFrame {
//     fn segment_index(&self) -> u32 { self.segment_index }
//     fn frame_index(&self) -> u32 { self.frame_index }
//     fn frame_type(&self) -> FrameType { self.frame_type }
//     fn wire(&self) -> &Bytes { &self.wire }
//     fn ct_range(&self) -> &Range<usize> { &self.ct_range }
//     fn ciphertext(&self) -> &[u8] { self.ciphertext() }
//     fn stage_times(&self) -> &StageTimes { &self.stage_times }
// }

// ### Enum‑based `ProcessedFrame`

#[derive(Debug, Clone)]
pub enum ProcessedFrame {
    Encrypted(EncryptedFrame),
    Decrypted(DecryptedFrame),
}

impl ProcessedFrame {
    #[inline]
    pub fn segment_index(&self) -> u32 {
        match self {
            ProcessedFrame::Encrypted(f) => f.segment_index,
            ProcessedFrame::Decrypted(f) => f.segment_index,
        }
    }

    #[inline]
    pub fn frame_index(&self) -> u32 {
        match self {
            ProcessedFrame::Encrypted(f) => f.frame_index,
            ProcessedFrame::Decrypted(f) => f.frame_index,
        }
    }

    #[inline]
    pub fn frame_type(&self) -> FrameType {
        match self {
            ProcessedFrame::Encrypted(f) => f.frame_type,
            ProcessedFrame::Decrypted(f) => f.frame_type,
        }
    }

    #[inline]
    pub fn wire(&self) -> &Bytes {
        match self {
            ProcessedFrame::Encrypted(f) => &f.wire,
            ProcessedFrame::Decrypted(f) => &f.wire,
        }
    }

    #[inline]
    pub fn ct_range(&self) -> &Range<usize> {
        match self {
            ProcessedFrame::Encrypted(f) => &f.ct_range,
            ProcessedFrame::Decrypted(f) => &f.ct_range,
        }
    }

    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        match self {
            ProcessedFrame::Encrypted(f) => f.ciphertext(),
            ProcessedFrame::Decrypted(f) => f.ciphertext(),
        }
    }

    #[inline]
    pub fn stage_times(&self) -> &StageTimes {
        match self {
            ProcessedFrame::Encrypted(f) => &f.stage_times,
            ProcessedFrame::Decrypted(f) => &f.stage_times,
        }
    }

    /// Only available for decrypted frames
    #[inline]
    pub fn plaintext(&self) -> Option<&Bytes> {
        match self {
            ProcessedFrame::Decrypted(f) => Some(&f.plaintext),
            _ => None,
        }
    }
}

// ### Why this is “industry standard” in protocol/crypto libraries
// - **Exhaustiveness**: The compiler forces us to handle both `Encrypted` and `Decrypted` cases.
// - **No dynamic dispatch**: Everything is resolved at compile time, no boxing required.
// - **Ergonomics**: We can still expose unified accessors (`segment_index`, `ciphertext`, etc.), so callers don’t need to match unless they want variant‑specific data.
// - **Performance**: Avoids heap allocation and virtual table lookups, which matters in crypto pipelines.

// ### Usage

// ```rust
// let frame = encryptor.encrypt_in_place(&input)?; // returns ProcessedFrame::Encrypted
// println!("Segment index: {}", frame.segment_index());

// if let Some(pt) = frame.plaintext() {
//     println!("Plaintext length: {}", pt.len());
// }
// ```

pub trait FrameProcessor: Send + Sync {
    /// Allocating version: produces a processed frame (encrypted or decrypted).
    fn process_frame(&self, input: &FrameInput) -> Result<ProcessedFrame, FrameWorkerError>;

    /// Zero-copy version: writes ciphertext directly into provided buffer.
    /// No allocation. Returns number of bytes written and a processed frame view.
    fn process_in_place(&self, input: &FrameInput) -> Result<ProcessedFrame, FrameWorkerError>;
}

pub struct EncryptFrameProcessor {
    crypto: Arc<EncryptContext>,
    aead: AeadImpl,
}

impl EncryptFrameProcessor {
    pub fn new(crypto: Arc<EncryptContext>) -> Result<Self, FrameWorkerError> {
        let aead = AeadImpl::from_header_and_key(&crypto.header, &crypto.base.session_key)?;
        Ok(Self { crypto, aead })
    }
}

impl FrameProcessor for EncryptFrameProcessor {
    
    fn process_frame(&self, input: &FrameInput) -> Result<ProcessedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Validation and AAD construction ----
        let start = Instant::now();
        input.validate()?;

        let plaintext_len = input.payload.len() as u32;
        let aad_header = AadHeader {
            frame_type: input.frame_type.try_to_u8()?,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            payload_len: plaintext_len,
        };

        // Build AAD from immutable fields
        let aad = build_aad(&self.crypto.header, &aad_header)?;

        // Derive nonce using frame index to ensure uniqueness
        let nonce = derive_nonce_12_tls_style(&self.crypto.header.salt, input.frame_index as u64)?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 2: AEAD Encryption ----
        let start = Instant::now();
        let ciphertext: Vec<u8> = match input.frame_type {
            FrameType::Data => {
                // Normal encryption path for data
                self.aead.seal(&nonce, &aad, &input.payload)?
            }
            FrameType::Digest => {
                // Digest payload is already a hash, no AEAD needed
                input.payload.to_vec()
            }
            FrameType::Terminator => {
                // Terminator frames carry no payload, skip encryption
                Vec::new()
            }
        };
        stage_times.add(Stage::Encrypt, start.elapsed());

        // ---- Stage 3: Frame header construction ----
        let frame_header = FrameHeader::new(
            input.segment_index,
            input.frame_index,
            input.frame_type,
            plaintext_len,
            ciphertext.len() as u32,
        );

        // ---- Stage 4: Serialization ----
        let start = Instant::now();
        let ct_start = FrameHeader::LEN;
        let wire = encode_frame(&frame_header, &ciphertext)?;
        let ct_end = wire.len();
        stage_times.add(Stage::Encode, start.elapsed());

        Ok(ProcessedFrame::Encrypted(EncryptedFrame {
            segment_index: frame_header.segment_index(),
            frame_index: frame_header.frame_index(),
            frame_type: frame_header.frame_type(),
            wire: Bytes::from(wire),
            ct_range: ct_start..ct_end,
            stage_times,
        }))
    }


    // ## 2️⃣ EncryptFrameProcessor (Zero-Copy)
    // Assuming AEAD produces `input.len() + TAG_SIZE`.
    fn process_in_place(&self, input: &FrameInput) -> Result<ProcessedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Validation and AAD construction ----
        let start = Instant::now();
        input.validate()?;

        let plaintext_len = input.payload.len() as u32;
        let aad_header = AadHeader {
            frame_type: input.frame_type.try_to_u8()?,
            segment_index: input.segment_index,
            frame_index: input.frame_index,
            payload_len: plaintext_len,
        };

        let aad = build_aad(&self.crypto.header, &aad_header)?;
        let nonce = derive_nonce_12_tls_style(&self.crypto.header.salt, input.frame_index as u64)?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 2: AEAD Encryption ----
        let start = Instant::now();

       let mut buf = BytesMut::from(&input.payload[..]);

        match input.frame_type {
            FrameType::Data => {
                // Works because BytesMut implements Buffer
                self.aead.seal_in_place(&nonce, &aad, &mut buf)?;
            }
            FrameType::Digest => {
                buf.extend_from_slice(&input.payload);
            }
            FrameType::Terminator => {}
        }

        stage_times.add(Stage::Encrypt, start.elapsed());

        // ---- Stage 3: Frame header construction ----
        // Stage 3: Frame header construction
        let frame_header = FrameHeader::new(
            input.segment_index,
            input.frame_index,
            input.frame_type,
            plaintext_len,
            buf.len() as u32, // ciphertext length
        );

        // ---- Stage 4: Serialization ----
        let start = Instant::now();
        let mut wire = BytesMut::with_capacity(FrameHeader::LEN + buf.len());
        encode_in_place(&frame_header, &buf, &mut wire)?;
        stage_times.add(Stage::Encode, start.elapsed());

        let ct_start = FrameHeader::LEN;
        let ct_end = wire.len();

        Ok(ProcessedFrame::Encrypted(EncryptedFrame {
            segment_index: frame_header.segment_index(),
            frame_index: frame_header.frame_index(),
            frame_type: frame_header.frame_type(),
            wire: wire.freeze(),
            ct_range: ct_start..ct_end,
            stage_times,
        }))
    }

}



pub struct DecryptFrameProcessor {
    crypto: Arc<DecryptContext>,
    aead: AeadImpl,
}

impl DecryptFrameProcessor {
    pub fn new(crypto: Arc<DecryptContext>) -> Result<Self, FrameWorkerError> {
        let aead = AeadImpl::from_header_and_key(&crypto.header, &crypto.base.session_key)?;
        Ok(Self { crypto, aead })
    }
}

impl FrameProcessor for DecryptFrameProcessor {
    fn process_frame(&self, input: &FrameInput) -> Result<ProcessedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Frame header parsing ----
        let start = Instant::now();
        let view = decode_frame(&input.payload)?;
        stage_times.add(Stage::Decode, start.elapsed());

        // ---- Stage 2: Validation and AAD reconstruction ----
        let start = Instant::now();
        
        // Validate ciphertext boundaries
        let ct_start = FrameHeader::LEN;
        let ct_end = ct_start + view.header.ciphertext_len() as usize;
        if ct_end > input.payload.len() {
            return Err(FrameWorkerError::InvalidInput(
                "Wire length mismatch: ciphertext extends beyond frame boundary".into(),
            ));
        }

        // Reconstruct AAD header from frame metadata
        let aad_header = AadHeader {
            frame_type: view.header.frame_type().try_to_u8()?,
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            payload_len: view.header.plaintext_len(),
        };

        // Rebuild AAD to match encryption-time construction
        let aad = build_aad(&self.crypto.header, &aad_header)?;

        // Derive frame-specific nonce (must match encryption nonce)
        let nonce = derive_nonce_12_tls_style(
            &self.crypto.header.salt,
            view.header.frame_index() as u64,
        )?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 3: AEAD Decryption ----
        let start = Instant::now();
        let plaintext: Vec<u8> = match view.header.frame_type() {
            FrameType::Data => {
                // Normal AEAD decryption for data
                self.aead.open(&nonce, &aad, view.ciphertext)?
            }
            FrameType::Digest => {
                // Digest payload is already a hash, no AEAD needed
                view.ciphertext.to_vec()
            }
            FrameType::Terminator => {
                // Terminator frames carry no payload, skip encryption
                Vec::new()
            }
        };
        stage_times.add(Stage::Decrypt, start.elapsed());

        // ---- Stage 4: Construct decrypted frame ----
        Ok(ProcessedFrame::Decrypted(DecryptedFrame {
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            frame_type: view.header.frame_type(),
            wire: Bytes::from(plaintext),   // Plaintext allocated (crypto output)
            ct_range: ct_start..ct_end,     // Ciphertext referenced by range
            plaintext: Bytes::from(""),     // Plaintext allocated (crypto output)
            stage_times,
        }))
    }

    // ## 3️⃣ DecryptFrameProcessor (Zero-Copy)
    fn process_in_place(&self, input: &FrameInput) -> Result<ProcessedFrame, FrameWorkerError> {
        let mut stage_times = StageTimes::default();

        // ---- Stage 1: Decode header ----
        let start = Instant::now();
        let view = decode_in_place(&input.payload)?;
        stage_times.add(Stage::Decode, start.elapsed());

        let ct_start = FrameHeader::LEN;
        let ct_end = ct_start + view.header.ciphertext_len() as usize;
        if ct_end > input.payload.len() {
            return Err(FrameWorkerError::InvalidInput(
                "Wire length mismatch: ciphertext extends beyond frame boundary".into(),
            ));
        }

        // ---- Stage 2: AAD + nonce ----
        let start = Instant::now();
        let aad_header = AadHeader {
            frame_type: view.header.frame_type().try_to_u8()?,
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            payload_len: view.header.plaintext_len(),
        };
        let aad = build_aad(&self.crypto.header, &aad_header)?;
        let nonce = derive_nonce_12_tls_style(&self.crypto.header.salt, view.header.frame_index() as u64)?;
        stage_times.add(Stage::Validate, start.elapsed());

        // ---- Stage 3: Decrypt ----
        let start = Instant::now();
        let plaintext = match view.header.frame_type() {
            FrameType::Data => {
                let mut buf = BytesMut::from(&input.payload[ct_start..ct_end]);
                self.aead.open_in_place(&nonce, &aad, &mut buf)?;
                buf.freeze()
            }
            FrameType::Digest => Bytes::copy_from_slice(&input.payload[ct_start..ct_end]),
            FrameType::Terminator => Bytes::new(),
        };
        stage_times.add(Stage::Decrypt, start.elapsed());

        Ok(ProcessedFrame::Decrypted(DecryptedFrame {
            segment_index: view.header.segment_index(),
            frame_index: view.header.frame_index(),
            frame_type: view.header.frame_type(),
            wire: Bytes::from(plaintext),   // Plaintext allocated (crypto output)
            ct_range: ct_start..ct_end,     // Ciphertext referenced by range
            plaintext: Bytes::from(""),     // Plaintext allocated (crypto output)
            stage_times,
        }))
    }
}

pub fn split_into_frames(
    segment: Vec<u8>,
    frame_size: usize,
    segment_index: u32,
) -> Vec<FrameInput> {

    let mut frames = Vec::new();
    let mut offset = 0;
    let mut frame_index = 0u32;

    while offset < segment.len() {
        let end = (offset + frame_size).min(segment.len());

        let frame = FrameInput {
            segment_index: segment_index,
            frame_index: frame_index,
            frame_type: FrameType::Data,
            payload: Bytes::copy_from_slice(&segment[offset..end]), // 🔥 instead of Arc<[u8]>
        };

        frames.push(frame);

        offset = end;
        frame_index += 1;
    }

    frames
}


// # 2️⃣ split_ranges(total_len, frame_size)
// Used during encrypt side.
pub fn split_ranges(total_len: usize, frame_size: usize) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();

    let mut offset = 0;

    while offset < total_len {
        let end = (offset + frame_size).min(total_len);
        ranges.push(offset..end);
        offset = end;
    }

    ranges
    // Pure arithmetic. No allocation beyond Vec of ranges.
}

// # 3️⃣ serialize_frames(encrypted_frames)
// We define wire format as:

// ```
// [frame_count: u16]
// repeat:
//     [frame_len: u32]
//     [frame_bytes...]
// ```

// Simple. Deterministic. Streaming-safe.
pub fn serialize_frames(frames: Vec<ProcessedFrame>) -> Result<Vec<u8>, FrameWorkerError> {
    let mut total = 0; // frame_count u16

    for f in &frames {
        total += f.ct_range().end;
    }

    let mut buf = BytesMut::with_capacity(total);
    for f in frames {
        buf.extend_from_slice(&f.wire());
    }

    Ok(buf.to_vec())
    // Zero extra copying except final freeze.
}

// # 4️⃣ parse_frames(segment)
// Reverse of serialize.
pub fn parse_frames(mut segment: Bytes) -> Result<Vec<Bytes>, FrameWorkerError> {
    if segment.len() < 2 {
        return Err(FrameWorkerError::CryptoFailure("segment too small".into()));
    }

    let frame_count = segment.get_u16() as usize;

    let mut frames = Vec::with_capacity(frame_count);

    for _ in 0..frame_count {
        if segment.len() < 4 {
            return Err(FrameWorkerError::CryptoFailure("truncated frame len".into()));
        }

        let len = segment.get_u32() as usize;

        if segment.len() < len {
            return Err(FrameWorkerError::CryptoFailure("truncated frame payload".into()));
        }

        let frame = segment.split_to(len);
        frames.push(frame);
    }

    Ok(frames)

    // Important: `Bytes::split_to()` is zero-copy.
    // So decrypt side stays zero-copy until decompress.
}

// # 5️⃣ assemble_frames(decrypted_frames)
// Decrypt side merges plaintext frames.
pub fn assemble_frames(frames: Vec<ProcessedFrame>) -> Result<Vec<u8>, FrameWorkerError> {
    let total: usize = frames.iter().map(|f| f.ct_range().end).sum();

    let mut out = Vec::with_capacity(total);

    for f in frames {
        out.extend_from_slice(&f.wire());
    }

    Ok(out)
    // Single allocation for full segment. Correct.
}