use std::sync::Arc;

use bytes::{Bytes};
use crossbeam::channel::bounded;

use crate::{compression::{Compressor, Decompressor}, stream_v2::{frame_worker::{DecryptedFrame, EncryptedFrame, FrameInput}, framing::{FrameError, FrameHeader, FrameType}, pipeline::frame_processor::{DecryptFrameProcessor, EncryptFrameProcessor, FrameProcessor, ProcessedFrame, assemble_frames, parse_frames, serialize_frames, split_into_frames, split_ranges}, segment_worker::{DecryptContext, DecryptedSegment, EncryptContext, EncryptedSegment, SegmentWorkerError}, segmenting::SegmentHeader}, telemetry::{StageTimes, TelemetryCounters}, types::StreamError};

// # 1️⃣ ProcessedSegment
// This is what flows through the outer streaming runtime.
pub struct ProcessedSegment {
    pub segment_index: u32,
    pub bytes: Bytes,
    pub fatal: Option<StreamError>,
}

impl ProcessedSegment {
    pub fn new(index: u32, bytes: Bytes) -> Self {
        Self {
            segment_index: index,
            bytes,
            fatal: None,
        }
    }

    pub fn fatal(err: StreamError) -> Self {
        Self {
            segment_index: 0,
            bytes: Bytes::new(),
            fatal: Some(err),
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.fatal.is_some()
    }

    pub fn unwrap_err(self) -> StreamError {
        self.fatal.unwrap()
    }

}

// #[derive(Debug, Clone)]
// pub enum ProcessedSegment {
//     Encrypted(EncryptedSegment),
//     Decrypted(DecryptedSegment),
// }

// impl ProcessedSegment {
//     #[inline]
//     pub fn header(&self) -> &SegmentHeader {
//         match self {
//             ProcessedSegment::Encrypted(s) => &s.header,
//             ProcessedSegment::Decrypted(s) => &s.header,
//         }
//     }

//     #[inline]
//     pub fn counters(&self) -> &TelemetryCounters {
//         match self {
//             ProcessedSegment::Encrypted(s) => &s.counters,
//             ProcessedSegment::Decrypted(s) => &s.counters,
//         }
//     }

//     #[inline]
//     pub fn stage_times(&self) -> &StageTimes {
//         match self {
//             ProcessedSegment::Encrypted(s) => &s.stage_times,
//             ProcessedSegment::Decrypted(s) => &s.stage_times,
//         }
//     }

//     /// Unified accessor: ciphertext for encrypted, plaintext for decrypted.
//     #[inline]
//     pub fn wire(&self) -> &Bytes {
//         match self {
//             ProcessedSegment::Encrypted(s) => &s.wire,
//             ProcessedSegment::Decrypted(s) => &s.bytes,
//         }
//     }

//     /// Variant-specific helpers if we want to distinguish
//     pub fn as_encrypted(&self) -> Option<&EncryptedSegment> {
//         if let ProcessedSegment::Encrypted(s) = self {
//             Some(s)
//         } else {
//             None
//         }
//     }

//     pub fn as_decrypted(&self) -> Option<&DecryptedSegment> {
//         if let ProcessedSegment::Decrypted(s) = self {
//             Some(s)
//         } else {
//             None
//         }
//     }
// }

// pub trait ProcessedSegment {
//     fn header(&self) -> &SegmentHeader;
//     fn counters(&self) -> &TelemetryCounters;
//     fn stage_times(&self) -> &StageTimes;

//     /// Access ciphertext/plaintext (wire) encrypted/decrypted.
//     fn wire(&self) -> &Bytes;
// }

// impl ProcessedSegment for EncryptedSegment {
//     fn header(&self) -> &SegmentHeader { &self.header }
//     fn counters(&self) -> &TelemetryCounters { &self.counters }
//     fn stage_times(&self) -> &StageTimes { &self.stage_times }

//     fn wire(&self) -> &Bytes { &self.wire }
// }

// impl ProcessedSegment for DecryptedSegment {
//     fn header(&self) -> &SegmentHeader { &self.header }
//     fn counters(&self) -> &TelemetryCounters { &self.counters }
//     fn stage_times(&self) -> &StageTimes { &self.stage_times }

//     fn wire(&self) -> &Bytes { &self.bytes }
// }

pub trait SegmentProcessor: Send + Sync + 'static {
    type Input;
    type Output;

    fn process(
        &self,
        index: u32,
        input: Self::Input,
    ) -> Result<Self::Output, SegmentWorkerError>;

    // ## 1️⃣ Frame Processor Trait (Zero-Copy)
    fn process_in_place(
        &self,
        index: u32,
        input: Bytes,
    ) -> Result<Self::Output, SegmentWorkerError>;

    // It writes ciphertext directly into provided buffer.
    // No allocation.
    // Returns number of bytes written.
}

pub struct EncryptProcessor {
    crypto: Arc<EncryptContext>,
    compressor: Compressor,
    crypto_worker: Arc<EncryptFrameProcessor>,
}

impl EncryptProcessor {
    pub fn new(crypto: Arc<EncryptContext>) -> Result<Self, SegmentWorkerError> {
        let crypto_worker = EncryptFrameProcessor::new(crypto.clone())?;
        Ok(Self {
            crypto,
            compressor: Compressor::new(),
            crypto_worker: Arc::new(crypto_worker),
        })
    }
}

impl SegmentProcessor for EncryptProcessor {
    type Input = Bytes;
    type Output = ProcessedSegment;

    fn process(
        &self,
        index: u32,
        segment: Bytes,
    ) -> Result<ProcessedSegment, SegmentWorkerError> {

        // 1️⃣ Compress
        let compressed = self.compressor.compress(&segment)?;
        
        // 2️⃣ Split into frames
        let frames = split_into_frames(
            compressed,
            self.crypto.base.frame_size,
            index,
        );

        // 3️⃣ Frame crypto
        let mut encrypted_frames = vec![ProcessedFrame::Encrypted(EncryptedFrame::default()); frames.len()];

        for frame in frames {
            let encrypted = 
                self.crypto_worker.process_frame(&frame)
                    .map_err(|e| SegmentWorkerError::FrameWorkerError(e))?;
            let idx = encrypted.frame_index() as usize;
            encrypted_frames[idx] = encrypted
        }

        // 4️⃣ Reassemble (serialize)
        let serialized = serialize_frames(encrypted_frames)?;

        Ok(ProcessedSegment::new(index, Bytes::from(serialized)))
    }
    
    // # 6️⃣ FIXED Zero-Copy + Parallel Encrypt (Safe Version)

    // Instead of writing directly into shared buffer,
    // we compute outputs per frame and collect.

    // Still minimal allocation: one Vec per frame (cipher output),
    // but no extra copying beyond final assemble.

    // This is the safe and correct approach.

    fn process_in_place(
        &self,
        index: u32,
        segment: Bytes,
    ) -> Result<ProcessedSegment, SegmentWorkerError> {

        // 1️⃣ Compress
        let compressed = self.compressor.compress(&segment)?;

        let frame_size = self.crypto.base.frame_size;
        let total_len = compressed.len();

        // 2️⃣ Split into frames
        let ranges = split_ranges(total_len, frame_size);

        let (tx, rx) = crossbeam::channel::bounded(ranges.len());

        for (frame_index, range) in ranges.iter().enumerate() {

            let input = compressed[range.clone()].to_vec();
            let processor = self.crypto_worker.clone();
            let tx = tx.clone();

            let frame = FrameInput {
                segment_index: index,
                frame_index: frame_index as u32,
                frame_type: FrameType::Data,
                payload: input,
            };

            self.frame_pool.submit(move || {
                let out = processor.process_in_place(&frame)?;
                tx.send((frame_index, out)).map_err(|e| SegmentWorkerError::StateError(e.to_string()))?;
                Ok::<_, SegmentWorkerError>(())
            });
        }

        drop(tx);

        // 3️⃣ Frame crypto
        let mut encrypted_frames = vec![ProcessedFrame::Encrypted(EncryptedFrame::default()); ranges.len()];

        for _ in 0..ranges.len() {
            let (i, out) = rx.recv().map_err(|e| SegmentWorkerError::StateError(e.to_string()))?;
            encrypted_frames[i] = out;
        }

        // 4️⃣ Reassemble (serialize)
        let serialized = serialize_frames(encrypted_frames)?;

        Ok(ProcessedSegment::new(index, Bytes::from(serialized)))
    }

    // Safe.
    // Bounded.
    // Parallel.
    // Deterministic.

}

pub struct DecryptProcessor {
    crypto: Arc<DecryptContext>,
    decompressor: Decompressor,
    crypto_worker: Arc<DecryptFrameProcessor>,
    header: Arc<SegmentHeader>,
}

impl DecryptProcessor {
    
    pub fn new(crypto: Arc<DecryptContext>, header: Arc<SegmentHeader>) -> Result<Self, SegmentWorkerError> {
        let crypto_worker = DecryptFrameProcessor::new(crypto.clone())?;
        Ok(Self {
            crypto,
            decompressor: Decompressor::new(),
            crypto_worker: Arc::new(crypto_worker),
            header: header,
        })
    }
}

impl SegmentProcessor for DecryptProcessor {
    type Input = Bytes;
    type Output = ProcessedSegment;

    fn process(
        &self,
        index: u32,
        segment: Bytes,
    ) -> Result<ProcessedSegment, SegmentWorkerError> {

        // 1️⃣ Parse frames
        let mut offset = 0;
        let mut frame_count: usize = 0;
        let mut decrypted_frames = vec![ProcessedFrame::Decrypted(DecryptedFrame::default()); self.header.frame_count() as usize];

        while offset < segment.len() {
            // Parse frame header to determine frame length
            let header = FrameHeader::from_bytes(&segment[offset..])?;
            let frame_len = FrameHeader::LEN + header.ciphertext_len() as usize;
            let end = offset + frame_len;

            // Validate frame doesn't extend beyond wire boundary
            if end > segment.len() {
                return Err(FrameError::Truncated.into());
            }
            
            // 2️⃣ Frame decrypt
            let frame = FrameInput { 
                segment_index: header.segment_index(), 
                frame_index: header.frame_index(), 
                frame_type:header.frame_type(), 
                payload: segment.slice(offset..end),
            };

            // Dispatch frame slice for decryption (zero-copy using Bytes::slice)
            let decrypted = self.crypto_worker.process_frame(&frame)?;
            let idx = decrypted.frame_index() as usize;
            decrypted_frames[idx] = decrypted;

            offset = end;
            frame_count += 1;
        }

        // 3️⃣ Reassemble
        let assembled = assemble_frames(decrypted_frames)?;

        // 4️⃣ Decompress
        let plaintext = self.decompressor.decompress(&assembled)?;

        Ok(ProcessedSegment::new(index, Bytes::from(plaintext)))
    }

    // # 7️⃣ FULL DecryptProcessor::process_in_place
    fn process_in_place(
        &self,
        index: u32,
        segment: Bytes,
    ) -> Result<ProcessedSegment, SegmentWorkerError> {

        // 1️⃣ Parse frames
        let mut offset = 0;
        let mut frame_count: usize = 0;

        let (tx, rx) = bounded(self.header.frame_count() as usize);

        while offset < segment.len() {
            // Parse frame header to determine frame length
            let header = FrameHeader::from_bytes(&segment[offset..])?;
            let frame_len = FrameHeader::LEN + header.ciphertext_len() as usize;
            let end = offset + frame_len;

            // Validate frame doesn't extend beyond wire boundary
            if end > segment.len() {
                return Err(FrameError::Truncated.into());
            }
            
            // 2️⃣ Frame decrypt
            let processor = self.crypto_worker.clone();
            let tx = tx.clone();

            let frame = FrameInput { 
                segment_index: header.segment_index(), 
                frame_index: header.frame_index(), 
                frame_type:header.frame_type(), 
                payload: segment.slice(offset..end),
            };

            // Dispatch frame slice for decryption (zero-copy using Bytes::slice)
            self.frame_pool.submit(move || {
                let out = processor.process_in_place(&frame).map_err(|e| SegmentWorkerError::FrameWorkerError(e))?;
                tx.send((header.frame_index() as usize, out)).map_err(|e| SegmentWorkerError::StateError(e.to_string()))?;
                Ok::<_, SegmentWorkerError>(())
            });

            offset = end;
            frame_count += 1;
        }

        drop(tx);

        // Collect in order
        let mut decrypted_frames = vec![ProcessedFrame::Decrypted(DecryptedFrame::default()); self.header.frame_count() as usize];

        for _ in 0..decrypted_frames.len() {
            let (i, out) = rx.recv().map_err(|e| SegmentWorkerError::StateError(e.to_string()))?;
            decrypted_frames[i] = out;
        }

        // 2️⃣ Reassemble
        let assembled = assemble_frames(decrypted_frames)?;

        // 3️⃣ Decompress
        let plaintext = self.decompressor.decompress(&assembled)?;

        Ok(ProcessedSegment::new(index, Bytes::from(plaintext)))
        // Perfect mirror of encrypt.
    }

}

