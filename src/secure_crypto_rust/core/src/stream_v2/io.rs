// # 📂 src/stream_v2/io.rs

// ## 📂 File: `src/stream_v2/io.rs`
// ## Normalized I/O + ordered encrypted writer (production-ready)

use std::io::{Read, Write};
use std::path::PathBuf;
use std::collections::BTreeMap;
use bytes::Bytes;

use crate::stream_v2::segment_worker::{DecryptedSegment, EncryptedSegment};
use crate::stream_v2::segmenting::types::SegmentFlags;
use crate::types::StreamError;
use crate::headers::{HeaderV1, HEADER_LEN_V1};
use crate::stream_v2::segmenting::{SegmentHeader, decode_segment_header, encode_segment};

/// Canonical input abstraction
pub enum InputSource {
    Reader(Box<dyn Read + Send>),
    File(PathBuf),
    Memory(Vec<u8>),
}

/// Canonical output abstraction
pub enum OutputSink {
    Writer(Box<dyn Write + Send>),
    File(PathBuf),
    Memory,
}

/// Normalize input source into a boxed reader
pub fn open_input(src: InputSource) -> Result<Box<dyn Read + Send>, StreamError> {
    let reader: Box<dyn Read + Send> = match src {
        InputSource::Reader(r) => r,
        InputSource::File(p) => Box::new(std::fs::File::open(p)?),
        InputSource::Memory(b) => Box::new(std::io::Cursor::new(b)),
    };
    Ok(reader)
}

/// Normalize output sink into a boxed writer
pub fn open_output(
    sink: OutputSink,
) -> Result<(Box<dyn Write + Send>, Option<Vec<u8>>), StreamError> {
    match sink {
        OutputSink::Writer(w) => Ok((w, None)),
        OutputSink::File(p) => Ok((Box::new(std::fs::File::create(p)?), None)),
        OutputSink::Memory => {
            let buf = Vec::new();
            Ok((Box::new(std::io::Cursor::new(buf.clone())), Some(buf)))
        }
    }
}

// ================= Header =================

pub fn write_header<W: Write>(w: &mut W, h: &HeaderV1) -> Result<(), StreamError> {
    let buf = crate::headers::encode_header_le(h).map_err(|e| StreamError::Header(e))?;
    w.write_all(&buf)?;
    Ok(())
}

pub fn read_header<R: Read>(r: &mut R) -> Result<HeaderV1, StreamError> {
    let mut buf = [0u8; HEADER_LEN_V1];
    r.read_exact(&mut buf)?;
    Ok(crate::headers::decode_header_le(&buf).map_err(|e| StreamError::Header(e))?)
}

// ================= Utilities =================
// We need this version for segmenting into canonical chunk sizes like 64 KiB, 128 KiB, etc.
pub fn read_exact_or_eof<R: Read>(
    r: &mut R,
    len: usize,
) -> Result<Bytes, StreamError> {
    let mut buf = vec![0u8; len];
    let mut off = 0;

    while off < len {
        let n = r.read(&mut buf[off..])?;
        if n == 0 {
            break;
        }
        off += n;
    }

    buf.truncate(off);
    Ok(Bytes::from(buf))
}
// pub fn read_exact_or_eof_1<R: Read>(
//     r: &mut R,
//     len: usize,
// ) -> Result<Bytes, StreamError> {
//     let mut buf = vec![0u8; len];
//     let n = r.read(&mut buf)?;
//     if n == 0 {
//         // EOF
//         return Ok(Bytes::new());
//     }
//     buf.truncate(n);
//     Ok(Bytes::from(buf))
// }

// ================= Segment I/O =================

pub fn read_segment<R: Read>(
    r: &mut R,
) -> Result<Option<(SegmentHeader, Bytes)>, StreamError> {
    let mut hdr_buf = [0u8; SegmentHeader::LEN];

    if r.read_exact(&mut hdr_buf).is_err() {
        return Ok(None);
    }

    let header = decode_segment_header(&hdr_buf).map_err(|e| StreamError::Segment(e))?;
    let mut wire = vec![0u8; header.wire_len as usize];
    r.read_exact(&mut wire)?;

    Ok(Some((header, Bytes::from(wire))))
}

// ================= Ordered writers =================

pub struct OrderedEncryptedWriter<'a, W: Write> {
    out: &'a mut W,
    next: u64,
    pending: BTreeMap<u64, EncryptedSegment>,
    final_index: Option<u64>,
}

impl<'a, W: Write> OrderedEncryptedWriter<'a, W> {
    pub fn new(out: &'a mut W) -> Self {
        Self {
            out,
            next: 0,
            pending: BTreeMap::new(),
            final_index: None,
        }
    }

    pub fn push(&mut self, segment: EncryptedSegment) -> Result<(), StreamError> {
        // Accept empty wire if FINAL_SEGMENT is set
        if segment.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && segment.wire.is_empty() {
            eprintln!("[ENCRYPT WRITER] Final empty segment {} detected", segment.header.segment_index);
            self.final_index = Some(segment.header.segment_index);
        }
        // Don’t write immediately — enqueue it
        self.pending.insert(segment.header.segment_index, segment);
        self.flush_ready()
    }

    pub fn finish(&mut self) -> Result<(), StreamError> {
        // Flush any pending segments in order
        while let Some(seg) = self.pending.remove(&self.next) {
            self.write(seg)?;
            self.next += 1;
        }

        // Validation: final marker must have been seen
        if self.final_index.is_none() {
            return Err(StreamError::Validation("Missing final segment".into()));
        }

        Ok(())
    }
    
    fn flush_ready(&mut self) -> Result<(), StreamError> {
        while let Some(seg) = self.pending.remove(&self.next) {
            self.write(seg)?;
            self.next += 1;
        }
        Ok(())
    }

    fn write(&mut self, segment: EncryptedSegment) -> Result<(), StreamError> {
        let segment_enc = encode_segment(&segment.header, &segment.wire).map_err(|e| StreamError::Segment(e))?;
            eprintln!("[ENCRYPT WRITER] Final writing segment {}", segment.header.segment_index);
        self.out.write_all(&segment_enc)?;
        Ok(())
    }
}

pub struct OrderedPlaintextWriter<'a, W: Write> {
    out: &'a mut W,
    next: u64,
    pending: BTreeMap<u64, DecryptedSegment>,
    final_index: Option<u64>,
}

impl<'a, W: Write> OrderedPlaintextWriter<'a, W> {
    pub fn new(out: &'a mut W) -> Self {
        Self {
            out,
            next: 0,
            pending: BTreeMap::new(),
            final_index: None,
        }
    }
    pub fn push(&mut self, segment: DecryptedSegment) -> Result<(), StreamError> {
        // Accept empty wire if FINAL_SEGMENT is set
        if segment.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && segment.frames.is_empty() {
            eprintln!("[PLAINTEXT WRITER] Final empty segment {} detected", segment.header.segment_index);
            self.final_index = Some(segment.header.segment_index);

            // Enqueue the final marker like any other segment
        }

        // Normal push logic
        eprintln!("[PLAINTEXT WRITER] Queuing segment {}", segment.header.segment_index);
        self.pending.insert(segment.header.segment_index, segment);
        self.flush_ready()
    }

    pub fn finish(&mut self) -> Result<(), StreamError> {
        // Flush any pending segments in order
        while let Some(segment) = self.pending.remove(&self.next) {
            self.write(segment)?;
            self.next += 1;
        }

        // Validation: final marker must have been seen
        if self.final_index.is_none() {
            return Err(StreamError::Validation("Missing final segment".into()));
        }

        eprintln!("[PLAINTEXT WRITER] Finished, final marker index {:?}", self.final_index);
        Ok(())
    }

    fn flush_ready(&mut self) -> Result<(), StreamError> {
        while let Some(segment) = self.pending.remove(&self.next) {
            self.write(segment)?;
            self.next += 1;
        }
        Ok(())
    }

    fn write(&mut self, segment: DecryptedSegment) -> Result<(), StreamError> {
        eprintln!("[PLAINTEXT WRITER] Writing segment {}", segment.header.segment_index);
        for frame in segment.frames {
            self.out.write_all(&frame)?;
        }
        Ok(())
    }
}
