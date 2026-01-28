// # 📂 src/stream_v2/io.rs

// ## 📂 File: `src/stream_v2/io.rs`
// ## Normalized I/O + ordered encrypted writer (production-ready)

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use bytes::Bytes;

use crate::headers::{HeaderV1};
use crate::stream_v2::segment_worker::{DecryptedSegment, EncryptedSegment};
use crate::stream_v2::segmenting::types::SegmentFlags;
use crate::stream_v2::segmenting::{SegmentHeader, decode_segment_header, encode_segment};
use crate::types::StreamError;

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
    with_buf: Option<bool>,
) -> Result<(Box<dyn Write + Send>, Option<Arc<Mutex<Vec<u8>>>>), StreamError> {
    match sink {
        OutputSink::Writer(w) => Ok((w, None)),
        OutputSink::File(p) => Ok((Box::new(std::fs::File::create(p)?), None)),
        OutputSink::Memory => {
            match with_buf {
                Some(true) => {
                    let buf = Arc::new(Mutex::new(Vec::new()));
                    let writer = SharedBufferWriter { buf: buf.clone() };
                    Ok((Box::new(writer), Some(buf)))
                },
                _ => {
                    // If we don’t need concurrent access, we can just use Cursor<Vec<u8>> directly:
                    let cursor = Cursor::new(Vec::new());
                    Ok((Box::new(cursor), None))
                }
            }
        }
    }
}

pub struct SharedBufferWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}
impl Write for SharedBufferWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.buf.lock().unwrap();
        guard.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    // fn main() -> Result<(), std::io::Error> {
    //     let (mut writer, maybe_buf) = open_output_shared(OutputSink::Memory)?;
    //     writer.write_all(b"hello world")?;

    //     if let Some(buf) = maybe_buf {
    //         let data = buf.lock().unwrap();
    //         println!("Captured output: {:?}", String::from_utf8_lossy(&data));
    //     }

    //     Ok(())
    // }
}

// ================= Header =================

pub fn write_header<W: Write>(w: &mut W, h: &HeaderV1) -> Result<(), StreamError> {
    let buf = crate::headers::encode_header_le(h).map_err(|e| StreamError::Header(e))?;
    w.write_all(&buf)?;
    Ok(())
}

fn read_header<R: Read>(r: &mut R) -> Result<HeaderV1, StreamError> {
    let mut buf = [0u8; HeaderV1::LEN];
    r.read_exact(&mut buf)?;
    Ok(crate::headers::decode_header_le(&buf).map_err(|e| StreamError::Header(e))?)
}

#[derive(Debug)]
pub struct PayloadReader<R: Read> {
    inner: R,
}

impl<R: Read> PayloadReader<R> {
    /// Construct without consuming header (rarely used)
    pub fn new(reader: R) -> Self {
        PayloadReader { inner: reader }
    }

    /// Consume header and return both parsed header and payload reader
    pub fn with_header(mut reader: R) -> Result<(HeaderV1, Self), StreamError> {
        let header = read_header(&mut reader)?;
        Ok((header, PayloadReader { inner: reader }))
    }
}

impl<R: Read> Read for PayloadReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for PayloadReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}


// ================= Utilities =================
/// Ensure the reader has advanced past the header (default 80 bytes).
pub fn assert_reader_after_header<R: Read + Seek + Send>(reader: &mut R, header_len: usize) -> Result<(), StreamError> {
    let pos = reader.seek(SeekFrom::Current(0))?;
    if pos < header_len as u64 {
        return Err(StreamError::Validation(format!(
            "Reader not advanced past header: pos={pos}, expected >= {header_len}"
        )));
    }
    Ok(())
}

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

// pub fn read_segment<R: Read>(
//     r: &mut R,
// ) -> Result<Option<(SegmentHeader, Bytes)>, StreamError> {
//     let mut hdr_buf = [0u8; SegmentHeader::LEN];

//     if r.read_exact(&mut hdr_buf).is_err() {
//         return Ok(None);
//     }

//     let header = decode_segment_header(&hdr_buf).map_err(|e| StreamError::Segment(e))?;
//     let mut wire = vec![0u8; header.wire_len as usize];
//     r.read_exact(&mut wire)?;

//     Ok(Some((header, Bytes::from(wire))))
// }
pub fn read_segment<R: Read>(
    r: &mut R,
) -> Result<Option<(SegmentHeader, Bytes)>, StreamError> {
    let mut hdr_buf = [0u8; SegmentHeader::LEN];

    // If we can't read a full header, it's true EOF
    if let Err(_) = r.read_exact(&mut hdr_buf) {
        return Ok(None);
    }

    let header = decode_segment_header(&hdr_buf).map_err(StreamError::Segment)?;
    // 🔍 Debug header summary
    // eprintln!("[IO:DECRYPT] Parsed header: {}", header.summary());

    // Allocate wire buffer according to header
    let mut wire = vec![0u8; header.wire_len as usize];
    if header.wire_len > 0 {
        r.read_exact(&mut wire)?;
    }

    // ✅ Special case: final empty segment
    // if header.flags.contains(SegmentFlags::FINAL_SEGMENT) && header.wire_len == 0 {
    //     eprintln!("[IO:DECRYPT] Empty FINAL_SEGMENT detected at index {}", header.segment_index);
    //     return Ok(Some((header, Bytes::new())));
    // }

    Ok(Some((header, Bytes::from(wire))))
}

// pub fn read_segment<R: Read>(
//     r: &mut R,
// ) -> Result<Option<(SegmentHeader, Bytes)>, StreamError> {
//     let mut hdr_buf = [0u8; SegmentHeader::LEN];

//     match r.read_exact(&mut hdr_buf) {
//         Ok(()) => {
//             // Successfully read a full segment header
//             let header = decode_segment_header(&hdr_buf)
//                 .map_err(StreamError::Segment)?;
//             let mut wire = vec![0u8; header.wire_len as usize];
//             r.read_exact(&mut wire)?;
//             Ok(Some((header, Bytes::from(wire))))
//         }
//         Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
//             // Graceful end of stream: no more segments
//             Ok(None)
//         }
//         Err(e) => {
//             // Propagate other I/O errors
//             Err(StreamError::Io(e))
//         }
//     }
// }

// ================= Ordered writers =================

pub struct OrderedEncryptedWriter<'a, W: Write> {
    out: &'a mut W,
    next: u32,
    pending: BTreeMap<u32, EncryptedSegment>,
    final_index: Option<u32>,
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
    next: u32,
    pending: BTreeMap<u32, DecryptedSegment>,
    final_index: Option<u32>,
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
    pub fn push(&mut self, segment: &DecryptedSegment) -> Result<(), StreamError> {
        // Accept empty wire if FINAL_SEGMENT is set
        if segment.header.flags.contains(SegmentFlags::FINAL_SEGMENT) && segment.bytes.is_empty() {
            eprintln!("[PLAINTEXT WRITER] Final empty segment {} detected", segment.header.segment_index);
            self.final_index = Some(segment.header.segment_index);

            // Enqueue the final marker like any other segment
        }

        // Normal push logic
        eprintln!("[PLAINTEXT WRITER] Queuing segment {}", segment.header.segment_index);
        self.pending.insert(segment.header.segment_index, segment.clone());
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
        self.out.write_all(&segment.bytes)?;
        Ok(())
    }
}
