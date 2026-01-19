// ### `src/telemetry/counters.rs`

//! telemetry/counters.rs
//! Mutable counters used during streaming pipelines.
//!
//! Summary: Collects frame counts and byte counts during encrypt/decrypt.
//! Converted into immutable TelemetrySnapshot at pipeline end.
use bincode::{Encode, Decode};
use std::ops::AddAssign;

/// Deterministic counters collected during stream processing
#[derive(Default, Clone, Debug, Encode, Decode, PartialEq)]
pub struct TelemetryCounters {
    pub frames_header: u64,
    pub frames_data: u64,
    pub frames_terminator: u64,
    pub frames_digest: u64,
    pub bytes_plaintext: u64,
    pub bytes_compressed: u64,
    pub bytes_ciphertext: u64,
    pub bytes_overhead: u64,   
}

impl TelemetryCounters {
    pub fn from_ref(counters: &TelemetryCounters) -> Self {
        counters.clone()
    }

    /// Record the stream header as overhead.
    pub fn add_header(&mut self, header_len: usize) {
        self.frames_header += 1;           // optional: count headers if we track them
        self.bytes_overhead += header_len as u64;
    }

    /// Record one encrypted data frame.
    ///
    /// - `pt_len`: plaintext length before compression
    /// - `comp_len`: compressed length (payload before encryption)
    /// - `ct_payload_len`: ciphertext payload length (fh.ct_len_in_frame)
    /// - `frame_overhead_len`: structural overhead (frame header + tag + any prefixes)
    pub fn add_encrypt_data(
        &mut self,
        pt_len: usize,
        comp_len: usize,
        ct_payload_len: usize,
        frame_overhead_len: usize,
    ) {
        self.frames_data += 1;
        self.bytes_plaintext += pt_len as u64;
        self.bytes_compressed += comp_len as u64;
        self.bytes_ciphertext += ct_payload_len as u64;
        self.bytes_overhead += frame_overhead_len as u64;
    }

    /// Record one decrypted data frame.
    ///
    /// - `pt_len`: plaintext length recovered after decompression
    /// - `comp_len`: compressed payload length before decompression
    /// - `ct_payload_len`: ciphertext payload length (fh.ct_len_in_frame)
    /// - `frame_overhead_len`: structural overhead (frame header + tag + any prefixes)
    pub fn add_decrypt_data(
        &mut self,
        pt_len: usize,
        comp_len: usize,
        ct_payload_len: usize,
        frame_overhead_len: usize,
    ) {
        self.frames_data += 1;
        self.bytes_plaintext += pt_len as u64;
        self.bytes_compressed += comp_len as u64;
        self.bytes_ciphertext += ct_payload_len as u64;
        self.bytes_overhead += frame_overhead_len as u64;
    }


    /// Mark a terminator frame processed.
    /// - `frame_overhead_len`: total encoded length of the terminator frame
    pub fn add_terminator(&mut self, frame_overhead_len: usize) {
        self.frames_terminator += 1;
        self.bytes_overhead += frame_overhead_len as u64;
    }
    /// Mark a digest frame processed.
    /// - `frame_overhead_len`: total encoded length of the digest frame
    pub fn add_digest(&mut self, frame_overhead_len: usize) {
        self.frames_digest += 1;
        self.bytes_overhead += frame_overhead_len as u64;
    }

    /// Return total framing overhead bytes counted during the stream.
    pub fn framing_overhead_bytes(&self) -> u64 {
        self.bytes_overhead
    }
    // This avoids:
    // * locks inside workers
    // * atomics
    // * false sharing
    pub fn merge(&mut self, other: &TelemetryCounters) {
        self.frames_header += other.frames_header;
        self.frames_data += other.frames_data;
        self.frames_terminator += other.frames_terminator;
        self.frames_digest += other.frames_digest;

        self.bytes_plaintext += other.bytes_plaintext;
        self.bytes_compressed += other.bytes_compressed;
        self.bytes_ciphertext += other.bytes_ciphertext;
        self.bytes_overhead += other.bytes_overhead;
    }
}


impl AddAssign for TelemetryCounters {
    fn add_assign(&mut self, rhs: Self) {
        self.frames_header      += rhs.frames_header;
        self.frames_data        += rhs.frames_data;
        self.frames_terminator  += rhs.frames_terminator;
        self.frames_digest      += rhs.frames_digest;

        self.bytes_plaintext    += rhs.bytes_plaintext;
        self.bytes_compressed   += rhs.bytes_compressed;
        self.bytes_ciphertext   += rhs.bytes_ciphertext;
        self.bytes_overhead     += rhs.bytes_overhead;
    }
}
