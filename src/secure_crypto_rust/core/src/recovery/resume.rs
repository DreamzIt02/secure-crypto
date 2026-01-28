// ## 📦 `src/recovery/resume.rs`

use crate::recovery::LogManager;
use crate::recovery::checkpoint::SegmentCheckpoint;
use crate::recovery::persist::{AsyncLogManager, UnifiedEntry};
use std::io;

/// Resume point for digest workers.
/// Represents the exact boundary where a worker can pick up processing.
#[derive(Debug, Clone)]
pub struct SegmentResumePoint {
    /// The segment currently being processed.
    pub segment_index: u32,
    /// First frame index that has NOT yet been authenticated/processed.
    pub next_frame_index: u32,
    /// The digest state captured at the end of the last successful frame.
    pub checkpoint: SegmentCheckpoint,
}

impl SegmentResumePoint {
    /// Create a new resume point.
    pub fn new(segment_index: u32, next_frame_index: u32, checkpoint: SegmentCheckpoint) -> Self {
        Self {
            segment_index,
            next_frame_index,
            checkpoint,
        }
    }
    fn format_log_line(&self) -> String {
        // 1. Create a specialized log entry string.
        // Format: SCHEDULER: RESUME_POINT|SEG_ID|NEXT_FRAME|ALG|STATE_BASE64
        let state_bytes = self.checkpoint.state.to_bytes();
        let encoded_state = if state_bytes.is_empty() {
            "RESTART".to_string()
        } else {
            // Use a fast base64 crate (standard in 2026)
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &state_bytes)
        };

        // 1. Construct the raw data string
        let raw_msg = format!("RESUME|{}|{}|{:?}|{}",
            self.segment_index, self.next_frame_index, self.checkpoint.alg, encoded_state);

        // 2. Compute Integrity Checksum (BLAKE3 keyed or standard)
        // We take the first 8 hex chars of the hash for brevity and speed
        let hash = blake3::hash(raw_msg.as_bytes());
        let hex_string = hash.to_hex(); // Now it's a standard String

        // CORRECT: explicitly use usize
        // let checksum = &hex_string[..8usize]; // Standard Strings often infer usize more easily
        // println!("Hash checksum: {}", checksum);

        // 3. Final format: RESUME|...|CHECKSUM
        let final_msg = format!("{}|{}", raw_msg, &hex_string[..8usize]);

        return  final_msg;
        
    }

    /// Persists the resume point to the Unified Log.
    /// In 2026, we use Base64 encoding for the binary state to ensure log readability.
    pub fn persist_sync(&self, log_manager: &mut LogManager) -> io::Result<()> {
        // 1. Create a specialized log entry string.
        let final_msg = self.format_log_line();

        log_manager.append(UnifiedEntry::Scheduler(final_msg))
    }

    pub fn persist(&self, log_manager: &AsyncLogManager) {
        // 1. Create a specialized log entry string.
        let final_msg = self.format_log_line();
        
        log_manager.append(UnifiedEntry::Scheduler(final_msg))
    }

    /// Summary for diagnostic tools.
    pub fn summary(&self) -> String {
        format!(
            "SegmentResumePoint(Seg: {}, NextFrame: {}, Alg: {:?})",
            self.segment_index, self.next_frame_index, self.checkpoint.alg
        )
    }
}

/// Helper to extract a ResumePoint from a log line during bootstrap.
pub fn parse_resume_line(line: &str) -> Option<(u32, u32, String)> {
    let content = line.strip_prefix("SCHEDULER: ")?;
    let mut parts: Vec<&str> = content.split('|').collect();
    
    // Check for integrity (Part 0..4 is data, Part 5 is checksum)
    if parts.len() < 6 { return None; }
    
    let provided_checksum = parts.pop()?; // Remove last part
    let data_to_verify = parts.join("|");
    
    let actual_hash = blake3::hash(data_to_verify.as_bytes());
    if &actual_hash.to_hex()[..8] != provided_checksum {
        eprintln!("CRITICAL: Corrupt log line detected (Checksum mismatch). Skipping.");
        return None;
    }

    Some((
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
        parts[4].to_string()
    ))
}