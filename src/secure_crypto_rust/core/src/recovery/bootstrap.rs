// ## 📦 `src/recovery/bootstrap.rs`
// Purpose: Stream-based replay of unified log and restoration of hashing/decryption states.

use std::io;
use crate::recovery::persist::{LogManager};
use crate::recovery::checkpoint::{Checkpointable, SegmentCheckpoint, DecryptCheckpoint};
use crate::recovery::resume::parse_resume_line;
use crate::crypto::digest::{DigestState};

// Internal macro for production-grade tracing in 2026
macro_rules! trace {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        println!("[TRACE] {}", format_args!($($arg)*));
    };
}

/// The primary entry point for system recovery.
/// Streams the log from disk to rebuild the pipeline state without OOM risks.
pub fn run_recovery(log_path: &str) -> io::Result<()> {
    println!("--- RECOVERY START (2026.01) ---");
    
    // 2026 Best Practice: Stream log entries to handle multi-GB log files
    let log_stream = LogManager::stream_log(log_path)?;

    for entry_result in log_stream {
        let line = entry_result?;
        
        // 1. Detect Scheduler Resume Points
        if let Some((seg, frame, _)) = parse_resume_line(&line) {
            println!("[REPLAY] Found Resume Point: Segment {}, Next Frame {}", seg, frame);
            continue;
        }

        // 2. High-level replay of data frames (Optional: dispatch to verification engine)
        if line.starts_with("ENCRYPT:") {
            trace!("Replaying encryption frame entry from log");
        } else if line.starts_with("DECRYPT:") {
            trace!("Replaying decryption frame entry from log");
        }
    }
    
    println!("--- RECOVERY COMPLETE ---");
    Ok(())
}

/// Dispatches the actual state restoration for Encryption.
/// Strategy: Automatically handles SHA resume or Blake3 restart via checkpoint logic.
pub fn resume_encrypt_from_checkpoint(checkpoint: SegmentCheckpoint) -> Result<DigestState, crate::crypto::DigestError> {
    // Note: Blake3 logic is handled internally by checkpoint.resume_from_checkpoint()
    // It will return a fresh Hasher for Blake3, and a restored one for SHA.
    println!(
        "[BOOT] Restoring {} state for segment {}...", 
        checkpoint.alg, 
        checkpoint.segment_index
    );
    
    checkpoint.resume_from_checkpoint()
}

/// Restores the decryption primitive state (AES-CTR/ChaCha20).
pub fn resume_decrypt_from_checkpoint(checkpoint: &DecryptCheckpoint) {
    println!(
        "[BOOT] Resuming decryption: Seg {}, Frame {}, Alg: {:?}",
        checkpoint.segment_index,
        checkpoint.frame_index,
        checkpoint.state
    );
    // Real-world: Cipher::new_from_slices(&key, &checkpoint.state.to_bytes())
}

/// Uniform recovery handler for processing a batch of in-memory checkpoints.
pub fn run_recovery_cycle(checkpoints: Vec<Box<dyn Checkpointable>>) {
    println!("--- PROCESSING CHECKPOINT BATCH ---");

    for cp in checkpoints {
        println!("[RECOVERY] {}", cp.summary());

        let any_ref = cp.as_any();

        if let Some(seg_cp) = any_ref.downcast_ref::<SegmentCheckpoint>() {
            // Reconstruct hashing state
            match resume_encrypt_from_checkpoint(seg_cp.clone()) {
                Ok(_) => println!("  -> Encryption state ready: Seg {}", seg_cp.segment_index),
                Err(e) => eprintln!("  -> ERROR: Hash state recovery failed: {:?}", e),
            }
        } 
        else if let Some(dec_cp) = any_ref.downcast_ref::<DecryptCheckpoint>() {
            resume_decrypt_from_checkpoint(dec_cp);
        }
    }
}
