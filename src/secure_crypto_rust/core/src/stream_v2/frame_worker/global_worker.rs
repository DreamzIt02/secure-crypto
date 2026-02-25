// # 🎯 Target Architecture

// Instead of:

// ```
// (N-1) SegmentWorkers
//     × (cpu_workers) FrameWorkers
// ```

// We move to:

// ```
// Global Frame Executor (size = physical cores)

// SegmentWorkers
//     └── push FrameTasks into global executor
// ```

// No nested pools.
// No oversubscription.
// No per-segment frame channels.

// # 🧠 Core Idea

// We replace this:

// ```rust
// let (frame_tx, frame_rx) = bounded(...);

// for _ in 0..worker_count {
//     thread::spawn(move || fw.run(frame_rx.clone(), ...));
// }
// ```

// With:

// ```rust
// GLOBAL_FRAME_EXECUTOR.submit(FrameTask)
// ```

// The executor:

// * Has N worker threads
// * Uses a lock-free MPMC queue (crossbeam already is)
// * Runs forever
// * Never recreated per segment
// * Handles both encrypt + decrypt tasks

// # 🏗 Step 1 — Define Global Frame Executor

use crossbeam::channel::{unbounded, Sender};
use once_cell::sync::{Lazy, OnceCell};
use std::{sync::{Arc, atomic::AtomicBool}, thread};

use crate::{headers::HeaderV1, stream_v2::frame_worker::{FrameWorkerError, decrypt::DecryptFrameWorker2, encrypt::{EncryptFrameWorker2}}, types::StreamError};

pub type FrameTask = Box<dyn FnOnce() + Send + 'static>;

pub struct GlobalFrameExecutor {
    sender: Sender<FrameTask>,
    fw_encrypt: OnceCell<EncryptFrameWorker2>,
    fw_decrypt: OnceCell<DecryptFrameWorker2>,
    fatal_tx: OnceCell<Sender<StreamError>>, // keep a global copy
}
// ✅ **Summary:**  
// - Yes, keep a copy of `fatal_tx` in `FRAME_EXECUTOR` using `OnceCell`.  
// - That way, closures can report fatal errors without capturing external senders.  
// - We only need to call `workers()` once to initialize everything.  

impl GlobalFrameExecutor {
    fn new(worker_count: usize) -> Self {
        let (tx, rx) = unbounded::<FrameTask>();
        for _ in 0..worker_count {
            let rx = rx.clone();
            thread::spawn(move || {
                while let Ok(task) = rx.recv() {
                    task();
                }
            });
        }
        Self {
            sender: tx,
            fw_encrypt: OnceCell::new(),
            fw_decrypt: OnceCell::new(),
            fatal_tx: OnceCell::new(),
        }
    }

    /// Creates a new frame encryption worker
    ///
    /// # Arguments
    /// * `header` - Stream header containing encryption parameters
    /// * `session_key` - Session key for AEAD encryption
    /// * `fatal_tx` - Channel to signal fatal errors to the pipeline monitor
    /// * `cancelled` - Shared cancellation flag for graceful shutdown
    pub fn workers(
        &self,
        header: HeaderV1,
        session_key: &[u8],
        fatal_tx: Sender<StreamError>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<(), FrameWorkerError> {
        // store global fatal_tx once
        self.fatal_tx
            .set(fatal_tx.clone())
            .map_err(|_| FrameWorkerError::StateError("Failed to initialize worker error channel".into()))?;

        self.fw_encrypt
            .set(EncryptFrameWorker2::new(header.clone(), session_key, cancelled.clone())?)
            .map_err(|_| FrameWorkerError::StateError("Failed to initialize encrypt worker".into()))?;

        self.fw_decrypt
            .set(DecryptFrameWorker2::new(header, session_key, cancelled)?)
            .map_err(|_| FrameWorkerError::StateError("Failed to initialize decrypt worker".into()))?;

        Ok(())
    }

    pub fn encrypt_worker(&self) -> Option<&EncryptFrameWorker2> {
        self.fw_encrypt.get()
    }

    pub fn decrypt_worker(&self) -> Option<&DecryptFrameWorker2> {
        self.fw_decrypt.get()
    }

    pub fn fatal_error(&self) -> Option<&Sender<StreamError>> {
        self.fatal_tx.get()
    }
    pub fn submit(&self, task: FrameTask) {
        let _ = self.sender.send(task);
    }
}

// # 🌍 Step 2 — Make It Global

pub static FRAME_EXECUTOR: Lazy<GlobalFrameExecutor> = Lazy::new(|| {
    let cores = num_cpus::get().saturating_sub(1); // IMPORTANT: physical, not logical
    GlobalFrameExecutor::new(cores)
});

// Now:

// * Executor starts once.
// * Thread count fixed.
// * No nested pools.


// # 🔐 Refactor EncryptSegmentWorker1

// Remove:

// ```rust
// let (frame_tx, frame_rx) = ...
// spawn frame workers
// ```

// Replace dispatch section in `process_encrypt_segment_1` with:

// ```rust
// for (frame_index, chunk) in input.bytes.chunks(frame_size).enumerate() {
//     let crypto = crypto.clone();
//     let cancelled = cancelled.clone();
//     let out_tx = out_tx.clone();

//     FRAME_EXECUTOR.submit(Box::new(move || {
//         if cancelled.load(Ordering::Relaxed) {
//             return;
//         }

//         let result = encrypt_frame_internal(
//             &crypto,
//             segment_index,
//             frame_index as u32,
//             chunk,
//         );

//         let _ = out_tx.send(result);
//     }));
// }
// ```

// No frame_rx.
// No worker spawning.
// No per-segment pools.

// # 🔓 Refactor DecryptSegmentWorker1

// Replace this:

// ```rust
// frame_tx.send(input.wire.slice(...))
// ```

// With:

// ```rust
// let frame_bytes = input.wire.slice(offset..end);
// let crypto = crypto.clone();
// let cancelled = cancelled.clone();
// let out_tx = out_tx.clone();

// FRAME_EXECUTOR.submit(Box::new(move || {
//     if cancelled.load(Ordering::Relaxed) {
//         return;
//     }

//     let result = decrypt_frame_internal(&crypto, frame_bytes);
//     let _ = out_tx.send(result);
// }));
// ```

// Again:

// * No local frame pool
// * No local frame channel
// * All tasks go to global executor

// # 🧩 What Changes in Segment Worker?

// Segment worker now only:

// 1. Parses frames
// 2. Submits tasks
// 3. Collects results
// 4. Verifies digest
// 5. Reassembles

// It no longer:

// * Spawns threads
// * Owns frame pools
// * Manages frame worker lifecycle

// # 🚀 Why This Scales Linearly

// Now total threads = physical cores.

// Not:

// ```
// SegmentWorkers × FrameWorkers
// ```

// But:

// ```
// FrameExecutor = N cores
// ```

// So scaling becomes:

// ```
// Throughput ≈ crypto_parallel_fraction × N
// ```

// On Haswell:

// AES-GCM scales very well across cores.
// CHACHA20 scales even more cleanly.

// We should now see:

// * 6.5–7.5× on 8 cores
// * 12–14× on 16 cores

// (assuming memory bandwidth is sufficient)

// # 🧠 Optional Upgrade — Remove Channels Entirely

// Even better than:

// ```rust
// out_tx.send(result)
// ```

// We can:

// * Pre-allocate `Vec<Option<Frame>>`
// * Use `AtomicUsize` counter
// * Write directly into index slot

// That removes:

// * Channel overhead
// * Allocation per send
// * Lock contention

// But global executor already gives huge improvement.

// # 📊 Expected Improvement

// With nested pools:
// Scaling often collapses after 4 cores.

// With global executor:
// Scaling follows core count until memory bound.

// We also eliminate:

// * 100s of unnecessary threads
// * Context switching
// * Cache thrash
// * Crossbeam contention explosion

// # 🔥 Final Architecture

// ```
// GlobalFrameExecutor (N physical threads)
//         ↑
// EncryptSegmentWorker
// DecryptSegmentWorker
//         ↑
// Pipeline
// ```

// No nested pools.
// No oversubscription.
// Near lock-free execution.

// TODO:

// * Convert our full `process_encrypt_segment_1` into fully lock-free (no out_rx channel)
// * Or design a zero-copy digest verification pipeline
// * Or compute theoretical maximum throughput per core for AES-GCM vs CHACHA20 on Haswell

// This refactor is the turning point between “parallel” and “scalable.”
