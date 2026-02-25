use std::{any::Any, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};

use crossbeam::channel::{Receiver, Sender};

use crate::{stream_v2::parallelism::HybridParallelismProfile, types::StreamError};

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub profile: HybridParallelismProfile,
    /// The final encrypted stream bytes, if the output sink was memory-backed.
    ///
    /// - `None` if the output was written directly to a file or external sink.
    /// - `Some(Vec<u8>)` if the pipeline wrote into an in-memory buffer.
    ///
    /// This field is primarily useful in tests, benchmarks, or integrations
    /// where we want to inspect the produced ciphertext alongside telemetry
    /// counters and stage timings.
    pub buf: Option<Arc<Mutex<Vec<u8>>>>,
}

impl PipelineConfig {
    pub fn new(profile: HybridParallelismProfile, buf: Option<Arc<Mutex<Vec<u8>>>>) -> Self {
        Self {
            profile,
            buf,
        }
    }
    pub fn with_buf(profile: HybridParallelismProfile) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Self { profile, buf: Some(buf.clone()) }, buf)
    }
}

pub trait Cancellation {
    fn fatal(&self, err: StreamError);
    fn is_cancelled(&self) -> bool;
}

#[derive(Clone)]
pub struct PipelineCancellation {
    pub fatal_tx: Sender<StreamError>, // monitor owns this
    pub cancelled: Arc<AtomicBool>,
    pub senders: Arc<Mutex<Vec<Box<dyn Any + Send>>>>,
    pub receivers: Arc<Mutex<Vec<Box<dyn Any + Send>>>>,
}

#[derive(Clone)]
pub struct CancelHandle {
    pub fatal_tx: Sender<StreamError>, // workers get plain Sender
    pub cancelled: Arc<AtomicBool>,
}

impl Cancellation for PipelineCancellation {
    #[inline]
    fn fatal(&self, err: StreamError) {
        // let _ = self.fatal_tx.send(err);
        // ✅ Don't ignore send errors
        match self.fatal_tx.send(err) {
            Ok(()) => {
                eprintln!("[CANCEL] Error sent to monitor");
            }
            Err(e) => {
                // This is critical - the monitor died or channel is full
                eprintln!("[CANCEL] ❌ FAILED to send error to monitor!");
                eprintln!("[CANCEL] ❌ Lost error: {}", e.0);
                // Store it locally or panic
                panic!("Fatal error could not be reported: {}", e.0);
            }
        }
        self.cancelled.store(true, Ordering::Relaxed);

        // Drop all monitored channels to unblock workers
        self.senders.lock().unwrap().clear();
        self.receivers.lock().unwrap().clear();
    }

    #[inline]
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

}

impl Cancellation for CancelHandle {
    #[inline]
    fn fatal(&self, err: StreamError) {
        eprintln!("[CANCEL] CancelHandle::fatal called: {}", err);
        //     let _ = self.fatal_tx.send(err);
        
        // ✅ Don't ignore send errors
        match self.fatal_tx.send(err) {
            Ok(()) => {
                eprintln!("[CANCEL] Error sent to monitor");
            }
            Err(e) => {
                // This is critical - the monitor died or channel is full
                eprintln!("[CANCEL] ❌ FAILED to send error to monitor!");
                eprintln!("[CANCEL] ❌ Lost error: {}", e.0);
                // Store it locally or panic
                panic!("Fatal error could not be reported: {}", e.0);
            }
        }
        
        self.cancelled.store(true, Ordering::Relaxed);
    }
    #[inline]
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

impl CancelHandle {
    #[inline]
    pub fn finish(self) {
        // Workers don’t own senders/receivers, so finish is a no‑op
        // Dropping fatal_tx clone signals monitor if this was the last sender
        // drop(self.fatal_tx);
    }
}
impl PipelineCancellation {
    pub fn handle(&self) -> CancelHandle {
        CancelHandle {
            cancelled: self.cancelled.clone(),
            fatal_tx: self.fatal_tx.clone(),
        }
    }

    pub fn new(
        senders: Vec<Box<dyn Any + Send>>,
        receivers: Vec<Box<dyn Any + Send>>,
    ) -> (Self, Receiver<StreamError>) {
        let (fatal_tx, fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        (
            Self {
                cancelled,
                fatal_tx,
                senders: Arc::new(Mutex::new(senders)),
                receivers: Arc::new(Mutex::new(receivers)),
            },
            fatal_rx,
        )
    }

    #[inline]
    pub fn finish(self) {
        // Drop monitored channels to unblock workers on success
        self.senders.lock().unwrap().clear();
        self.receivers.lock().unwrap().clear();

        // Dropping fatal_tx closes channel once worker clones are gone
        // fatal_tx is dropped here when self is consumed
        // drop(self.fatal_tx);
    }
}
