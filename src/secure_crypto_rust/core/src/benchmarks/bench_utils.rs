
use chrono::{Utc};
use rand::Rng; // bring the Rng trait into scope
use rand::RngCore;
use std::fs::File;
use std::io::BufWriter;
use std::io::{Write};
use std::io::{Read};
use std::path::Path;
use std::path::PathBuf;
use sysinfo::{System, ProcessesToUpdate}; // only these are needed
use async_stream::stream;
use futures::Stream;

use crate::stream_v2::core::MasterKey;

pub fn dummy_master_key() -> MasterKey {
    MasterKey::new(vec![0x11u8; 32]) // valid 32-byte key
}

/// Timestamp in ISO8601 UTC
pub fn get_timestamp() -> String {
    Utc::now().to_rfc3339()
}

/// Random bytes
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Measure memory usage of current process in MB

pub fn measure_memory_mb() -> f64 {
    let mut sys = System::new_all();

    // Refresh all processes
    sys.refresh_processes(ProcessesToUpdate::All, true);

    if let Ok(pid) = sysinfo::get_current_pid() {
        if let Some(proc) = sys.process(pid) {
            // proc.memory() returns kilobytes
            return proc.memory() as f64 / 1024.0; // KB → MB
        }
    }
    0.0
}


/// Measure CPU percent over a duration

pub fn measure_cpu_percent(duration_sec: f64) -> f64 {
    let mut sys = System::new();
    sys.refresh_cpu_usage();

    // Warm-up sample
    let _ = sys.global_cpu_usage();

    // Sleep for the requested duration
    std::thread::sleep(std::time::Duration::from_secs_f64(duration_sec));

    // Refresh and measure again
    sys.refresh_cpu_usage();
    sys.global_cpu_usage() as f64
}



/// Sync random chunk source
pub fn random_chunk_source(total_bytes: usize, max_chunk: usize) -> impl Iterator<Item = Vec<u8>> {
    let mut remaining = total_bytes;
    std::iter::from_fn(move || {
        if remaining == 0 {
            None
        } else {
            let n = remaining.min(max_chunk);
            remaining -= n;
            Some(random_bytes(n))
        }
    })
}

/// Async random chunk source
pub fn random_chunk_source_async(total_bytes: usize, max_chunk: usize) -> impl Stream<Item = Vec<u8>> {
    stream! {
        let mut remaining = total_bytes;
        while remaining > 0 {
            let n = remaining.min(max_chunk);
            remaining -= n;
            yield random_bytes(n);
        }
    }
}

/// Fragmented source

pub fn fragmented_source(data: &[u8], min_frag: usize, max_frag: usize) -> impl Iterator<Item = Vec<u8>> + '_ {
    let mut pos = 0;
    std::iter::from_fn(move || {
        if pos >= data.len() {
            None
        } else {
            // gen_range is from the Rng trait
            let frag = rand::thread_rng().gen_range(min_frag..=max_frag);
            let end = (pos + frag).min(data.len());
            let chunk = data[pos..end].to_vec();
            pos = end;
            Some(chunk)
        }
    })
}


/// Async fragmented source
pub fn fragmented_source_async<'a>(data: &'a [u8], min_frag: usize, max_frag: usize) -> impl Stream<Item = Vec<u8>> + 'a {
    stream! {
        let mut pos = 0;
        while pos < data.len() {
            let frag = rand::thread_rng().gen_range(min_frag..=max_frag);
            let end = (pos + frag).min(data.len());
            let chunk = data[pos..end].to_vec();
            pos = end;
            yield chunk;
        }
    }
}

/// Sync file reader
pub fn sync_file_reader(path: &Path, chunk_size: usize) -> impl Iterator<Item = Vec<u8>> {
    let mut file = File::open(path).expect("file not found");
    std::iter::from_fn(move || {
        let mut buf = vec![0u8; chunk_size];
        match file.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => Some(buf[..n].to_vec()),
            Err(_) => None,
        }
    })
}

/// Async file reader

// pub fn async_file_reader(path: PathBuf, chunk_size: usize) -> impl Stream<Item = Vec<u8>> {
//     stream! {
//         let mut file = AsyncFile::open(path).await.expect("file not found");
//         loop {
//             let mut buf = vec![0u8; chunk_size];
//             match file.read(&mut buf).await {
//                 Ok(0) => break, // EOF
//                 Ok(n) => yield buf[..n].to_vec(),
//                 Err(_) => break,
//             }
//         }
//     }
// }

/// Safe cleanup sync
pub fn safe_cleanup_sync<T: ?Sized>(obj: &T)
where
    T: Cleanup,
{
    obj.cleanup();
}

/// Safe cleanup async
pub async fn safe_cleanup_async<T: ?Sized>(obj: &T)
where
    T: AsyncCleanup,
{
    obj.cleanup().await;
}

/// Trait for cleanup
pub trait Cleanup {
    fn cleanup(&self);
}

/// Trait for async cleanup
#[async_trait::async_trait]
pub trait AsyncCleanup {
    async fn cleanup(&self);
}

/// Safe remove
pub fn safe_remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// helper: create plain.dat of given size 
pub fn create_plain_file(path: &str, size_bytes: usize) { 
    let file = File::create(path).expect("Unable to create file"); 
    let mut writer = BufWriter::new(file); 
    let data = random_bytes(1024); // 1 KB buffer 
    let mut written = 0; 
    
    while written < size_bytes { 
        let remaining = size_bytes - written; 
        let chunk = if remaining < data.len() { 
            &data[..remaining] 
        } 
        else { 
            &data 
        }; 
        writer.write_all(chunk).expect("Write failed"); 
        written += chunk.len(); 
    } 
    writer.flush().expect("Flush failed");
}

pub fn cleanup_file(path: Option<PathBuf>) {
    if let Some(p) = path {
        if p.exists() {
            if let Err(e) = std::fs::remove_file(&p) {
                eprintln!("Failed to delete temp file {:?}: {}", p, e);
            }
        }
    }
}

// ### 🧩 Key Notes
// - `async-stream` crate is used to yield values asynchronously.
// - `sysinfo` provides CPU and memory info; CPU usage is sampled before and after a sleep.
// - Traits `Cleanup` and `AsyncCleanup` mimic Python’s `cleanup` method detection.
// - `safe_remove` ignores missing files.
