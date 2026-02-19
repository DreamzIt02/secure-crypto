use std::collections::HashMap;
use std::process::Command;
use uuid::Uuid;
use sysinfo::{System, Disks, get_current_pid}; // only these are needed

/// Safe helpers

pub fn safe_run(cmd: &[&str]) -> Option<String> {
    if cmd.is_empty() {
        return None;
    }
    let output = Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

pub fn safe_sysinfo_call<T, F: FnOnce() -> T>(callable: F, default: T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(callable))
        .unwrap_or(default)
}

/// Container detection

pub fn detect_container() -> Option<String> {
    if let Ok(data) = std::fs::read_to_string("/proc/1/cgroup") {
        if data.contains("docker") || data.contains("containerd") {
            return Some("docker".to_string());
        }
        if data.contains("podman") {
            return Some("podman".to_string());
        }
    }
    None
}

/// Git metadata

pub fn collect_git_metadata() -> HashMap<String, Option<String>> {
    let mut map = HashMap::new();
    map.insert("commit".to_string(), safe_run(&["git", "rev-parse", "HEAD"]));
    map.insert("branch".to_string(), safe_run(&["git", "rev-parse", "--abbrev-ref", "HEAD"]));
    map.insert(
        "dirty".to_string(),
        Some(
            safe_run(&["git", "status", "--porcelain"])
                .map(|s| (!s.is_empty()).to_string())
                .unwrap_or("false".to_string()),
        ),
    );
    map
}

/// CPU metadata

pub fn collect_cpu_metadata(sys: &System) -> HashMap<String, Option<String>> {
    let mut map = HashMap::new();

    // physical_core_count is an associated function, not a method
    map.insert(
        "physical_cores".to_string(),
        Some(System::physical_core_count().unwrap_or(0).to_string()),
    );

    // logical cores from the cpus slice
    map.insert("logical_cores".to_string(), Some(sys.cpus().len().to_string()));

    // max frequency from the first CPU
    map.insert(
        "max_frequency_mhz".to_string(),
        sys.cpus().iter().map(|c| c.frequency().to_string()).next(),
    );

    if cfg!(target_os = "linux") {
        map.insert("flags".to_string(), safe_run(&["bash", "-lc", "lscpu | grep Flags"]));
    }

    map
}

/// Memory metadata

pub fn collect_memory_metadata(sys: &System) -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert(
        "total_ram_mb".to_string(),
        (sys.total_memory() / 1024).to_string(),
    );
    map
}

/// Disk metadata

pub fn collect_disk_metadata(_sys: &System) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // Create a Disks collection and refresh it
    let mut disks = Disks::new();
    disks.refresh(true);

    let disk_names: Vec<String> = disks
        .iter()
        .map(|d| d.name().to_string_lossy().to_string())
        .collect();

    map.insert("disks".to_string(), format!("{:?}", disk_names));
    map
}



/// Process metadata

pub fn collect_process_metadata(sys: &System) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(pid) = get_current_pid() {
        if let Some(proc) = sys.process(pid) {
            map.insert("pid".to_string(), proc.pid().to_string());
            map.insert("name".to_string(), proc.name().display().to_string());

            // exe() returns Option<&Path>, so unwrap safely
            let exe_str = proc.exe()
                .map(|p| p.display().to_string()) // or p.to_string_lossy().to_string()
                .unwrap_or_else(|| "<unknown>".to_string());
            map.insert("exe".to_string(), exe_str);

            map.insert("cpu_usage".to_string(), proc.cpu_usage().to_string());
            map.insert("memory_kb".to_string(), proc.memory().to_string());
        }
    }
    map
}

/// Environment metadata

pub fn collect_environment_metadata() -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(val) = std::env::var("VIRTUAL_ENV") {
        map.insert("virtual_env".to_string(), val);
    }
    if let Ok(val) = std::env::var("CONDA_DEFAULT_ENV") {
        map.insert("conda_env".to_string(), val);
    }
    for (k, v) in std::env::vars() {
        if k.starts_with("BENCH_") || k.starts_with("APP_") || k.starts_with("ENV_") {
            map.insert(k, v);
        }
    }
    map
}

/// System metadata

pub fn collect_system_metadata(sys: &System) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // These are associated functions, not instance methods
    map.insert("os".to_string(), System::name().unwrap_or_default());
    map.insert("os_version".to_string(), System::os_version().unwrap_or_default());
    map.insert("machine".to_string(), System::host_name().unwrap_or_default());

    // Processor info from the first CPU
    map.insert(
        "processor".to_string(),
        sys.cpus().get(0).map(|c| c.brand().to_string()).unwrap_or_default(),
    );

    map.insert("container".to_string(), detect_container().unwrap_or_default());
    map
}

/// Master collector

pub fn collect_metadata() -> HashMap<String, serde_json::Value> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut map = HashMap::new();
    map.insert("schema_version".to_string(), serde_json::json!("2.0"));
    map.insert("benchmark_version".to_string(), serde_json::json!("1.0"));
    map.insert("run_id".to_string(), serde_json::json!(Uuid::new_v4().to_string()));
    map.insert(
        "timestamp".to_string(),
        serde_json::json!(chrono::Utc::now().to_rfc3339()),
    );

    map.insert("system".to_string(), serde_json::json!(collect_system_metadata(&sys)));
    map.insert("cpu".to_string(), serde_json::json!(collect_cpu_metadata(&sys)));
    map.insert("memory".to_string(), serde_json::json!(collect_memory_metadata(&sys)));
    map.insert("disk".to_string(), serde_json::json!(collect_disk_metadata(&sys)));
    map.insert("process".to_string(), serde_json::json!(collect_process_metadata(&sys)));
    map.insert("git".to_string(), serde_json::json!(collect_git_metadata()));
    map.insert("environment".to_string(), serde_json::json!(collect_environment_metadata()));

    map
}

// ### 🧩 Key Notes
// - Uses `sysinfo` crate for CPU, memory, disk, and process metadata.
// - Uses `uuid` and `chrono` crates for run ID and timestamp.
// - `safe_run` wraps shell commands like `git` or `lscpu`.
// - `detect_container` checks `/proc/1/cgroup` for Docker/Podman markers.
// - Returns metadata as a `HashMap<String, serde_json::Value>` so we can serialize easily.
