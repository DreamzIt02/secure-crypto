// ## 3. `src/scheduler/policy.rs`

// Purpose: compaction policy + scheduler cycle.

//! scheduler/policy.rs
//! Hybrid compaction policy and scheduler cycle runner.

pub struct HybridCompactionPolicy {
    pub threshold: usize,
    pub compacted: bool,
}

impl HybridCompactionPolicy {
    pub fn new(threshold: usize) -> Self {
        Self { threshold, compacted: false }
    }

    pub fn should_compact(&self, current_size: usize) -> bool {
        current_size >= self.threshold
    }

    pub fn mark_compacted(&mut self) {
        self.compacted = true;
    }
}

/// Scheduler cycle runner
pub fn spawn_scheduler_cycle(policy: &mut HybridCompactionPolicy, log_size: usize) {
    if policy.should_compact(log_size) {
        policy.mark_compacted();
        // trigger compaction cycle
    }
}
