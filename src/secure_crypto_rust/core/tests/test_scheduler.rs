#[cfg(test)]
mod scheduler_tests {
    use crypto_core::stream_v2::parallelism::{Scheduler, WorkerTarget};


    #[test]
    fn dispatch_small_segment_goes_to_cpu() {
        let mut sched = Scheduler::new(2, 2, 4 * 1024 * 1024); // 4 MB threshold
        let target = sched.dispatch(1024 * 1024); // 1 MB
        match target {
            WorkerTarget::Cpu(_) => {} // expected
            WorkerTarget::Gpu(_) => panic!("1 MB segment should not go to GPU"),
        }
    }

    #[test]
    fn dispatch_large_segment_goes_to_gpu() {
        let mut sched = Scheduler::new(2, 2, 4 * 1024 * 1024); // 4 MB threshold
        let target = sched.dispatch(8 * 1024 * 1024); // 8 MB
        match target {
            WorkerTarget::Gpu(_) => {} // expected
            WorkerTarget::Cpu(_) => panic!("8 MB segment should have gone to GPU"),
        }
    }

    #[test]
    fn gpu_load_balancing() {
        let mut sched = Scheduler::new(0, 2, 4 * 1024 * 1024);
        let t1 = sched.dispatch(5 * 1024 * 1024);
        let t2 = sched.dispatch(6 * 1024 * 1024);
        assert_ne!(t1, t2, "two large segments should be balanced across GPUs");
    }
}
