#[cfg(test)]
mod tests {
    use crypto_core::recovery::{UnifiedEntry, compact_unified_log};


    // #[test]
    // fn test_append_and_replay() {
    //     let mut log = LogManager::new("test_audit.log", 10);
    //     log.append(UnifiedEntry::Scheduler("cycle-start".into())).expect("REASON");
    //     log.append(UnifiedEntry::Encrypt(vec![1,2,3]));
    //     assert_eq!(log.replay().len(), 2);
    // }

    #[test]
    fn test_compaction_removes_redundant_scheduler() {
        let mut entries = vec![
            UnifiedEntry::Scheduler("cycle".into()),
            UnifiedEntry::Scheduler("cycle".into()),
            UnifiedEntry::Encrypt(vec![1]),
        ];
        compact_unified_log(&mut entries);
        assert_eq!(entries.len(), 2);
    }
}
