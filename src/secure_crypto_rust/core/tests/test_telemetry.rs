#[cfg(test)]
mod telemetry_snapshot_tests {
    use std::time::Duration;
    use std::collections::HashMap;

    use crypto_core::telemetry::{Stage, StageTimes, TelemetryCounters, TelemetrySnapshot, TelemetryTimer};

    fn make_counters() -> TelemetryCounters {
        TelemetryCounters {
            frames_header: 1,
            frames_data: 2,
            frames_digest: 1,
            frames_terminator: 1,
            bytes_plaintext: 100,
            bytes_compressed: 80,
            bytes_ciphertext: 120,
            bytes_overhead: 16,
        }
    }

    fn make_timer() -> TelemetryTimer {
        let mut timer = TelemetryTimer::new();
        std::thread::sleep(Duration::from_millis(20)); // ensure elapsed > stage times
        // simulate elapsed time
        timer.stage_times = StageTimes {
            times: {
                let mut map = HashMap::new();
                map.insert(Stage::Read, Duration::from_millis(5));
                map.insert(Stage::Write, Duration::from_millis(10));
                map
            }
        };
        timer.finish();
        timer
    }

    #[test]
    fn snapshot_initializes_output_none() {
        let counters = make_counters();
        let timer = make_timer();
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(3));

        assert!(snapshot.output.is_none());
    }

    #[test]
    fn attach_output_sets_output_field() {
        let counters = make_counters();
        let timer = make_timer();
        let mut snapshot = TelemetrySnapshot::from(&counters, &timer, Some(3));

        let buf = vec![1, 2, 3, 4];
        snapshot.attach_output(buf.clone());

        assert!(snapshot.output.is_some());
        assert_eq!(snapshot.output.unwrap(), buf);
    }

    #[test]
    fn compression_ratio_is_capped_at_one() {
        let mut counters = make_counters();
        counters.bytes_compressed = counters.bytes_plaintext * 2; // artificially inflate
        let timer = make_timer();
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(1));

        assert!(snapshot.compression_ratio <= 1.0);
    }

    #[test]
    fn throughput_is_computed() {
        let counters = make_counters();
        let timer = make_timer();
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(1));

        assert!(snapshot.throughput_plaintext_bytes_per_sec > 0.0);
    }

    #[test]
    fn sanity_check_passes_for_valid_snapshot() {
        let counters = make_counters();
        let timer = make_timer();
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(2));

        assert!(snapshot.sanity_check());
    }

    #[test]
    fn sanity_check_fails_if_ciphertext_less_than_compressed() {
        let mut counters = make_counters();
        counters.bytes_ciphertext = 50; // less than compressed
        let timer = make_timer();
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(1));

        assert!(!snapshot.sanity_check());
    }

    #[test]
    fn sanity_check_fails_if_stage_time_exceeds_elapsed() {
        let counters = make_counters();
        let mut timer = make_timer();
        // artificially inflate stage times
        timer.stage_times.times.insert(Stage::Encrypt, timer.elapsed() + Duration::from_millis(1));
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(1));

        assert!(!snapshot.sanity_check());
    }

    #[test]
    fn attach_output_and_output_bytes_match() {
        let counters = make_counters();
        let timer = make_timer();
        let mut snapshot = TelemetrySnapshot::from(&counters, &timer, Some(1));

        let buf = vec![0xde, 0xad, 0xbe, 0xef];
        snapshot.attach_output(buf.clone());

        assert_eq!(snapshot.output_bytes(), counters.bytes_ciphertext);
        assert_eq!(snapshot.output.unwrap(), buf);
    }

    #[test]
    fn total_stage_time_is_sum_of_stage_durations() {
        let counters = make_counters();
        let timer = make_timer();
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(2));

        let expected = Duration::from_millis(15);
        assert_eq!(snapshot.total_stage_time(), expected);
    }

    #[test]
    fn has_all_stages_detects_missing_stage() {
        let counters = make_counters();
        let timer = make_timer();
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(2));

        let expected = vec![Stage::Read, Stage::Write, Stage::Encrypt];
        assert!(!snapshot.has_all_stages(&expected));
    }

    #[test]
    fn output_bytes_matches_ciphertext_count() {
        let counters = make_counters();
        let timer = make_timer();
        let snapshot = TelemetrySnapshot::from(&counters, &timer, Some(2));

        assert_eq!(snapshot.output_bytes(), counters.bytes_ciphertext);
    }
}
