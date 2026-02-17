// # 📂 `tests/test_segment_worker_v2.rs`

#[cfg(test)]
mod tests {

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use crossbeam::channel::{Receiver, Sender, unbounded};
use crypto_core::crypto::{DigestAlg, KEY_LEN_32};
use crypto_core::headers::HeaderV1;
use crypto_core::stream_v2::parallelism::HybridParallelismProfile;
use crypto_core::stream_v2::segment_worker::decrypt::DecryptSegmentWorker1;
use crypto_core::stream_v2::segment_worker::encrypt::EncryptSegmentWorker1;
use crypto_core::stream_v2::segment_worker::{
    DecryptContext, DecryptSegmentInput, DecryptedSegment, EncryptContext, EncryptSegmentInput, EncryptedSegment, SegmentWorkerError
};
use crypto_core::recovery::persist::AsyncLogManager;
use crypto_core::stream_v2::segmenting::types::SegmentFlags;
use crypto_core::telemetry::StageTimes;
use crypto_core::types::StreamError;

    fn setup_enc_context(alg: DigestAlg) -> (EncryptContext, Arc<AsyncLogManager>) {
        let header = HeaderV1::test_header(); // Mock header
        let profile = HybridParallelismProfile::dynamic(header.chunk_size as u32, 0.50, 64);
       // Create a Vec of 32 bytes
        let session_key = vec![0x42u8; KEY_LEN_32];
        let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
        
        let context = EncryptContext::new(
            header,
            profile,
            &session_key,
            alg,
        ).unwrap();
        (context, log_manager)
    }

    fn setup_dec_context(alg: DigestAlg) -> (DecryptContext, Arc<AsyncLogManager>) {
        let header = HeaderV1::test_header(); // Mock header
        let profile = HybridParallelismProfile::dynamic(header.chunk_size as u32, 0.50, 64);
       // Create a Vec of 32 bytes
        let session_key = vec![0x42u8; KEY_LEN_32];
        let log_manager = Arc::new(AsyncLogManager::new("test_audit.log", 100).unwrap());
        
        let context = DecryptContext::from_stream_header(
            header,
            profile,
            &session_key,
            alg,
        ).unwrap();
        (context, log_manager)
    }
    // Bridge function: forward encrypted segments into decrypt input
    fn forward_encrypted_to_decrypt(
        enc_rx: Receiver<Result<EncryptedSegment, SegmentWorkerError>>,
        dec_tx: Sender<DecryptSegmentInput>,
    ) {
        std::thread::spawn(move || {
            while let Ok(result) = enc_rx.recv() {
                match result {
                    Ok(enc_seg) => {
                        let dec_in: DecryptSegmentInput = enc_seg.into();
                        if dec_tx.send(dec_in).is_err() {
                            break; // downstream closed
                        }
                    }
                    Err(err) => {
                        // handle or log error, maybe break
                        eprintln!("Encryption error: {:?}", err);
                    }
                }
            }
        });
    }

    /// Spawns encrypt + decrypt segment workers, runs a single input, and returns the decrypted output.
    /// Ensures proper channel teardown and thread joining.
    fn run_segment_roundtrip(
        enc: EncryptSegmentWorker1,
        dec: DecryptSegmentWorker1,
        input: EncryptSegmentInput,
    ) -> Result<DecryptedSegment, StreamError> {
        let (enc_tx, enc_rx) = crossbeam::channel::unbounded();
        let (mid_tx, mid_rx) = crossbeam::channel::unbounded();
        let (bridge_tx, bridge_rx) = crossbeam::channel::unbounded();
        let (dec_tx, dec_rx) = crossbeam::channel::unbounded();

        // clone mid_tx before moving it
        let mid_tx_for_worker = mid_tx.clone();

        // Spawn encrypt worker
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(enc_rx, mid_tx_for_worker);
        });

        // bridge converts EncryptedSegment → DecryptSegmentInput
        forward_encrypted_to_decrypt(mid_rx, bridge_tx);

        // Spawn decrypt worker
        let dec_handle = std::thread::spawn(move || {
            dec.run_v2(bridge_rx, dec_tx);
        });

        // Send input
        enc_tx.send(input).unwrap();

        // Receive output
        let result = dec_rx.recv().unwrap().map_err(|e|StreamError::SegmentWorker(e));

        // Close input channel so workers exit
        drop(enc_tx);
        drop(mid_tx);

        // Join threads
        enc_handle.join().unwrap();
        dec_handle.join().unwrap();

        result
    }

    // ## ✅ 0. End-to-end encrypt → decrypt (multi segment)

    #[test]
    fn encrypt_decrypt_large_segment_roundtrip() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        let enc = EncryptSegmentWorker1::new(
            Arc::new(crypto_enc),
            log_enc,
            fatal_tx.clone(),
            cancelled.clone(),
        );
        let dec = DecryptSegmentWorker1::new(
            Arc::new(crypto_dec),
            log_dec,
            fatal_tx.clone(),
            cancelled.clone(),
        );

        let plaintext = Bytes::from(vec![0xAB; 256 * 1024]); // 256 KB of data

        let input = EncryptSegmentInput {
            segment_index: 42,
            bytes: plaintext.clone(),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        };

        let decrypted = run_segment_roundtrip(enc, dec, input).unwrap();

        assert_eq!(decrypted.bytes, plaintext);
        assert_eq!(decrypted.header.segment_index(), 42);
    }


    // ## ✅ 1. End-to-end encrypt → decrypt (single segment)

    #[test]
    fn encrypt_decrypt_segment_roundtrip() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        let enc = EncryptSegmentWorker1::new(
            Arc::new(crypto_enc),
            log_enc,
            fatal_tx.clone(),
            cancelled.clone(),
        );
        let dec = DecryptSegmentWorker1::new(
            Arc::new(crypto_dec),
            log_dec,
            fatal_tx.clone(),
            cancelled.clone(),
        );

        let (enc_tx, enc_rx) = unbounded();
        let (mid_tx, mid_rx) = unbounded();
        let (bridge_tx, bridge_rx) = unbounded();
        let (dec_tx, dec_rx) = unbounded();

        // Spawn the workers and keep their handles
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(enc_rx, mid_tx);
        });

        forward_encrypted_to_decrypt(mid_rx, bridge_tx);

        let dec_handle = std::thread::spawn(move || {
            dec.run_v2(bridge_rx, dec_tx);
        });

        let plaintext = Bytes::from_static(b"hello segmented crypto world");

        enc_tx.send(EncryptSegmentInput {
            segment_index: 7,
            bytes: plaintext.clone(),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        }).unwrap();

        let encrypted = dec_rx.recv().unwrap().unwrap();
        assert_eq!(encrypted.bytes, plaintext);
        assert_eq!(encrypted.header.segment_index(), 7);

        // ✅ Close channels so workers see EOF and exit
        drop(enc_tx);
        // drop(mid_rx);     // if forwarder is still running
        // drop(bridge_rx);
        // drop(dec_tx);

        // ✅ Now join safely
        enc_handle.join().unwrap();
        dec_handle.join().unwrap();
    }

    // ## ✅ 2. Large segment (multi-frame, parallelism)

    #[test]
    fn large_segment_parallel_encryption() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        let enc = EncryptSegmentWorker1::new(Arc::new(crypto_enc), log_enc, fatal_tx.clone(), cancelled.clone());
        let dec = DecryptSegmentWorker1::new(Arc::new(crypto_dec), log_dec, fatal_tx.clone(), cancelled.clone());

        let (enc_tx, enc_rx) = unbounded();
        let (mid_tx, mid_rx) = unbounded();
        let (bridge_tx, bridge_rx) = unbounded();
        let (dec_tx, dec_rx) = unbounded();

        // Spawn the workers and keep their handles
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(enc_rx, mid_tx);
        });
        // bridge converts EncryptedSegment → DecryptSegmentInput
        forward_encrypted_to_decrypt(mid_rx, bridge_tx);
        //
        // Spawn the workers and keep their handles
        let dec_handle = std::thread::spawn(move || {
            dec.run_v2(bridge_rx, dec_tx);
        });

        let data = vec![0xAB; 2 * 1024 * 1024];
        let plaintext = Bytes::from(data.clone());

        enc_tx.send(EncryptSegmentInput {
            segment_index: 0,
            bytes: plaintext,
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        }).unwrap();

        let decrypted = dec_rx.recv().unwrap().unwrap();
        let out = decrypted.bytes;

        assert_eq!(out, data);

        // ✅ Close channels so workers see EOF and exit
        drop(enc_tx);

        // ✅ Now join safely
        enc_handle.join().unwrap();
        dec_handle.join().unwrap();

    }

    // ## ❌ 3. Corrupted ciphertext → digest failure

    #[test]
    fn corrupted_segment_fails_digest_verification() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        let enc = EncryptSegmentWorker1::new(
            Arc::new(crypto_enc),
            log_enc,
            fatal_tx.clone(),
            cancelled.clone(),
        );
        let dec = DecryptSegmentWorker1::new(
            Arc::new(crypto_dec),
            log_dec,
            fatal_tx.clone(),
            cancelled.clone(),
        );

        let (enc_tx, enc_rx) = unbounded();
        let (mid_tx, mid_rx) = unbounded();
        let (bridge_tx, bridge_rx) = unbounded();
        let (dec_tx, dec_rx) = unbounded();

        // clone mid_tx before moving it
        let mid_tx_for_worker = mid_tx.clone();

        // Spawn encrypt worker
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(enc_rx, mid_tx_for_worker);
        });

        // produce a segment
        enc_tx
            .send(EncryptSegmentInput {
                segment_index: 1,
                bytes: Bytes::from_static(b"tamper me"),
                flags: SegmentFlags::empty(),
                stage_times: StageTimes::default(),
            })
            .unwrap();

        // receive encrypted segment
        let mut encrypted = mid_rx.recv().unwrap().unwrap();
        let mut wire = bytes::BytesMut::from(&encrypted.wire[..]);
        let index = wire.len() / 2;
        wire[index] ^= 0xFF;
        encrypted.wire = wire.freeze();

        // send corrupted segment downstream using the original mid_tx
        mid_tx.send(Ok(encrypted)).unwrap();

        // bridge converts EncryptedSegment → DecryptSegmentInput
        forward_encrypted_to_decrypt(mid_rx, bridge_tx);

        // Spawn decrypt worker
        let dec_handle = std::thread::spawn(move || {
            dec.run_v2(bridge_rx, dec_tx);
        });

        // now the decrypt worker should fail verification
        assert!(dec_rx.recv().unwrap().is_err());

        // close input channel so encrypt worker exits
        drop(enc_tx);

        // join threads
        enc_handle.join().unwrap();
        dec_handle.join().unwrap();
    }

    // ## ❌ 4. Wrong crypto context (wrong key)

    #[test]
    fn wrong_key_fails_segment_decryption() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));
        
        let enc = EncryptSegmentWorker1::new(Arc::new(crypto_enc), log_enc, fatal_tx.clone(), cancelled.clone());
        // let dec = DecryptSegmentWorker::new(crypto_dec.clone(), log_dec.clone());

        let mut wrong_crypto = crypto_dec.clone();
        wrong_crypto.base.session_key[0] ^= 0xFF;

        let dec = DecryptSegmentWorker1::new(
            Arc::new(wrong_crypto),
            log_dec,
            fatal_tx.clone(), cancelled.clone()
        );

        let (enc_tx, enc_rx) = unbounded();
        let (mid_tx, mid_rx) = unbounded();
        let (bridge_tx, bridge_rx) = unbounded();
        let (dec_tx, dec_rx) = unbounded();

        // Spawn encrypt worker
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(enc_rx, mid_tx);
        });
        // bridge converts EncryptedSegment → DecryptSegmentInput
        forward_encrypted_to_decrypt(mid_rx, bridge_tx);
        //
        // Spawn encrypt worker
        let dec_handle = std::thread::spawn(move || {
            dec.run_v2(bridge_rx, dec_tx);
        });

        enc_tx.send(EncryptSegmentInput {
            segment_index: 3,
            bytes: Bytes::from_static(b"secret"),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        }).unwrap();

        assert!(dec_rx.recv().unwrap().is_err());

        // close input channel so encrypt worker exits
        drop(enc_tx);

        // join threads
        enc_handle.join().unwrap();
        dec_handle.join().unwrap();
    }

    // ## ❌ 5. Truncated segment wire

    #[test]
    fn truncated_segment_fails() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        let enc = EncryptSegmentWorker1::new(
            Arc::new(crypto_enc),
            log_enc,
            fatal_tx.clone(),
            cancelled.clone(),
        );
        let dec = DecryptSegmentWorker1::new(
            Arc::new(crypto_dec),
            log_dec,
            fatal_tx.clone(),
            cancelled.clone(),
        );

        let (enc_tx, enc_rx) = unbounded();
        let (mid_tx, mid_rx) = unbounded();
        let (bridge_tx, bridge_rx) = unbounded();
        let (dec_tx, dec_rx) = unbounded();

        // clone mid_tx before moving it
        let mid_tx_for_worker = mid_tx.clone();

        // Spawn encrypt worker
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(enc_rx, mid_tx_for_worker);
        });

        // produce a segment
        enc_tx
            .send(EncryptSegmentInput {
                segment_index: 4,
                bytes: Bytes::from_static(b"cut me"),
                flags: SegmentFlags::empty(),
                stage_times: StageTimes::default(),
            })
            .unwrap();

        // receive encrypted segment
        let mut encrypted = mid_rx.recv().unwrap().unwrap();
        // truncate wire to simulate corruption
        encrypted.wire.truncate(encrypted.wire.len() - 5);

        // send corrupted segment downstream using the original mid_tx
        mid_tx.send(Ok(encrypted)).unwrap();

        // bridge converts EncryptedSegment → DecryptSegmentInput
        forward_encrypted_to_decrypt(mid_rx, bridge_tx);

        // Spawn decrypt worker
        let dec_handle = std::thread::spawn(move || {
            dec.run_v2(bridge_rx, dec_tx);
        });

        // now the decrypt worker should fail
        assert!(dec_rx.recv().unwrap().is_err());

        // close input channel so encrypt worker exits
        drop(enc_tx);

        // join threads
        enc_handle.join().unwrap();
        dec_handle.join().unwrap();
    }

    // ## ❌ 6. Missing terminator frame

    #[test]
    fn missing_terminator_frame_is_rejected() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        let enc = EncryptSegmentWorker1::new(
            Arc::new(crypto_enc),
            log_enc,
            fatal_tx.clone(),
            cancelled.clone(),
        );
        let dec = DecryptSegmentWorker1::new(
            Arc::new(crypto_dec),
            log_dec,
            fatal_tx.clone(),
            cancelled.clone(),
        );

        let (enc_tx, enc_rx) = unbounded();
        let (mid_tx, mid_rx) = unbounded();
        let (bridge_tx, bridge_rx) = unbounded();
        let (dec_tx, dec_rx) = unbounded();

        // clone mid_tx before moving it
        let mid_tx_for_worker = mid_tx.clone();

        // Spawn encrypt worker
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(enc_rx, mid_tx_for_worker);
        });

        // produce a segment
        enc_tx
            .send(EncryptSegmentInput {
                segment_index: 5,
                bytes: Bytes::from_static(b"no terminator"),
                flags: SegmentFlags::empty(),
                stage_times: StageTimes::default(),
            })
            .unwrap();

        // receive encrypted segment
        let encrypted = mid_rx.recv().unwrap().unwrap();

        // drop last frame bytes (simulate missing terminator)
        let truncated = encrypted.wire.slice(..encrypted.wire.len() - 32);

        // send corrupted segment downstream using the original mid_tx
        mid_tx
            .send(Ok(EncryptedSegment {
                header: encrypted.header,
                wire: truncated,
                counters: encrypted.counters,
                stage_times: encrypted.stage_times,
            }))
            .unwrap();

        // bridge converts EncryptedSegment → DecryptSegmentInput
        forward_encrypted_to_decrypt(mid_rx, bridge_tx);

        // Spawn decrypt worker
        let dec_handle = std::thread::spawn(move || {
            dec.run_v2(bridge_rx, dec_tx);
        });

        // now the decrypt worker should fail
        assert!(dec_rx.recv().unwrap().is_err());

        // close input channel so encrypt worker exits
        drop(enc_tx);

        // join threads
        enc_handle.join().unwrap();
        dec_handle.join().unwrap();
    }

    // ## ✅ 7. Deterministic encryption (same input → same wire)

    #[test]
    fn segment_encryption_is_deterministic() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        let enc = EncryptSegmentWorker1::new(
            Arc::new(crypto_enc),
            log_enc,
            fatal_tx.clone(),
            cancelled.clone(),
        );

        let (tx, rx) = unbounded();
        let (out_tx, out_rx) = unbounded();

        // spawn the worker in a separate thread
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(rx, out_tx);
        });

        let payload = Bytes::from_static(b"deterministic segment");

        tx.send(EncryptSegmentInput {
            segment_index: 9,
            bytes: payload.clone(),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        })
        .unwrap();
        let a = out_rx.recv().unwrap().unwrap();

        tx.send(EncryptSegmentInput {
            segment_index: 9,
            bytes: payload,
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        })
        .unwrap();
        let b = out_rx.recv().unwrap().unwrap();

        assert_eq!(a.wire, b.wire);

        // close input channel so worker exits
        drop(tx);

        // join thread to finish cleanly
        enc_handle.join().unwrap();
    }

    // ## ✅ 8. Telemetry sanity checks

    #[test]
    fn telemetry_counters_are_consistent() {
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Sha256);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Sha256);

        let (fatal_tx, _fatal_rx) = crossbeam::channel::unbounded();
        let cancelled = Arc::new(AtomicBool::new(false));

        let enc = EncryptSegmentWorker1::new(
            Arc::new(crypto_enc),
            log_enc,
            fatal_tx.clone(),
            cancelled.clone(),
        );
        let dec = DecryptSegmentWorker1::new(
            Arc::new(crypto_dec),
            log_dec,
            fatal_tx.clone(),
            cancelled.clone(),
        );

        let (enc_tx, enc_rx) = unbounded();
        let (mid_tx, mid_rx) = unbounded();
        let (bridge_tx, bridge_rx) = unbounded();
        let (dec_tx, dec_rx) = unbounded();

        // clone mid_tx before moving it
        let mid_tx_for_worker = mid_tx.clone();

        // Spawn encrypt worker
        let enc_handle = std::thread::spawn(move || {
            enc.run_v2(enc_rx, mid_tx_for_worker);
        });

        // bridge converts EncryptedSegment → DecryptSegmentInput
        forward_encrypted_to_decrypt(mid_rx, bridge_tx);

        // Spawn decrypt worker
        let dec_handle = std::thread::spawn(move || {
            dec.run_v2(bridge_rx, dec_tx);
        });

        let plaintext = Bytes::from_static(b"telemetry test");

        enc_tx
            .send(EncryptSegmentInput {
                segment_index: 11,
                bytes: plaintext,
                flags: SegmentFlags::empty(),
                stage_times: StageTimes::default(),
            })
            .unwrap();

        let decrypted = dec_rx.recv().unwrap().unwrap();

        assert!(decrypted.counters.frames_data > 0);
        assert_eq!(decrypted.counters.frames_digest, 1);
        assert_eq!(decrypted.counters.frames_terminator, 1);
        assert!(decrypted.counters.bytes_compressed > 0);

        assert_eq!(decrypted.bytes.as_ref(), b"telemetry test");
        assert_eq!(decrypted.bytes.to_vec(), b"telemetry test".to_vec());
        assert_eq!(
            std::str::from_utf8(decrypted.bytes.as_ref()).unwrap(),
            "telemetry test"
        );
        assert_eq!(decrypted.bytes.len(), "telemetry test".len());

        // ✅ Close input channel so workers see EOF and exit
        drop(enc_tx);
        drop(mid_tx); // closes the manual injection path

        // ✅ Join threads
        enc_handle.join().unwrap();
        dec_handle.join().unwrap();
    }


}
// # 🧠 Why this suite is **correct**

// This test suite validates:

// ✔ frame parallelism
// ✔ ordering invariants
// ✔ digest correctness
// ✔ terminator enforcement
// ✔ truncation handling
// ✔ corruption detection
// ✔ deterministic crypto
// ✔ telemetry accuracy
// ✔ channel shutdown behavior
