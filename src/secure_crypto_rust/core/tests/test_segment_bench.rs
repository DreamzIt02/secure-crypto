// # 📂 `tests/test_segment_bench.rs`

#[cfg(test)]
mod tests {
    use std::{sync::{Arc, atomic::AtomicBool}, thread};

    use bytes::Bytes;
    use crossbeam::channel::{Receiver, Sender, unbounded};
    use crypto_core::{crypto::{DigestAlg, KEY_LEN_32}, headers::HeaderV1, recovery::AsyncLogManager, stream_v2::{parallelism::HybridParallelismProfile, segment_worker::{DecryptContext, DecryptSegmentInput, DecryptSegmentWorker1, DecryptedSegment, EncryptContext, EncryptSegmentInput, EncryptSegmentWorker1, EncryptedSegment, SegmentWorkerError}, segmenting::types::SegmentFlags}, telemetry::StageTimes, types::StreamError};

    fn setup_enc_context(alg: DigestAlg, chunk_size: usize) -> (EncryptContext, Arc<AsyncLogManager>) {
        let header = HeaderV1{ chunk_size: chunk_size as u32, ..HeaderV1::test_header() }; // Mock header
        let profile = HybridParallelismProfile::semi_dynamic(header.chunk_size as u32, 0.50, 64);
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

    fn setup_dec_context(alg: DigestAlg, chunk_size: usize) -> (DecryptContext, Arc<AsyncLogManager>) {
        let header = HeaderV1{ chunk_size: chunk_size as u32, ..HeaderV1::test_header() }; // Mock header
        let profile = HybridParallelismProfile::semi_dynamic(header.chunk_size as u32, 0.50, 64);
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

    fn run_segment_encrypt(
        enc: EncryptSegmentWorker1,
        input: EncryptSegmentInput,
    ) -> Result<EncryptedSegment, StreamError> {
        let (enc_tx, enc_rx) = crossbeam::channel::unbounded();
        let (mid_tx, mid_rx) = crossbeam::channel::unbounded();

        let enc_handle = std::thread::spawn(move || {
            enc.run_v1(enc_rx, mid_tx);
        });

        enc_tx.send(input).map_err(|_| StreamError::ChannelSend)?;
        drop(enc_tx);

        let enc_result = mid_rx.recv()
            .map_err(|_| StreamError::ChannelRecv)?
            .map_err(StreamError::SegmentWorker)?;

        drop(mid_rx);

        enc_handle.join().map_err(|_| StreamError::ThreadPanic)?;

        Ok(enc_result)
    }

    fn run_segment_decrypt(
        dec: DecryptSegmentWorker1,
        enc_seg: EncryptedSegment,
    ) -> Result<DecryptedSegment, StreamError> {
        let (bridge_tx, bridge_rx) = crossbeam::channel::unbounded();
        let (dec_tx, dec_rx) = crossbeam::channel::unbounded();

        let dec_handle = std::thread::spawn(move || {
            dec.run_v1(bridge_rx, dec_tx);
        });

        let dec_in: DecryptSegmentInput = enc_seg.into();
        bridge_tx.send(dec_in).map_err(|_| StreamError::ChannelSend)?;
        drop(bridge_tx);

        let dec_result = dec_rx.recv()
            .map_err(|_| StreamError::ChannelRecv)?
            .map_err(StreamError::SegmentWorker)?;

        drop(dec_rx);

        dec_handle.join().map_err(|_| StreamError::ThreadPanic)?;

        Ok(dec_result)
    }
    
    // Bridge function: forward encrypted segments into decrypt input
    fn forward_encrypted_to_decrypt(
        enc_rx: Receiver<Result<EncryptedSegment, SegmentWorkerError>>,
        dec_tx: Sender<DecryptSegmentInput>,
    ) -> Receiver<Result<EncryptedSegment, SegmentWorkerError>> {
        // Channel to return encrypted segments (or errors) back to caller
        let (result_tx, result_rx) = unbounded();

        thread::spawn(move || {
            while let Ok(result) = enc_rx.recv() {
                match result {
                    Ok(enc_seg) => {
                        // forward to decrypt
                        let dec_in: DecryptSegmentInput = enc_seg.clone().into();
                        if dec_tx.send(dec_in).is_err() {
                            break; // downstream closed
                        }
                        // send encrypted segment back to caller
                        if result_tx.send(Ok(enc_seg)).is_err() {
                            break; // caller dropped
                        }
                    }
                    Err(err) => {
                        eprintln!("Encryption error: {:?}", err);
                        // propagate error to caller
                        if result_tx.send(Err(err)).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        result_rx
    }

    /// Spawns encrypt + decrypt segment workers, runs a single input, and returns the decrypted output.
    /// Ensures proper channel teardown and thread joining.
    fn run_segment_roundtrip(
        enc: EncryptSegmentWorker1,
        dec: DecryptSegmentWorker1,
        input: EncryptSegmentInput,
    ) -> Result<(EncryptedSegment, DecryptedSegment), StreamError> {
        let (enc_tx, enc_rx) = crossbeam::channel::unbounded();
        let (mid_tx, mid_rx) = crossbeam::channel::unbounded();
        let (bridge_tx, bridge_rx) = crossbeam::channel::unbounded();
        let (dec_tx, dec_rx) = crossbeam::channel::unbounded();

        // Spawn encrypt worker
        let enc_handle = std::thread::spawn(move || {
            enc.run_v1(enc_rx, mid_tx);
        });

        // Spawn decrypt worker
        let dec_handle = std::thread::spawn(move || {
            dec.run_v1(bridge_rx, dec_tx);
        });

        // Spawn bridge
        let result_rx = forward_encrypted_to_decrypt(mid_rx, bridge_tx);

        // ✅ Send input FIRST
        enc_tx.send(input).unwrap();

        // Close input so encrypt worker exits after 1 segment
        drop(enc_tx);

        // Receive encrypted segment
        let enc_result = result_rx
            .recv()
            .unwrap()
            .map_err(StreamError::SegmentWorker)?;

        // Receive decrypted segment
        let dec_result = dec_rx
            .recv()
            .unwrap()
            .map_err(StreamError::SegmentWorker)?;

        // Close receivers so bridge exits
        drop(result_rx);
        drop(dec_rx);

        enc_handle.join().unwrap();
        dec_handle.join().unwrap();

        Ok((enc_result, dec_result))
    }
    
    #[test]
    fn encrypt_large_segment() {
        let chunk_size = 32 * 1024 * 1024; // 32 MB
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Blake3, chunk_size);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Blake3, chunk_size);

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
            fatal_tx,
            cancelled,
        );

         // Step 1: initialize workers once
        let plaintext = Bytes::from(vec![0xAB; chunk_size]);

        let input = EncryptSegmentInput {
            segment_index: 42,
            bytes: plaintext.clone(),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        };

        let encrypted = run_segment_encrypt(enc, input).unwrap();

        assert!(encrypted.wire.len() > plaintext.len());

        let decrypted = run_segment_decrypt(dec, encrypted.clone()).unwrap();

        assert_eq!(decrypted.bytes, plaintext);

        println!("{}", encrypted.stage_times);
        println!("{}", decrypted.stage_times);

    }

    #[test]
    fn encrypt_decrypt_large_segment_roundtrip() {
        let chunk_size = 32 * 1024 * 1024; // 32 MB
        let (crypto_enc, log_enc) = setup_enc_context(DigestAlg::Blake3, chunk_size);
        let (crypto_dec, log_dec) = setup_dec_context(DigestAlg::Blake3, chunk_size);

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

        let plaintext = Bytes::from(vec![0xAB; chunk_size]);

        let input = EncryptSegmentInput {
            segment_index: 42,
            bytes: plaintext.clone(),
            flags: SegmentFlags::empty(),
            stage_times: StageTimes::default(),
        };

        let (encrypted, decrypted) = run_segment_roundtrip(enc, dec, input).unwrap();

        assert_eq!(decrypted.bytes, plaintext);
        assert_eq!(decrypted.header.segment_index(), 42);

        println!("{}", encrypted.counters);
        println!("{}", encrypted.stage_times);
        println!("{}", decrypted.counters);
        println!("{}", decrypted.stage_times);

    }

}
