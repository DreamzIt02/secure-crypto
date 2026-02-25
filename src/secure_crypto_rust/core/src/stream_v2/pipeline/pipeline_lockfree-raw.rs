use std::{io::{Read, Write}, sync::{Arc, atomic::{AtomicBool, Ordering}}, thread};

use bytes::Bytes;
use crossbeam::channel::bounded;

use crate::{stream_v2::{io, pipeline::{PipelineConfig, segment_processor::{ProcessedSegment, SegmentProcessor}}}, telemetry::{TelemetryCounters, TelemetrySnapshot}, types::StreamError};

pub fn process_stream_lockfree<P, R, W>(
    mut reader: R,
    mut writer: W,
    processor: Arc<P>,
    config: &PipelineConfig,
) -> Result<TelemetrySnapshot, StreamError>
where
    P: SegmentProcessor<Input = Bytes, Output = ProcessedSegment>,
    R: Read + Send,
    W: Write + Send,
{
    let inflight = config.profile.inflight_segments();

    let (seg_tx, seg_rx) = bounded::<(u32, Bytes)>(inflight);
    let (out_tx, out_rx) = bounded::<ProcessedSegment>(inflight);

    let cancelled = Arc::new(AtomicBool::new(false));

    thread::scope(|scope| {

        // ============================================================
        // Reader (bounded streaming)
        // ============================================================
        {
            let seg_tx = seg_tx.clone();
            let cancel = cancelled.clone();
            let segment_size = processor.segment_size();

            scope.spawn(move || -> Result<(), StreamError> {
                let mut index = 0u32;

                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }

                    let buf = io::read_exact_or_eof(&mut reader, segment_size)?;

                    if buf.is_empty() {
                        break;
                    }

                    seg_tx.send((index, Bytes::from(buf)))
                        .map_err(|_| StreamError::PipelineError("seg channel closed".into()))?;

                    index += 1;
                }

                drop(seg_tx);
                Ok(())
            });
        }

        drop(seg_tx);

        // ============================================================
        // Workers
        // ============================================================
        for _ in 0..config.profile.cpu_workers() {
            let rx = seg_rx.clone();
            let tx = out_tx.clone();
            let processor = processor.clone();
            let cancel = cancelled.clone();

            scope.spawn(move || {
                while let Ok((index, segment)) = rx.recv() {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }

                    match processor.process(index, segment) {
                        Ok(out) => {
                            if tx.send(out).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            cancel.store(true, Ordering::Relaxed);
                            let _ = tx.send(ProcessedSegment::fatal(e));
                            break;
                        }
                    }
                }
            });
        }

        drop(out_tx);
        drop(seg_rx);

        // ============================================================
        // Ordered writer (single commit authority)
        // ============================================================
        let mut ordered = OrderedCommit::new(&mut writer);
        let mut telemetry = TelemetryCounters::default();

        for seg in out_rx.iter() {
            if cancelled.load(Ordering::Relaxed) {
                break;
            }

            if seg.is_fatal() {
                cancelled.store(true, Ordering::Relaxed);
                return Err(seg.unwrap_err());
            }

            telemetry.merge(&seg.telemetry);

            ordered.push(seg)?;
        }

        ordered.finish()?;

        Ok::<_, StreamError>(())
    })?;

    Ok(TelemetrySnapshot::from_aggregator())
}
