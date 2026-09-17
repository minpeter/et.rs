use super::*;
use crate::client_terminal::TerminalModeState;
use std::sync::mpsc;

struct BatchWriter {
    writes: mpsc::Sender<Vec<u8>>,
    results: mpsc::Receiver<io::Result<usize>>,
    flushes: Arc<Mutex<usize>>,
}

impl Write for BatchWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes.send(bytes.to_vec()).unwrap();
        self.results.recv_timeout(Duration::from_secs(3)).unwrap()
    }

    fn flush(&mut self) -> io::Result<()> {
        *self.flushes.lock().unwrap() += 1;
        Ok(())
    }
}

#[test]
fn adjacent_admitted_packets_render_once_and_keep_packet_accounting() {
    for mode in [
        FlowControlMode::None,
        FlowControlMode::Backpressure,
        FlowControlMode::Discard,
    ] {
        let (writes, written) = mpsc::channel();
        let (results, responses) = mpsc::channel();
        let flushes = Arc::new(Mutex::new(0));
        let mut output = ConsoleOutput::new(
            mode,
            Box::new(BatchWriter {
                writes,
                results: responses,
                flushes: Arc::clone(&flushes),
            }),
        )
        .unwrap();
        let modes = TerminalModeState::default();
        let other_modes = TerminalModeState::default();
        assert!(output.try_write(b"gate", &modes).unwrap());
        assert_eq!(written.recv().unwrap(), b"gate");
        // Distinct trackers and a split mode sequence must retain their owners.
        for (packet, tracker) in [
            (b"\x1b[2J\x1b[H\x1b[?1049".as_slice(), &modes),
            (b"hpaint\x1b[6n", &modes),
            (b"\x1b[?1049l\x1b[6n\x1b[6n", &other_modes),
            (b"\x1b[", &modes),
            (b"6n", &modes),
        ] {
            assert!(output.try_write(packet, tracker).unwrap());
        }
        results.send(Ok(4)).unwrap();
        let batch = written.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            batch,
            b"\x1b[2J\x1b[H\x1b[?1049hpaint\x1b[6n\x1b[?1049l\x1b[6n\x1b[6n\x1b[6n"
        );
        assert!(!modes.alternate_screen());
        assert_eq!(output.take_cursor_reports().unwrap(), 0);
        assert_eq!(*flushes.lock().unwrap(), 1);
        // Stop admission without losing access to completion accounting.
        output
            .shared
            .as_ref()
            .unwrap()
            .state
            .lock()
            .unwrap()
            .stopping = true;
        results.send(Ok(batch.len())).unwrap();
        output.wait_worker_done();
        assert!(modes.alternate_screen());
        assert!(!other_modes.alternate_screen());
        // Existing semantics: one report per packet containing a full request,
        // not per sequence, and no new report assembled across packet edges.
        assert_eq!(output.take_cursor_reports().unwrap(), 2);
        assert_eq!(output.take_cursor_reports().unwrap(), 0);
        assert_eq!(*flushes.lock().unwrap(), 2);
        assert_eq!(output.worker_progress().unwrap(), 2);
        assert!(written.try_recv().is_err());
        output.finish_gracefully().unwrap();
    }
}

#[test]
fn batched_partial_writes_retry_exact_suffix_and_report_progress() {
    let (writes, written) = mpsc::channel();
    let (results, responses) = mpsc::channel();
    let flushes = Arc::new(Mutex::new(0));
    let mut output = ConsoleOutput::new(
        FlowControlMode::Backpressure,
        Box::new(BatchWriter {
            writes,
            results: responses,
            flushes: Arc::clone(&flushes),
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"gate", &modes).unwrap());
    assert_eq!(written.recv().unwrap(), b"gate");
    assert!(output.try_write(b"ab\x1b[?1049", &modes).unwrap());
    assert!(output.try_write(b"hXYZ\x1b[6n", &modes).unwrap());
    results.send(Ok(4)).unwrap();
    assert_eq!(written.recv().unwrap(), b"ab\x1b[?1049hXYZ\x1b[6n");
    results.send(Ok(3)).unwrap();
    assert_eq!(written.recv().unwrap(), b"[?1049hXYZ\x1b[6n");
    assert_eq!(output.worker_progress().unwrap(), 2);
    results
        .send(Err(io::ErrorKind::Interrupted.into()))
        .unwrap();
    assert_eq!(written.recv().unwrap(), b"[?1049hXYZ\x1b[6n");
    assert_eq!(output.worker_progress().unwrap(), 2);
    results.send(Ok(9)).unwrap();
    assert_eq!(written.recv().unwrap(), b"Z\x1b[6n");
    assert_eq!(output.worker_progress().unwrap(), 3);
    assert!(!modes.alternate_screen());
    assert_eq!(output.take_cursor_reports().unwrap(), 0);
    assert_eq!(*flushes.lock().unwrap(), 3);
    output
        .shared
        .as_ref()
        .unwrap()
        .state
        .lock()
        .unwrap()
        .stopping = true;
    results.send(Ok(5)).unwrap();
    output.wait_worker_done();
    assert_eq!(output.worker_progress().unwrap(), 4);
    assert!(modes.alternate_screen());
    assert_eq!(output.take_cursor_reports().unwrap(), 1);
    assert_eq!(*flushes.lock().unwrap(), 4);
    output.finish_gracefully().unwrap();
}

#[test]
fn delivered_packet_is_confirmed_before_batched_suffix_fails() {
    let (writes, written) = mpsc::channel();
    let (results, responses) = mpsc::channel();
    let flushes = Arc::new(Mutex::new(0));
    let mut output = ConsoleOutput::new(
        FlowControlMode::None,
        Box::new(BatchWriter {
            writes,
            results: responses,
            flushes: Arc::clone(&flushes),
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"gate", &modes).unwrap());
    assert_eq!(written.recv().unwrap(), b"gate");
    assert!(output.try_write(b"\x1b[?1049h\x1b[6n", &modes).unwrap());
    assert!(output.try_write(b"\x1b[?1049l\x1b[6n", &modes).unwrap());
    results.send(Ok(4)).unwrap();
    assert_eq!(
        written.recv().unwrap(),
        b"\x1b[?1049h\x1b[6n\x1b[?1049l\x1b[6n"
    );
    results.send(Ok(12)).unwrap();
    assert_eq!(written.recv().unwrap(), b"\x1b[?1049l\x1b[6n");
    // The suffix is still blocked. Cleanup and cursor replies must already
    // know that the first original packet crossed the flush boundary.
    assert!(modes.alternate_screen());
    assert_eq!(output.take_cursor_reports().unwrap(), 1);
    assert_eq!(output.worker_progress().unwrap(), 2);
    results.send(Err(io::ErrorKind::BrokenPipe.into())).unwrap();
    output.wait_worker_done();
    assert!(modes.alternate_screen());
    assert_eq!(output.take_cursor_reports().unwrap(), 0);
    assert_eq!(*flushes.lock().unwrap(), 2);
    assert_eq!(
        output.finish_gracefully().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn flush_retry_never_rewrites_accepted_bytes_or_confirms_failed_flush() {
    struct FlushWriter {
        bytes: Vec<u8>,
        failure: Option<io::ErrorKind>,
    }
    impl Write for FlushWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.failure.take().map_or(Ok(()), |kind| Err(kind.into()))
        }
    }
    for failure in [io::ErrorKind::Interrupted, io::ErrorKind::BrokenPipe] {
        let output = ConsoleOutput::new(FlowControlMode::None, Box::new(Vec::<u8>::new())).unwrap();
        let mut writer = FlushWriter {
            bytes: Vec::new(),
            failure: Some(failure),
        };
        let mut delivered = Vec::new();
        let result = write_all_with_progress(
            output.shared.as_ref().unwrap(),
            &mut writer,
            b"unique",
            &mut |count| delivered.push(count),
        );
        assert_eq!(writer.bytes, b"unique");
        assert_eq!(output.worker_progress().unwrap(), 1);
        if failure == io::ErrorKind::Interrupted {
            result.unwrap();
            assert_eq!(delivered, [6]);
        } else {
            assert_eq!(result.unwrap_err().kind(), failure);
            assert!(delivered.is_empty());
        }
    }
}

#[test]
fn windows_helper_acknowledgements_confirm_prefix_before_later_failure() {
    for final_ack in [0u32, 7, 8] {
        let output = ConsoleOutput::new(FlowControlMode::None, Box::new(Vec::<u8>::new())).unwrap();
        let acks = [
            3u32.to_le_bytes(),
            final_ack.to_le_bytes(),
            0u32.to_le_bytes(),
        ]
        .concat();
        let mut writer = WindowsHelperWriter {
            input: Vec::new(),
            ack: io::Cursor::new(acks),
        };
        let mut delivered = Vec::new();
        let result = write_all_with_progress(
            output.shared.as_ref().unwrap(),
            &mut writer,
            b"0123456789",
            &mut |count| delivered.push(count),
        );
        assert_eq!(
            writer.input,
            [10u32.to_le_bytes().as_slice(), b"0123456789"].concat()
        );
        if final_ack == 7 {
            result.unwrap();
            assert_eq!(delivered, [3, 7]);
            assert_eq!(output.worker_progress().unwrap(), 2);
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert_eq!(delivered, [3]);
            assert_eq!(output.worker_progress().unwrap(), 1);
        }
    }
}

#[test]
fn windows_helper_flushes_before_ack_and_never_acknowledges_failed_flush() {
    struct Sink {
        events: Arc<Mutex<Vec<String>>>,
        limit: usize,
        fail_flush: bool,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(self.limit);
            self.events.lock().unwrap().push(format!(
                "write:{}",
                String::from_utf8_lossy(&bytes[..count])
            ));
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.events.lock().unwrap().push("flush".into());
            if self.fail_flush {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            }
        }
    }
    struct Acks(Arc<Mutex<Vec<String>>>);
    impl Write for Acks {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = u32::from_le_bytes(bytes.try_into().unwrap());
            self.0.lock().unwrap().push(format!("ack:{count}"));
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for (limit, fail_flush, expected) in [
        (10, false, vec!["write:abcde", "flush", "ack:5", "ack:0"]),
        (
            3,
            false,
            vec![
                "write:abc",
                "flush",
                "ack:3",
                "write:de",
                "flush",
                "ack:2",
                "ack:0",
            ],
        ),
        (3, true, vec!["write:abc", "flush"]),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let input = [5u32.to_le_bytes().as_slice(), b"abcde"].concat();
        let status = copy_windows_helper_output(
            io::Cursor::new(input),
            Sink {
                events: Arc::clone(&events),
                limit,
                fail_flush,
            },
            Acks(Arc::clone(&events)),
        );
        assert_eq!(status, i32::from(fail_flush));
        assert_eq!(*events.lock().unwrap(), expected);
    }
}

#[test]
fn interrupt_preserves_writer_owned_batch_and_filters_next_tmux_queue() {
    let (writes, written) = mpsc::channel();
    let (results, responses) = mpsc::channel();
    let mut output = ConsoleOutput::new(
        FlowControlMode::None,
        Box::new(BatchWriter {
            writes,
            results: responses,
            flushes: Arc::new(Mutex::new(0)),
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"gate\n", &modes).unwrap());
    assert_eq!(written.recv().unwrap(), b"gate\n");
    assert!(output
        .try_write(b"%session-changed $1 test\n", &modes)
        .unwrap());
    assert!(output
        .try_write(b"%extended-output %0 0 : ", &modes)
        .unwrap());
    results.send(Ok(5)).unwrap();
    let batch = written.recv().unwrap();
    assert_eq!(batch, b"%session-changed $1 test\n%extended-output %0 0 : ");
    // Removing the batch releases the full queue capacity, even while blocked.
    let pending = format!(
        "tail\n%output %0 {}\n%layout-change @1 layout\n",
        "x".repeat(OUTPUT_BYTES - b"tail\n%output %0 \n%layout-change @1 layout\n".len())
    );
    assert!(output.try_write(pending.as_bytes(), &modes).unwrap());
    assert!(!output.try_write(b"held", &modes).unwrap());
    assert_eq!(output.interrupt().unwrap(), OUTPUT_BYTES - 30);
    assert!(output.try_write(b"prompt", &modes).unwrap());
    results.send(Ok(batch.len())).unwrap();
    assert_eq!(
        written.recv().unwrap(),
        b"tail\n%layout-change @1 layout\nprompt"
    );
    output
        .shared
        .as_ref()
        .unwrap()
        .state
        .lock()
        .unwrap()
        .stopping = true;
    results.send(Ok(36)).unwrap();
    output.wait_worker_done();
    output.finish_gracefully().unwrap();
}

struct GatedWriter {
    entered: mpsc::SyncSender<usize>,
    release: mpsc::Receiver<()>,
}

impl Write for GatedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered
            .send(bytes.len())
            .map_err(|_| io::Error::other("test observer closed"))?;
        self.release
            .recv()
            .map_err(|_| io::Error::other("test release closed"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn full_backpressure_queue_does_not_block_control_progress() {
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let output = ConsoleOutput::new(
        FlowControlMode::Backpressure,
        Box::new(GatedWriter {
            entered: entered_tx,
            release: release_rx,
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(&vec![1; OUTPUT_BYTES], &modes).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), OUTPUT_BYTES);
    assert!(output.try_write(&vec![2; OUTPUT_BYTES], &modes).unwrap());

    assert!(!output.try_write(&[3], &modes).unwrap());
    let (control_tx, control_rx) = mpsc::sync_channel(1);
    control_tx.send("ctrl-c").unwrap();
    assert_eq!(control_rx.recv().unwrap(), "ctrl-c");
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), OUTPUT_BYTES);
    release_tx.send(()).unwrap();
    drop(output);
}

#[test]
fn discard_eviction_does_not_change_confirmed_terminal_mode() {
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let output = ConsoleOutput::new(
        FlowControlMode::Discard,
        Box::new(GatedWriter {
            entered: entered_tx,
            release: release_rx,
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"visible", &modes).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), 7);
    assert!(output.try_write(b"\x1b[?1049h", &modes).unwrap());
    assert!(output.try_write(&[b'n'; OUTPUT_BYTES], &modes).unwrap());

    assert!(!modes.alternate_screen());
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), OUTPUT_BYTES);
    release_tx.send(()).unwrap();
    drop(output);
    assert!(!modes.alternate_screen());
}

#[test]
fn evicted_alternate_leave_preserves_confirmed_enter_state() {
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let output = ConsoleOutput::new(
        FlowControlMode::Discard,
        Box::new(GatedWriter {
            entered: entered_tx,
            release: release_rx,
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"\x1b[?1049h", &modes).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), 8);
    assert!(output.try_write(b"blocking", &modes).unwrap());
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), 8);
    assert!(modes.alternate_screen());
    assert!(output.try_write(b"\x1b[?1049l", &modes).unwrap());
    assert!(output.try_write(&[b'n'; OUTPUT_BYTES], &modes).unwrap());

    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), OUTPUT_BYTES);
    release_tx.send(()).unwrap();
    drop(output);
    assert!(modes.alternate_screen());
}

#[test]
fn clean_remote_session_end_drains_admitted_output_before_returning() {
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let output = ConsoleOutput::new(
        FlowControlMode::Backpressure,
        Box::new(GatedWriter {
            entered: entered_tx,
            release: release_rx,
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"first", &modes).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), 5);
    assert!(output.try_write(b"second", &modes).unwrap());
    let (done_tx, done_rx) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        done_tx
            .send(output.complete(ConsoleCompletion::RemoteSessionEnded))
            .unwrap();
    });

    assert!(done_rx.try_recv().is_err());
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), 6);
    assert!(done_rx.try_recv().is_err());
    release_tx.send(()).unwrap();
    assert!(done_rx.recv().unwrap().is_ok());
}

#[test]
fn graceful_finish_is_idempotent() {
    let mut output =
        ConsoleOutput::new(FlowControlMode::Backpressure, Box::new(Vec::<u8>::new())).unwrap();
    assert!(output.finish_gracefully().is_ok());
    assert!(output.finish_gracefully().is_ok());
}

#[test]
fn graceful_finish_surfaces_last_write_error() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = ConsoleOutput::new(FlowControlMode::Backpressure, Box::new(Broken)).unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"last", &modes).unwrap());

    assert_eq!(
        output.finish_gracefully().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn local_input_close_cancels_blocked_output_before_join() {
    enum Gate {
        Cancel,
    }
    struct CancelWriter {
        entered: mpsc::SyncSender<()>,
        gate: mpsc::Receiver<Gate>,
    }
    impl Write for CancelWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            self.entered.send(()).unwrap();
            match self.gate.recv().unwrap() {
                Gate::Cancel => Err(io::Error::new(io::ErrorKind::BrokenPipe, "cancelled")),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (gate_tx, gate_rx) = mpsc::channel();
    let output = ConsoleOutput::new_with_cancel(
        FlowControlMode::Backpressure,
        Box::new(CancelWriter {
            entered: entered_tx,
            gate: gate_rx,
        }),
        Box::new(move || gate_tx.send(Gate::Cancel).unwrap()),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"blocked", &modes).unwrap());
    entered_rx.recv().unwrap();

    let (done_tx, done_rx) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        let result = output.complete(ConsoleCompletion::LocalInputClosed);
        done_tx.send(result).unwrap();
    });
    assert!(done_rx.recv().unwrap().is_ok());
}

#[test]
fn remote_session_end_cancels_writer_after_graceful_drain_stalls() {
    struct BlockedWriter {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Write for BlockedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::channel();
    let (cancelled_tx, cancelled_rx) = mpsc::sync_channel(0);
    let output = ConsoleOutput::new_with_cancel(
        FlowControlMode::Backpressure,
        Box::new(BlockedWriter {
            entered: entered_tx,
            release: release_rx,
        }),
        Box::new(move || {
            cancelled_tx.send(()).unwrap();
            release_tx.send(()).unwrap();
        }),
    )
    .unwrap();
    assert!(output
        .try_write(b"blocked", &TerminalModeState::default())
        .unwrap());
    entered_rx.recv().unwrap();

    let (done_tx, done_rx) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        done_tx
            .send(output.complete(ConsoleCompletion::RemoteSessionEnded))
            .unwrap();
    });
    cancelled_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("stalled graceful drain did not invoke cancellation");
    assert!(done_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .is_ok());
}

#[test]
fn stalled_remote_completion_does_not_join_an_uninterruptible_write() {
    struct UninterruptibleWriter {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Write for UninterruptibleWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::channel();
    let (cancelled_tx, cancelled_rx) = mpsc::sync_channel(0);
    let output = ConsoleOutput::new_with_cancel(
        FlowControlMode::Backpressure,
        Box::new(UninterruptibleWriter {
            entered: entered_tx,
            release: release_rx,
        }),
        Box::new(move || cancelled_tx.send(()).unwrap()),
    )
    .unwrap();
    assert!(output
        .try_write(b"blocked", &TerminalModeState::default())
        .unwrap());
    entered_rx.recv().unwrap();

    let (done_tx, done_rx) = mpsc::sync_channel(0);
    std::thread::spawn(move || {
        done_tx
            .send(output.complete(ConsoleCompletion::RemoteSessionEnded))
            .unwrap();
    });
    cancelled_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("stalled graceful drain did not invoke cancellation");
    assert!(done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("completion joined an uninterruptible writer")
        .is_ok());
    release_tx.send(()).unwrap();
}

#[test]
fn partial_writes_report_progress_before_completion_and_drain_every_byte() {
    struct PartialWriter {
        output: Arc<Mutex<Vec<u8>>>,
        calls: usize,
        second_entered: mpsc::SyncSender<()>,
        release_second: mpsc::Receiver<()>,
    }
    impl Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.calls == 1 {
                self.second_entered.send(()).unwrap();
                self.release_second.recv().unwrap();
            }
            self.calls += 1;
            self.output.lock().unwrap().push(bytes[0]);
            Ok(1)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            queue: VecDeque::new(),
            bytes: 0,
            stopping: false,
            error: None,
            cursor_reports: 0,
            worker_done: false,
            worker_progress: 0,
            stream: et_core::output_interrupt::TerminalStream::default(),
            skip_until_newline: false,
        }),
        wake: Condvar::new(),
    });
    let output = Arc::new(Mutex::new(Vec::new()));
    let (second_entered_tx, second_entered_rx) = mpsc::sync_channel(0);
    let (release_second_tx, release_second_rx) = mpsc::sync_channel(0);
    let worker_shared = Arc::clone(&shared);
    let worker_output = Arc::clone(&output);
    let worker = std::thread::spawn(move || {
        let mut writer = PartialWriter {
            output: worker_output,
            calls: 0,
            second_entered: second_entered_tx,
            release_second: release_second_rx,
        };
        write_all_with_progress(&worker_shared, &mut writer, b"ok", &mut |_| {})
    });

    second_entered_rx.recv().unwrap();
    assert_eq!(*output.lock().unwrap(), b"o");
    assert_eq!(shared.state.lock().unwrap().worker_progress, 1);
    release_second_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert_eq!(*output.lock().unwrap(), b"ok");
    assert_eq!(shared.state.lock().unwrap().worker_progress, 2);
}

#[test]
fn remote_session_end_drains_every_partial_write_before_returning() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RecordingPartialWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for RecordingPartialWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().push(bytes[0]);
            Ok(1)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let written = Arc::new(Mutex::new(Vec::new()));
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_observer = Arc::clone(&cancelled);
    let output = ConsoleOutput::new_with_cancel(
        FlowControlMode::Backpressure,
        Box::new(RecordingPartialWriter(Arc::clone(&written))),
        Box::new(move || cancel_observer.store(true, Ordering::Release)),
    )
    .unwrap();
    assert!(output
        .try_write(b"partial", &TerminalModeState::default())
        .unwrap());

    output
        .complete(ConsoleCompletion::RemoteSessionEnded)
        .unwrap();
    assert_eq!(*written.lock().unwrap(), b"partial");
    assert!(!cancelled.load(Ordering::Acquire));
}

#[cfg(unix)]
#[test]
fn cancellable_stdout_fails_when_output_is_closed() {
    use std::os::unix::net::UnixStream;

    let (output, peer) = UnixStream::pair().unwrap();
    let file = File::from(rustix::io::dup(output.as_fd()).unwrap());
    drop(output);
    drop(peer);
    let (cancel, _cancel_signal) = et_net::local::wake_pair().unwrap();
    let mut writer = CancellableStdout { file, cancel };

    let (done_tx, done_rx) = mpsc::sync_channel(0);
    std::thread::spawn(move || done_tx.send(writer.write(b"closed")).unwrap());
    let error = done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("closed output readiness caused write to spin")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn last_packet_broken_pipe_is_reported_without_another_packet() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let output = ConsoleOutput::new(FlowControlMode::Discard, Box::new(Broken)).unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(b"last", &modes).unwrap());
    output.wait_worker_done();
    assert_eq!(
        output.check_error().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}
