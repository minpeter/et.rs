use super::*;
use crate::client_terminal::TerminalModeState;
use std::sync::mpsc;

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
        write_all_with_progress(&worker_shared, &mut writer, b"ok")
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
