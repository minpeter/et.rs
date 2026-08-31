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
fn blocked_writer_shutdown_is_cancelled_before_join() {
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
        drop(output);
        done_tx.send(()).unwrap();
    });
    done_rx.recv().unwrap();
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
