use super::*;
use crate::client_terminal::TerminalModeState;

struct RecordedOutput(Arc<Mutex<Vec<u8>>>);

impl Write for RecordedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_interrupt_default_console_delivers_small_output_to_its_writer() {
    // Given: a default console with an observable output sink.
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let output = ConsoleOutput::new(
        FlowControlMode::None,
        Box::new(RecordedOutput(Arc::clone(&bytes))),
    )
    .unwrap();
    // When: a terminal packet is admitted and remote completion drains it.
    assert!(output
        .try_write(b"ET_SMALL_OUTPUT_OK", &TerminalModeState::default())
        .unwrap());
    output
        .complete(ConsoleCompletion::RemoteSessionEnded)
        .unwrap();
    // Then: the configured writer, not an unrelated process stdout, receives
    // the exact small output. This is a byte assertion, not a worker flag.
    assert_eq!(*bytes.lock().unwrap(), b"ET_SMALL_OUTPUT_OK");
}

struct GatedOutput {
    bytes: Arc<Mutex<Vec<u8>>>,
    entered: std::sync::mpsc::Sender<()>,
    release: Option<std::sync::mpsc::Receiver<()>>,
}

impl Write for GatedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(release) = self.release.take() {
            self.entered.send(()).map_err(io::Error::other)?;
            release
                .recv_timeout(Duration::from_secs(3))
                .map_err(io::Error::other)?;
        }
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

type ConsoleGate = (
    ConsoleOutput,
    Arc<Mutex<Vec<u8>>>,
    std::sync::mpsc::Sender<()>,
);

#[test]
fn output_interrupt_preserves_console_output_below_the_flush_threshold() {
    // Given unsent output below upstream's 64 KiB interrupt threshold.
    for size in [6, 64 * 1024 - 1] {
        let (output, bytes, release) = gated_output(FlowControlMode::None, b"prefix\n");
        let pending = vec![b'x'; size];
        assert!(output
            .try_write(&pending, &TerminalModeState::default())
            .unwrap());
        // When the user interrupts while the writer still owns the prefix.
        output.interrupt().unwrap();
        release.send(()).unwrap();
        output
            .complete(ConsoleCompletion::RemoteSessionEnded)
            .unwrap();
        // Then small output remains byte-exact.
        assert_eq!(
            *bytes.lock().unwrap(),
            [b"prefix\n".as_slice(), &pending].concat()
        );
    }
}

fn gated_output(mode: FlowControlMode, prefix: &[u8]) -> ConsoleGate {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (entered, entering) = std::sync::mpsc::channel();
    let (release, releasing) = std::sync::mpsc::channel();
    let output = ConsoleOutput::new(
        mode,
        Box::new(GatedOutput {
            bytes: Arc::clone(&bytes),
            entered,
            release: Some(releasing),
        }),
    )
    .unwrap();
    assert!(output
        .try_write(prefix, &TerminalModeState::default())
        .unwrap());
    entering.recv_timeout(Duration::from_secs(3)).unwrap();
    (output, bytes, release)
}

#[test]
fn output_interrupt_saturated_console_delivers_prefix_then_new_prompt() {
    for mode in [
        FlowControlMode::None,
        FlowControlMode::Backpressure,
        FlowControlMode::Discard,
    ] {
        // Given: a writer-owned prefix and an exactly full unsent console queue.
        let (output, bytes, release) = gated_output(mode, b"prefix\n");
        let modes = TerminalModeState::default();
        assert!(output.try_write(&vec![b'x'; OUTPUT_BYTES], &modes).unwrap());
        // When: interrupt discards the queued flood, then a new prompt arrives.
        output.interrupt().unwrap();
        assert!(output.try_write(b"ET_CTRL_C_OK", &modes).unwrap());
        release.send(()).unwrap();
        output
            .complete(ConsoleCompletion::RemoteSessionEnded)
            .unwrap();
        // Then: assert actual sink bytes, not queue/worker implementation state.
        assert_eq!(*bytes.lock().unwrap(), b"prefix\nET_CTRL_C_OK");
    }
}

#[test]
fn output_interrupt_console_finishes_in_flight_tmux_line_and_keeps_layout() {
    // Given: the transport writer already owns a partial tmux output line.
    let prefix = b"%extended-output %0 0 : ";
    let (output, bytes, release) = gated_output(FlowControlMode::None, prefix);
    let modes = TerminalModeState::default();
    let queued = format!(
        "tail\n%output %0 {}\n%layout-change @1 layout\n",
        "x".repeat(64 * 1024 - b"tail\n%output %0 \n%layout-change @1 layout\n".len())
    );
    assert!(output.try_write(queued.as_bytes(), &modes).unwrap());
    // When: queued pane output is interrupted before the first write completes.
    output.interrupt().unwrap();
    release.send(()).unwrap();
    output
        .complete(ConsoleCompletion::RemoteSessionEnded)
        .unwrap();
    // Then: the existing line terminates and control notifications stay intact.
    assert_eq!(
        *bytes.lock().unwrap(),
        b"%extended-output %0 0 : tail\n%layout-change @1 layout\n"
    );
}

#[test]
fn output_interrupt_console_skips_only_the_dropped_tmux_continuation() {
    // Given: an incomplete pane line is wholly unsent behind a notification.
    let prefix = b"%session-changed $1 test\n";
    let (output, bytes, release) = gated_output(FlowControlMode::None, prefix);
    let modes = TerminalModeState::default();
    assert!(output
        .try_write(
            format!(
                "%output %0 {}",
                "x".repeat(64 * 1024 - b"%output %0 ".len())
            )
            .as_bytes(),
            &modes
        )
        .unwrap());
    // When: an interrupt is followed by more of that line and a notification.
    output.interrupt().unwrap();
    assert!(output.try_write(b"more-pane-data", &modes).unwrap());
    assert!(output.try_write(b"\n%window-add @2\n", &modes).unwrap());
    release.send(()).unwrap();
    output
        .complete(ConsoleCompletion::RemoteSessionEnded)
        .unwrap();
    // Then: no orphan pane fragment or lost notification reaches the sink.
    assert_eq!(
        *bytes.lock().unwrap(),
        b"%session-changed $1 test\n%window-add @2\n"
    );
}
