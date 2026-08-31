use super::*;
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
    // Given: the writer and its bounded queue are both full.
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
    assert!(output.try_write(&vec![1; OUTPUT_BYTES]).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), OUTPUT_BYTES);
    assert!(output.try_write(&vec![2; OUTPUT_BYTES]).unwrap());

    // When: admission fails and the next control action runs on the same thread.
    assert!(!output.try_write(&[3]).unwrap());
    let (control_tx, control_rx) = mpsc::sync_channel(1);
    control_tx.send("ctrl-c").unwrap();

    // Then: control progresses before the deliberately slow writer is released.
    assert_eq!(control_rx.recv().unwrap(), "ctrl-c");
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), OUTPUT_BYTES);
    release_tx.send(()).unwrap();
    drop(output);
}

#[test]
fn discard_stays_bounded_with_a_deliberately_slow_consumer() {
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
    assert!(output.try_write(&vec![1; OUTPUT_BYTES]).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), OUTPUT_BYTES);

    assert!(output.try_write(&vec![2; OUTPUT_BYTES]).unwrap());
    assert!(output.try_write(&vec![3; OUTPUT_BYTES]).unwrap());

    let shared = output.shared.as_ref().unwrap();
    let state = shared.state.lock().unwrap();
    assert_eq!(state.bytes, OUTPUT_BYTES);
    assert_eq!(state.queue.len(), 1);
    assert_eq!(state.queue.front().unwrap()[0], 3);
    drop(state);
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), OUTPUT_BYTES);
    release_tx.send(()).unwrap();
    drop(output);
}
