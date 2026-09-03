#![cfg(unix)]

use super::*;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use crate::client_terminal::send_buffer;
use et_core::proto::TerminalBuffer;
use prost::Message;

#[test]
fn full_forwarding_backlog_stops_polling_network_readability() {
    let flags = network_poll_flags(false, true);

    assert!(!flags.contains(PollFlags::IN));
    assert!(flags.contains(PollFlags::HUP | PollFlags::ERR));
}

#[test]
fn available_forwarding_backlog_keeps_polling_network_readability() {
    let flags = network_poll_flags(false, false);

    assert!(flags.contains(PollFlags::IN));
}

struct GatedConsole {
    entered: mpsc::SyncSender<usize>,
    release: mpsc::Receiver<()>,
}

impl Write for GatedConsole {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered
            .send(bytes.len())
            .map_err(|_| io::Error::other("console observer closed"))?;
        self.release
            .recv()
            .map_err(|_| io::Error::other("console release closed"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn pending_console_output_does_not_block_terminal_input() {
    // Given: a deliberately blocked console and a completely full queue.
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let output = crate::client_output::ConsoleOutput::new(
        et_cli::client::FlowControlMode::Backpressure,
        Box::new(GatedConsole {
            entered: entered_tx,
            release: release_rx,
        }),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(&vec![1; 64 * 1024], &modes).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), 64 * 1024);
    assert!(output.try_write(&vec![2; 64 * 1024], &modes).unwrap());
    let packet = et_core::packet::Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(b"pending".to_vec()),
        }
        .encode_to_vec(),
    );
    let mut modes = TerminalModeState::default();
    assert!(matches!(
        route_server_packet(packet, true, &mut modes, &output).unwrap(),
        DisplayOutcome::Pending(_)
    ));

    // When: Ctrl-C input is sent while output remains blocked.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let connector = thread::spawn(move || TcpStream::connect(address).unwrap());
    let (server_stream, _) = listener.accept().unwrap();
    let client_stream = connector.join().unwrap();
    let key = [31u8; 32];
    let mut sender = Connection::new_client(client_stream, &key);
    let mut receiver = Connection::new_server(server_stream, &key);
    send_buffer(&mut sender, b"\x03").unwrap();

    // Then: input arrives before either console write is released.
    let received = receiver.read_packet().unwrap();
    let input = TerminalBuffer::decode(received.payload()).unwrap();
    assert_eq!(input.buffer.as_deref(), Some(b"\x03".as_slice()));
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), 64 * 1024);
    release_tx.send(()).unwrap();
    drop(output);
}

#[test]
fn remote_completion_bounds_a_retained_packet_behind_stalled_output() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::channel();
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    let cancel_observer = std::sync::Arc::clone(&cancelled);
    let output = crate::client_output::ConsoleOutput::new_with_cancel(
        et_cli::client::FlowControlMode::Backpressure,
        Box::new(GatedConsole {
            entered: entered_tx,
            release: release_rx,
        }),
        Box::new(move || cancel_observer.store(true, Ordering::Release)),
    )
    .unwrap();
    let modes = TerminalModeState::default();
    assert!(output.try_write(&vec![1; 64 * 1024], &modes).unwrap());
    assert_eq!(entered_rx.recv().unwrap(), 64 * 1024);
    assert!(output.try_write(&vec![2; 64 * 1024], &modes).unwrap());
    let retained = et_core::packet::Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(b"retained".to_vec()),
        }
        .encode_to_vec(),
    );
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();
    let (done_tx, done_rx) = mpsc::sync_channel(0);
    thread::spawn(move || {
        let mut terminal_modes = TerminalModeState::default();
        done_tx
            .send(finish_remote_completion(
                output,
                Some(retained),
                VecDeque::new(),
                true,
                &mut terminal_modes,
                &mut forwarder,
                None,
            ))
            .unwrap();
    });

    assert!(done_rx
        .recv_timeout(Duration::from_secs(4))
        .expect("retained output kept remote completion blocked")
        .is_ok());
    assert!(cancelled.load(Ordering::Acquire));

    // Let the detached writer finish so the test leaves no blocked thread.
    release_tx.send(()).unwrap();
    assert_eq!(entered_rx.recv().unwrap(), 64 * 1024);
    release_tx.send(()).unwrap();
}

#[test]
fn remote_completion_attempts_retained_output_before_draining() {
    let output = crate::client_output::ConsoleOutput::new(
        et_cli::client::FlowControlMode::Backpressure,
        Box::new(Vec::<u8>::new()),
    )
    .unwrap();
    let retained = et_core::packet::Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        TerminalBuffer {
            buffer: Some(vec![b'x'; 64 * 1024 + 1]),
        }
        .encode_to_vec(),
    );
    let mut terminal_modes = TerminalModeState::default();
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();

    let error = finish_remote_completion(
        output,
        Some(retained),
        VecDeque::new(),
        true,
        &mut terminal_modes,
        &mut forwarder,
        None,
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("terminal output packet exceeds console queue capacity"),
        "unexpected error: {error}"
    );
}
