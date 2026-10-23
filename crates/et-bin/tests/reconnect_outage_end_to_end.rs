#![forbid(unsafe_code)]

//! Regression test for the sleep/wake disconnect: when the network is
//! unreachable while the client tries to reconnect (e.g. a MacBook waking
//! before Wi-Fi is back), every attempt fails with a transient error. The
//! client used to exit with "could not reach the ET server" after the first
//! failed attempt; it must instead keep retrying until the link returns,
//! without writing client-local reconnect status into the terminal. Input
//! typed while the link is down must reach the shell after recovery, in
//! order, like the upstream client's queued input.

// The shared stack helper exports more than this test needs.
#[allow(dead_code)]
#[path = "reconnect_stack/mod.rs"]
mod reconnect_stack;

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use reconnect_stack::Stack;

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn client_retries_reconnect_through_network_outage() {
    let mut stack = Stack::start();
    let proxy = OutageProxy::start(stack.port);
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 30,
            cols: 90,
            pixel_width: 900,
            pixel_height: 600,
        })
        .unwrap();
    let mut client = CommandBuilder::new(env!("CARGO_BIN_EXE_et"));
    client.args([
        "--terminal-path",
        stack.terminal.to_str().unwrap(),
        "--serverfifo",
        stack.router.to_str().unwrap(),
        "--logdir",
        stack.directory.to_str().unwrap(),
        "--keepalive=1",
        "--port",
        &proxy.port.to_string(),
        "127.0.0.1",
    ]);
    client.env(
        "PATH",
        format!(
            "{}:{}",
            stack.directory.display(),
            std::env::var("PATH").unwrap()
        ),
    );
    client.env("TERM", "xterm-256color");
    client.env("ET_SSH_COUNT", &stack.ssh_count);
    let client_ready = stack.directory.join("client-ready");
    client.env("ET_SSH_READY", &client_ready);
    let mut child = pair.slave.spawn_command(client).unwrap();
    drop(pair.slave);
    let mut writer = pair.master.take_writer().unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let (output_tx, output_rx) = mpsc::sync_channel(64);
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) if output_tx.send(chunk[..count].to_vec()).is_err() => break,
                Ok(_) => {}
            }
        }
    });
    wait_for_file(&client_ready, b"ready");

    // A short prompt keeps the partial line's echo below from wrapping:
    // CI hosts (macOS runners) have prompts long enough to wrap at 90 columns.
    writer
        .write_all(b"PS1='> '; printf 'FIRST-PID:%s\\n' \"$$\"\n")
        .unwrap();
    let (mut output, first_pid) = receive_number(&output_rx, Vec::new(), b"FIRST-PID:");
    // Start a line before the outage; the shell's echo proves it arrived.
    writer.write_all(b"echo \"JOINED:BEFORE").unwrap();
    output = receive_marker(&output_rx, output, b"JOINED:BEFORE");

    // Drop the link and refuse every reconnect attempt for a while, like a
    // laptop that wakes from sleep before its network is back.
    proxy.outage();
    proxy.wait_for_refused(2);
    // Finish the line while the link is down. Two more refused attempts
    // mean a whole retry wait ran after these bytes were typed, so the wait
    // (not the recovered session) is what read them.
    writer.write_all(b"-$((7*9))-TYPED\"\n").unwrap();
    proxy.wait_for_refused(4);
    proxy.restore();

    // The kept input runs first, completing the line started before the
    // outage; only the shell's evaluation prints `63`, never the echo.
    output = receive_marker(&output_rx, output, b"JOINED:BEFORE-63-TYPED");
    writer
        .write_all(b"printf 'AFTER-PID:%s\\n' \"$$\"\n")
        .unwrap();
    let (mut output, after_pid) = receive_number(&output_rx, output, b"AFTER-PID:");
    // Same shell process: the session recovered instead of restarting.
    assert_eq!(first_pid, after_pid, "output={}", text(&output));

    writer.write_all(b"exit\n").unwrap();
    let status = child.wait().unwrap();
    while let Ok(chunk) = output_rx.recv_timeout(TIMEOUT) {
        output.extend(chunk);
    }
    let text = text(&output);
    assert!(status.success(), "status={status:?} output={text}");
    assert!(
        !text.contains("could not reach the ET server"),
        "client gave up during the outage: {text}"
    );
    assert!(
        !text.contains("connection lost, reconnecting"),
        "client wrote reconnect status text into the terminal: {text}"
    );
    for control in [b"\x1b[22;2t".as_slice(), b"\x1b[23;2t", b"\x1b]2;et:"] {
        assert!(
            !output
                .windows(control.len())
                .any(|window| window == control),
            "client wrote reconnect status control bytes into the terminal: {output:?}"
        );
    }
    let refused = proxy.join();
    assert!(
        refused >= 2,
        "expected multiple retried reconnect attempts, saw {refused}"
    );
    let client_log = fs::read_dir(&stack.directory)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("etclient-"))
        .expect("client log file")
        .path();
    let client_log = fs::read_to_string(client_log).unwrap();
    assert!(
        client_log.contains("reconnect attempt failed, retrying:"),
        "retry failure missing from client log: {client_log}"
    );
    stack.shutdown();
}

/// A link that goes silent without any TCP error (an address change, a NAT
/// dropping the flow) is found only by keep-alives. Like upstream
/// `TerminalClient::run`, the client probes one interval after the last
/// packet it read and reconnects when that probe is still unanswered one
/// interval later: two intervals, not three.
#[test]
fn client_reconnects_two_keepalive_intervals_after_the_link_goes_silent() {
    let mut stack = Stack::start();
    let proxy = BlackholeProxy::start(stack.port);
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 30,
            cols: 90,
            pixel_width: 900,
            pixel_height: 600,
        })
        .unwrap();
    let mut client = CommandBuilder::new(env!("CARGO_BIN_EXE_et"));
    client.args([
        "--terminal-path",
        stack.terminal.to_str().unwrap(),
        "--serverfifo",
        stack.router.to_str().unwrap(),
        "--logdir",
        stack.directory.to_str().unwrap(),
        "--keepalive=1",
        "--port",
        &proxy.port.to_string(),
        "127.0.0.1",
    ]);
    client.env(
        "PATH",
        format!(
            "{}:{}",
            stack.directory.display(),
            std::env::var("PATH").unwrap()
        ),
    );
    client.env("TERM", "xterm-256color");
    client.env("ET_SSH_COUNT", &stack.ssh_count);
    let client_ready = stack.directory.join("client-ready");
    client.env("ET_SSH_READY", &client_ready);
    let mut child = pair.slave.spawn_command(client).unwrap();
    drop(pair.slave);
    let mut writer = pair.master.take_writer().unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let (output_tx, output_rx) = mpsc::sync_channel(64);
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) if output_tx.send(chunk[..count].to_vec()).is_err() => break,
                Ok(_) => {}
            }
        }
    });
    wait_for_file(&client_ready, b"ready");
    writer
        .write_all(b"PS1='> '; printf 'FIRST-PID:%s\\n' \"$$\"\n")
        .unwrap();
    let (output, first_pid) = receive_number(&output_rx, Vec::new(), b"FIRST-PID:");
    // Let the idle keep-alive exchange settle into its cadence.
    thread::sleep(Duration::from_millis(2500));

    let last_delivered = proxy.blackhole();
    let reconnected = proxy.wait_for_reconnect();
    let silence = reconnected.saturating_duration_since(last_delivered);
    // One interval to the probe, one more for its reply, plus scheduling.
    assert!(
        silence >= Duration::from_millis(1900) && silence < Duration::from_millis(2700),
        "reconnect started {silence:?} after the last packet reached the client"
    );

    writer
        .write_all(b"printf 'AFTER-PID:%s\\n' \"$$\"\n")
        .unwrap();
    let (mut output, after_pid) = receive_number(&output_rx, output, b"AFTER-PID:");
    assert_eq!(first_pid, after_pid, "output={}", text(&output));
    writer.write_all(b"exit\n").unwrap();
    let status = child.wait().unwrap();
    while let Ok(chunk) = output_rx.recv_timeout(TIMEOUT) {
        output.extend(chunk);
    }
    assert!(
        status.success(),
        "status={status:?} output={}",
        text(&output)
    );
    stack.shutdown();
}

fn text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

/// TCP relay whose first connection can go silent: bytes in both directions
/// are read and dropped, and nothing is closed, so neither end sees an error.
/// Later connections relay normally.
struct BlackholeProxy {
    port: u16,
    silent: Arc<AtomicBool>,
    /// When the last byte of the first connection reached the client.
    last_delivered: Arc<Mutex<Instant>>,
    accepted: mpsc::Receiver<Instant>,
}

impl BlackholeProxy {
    fn start(backend_port: u16) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let silent = Arc::new(AtomicBool::new(false));
        let last_delivered = Arc::new(Mutex::new(Instant::now()));
        let (accepted_tx, accepted) = mpsc::channel();
        let (relay_silent, relay_delivered) = (Arc::clone(&silent), Arc::clone(&last_delivered));
        thread::spawn(move || {
            for (index, client) in listener.incoming().enumerate() {
                let Ok(client) = client else { return };
                let _ = accepted_tx.send(Instant::now());
                let Ok(backend) = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port)) else {
                    return;
                };
                // Only the first connection goes silent.
                let silent = if index == 0 {
                    Arc::clone(&relay_silent)
                } else {
                    Arc::new(AtomicBool::new(false))
                };
                let delivered = (index == 0).then(|| Arc::clone(&relay_delivered));
                let (client_reader, backend_writer) =
                    (client.try_clone().unwrap(), backend.try_clone().unwrap());
                let upstream_silent = Arc::clone(&silent);
                thread::spawn(move || {
                    forward(client_reader, backend_writer, &upstream_silent, None)
                });
                thread::spawn(move || forward(backend, client, &silent, delivered.as_deref()));
            }
        });
        Self {
            port,
            silent,
            last_delivered,
            accepted,
        }
    }

    /// Silence the first connection; returns when it last delivered a byte
    /// to the client.
    fn blackhole(&self) -> Instant {
        // The first connection is the session itself.
        self.accepted.recv_timeout(TIMEOUT).unwrap();
        let delivered = self.last_delivered.lock().unwrap();
        self.silent.store(true, Ordering::SeqCst);
        *delivered
    }

    fn wait_for_reconnect(&self) -> Instant {
        self.accepted.recv_timeout(TIMEOUT).unwrap()
    }
}

/// Copy `from` into `to` until EOF, dropping everything once `silent`.
fn forward(
    mut from: TcpStream,
    mut to: TcpStream,
    silent: &AtomicBool,
    delivered: Option<&Mutex<Instant>>,
) {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = match from.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        // Deliver under the lock, so `blackhole` sees either no delivery or
        // the time of this one.
        let guard = delivered.map(|delivered| delivered.lock().unwrap());
        if silent.load(Ordering::SeqCst) {
            continue;
        }
        if to.write_all(&buffer[..count]).is_err() {
            return;
        }
        if let Some(mut at) = guard {
            *at = Instant::now();
        }
    }
}

/// TCP relay that can simulate a network outage: while down it accepts and
/// immediately drops every connection, so reconnect attempts fail the way
/// they do against an unreachable or half-up network.
struct OutageProxy {
    port: u16,
    outage: mpsc::SyncSender<()>,
    restore: mpsc::SyncSender<()>,
    refused: mpsc::Receiver<usize>,
    worker: Option<thread::JoinHandle<io::Result<usize>>>,
}

impl OutageProxy {
    fn start(backend_port: u16) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (outage_tx, outage_rx) = mpsc::sync_channel(1);
        let (restore_tx, restore_rx) = mpsc::sync_channel::<()>(1);
        let (refused_tx, refused_rx) = mpsc::sync_channel(2);
        let worker = thread::spawn(move || {
            let (first, _) = listener.accept()?;
            let backend = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let relays = relay(&first, &backend)?;
            outage_rx
                .recv_timeout(TIMEOUT)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let _ = first.shutdown(Shutdown::Both);
            let _ = backend.shutdown(Shutdown::Both);
            join_relays(relays)?;
            // Outage: drop every attempt until the test restores the link.
            let mut refused = 0usize;
            let recovered = loop {
                let (attempt, _) = listener.accept()?;
                if restore_rx.try_recv().is_ok() {
                    break attempt;
                }
                let _ = attempt.shutdown(Shutdown::Both);
                refused += 1;
                let _ = refused_tx.try_send(refused);
            };
            let backend = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let relays = relay(&recovered, &backend)?;
            join_relays(relays)?;
            // After the shell exits the server closes the connection; the
            // client reconnects once more to learn the session ended.
            let (final_client, _) = listener.accept()?;
            let final_backend = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let final_relays = relay(&final_client, &final_backend)?;
            join_relays(final_relays)?;
            Ok(refused)
        });
        Self {
            port,
            outage: outage_tx,
            restore: restore_tx,
            refused: refused_rx,
            worker: Some(worker),
        }
    }

    fn outage(&self) {
        self.outage.send(()).unwrap();
    }

    fn restore(&self) {
        self.restore.send(()).unwrap();
    }

    fn wait_for_refused(&self, minimum: usize) {
        loop {
            let refused = self.refused.recv_timeout(TIMEOUT).unwrap();
            if refused >= minimum {
                return;
            }
        }
    }

    fn join(mut self) -> usize {
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

type Relays = (
    thread::JoinHandle<io::Result<u64>>,
    thread::JoinHandle<io::Result<u64>>,
);

/// Relay both directions. When either side closes, close both, as a real
/// proxy does: a client must not need keep-alive silence to notice.
fn relay(client: &TcpStream, backend: &TcpStream) -> io::Result<Relays> {
    fn copy_then_close(mut from: TcpStream, mut to: TcpStream) -> io::Result<u64> {
        let copied = io::copy(&mut from, &mut to);
        let _ = from.shutdown(Shutdown::Both);
        let _ = to.shutdown(Shutdown::Both);
        copied
    }
    let (client_reader, client_writer) = (client.try_clone()?, client.try_clone()?);
    let (backend_reader, backend_writer) = (backend.try_clone()?, backend.try_clone()?);
    Ok((
        thread::spawn(move || copy_then_close(client_reader, backend_writer)),
        thread::spawn(move || copy_then_close(backend_reader, client_writer)),
    ))
}

fn join_relays((first, second): Relays) -> io::Result<()> {
    for worker in [first, second] {
        match worker.join() {
            Ok(Ok(_)) => {}
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(io::Error::other("relay worker panicked")),
        }
    }
    Ok(())
}

fn receive_number(
    receiver: &mpsc::Receiver<Vec<u8>>,
    mut output: Vec<u8>,
    marker: &[u8],
) -> (Vec<u8>, u32) {
    loop {
        if let Some(value) = marker_number(&output, marker) {
            return (output, value);
        }
        output.extend(receiver.recv_timeout(TIMEOUT).unwrap_or_else(|error| {
            panic!(
                "timed out waiting for {}: {error}; output={}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&output)
            )
        }));
    }
}

fn receive_marker(
    receiver: &mpsc::Receiver<Vec<u8>>,
    mut output: Vec<u8>,
    marker: &[u8],
) -> Vec<u8> {
    while !output.windows(marker.len()).any(|window| window == marker) {
        output.extend(receiver.recv_timeout(TIMEOUT).unwrap_or_else(|error| {
            panic!(
                "timed out waiting for {}: {error}; output={}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&output)
            )
        }));
    }
    output
}

fn marker_number(output: &[u8], marker: &[u8]) -> Option<u32> {
    output
        .windows(marker.len())
        .enumerate()
        .filter(|(_, window)| *window == marker)
        .find_map(|(offset, _)| {
            String::from_utf8_lossy(&output[offset + marker.len()..])
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        })
}

fn wait_for_file(path: &std::path::Path, expected: &[u8]) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if fs::read(path).is_ok_and(|contents| contents == expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
