#![forbid(unsafe_code)]

//! Regression test for the sleep/wake disconnect: when the network is
//! unreachable while the client tries to reconnect (e.g. a MacBook waking
//! before Wi-Fi is back), every attempt fails with a transient error. The
//! client used to exit with "could not reach the ET server" after the first
//! failed attempt; it must instead keep retrying until the link returns.

// The shared stack helper exports more than this test needs.
#[allow(dead_code)]
#[path = "reconnect_stack/mod.rs"]
mod reconnect_stack;

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use reconnect_stack::Stack;

const TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough for several reconnect attempts (retry delay is one second).
const OUTAGE: Duration = Duration::from_secs(4);

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
        "--keepalive=1",
        "-p",
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
        .write_all(b"printf 'FIRST-PID:%s\\n' \"$$\"\n")
        .unwrap();
    let (mut output, first_pid) = receive_number(&output_rx, Vec::new(), b"FIRST-PID:");

    // Drop the link and refuse every reconnect attempt for a while, like a
    // laptop that wakes from sleep before its network is back.
    proxy.outage();
    thread::sleep(OUTAGE);
    proxy.restore();

    // The client announces the retry loop on the first failed attempt.
    output = receive_until(&output_rx, output, b"connection lost, reconnecting");

    // Input typed while the link is down is dropped, so keep asking until
    // the recovered session answers.
    let mut after_pid = None;
    for _ in 0..15 {
        writer
            .write_all(b"printf 'AFTER-PID:%s\\n' \"$$\"\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(value) = marker_number(&output, b"AFTER-PID:") {
                after_pid = Some(value);
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match output_rx.recv_timeout(remaining) {
                Ok(chunk) => output.extend(chunk),
                Err(_) => break,
            }
        }
        if after_pid.is_some() {
            break;
        }
    }
    // Same shell process: the session recovered instead of restarting.
    assert_eq!(Some(first_pid), after_pid, "output={}", text(&output));

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
    let refused = proxy.join();
    assert!(
        refused >= 2,
        "expected multiple retried reconnect attempts, saw {refused}"
    );
    stack.shutdown();
}

fn text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

/// TCP relay that can simulate a network outage: while down it accepts and
/// immediately drops every connection, so reconnect attempts fail the way
/// they do against an unreachable or half-up network.
struct OutageProxy {
    port: u16,
    outage: mpsc::SyncSender<()>,
    restore: mpsc::SyncSender<()>,
    worker: Option<thread::JoinHandle<io::Result<usize>>>,
}

impl OutageProxy {
    fn start(backend_port: u16) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (outage_tx, outage_rx) = mpsc::sync_channel(1);
        let (restore_tx, restore_rx) = mpsc::sync_channel::<()>(1);
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
            worker: Some(worker),
        }
    }

    fn outage(&self) {
        self.outage.send(()).unwrap();
    }

    fn restore(&self) {
        self.restore.send(()).unwrap();
    }

    fn join(mut self) -> usize {
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

type Relays = (
    thread::JoinHandle<io::Result<u64>>,
    thread::JoinHandle<io::Result<u64>>,
);

fn relay(client: &TcpStream, backend: &TcpStream) -> io::Result<Relays> {
    let mut client_reader = client.try_clone()?;
    let mut client_writer = client.try_clone()?;
    let mut backend_reader = backend.try_clone()?;
    let mut backend_writer = backend.try_clone()?;
    Ok((
        thread::spawn(move || io::copy(&mut client_reader, &mut backend_writer)),
        thread::spawn(move || io::copy(&mut backend_reader, &mut client_writer)),
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

fn receive_until(
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
