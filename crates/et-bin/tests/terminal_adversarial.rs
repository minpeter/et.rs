#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{TermInit, TerminalBuffer, TerminalPacketType};
use et_net::local_packet::{
    parse_status, read_local_packet, status_packet, write_local_packet, REGISTRATION_STATUS,
    STARTUP_STATUS,
};
use nix::sys::signal::kill;
use nix::unistd::Pid;
use prost::Message;
use wait_timeout::ChildExt;

const ID: &str = "abcdefghijklmnop";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn malformed_initialization_and_shell_spawn_failure_are_typed() {
    let malformed = Fixture::new("malformed-init");
    let mut malformed_child = malformed.spawn();
    write_credentials(&mut malformed_child);
    let mut malformed_router = malformed.accept();
    let _ = read_local_packet(&mut malformed_router).unwrap();
    acknowledge_registration(&mut malformed_router);
    malformed.wait_ready();
    send(
        &mut malformed_router,
        TerminalPacketType::TerminalBuffer,
        &TerminalBuffer {
            buffer: Some(Vec::new()),
        },
    );
    assert!(!malformed_child
        .wait_timeout(TIMEOUT)
        .unwrap()
        .unwrap()
        .success());

    let spawn_failure = Fixture::new("spawn-failure");
    let mut failed_child = spawn_failure.spawn_with_shell("/definitely/missing/et-shell");
    write_credentials(&mut failed_child);
    let mut failed_router = spawn_failure.accept();
    let _ = read_local_packet(&mut failed_router).unwrap();
    acknowledge_registration(&mut failed_router);
    spawn_failure.wait_ready();
    send(
        &mut failed_router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    assert!(!failed_child
        .wait_timeout(TIMEOUT)
        .unwrap()
        .unwrap()
        .success());
}

#[test]
fn shell_exit_reaps_background_process_group() {
    let fixture = Fixture::new("process-group");
    let shell = fixture.directory.join("background-shell");
    fs::write(&shell, "#!/bin/sh\nsleep 30 & printf 'BG:%s\\n' \"$!\"\n").unwrap();
    fs::set_permissions(&shell, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = fixture.spawn_with_shell(shell.to_str().unwrap());
    write_credentials(&mut child);
    let mut router = fixture.accept();
    let _ = read_local_packet(&mut router).unwrap();
    acknowledge_registration(&mut router);
    fixture.wait_ready();
    let mut output_reader = router.try_clone().unwrap();
    let (output_tx, output_rx) = mpsc::sync_channel(64);
    std::thread::spawn(move || {
        while let Ok(packet) = read_local_packet(&mut output_reader) {
            if output_tx.send(packet).is_err() {
                break;
            }
        }
    });
    send(
        &mut router,
        TerminalPacketType::TerminalInit,
        &TermInit {
            environmentnames: Vec::new(),
            environmentvalues: Vec::new(),
            flowcontrol: None,
        },
    );
    let mut output = String::new();
    let pid = loop {
        let packet = output_rx.recv_timeout(TIMEOUT).unwrap();
        if packet.header() == STARTUP_STATUS {
            parse_status(&packet, STARTUP_STATUS).unwrap();
            continue;
        }
        let bytes = TerminalBuffer::decode(packet.payload())
            .unwrap()
            .buffer
            .unwrap();
        output.push_str(&String::from_utf8_lossy(&bytes));
        if let Some(pid) = background_pid(&output) {
            break pid;
        }
    };
    assert!(child.wait_timeout(TIMEOUT).unwrap().unwrap().success());
    assert!(kill(Pid::from_raw(pid), None).is_err(), "orphan pid {pid}");
}

fn background_pid(output: &str) -> Option<i32> {
    output.match_indices("BG:").find_map(|(offset, _)| {
        let digits = output[offset + 3..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        (!digits.is_empty())
            .then(|| digits.parse::<i32>().ok())
            .flatten()
    })
}

fn acknowledge_registration(router: &mut impl Write) {
    write_local_packet(router, &status_packet(REGISTRATION_STATUS, Ok(()))).unwrap();
}

fn send<M: Message>(router: &mut impl Write, kind: TerminalPacketType, message: &M) {
    write_local_packet(router, &Packet::new(kind as u8, message.encode_to_vec())).unwrap();
}

fn write_credentials(child: &mut std::process::Child) {
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{ID}/{KEY}_xterm-256color").unwrap();
}

struct Fixture {
    directory: std::path::PathBuf,
    socket: std::path::PathBuf,
    listener: UnixListener,
    ready_socket: std::path::PathBuf,
    ready_listener: UnixListener,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("et-rs-terminal-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("router.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        et_net::local::write_registration_ack_capability(&socket).unwrap();
        let ready_socket = directory.join("ready.sock");
        let ready_listener = UnixListener::bind(&ready_socket).unwrap();
        Self {
            directory,
            socket,
            listener,
            ready_socket,
            ready_listener,
        }
    }

    fn accept(&self) -> std::os::unix::net::UnixStream {
        let listener = self.listener.try_clone().unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = sender.send(listener.accept().map(|(stream, _)| stream));
        });
        let stream = receiver
            .recv_timeout(TIMEOUT)
            .expect("timed out waiting for terminal router connection")
            .unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        stream
    }

    fn spawn(&self) -> std::process::Child {
        self.spawn_with_shell("/bin/sh")
    }

    fn spawn_with_shell(&self, shell: &str) -> std::process::Child {
        Command::new(env!("CARGO_BIN_EXE_et"))
            .args([
                "terminal",
                "--session-child",
                "--ready-socket",
                self.ready_socket.to_str().unwrap(),
                "--serverfifo",
            ])
            .arg(&self.socket)
            .env("SHELL", shell)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn wait_ready(&self) {
        let (sender, receiver) = mpsc::sync_channel(1);
        let listener = self.ready_listener.try_clone().unwrap();
        std::thread::spawn(move || {
            let result = listener.accept().and_then(|(mut stream, _)| {
                let mut ready = [0u8; 1];
                std::io::Read::read_exact(&mut stream, &mut ready)?;
                Ok(ready)
            });
            let _ = sender.send(result);
        });
        assert_eq!(receiver.recv_timeout(TIMEOUT).unwrap().unwrap(), [1]);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
