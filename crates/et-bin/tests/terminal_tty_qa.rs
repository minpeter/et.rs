#![forbid(unsafe_code)]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(10);
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

#[test]
fn real_tty_restores_termios_and_propagates_resize() {
    let stack = Stack::start();
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 30,
            cols: 90,
            pixel_width: 900,
            pixel_height: 600,
        })
        .unwrap();
    let client = shell_quote(env!("CARGO_BIN_EXE_et"));
    let terminal = shell_quote(stack.terminal.to_str().unwrap());
    let router = shell_quote(stack.router.to_str().unwrap());
    let command = format!(
        "before=$(stty -g); {client} --terminal-path {terminal} --serverfifo {router} \
         -p {} -c \"printf 'TTY-G004\\\\n'; stty size\" 127.0.0.1; \
         code=$?; after=$(stty -g); restored=no; \
         [ \"$before\" = \"$after\" ] && restored=yes; \
         printf '\\nTERMIOS-RESTORED:%s:CODE:%s\\n' \"$restored\" \"$code\"",
        stack.port
    );
    let mut shell = CommandBuilder::new("/bin/sh");
    shell.arg("-c");
    shell.arg(command);
    shell.env(
        "PATH",
        format!(
            "{}:{}",
            stack.directory.display(),
            std::env::var("PATH").unwrap()
        ),
    );
    shell.env("TERM", "xterm-256color");
    let mut child = pair.slave.spawn_command(shell).unwrap();
    drop(pair.slave);
    let mut output = String::new();
    pair.master
        .try_clone_reader()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "status={status:?} output={output:?}");
    assert!(output.contains("TTY-G004"), "{output:?}");
    assert!(output.contains("30 90"), "{output:?}");
    assert!(output.contains("TERMIOS-RESTORED:yes:CODE:0"), "{output:?}");
}

#[test]
fn real_tty_forwards_input_control_bytes_and_live_resize() {
    let stack = Stack::start();
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
        "-p",
        &stack.port.to_string(),
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
    let mut child = pair.slave.spawn_command(client).unwrap();
    drop(pair.slave);
    let mut writer = pair.master.take_writer().unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let (sender, receiver) = mpsc::sync_channel(32);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    if sender.send(chunk[..count].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    writer.write_all(b"printf 'FIRST\\n'\n").unwrap();
    let mut output = receive_until(&receiver, Vec::new(), b"FIRST\r\n");
    pair.master
        .resize(PtySize {
            rows: 40,
            cols: 100,
            pixel_width: 1000,
            pixel_height: 800,
        })
        .unwrap();
    writer
        .write_all(
            b"printf 'LIVE:%s\\n' \"$(stty size)\"; printf 'BIN:\\001\\177\\n'; \
              printf 'READY\\n'; sleep 30\n",
        )
        .unwrap();
    output = receive_until(&receiver, output, b"READY\r\n");
    writer.write_all(b"\x03printf 'CTRL\\n'; exit\n").unwrap();
    while let Ok(chunk) = receiver.recv_timeout(TIMEOUT) {
        output.extend(chunk);
    }
    let status = child.wait().unwrap();
    assert!(status.success(), "status={status:?} output={output:?}");
    assert!(output.windows(11).any(|window| window == b"LIVE:40 100"));
    assert!(output.windows(6).any(|window| window == b"BIN:\x01\x7f"));
    assert!(output.windows(4).any(|window| window == b"CTRL"));
}

fn receive_until(
    receiver: &mpsc::Receiver<Vec<u8>>,
    mut output: Vec<u8>,
    marker: &[u8],
) -> Vec<u8> {
    while !output.windows(marker.len()).any(|window| window == marker) {
        match receiver.recv_timeout(TIMEOUT) {
            Ok(chunk) => output.extend(chunk),
            Err(error) => panic!("waiting for marker {marker:?}: {error}; output={output:?}"),
        }
    }
    output
}

struct Stack {
    directory: std::path::PathBuf,
    router: std::path::PathBuf,
    terminal: std::path::PathBuf,
    port: u16,
    server: std::process::Child,
}

impl Stack {
    fn start() -> Self {
        let fixture = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("et-rs-tty-qa-{}-{fixture}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let router = directory.join("router.sock");
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let config = directory.join("et.cfg");
        fs::write(
            &config,
            format!(
                "[Networking]\nport={port}\nbind_ip=127.0.0.1\n\
                 [Debug]\nserverfifo={}\n",
                router.display()
            ),
        )
        .unwrap();
        let mut server = Command::new(env!("CARGO_BIN_EXE_et"))
            .args(["server", "--cfgfile"])
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_ready(&mut server, port, &router);
        let ssh = directory.join("ssh");
        fs::write(
            &ssh,
            "#!/bin/sh\nif [ \"$1\" = \"-G\" ]; then\n\
             printf 'hostname 127.0.0.1\\nuser tester\\n'; exit 0; fi\n\
             for last do :; done\nexec /bin/sh -c \"$last\"\n",
        )
        .unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
        let terminal = directory.join("etterminal");
        symlink(env!("CARGO_BIN_EXE_et"), &terminal).unwrap();
        Self {
            directory,
            router,
            terminal,
            port,
            server,
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let pid = Pid::from_raw(i32::try_from(self.server.id()).unwrap());
        let _ = kill(pid, Signal::SIGTERM);
        let _ = self.server.wait_timeout(TIMEOUT);
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn wait_ready(server: &mut std::process::Child, port: u16, router: &std::path::Path) {
    let stdout = server.stdout.take().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    assert_eq!(
        receiver.recv_timeout(TIMEOUT).unwrap().unwrap(),
        format!(
            "ETSERVER_READY tcp=127.0.0.1:{port} router={}\n",
            router.display()
        )
    );
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
