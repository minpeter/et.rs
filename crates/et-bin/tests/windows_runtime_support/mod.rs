mod process;
mod shell;

pub use process::ProcessExitObserver;
pub use shell::Shell;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use et_core::keys::{gen_id_passkey, passkey_to_key};
use et_core::proto::{ConnectResponse, ConnectStatus, InitialPayload, InitialResponse};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use et_net::handshake::client_request;
use process::OwnedChild;
use prost::Message;

pub const TIMEOUT: Duration = Duration::from_secs(45);

pub struct Stack {
    directory: PathBuf,
    address: SocketAddr,
    id: String,
    key: String,
    server: Option<OwnedChild>,
    terminal: Option<OwnedChild>,
    cleaned: bool,
}

impl Stack {
    pub fn start() -> Self {
        Self::start_with_setup(|_| {})
    }

    fn start_with_setup(before_config: impl FnOnce(&std::path::Path)) -> Self {
        let (id, key) = gen_id_passkey();
        let directory = std::env::temp_dir().join(format!("et-win-{}-{id}", std::process::id()));
        let router = directory.join("router");
        // The CLI deliberately rejects port zero. Reserve an ephemeral port and
        // fail on bind collision rather than retrying or using a fleet endpoint.
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = reserved.local_addr().unwrap();
        let config = directory.join("et.cfg");
        fs::create_dir(&directory).unwrap();
        let mut stack = Self {
            directory,
            address,
            id,
            key,
            server: None,
            terminal: None,
            cleaned: false,
        };
        before_config(&stack.directory);
        fs::write(
            &config,
            format!(
                "[Networking]\nport={}\nbind_ip=127.0.0.1\n[Debug]\nserverfifo={}\n",
                address.port(),
                router.display()
            ),
        )
        .unwrap();
        drop(reserved);
        let mut command = binary();
        command
            .args(["server", "--cfgfile"])
            .arg(config)
            .arg("--logdir")
            .arg(&stack.directory)
            .stdout(Stdio::piped());
        stack.server = Some(OwnedChild::spawn(&mut command));
        let stdout = stack.server.as_mut().unwrap().0.stdout.take().unwrap();
        let ready = observe(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            line
        });
        assert_eq!(
            ready,
            format!("ETSERVER_READY tcp={address} router={}\n", router.display())
        );
        println!("{ready}");
        assert!(et_net::local::supports_registration_ack(&router));
        let (local_address, _) = et_net::local::read_endpoint(&router).unwrap();
        assert!(local_address.ip().is_loopback());

        let mut command = binary();
        command
            .args([
                "terminal",
                "--session-child",
                "--ready-socket",
                "inherited",
                "--serverfifo",
            ])
            .arg(router)
            .arg("--logdir")
            .arg(&stack.directory)
            .env("ET_SHELL", process::powershell())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        stack.terminal = Some(OwnedChild::spawn(&mut command));
        let terminal = &mut stack.terminal.as_mut().unwrap().0;
        let mut stdout = terminal.stdout.take().unwrap();
        let stdin = terminal.stdin.take().unwrap();
        // Subscribe before writing credentials; the exact registered frame is
        // emitted only after the server commits the terminal registration.
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let mut status = [0u8; 7];
            let result = stdout.read_exact(&mut status).map(|()| status);
            sender.send(result).unwrap();
        });
        writeln!(&stdin, "{}/{}_xterm-256color", stack.id, stack.key).unwrap();
        drop(stdin);
        assert_eq!(
            receiver.recv_timeout(TIMEOUT).unwrap().unwrap(),
            *b"ETS1\x01\0\0"
        );
        worker.join().unwrap();
        println!("REGISTERED terminal_pid={}", terminal.id());
        stack
    }

    pub fn handshake(&self, expected: ConnectStatus) -> TcpStream {
        let mut stream = TcpStream::connect_timeout(&self.address, TIMEOUT).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        write_proto(&mut stream, &client_request(&self.id)).unwrap();
        let response: ConnectResponse = read_proto_limited(&mut stream, 64 * 1024).unwrap();
        assert_eq!(response.status, Some(expected as i32), "{response:?}");
        println!("HANDSHAKE {expected:?}");
        stream
    }

    pub fn connect(&self) -> Connection {
        let stream = self.handshake(ConnectStatus::NewClient);
        let mut client = Connection::new_client(stream, &passkey_to_key(&self.key).unwrap());
        client
            .write_packet(253, &InitialPayload::default().encode_to_vec())
            .unwrap();
        let packet = client
            .read_packet_until(std::time::Instant::now() + TIMEOUT)
            .unwrap();
        assert_eq!(packet.header(), 252);
        let response = InitialResponse::decode(packet.payload()).unwrap();
        assert_eq!(response.error, None, "{response:?}");
        client
    }

    pub fn wait_terminal(&mut self, success: bool) {
        let status = self.terminal.as_mut().unwrap().wait();
        assert_eq!(status.success(), success, "terminal exit: {status}");
        println!("TERMINAL_REAPED {status}");
    }

    pub fn stop_server(&mut self) {
        let mut server = self.server.take().unwrap();
        server.0.kill().unwrap();
        println!("SERVER_REAPED {}", server.wait());
    }

    pub fn finish(mut self) {
        if self.server.is_some() {
            self.stop_server();
        }
        drop(self.terminal.take());
        fs::remove_dir_all(&self.directory).expect("fixture directory cleanup failed");
        self.cleaned = true;
        println!("FIXTURE_REMOVED {}", self.directory.display());
    }
}

#[path = "setup_tests.rs"]
mod setup_tests;

impl Drop for Stack {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        drop(self.server.take());
        drop(self.terminal.take());
        match fs::remove_dir_all(&self.directory) {
            Ok(()) => println!("FIXTURE_REMOVED {}", self.directory.display()),
            Err(error) => eprintln!("fixture cleanup failed: {error}"),
        }
    }
}

fn binary() -> Command {
    // CI's downloadable test executable can run on a toolchain-free host.
    Command::new(
        std::env::var_os("ET_WINDOWS_RUNTIME_BINARY")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_et").into()),
    )
}

fn observe<T: Send + 'static>(read: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || sender.send(read()).is_ok());
    let result = receiver
        .recv_timeout(TIMEOUT)
        .expect("process readiness event timed out");
    assert!(worker.join().unwrap());
    result
}
