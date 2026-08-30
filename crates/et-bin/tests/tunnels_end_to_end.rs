#![forbid(unsafe_code)]

mod reconnect_stack;
mod tunnel_support;

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use reconnect_stack::{mkfifo, shell_quote, Stack};
use tunnel_support::SingleCutProxy;

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn ssh_config_local_and_remote_tunnels_relay_real_tcp_payloads() {
    let mut stack = Stack::start();
    let local_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_destination_port = local_destination.local_addr().unwrap().port();
    let local_echo = spawn_tcp_echo(local_destination);
    let local_source_port = reserve_port();
    let reverse_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let reverse_destination_port = reverse_destination.local_addr().unwrap().port();
    let reverse_echo = spawn_tcp_echo(reverse_destination);
    let reverse_source_port = reserve_port();
    let gate = stack.directory.join("ssh-config-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1\nuser tester\n\
         localforward {local_source_port} [127.0.0.1]:{local_destination_port}\n\
         remoteforward {reverse_source_port} [127.0.0.1]:{reverse_destination_port}\n"
    );
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"));
    client
        .env("PATH", &stack.directory)
        .env("ET_SSH_COUNT", &stack.ssh_count)
        .env("ET_SSH_CONFIG", config)
        .env("ET_SSH_READY", &gate)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .args(["--terminal-path"])
        .arg(&stack.terminal)
        .args(["--serverfifo"])
        .arg(&stack.router)
        .arg("-N")
        .arg(format!("tester@127.0.0.1:{}", stack.port));
    let mut client = client.spawn().unwrap();

    await_fifo(&gate);
    assert_tcp_round_trip(local_source_port, b"config-local");
    assert_tcp_round_trip(reverse_source_port, b"config-reverse");

    stop(&mut client);
    local_echo.join().unwrap();
    reverse_echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn cli_local_and_reverse_tunnels_relay_real_tcp_payloads() {
    let mut stack = Stack::start();
    let local_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_destination_port = local_destination.local_addr().unwrap().port();
    let local_echo = spawn_tcp_echo(local_destination);
    let local_source_port = reserve_port();
    let local_gate = stack.directory.join("local-ready");
    mkfifo(&local_gate);
    let mut local_client = spawn_client(
        &stack,
        &format!("{local_source_port}:{local_destination_port}"),
        false,
        &local_gate,
        None,
        true,
        None,
    );
    await_fifo(&local_gate);
    assert_tcp_round_trip(local_source_port, b"local");
    stop(&mut local_client);
    local_echo.join().unwrap();

    let reverse_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let reverse_destination_port = reverse_destination.local_addr().unwrap().port();
    let reverse_echo = spawn_tcp_echo(reverse_destination);
    let reverse_source_port = reserve_port();
    let reverse_gate = stack.directory.join("reverse-ready");
    mkfifo(&reverse_gate);
    let mut reverse_client = spawn_client(
        &stack,
        &format!("{reverse_source_port}:{reverse_destination_port}"),
        true,
        &reverse_gate,
        None,
        false,
        None,
    );
    await_fifo(&reverse_gate);
    assert_tcp_round_trip(reverse_source_port, b"reverse");
    stop(&mut reverse_client);
    reverse_echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn cli_ssh_agent_forwarding_relays_a_real_unix_socket() {
    let mut stack = Stack::start();
    let local_agent_path = stack.directory.join("local-agent.sock");
    let local_agent = UnixListener::bind(&local_agent_path).unwrap();
    let agent_echo = thread::spawn(move || {
        let (mut stream, _) = local_agent.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).unwrap();
        stream.write_all(&payload).unwrap();
    });
    let gate = stack.directory.join("agent-ready");
    mkfifo(&gate);
    let mut client = spawn_client(
        &stack,
        "",
        true,
        &gate,
        Some(local_agent_path.to_str().unwrap()),
        false,
        None,
    );
    let remote_agent_path = await_fifo(&gate);
    let mut remote = UnixStream::connect(&remote_agent_path).unwrap();
    remote.set_read_timeout(Some(TIMEOUT)).unwrap();
    remote.write_all(b"agent").unwrap();
    let mut echoed = [0u8; 5];
    remote.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"agent");
    drop(remote);
    stop(&mut client);
    agent_echo.join().unwrap();
    stack.shutdown();
    assert!(!std::path::Path::new(&remote_agent_path).exists());
    assert!(!std::path::Path::new(&remote_agent_path)
        .parent()
        .unwrap()
        .exists());
}

#[test]
fn active_local_tunnel_survives_et_reconnect() {
    let mut stack = Stack::start();
    let proxy = SingleCutProxy::start(stack.port);
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    let echo = thread::spawn(move || {
        let (mut stream, _) = destination.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        for _ in 0..2 {
            let mut payload = [0u8; 5];
            stream.read_exact(&mut payload).unwrap();
            stream.write_all(&payload).unwrap();
        }
    });
    let source_port = reserve_port();
    let gate = stack.directory.join("reconnect-tunnel-ready");
    mkfifo(&gate);
    let mut client = spawn_client(
        &stack,
        &format!("{source_port}:{destination_port}"),
        false,
        &gate,
        None,
        true,
        Some(proxy.port),
    );
    await_fifo(&gate);
    // Wait until the local source accepts (listener bound after handshake).
    let mut application = wait_connect(source_port);
    application.set_read_timeout(Some(TIMEOUT)).unwrap();
    assert_stream_round_trip(&mut application, b"first");
    proxy.cut();
    application.write_all(b"again").unwrap();
    proxy.resume();
    let mut echoed = [0u8; 5];
    application.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"again");
    drop(application);
    stop(&mut client);
    echo.join().unwrap();
    proxy.join();
    stack.shutdown();
}

fn spawn_client(
    stack: &Stack,
    tunnel: &str,
    reverse: bool,
    gate: &std::path::Path,
    agent: Option<&str>,
    no_terminal: bool,
    endpoint_port: Option<u16>,
) -> Child {
    let command = if agent.is_some() {
        format!(
            "printf %s \"$SSH_AUTH_SOCK\" > {}; exec tail -f /dev/null",
            shell_quote(gate.to_str().unwrap())
        )
    } else {
        format!(
            "printf ready > {}; exec tail -f /dev/null",
            shell_quote(gate.to_str().unwrap())
        )
    };
    let mut process = Command::new(env!("CARGO_BIN_EXE_et"));
    process
        .env("PATH", &stack.directory)
        .env("ET_SSH_COUNT", &stack.ssh_count)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .args(["--terminal-path"])
        .arg(&stack.terminal)
        .args(["--serverfifo"])
        .arg(&stack.router);
    if no_terminal {
        process.env("ET_SSH_READY", gate).arg("-N");
    } else {
        process.args(["--command", &command]);
    }
    if let Some(agent) = agent {
        process.args(["--forward-ssh-agent", "--ssh-socket", agent]);
    } else if reverse {
        process.args(["--reverse-tunnel", tunnel]);
    } else {
        process.args(["--tunnel", tunnel]);
    }
    process
        .arg(format!(
            "tester@127.0.0.1:{}",
            endpoint_port.unwrap_or(stack.port)
        ))
        .spawn()
        .unwrap()
}

fn spawn_tcp_echo(listener: TcpListener) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // Accept multiple times so readiness retries do not exhaust a one-shot echo.
        let deadline = std::time::Instant::now() + TIMEOUT + TIMEOUT;
        listener
            .set_nonblocking(true)
            .expect("echo listener nonblocking");
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).ok();
                    stream.set_read_timeout(Some(TIMEOUT)).ok();
                    let mut payload = [0u8; 16];
                    if let Ok(count) = stream.read(&mut payload) {
                        if count > 0 {
                            let _ = stream.write_all(&payload[..count]);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // Brief park while waiting for the next tunnel probe.
                    thread::park_timeout(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    })
}

fn assert_tcp_round_trip(port: u16, payload: &[u8]) {
    // Poll until the tunnel source is bound and the multiplex path is live.
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut last = None;
    while std::time::Instant::now() < deadline {
        match TcpStream::connect_timeout(
            &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_millis(50),
        ) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                stream.set_write_timeout(Some(TIMEOUT)).unwrap();
                match try_stream_round_trip(&mut stream, payload) {
                    Ok(()) => return,
                    Err(error) => last = Some(error),
                }
            }
            Err(error) => last = Some(error),
        }
    }
    panic!(
        "tunnel round-trip on port {port} failed within {TIMEOUT:?}: {:?}",
        last
    );
}

fn try_stream_round_trip(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(payload)?;
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed)?;
    if echoed != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "echo mismatch",
        ));
    }
    Ok(())
}

fn wait_connect(port: u16) -> TcpStream {
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut last = None;
    while std::time::Instant::now() < deadline {
        match TcpStream::connect_timeout(
            &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_millis(50),
        ) {
            Ok(stream) => return stream,
            Err(error) => last = Some(error),
        }
    }
    panic!("connect to local tunnel {port} failed: {last:?}");
}

fn assert_stream_round_trip(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).unwrap();
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, payload);
}

fn reserve_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn await_fifo(path: &std::path::Path) -> String {
    let path = path.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(fs::read_to_string(path));
    });
    receiver.recv_timeout(TIMEOUT).unwrap().unwrap()
}

fn stop(child: &mut Child) {
    child.kill().unwrap();
    let _ = child.wait().unwrap();
}
