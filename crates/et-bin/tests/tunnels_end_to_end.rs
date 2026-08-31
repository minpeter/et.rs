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
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn ssh_config_local_and_remote_tunnels_relay_real_tcp_payloads() {
    let mut stack = Stack::start();
    let local_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_destination_port = local_destination.local_addr().unwrap().port();
    let local_echo = spawn_tcp_echo_once(local_destination, b"config-local");
    let local_source_port = reserve_port();
    let reverse_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let reverse_destination_port = reverse_destination.local_addr().unwrap().port();
    let reverse_echo = spawn_tcp_echo_once(reverse_destination, b"config-reverse");
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

    await_fifo(&gate, &mut client);
    assert_ready_tcp_round_trip(local_source_port, b"config-local");
    assert_ready_tcp_round_trip(reverse_source_port, b"config-reverse");

    stop(&mut client);
    local_echo.join().unwrap();
    reverse_echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn ssh_config_hardening_imported_bind_failure_skips_only_that_row() {
    let mut stack = Stack::start();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    let echo = spawn_tcp_echo_once(destination, b"usable-import");
    let usable_port = reserve_port();
    let gate = stack.directory.join("imported-bind-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1
user tester
gatewayports no
         localforward {occupied_port} [127.0.0.1]:{destination_port}
         localforward {usable_port} [127.0.0.1]:{destination_port}
"
    );
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"));
    client
        .env("PATH", &stack.directory)
        .env("ET_SSH_COUNT", &stack.ssh_count)
        .env("ET_SSH_CONFIG", config)
        .env("ET_SSH_READY", &gate)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["--logtostdout", "--terminal-path"])
        .arg(&stack.terminal)
        .args(["--serverfifo"])
        .arg(&stack.router)
        .arg("-N")
        .arg(format!("tester@127.0.0.1:{}", stack.port));
    let mut client = client.spawn().unwrap();

    let ready = {
        let gate = gate.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = sender.send(fs::read_to_string(gate));
        });
        receiver
            .recv_timeout(TIMEOUT)
            .expect("imported bind failure prevented client readiness")
            .unwrap()
    };
    assert_eq!(ready, "ready");
    assert_ready_tcp_round_trip(usable_port, b"usable-import");

    stop(&mut client);
    let mut output = String::new();
    client
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.contains("WARNING"))
            .count(),
        1
    );
    drop(occupied);
    echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn cumulative_local_forwards_deduplicate_exact_rows_but_preserve_distinct_destinations() {
    // Given
    let mut stack = Stack::start();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    let echo = spawn_tcp_echo_once(destination, b"cumulative");
    let distinct_destination_port = reserve_port();
    let source_port = reserve_port();
    let gate = stack.directory.join("cumulative-local-ready");
    mkfifo(&gate);
    let exact = format!("localhost:{source_port}:127.0.0.1:{destination_port}");
    let config = format!(
        "hostname 127.0.0.1\nuser tester\ngatewayports no\n\
         localforward {source_port} [127.0.0.1]:{destination_port}\n\
         localforward {source_port} [127.0.0.1]:{destination_port}\n\
         localforward {source_port} [127.0.0.1]:{distinct_destination_port}\n"
    );
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"));
    client
        .env("PATH", &stack.directory)
        .env("ET_SSH_COUNT", &stack.ssh_count)
        .env("ET_SSH_CONFIG", config)
        .env("ET_SSH_READY", &gate)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["--logtostdout", "--terminal-path"])
        .arg(&stack.terminal)
        .args(["--serverfifo"])
        .arg(&stack.router)
        .args(["-N", "--tunnel", &exact, "--tunnel", &exact])
        .arg(format!("tester@127.0.0.1:{}", stack.port));

    // When
    let mut client = client.spawn().unwrap();
    assert_eq!(await_fifo(&gate, &mut client), "ready");
    assert_ready_tcp_round_trip(source_port, b"cumulative");

    // Then
    stop(&mut client);
    let mut output = String::new();
    client
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.contains("WARNING"))
            .count(),
        1,
        "only the distinct same-source row should reach bind-failure policy: {output}"
    );
    echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn ssh_config_hardening_explicit_bind_failure_remains_fatal() {
    let mut stack = Stack::start();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &stack.directory)
        .env("ET_SSH_COUNT", &stack.ssh_count)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .args(["--terminal-path"])
        .arg(&stack.terminal)
        .args(["--serverfifo"])
        .arg(&stack.router)
        .args(["-N", "--tunnel"])
        .arg(format!("{occupied_port}:1"))
        .arg(format!("tester@127.0.0.1:{}", stack.port))
        .spawn()
        .unwrap();

    let status = client
        .wait_timeout(TIMEOUT)
        .unwrap()
        .expect("explicit bind failure did not terminate the client");

    assert!(!status.success());
    drop(occupied);
    stack.shutdown();
}

#[test]
fn ssh_config_mixed_unix_tcp_tunnels_relay_on_both_axes() {
    let mut stack = Stack::start();

    let local_unix_source = stack.directory.join("local-unix-source.sock");
    let local_tcp_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_tcp_destination_port = local_tcp_destination.local_addr().unwrap().port();
    let local_tcp_echo = spawn_tcp_echo_once(local_tcp_destination, b"local-unix-source");

    let local_tcp_source_port = reserve_port();
    let local_unix_destination_path = stack.directory.join("local-unix-destination.sock");
    let local_unix_destination = UnixListener::bind(&local_unix_destination_path).unwrap();
    let local_unix_echo = spawn_unix_echo(local_unix_destination, b"local-unix-destination");

    let remote_unix_source = stack.directory.join("remote-unix-source.sock");
    let remote_tcp_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let remote_tcp_destination_port = remote_tcp_destination.local_addr().unwrap().port();
    let remote_tcp_echo = spawn_tcp_echo_once(remote_tcp_destination, b"remote-unix-source");

    let remote_tcp_source_port = reserve_port();
    let remote_unix_destination_path = stack.directory.join("remote-unix-destination.sock");
    let remote_unix_destination = UnixListener::bind(&remote_unix_destination_path).unwrap();
    let remote_unix_echo = spawn_unix_echo(remote_unix_destination, b"remote-unix-destination");

    let gate = stack.directory.join("ssh-config-mixed-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1\nuser tester\n\
         localforward {} [127.0.0.1]:{local_tcp_destination_port}\n\
         localforward [127.0.0.1]:{local_tcp_source_port} {}\n\
         remoteforward {} [127.0.0.1]:{remote_tcp_destination_port}\n\
         remoteforward [127.0.0.1]:{remote_tcp_source_port} {}\n",
        local_unix_source.display(),
        local_unix_destination_path.display(),
        remote_unix_source.display(),
        remote_unix_destination_path.display(),
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

    await_fifo(&gate, &mut client);
    assert_unix_round_trip(&local_unix_source, b"local-unix-source");
    assert_ready_tcp_round_trip(local_tcp_source_port, b"local-unix-destination");
    assert_unix_round_trip(&remote_unix_source, b"remote-unix-source");
    assert_ready_tcp_round_trip(remote_tcp_source_port, b"remote-unix-destination");

    stop(&mut client);
    local_tcp_echo.join().unwrap();
    local_unix_echo.join().unwrap();
    remote_tcp_echo.join().unwrap();
    remote_unix_echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn cli_local_and_reverse_tunnels_relay_real_tcp_payloads() {
    let mut stack = Stack::start();
    let local_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_destination_port = local_destination.local_addr().unwrap().port();
    let local_echo = spawn_tcp_echo_once(local_destination, b"local");
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
    await_fifo(&local_gate, &mut local_client);
    assert_ready_tcp_round_trip(local_source_port, b"local");
    stop(&mut local_client);
    local_echo.join().unwrap();
    stack.shutdown();

    let mut stack = Stack::start();
    let reverse_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let reverse_destination_port = reverse_destination.local_addr().unwrap().port();
    let reverse_echo = spawn_tcp_echo_once(reverse_destination, b"reverse");
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
    await_fifo(&reverse_gate, &mut reverse_client);
    assert_ready_tcp_round_trip(reverse_source_port, b"reverse");
    stop(&mut reverse_client);
    reverse_echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn cli_remote_unix_tunnel_relays_on_a_fresh_source_path() {
    // Given
    let mut stack = Stack::start();
    let source = stack.directory.join("cli-remote-source.sock");
    let destination_path = stack.directory.join("cli-remote-destination.sock");
    let destination = UnixListener::bind(&destination_path).unwrap();
    let echo = spawn_unix_echo(destination, b"cli-remote-unix");
    let gate = stack.directory.join("cli-remote-unix-ready");
    mkfifo(&gate);
    let mut client = spawn_client(
        &stack,
        &format!("{}:{}", source.display(), destination_path.display()),
        true,
        &gate,
        None,
        true,
        None,
    );

    // When
    assert_eq!(await_fifo(&gate, &mut client), "ready");
    assert_unix_round_trip(&source, b"cli-remote-unix");

    // Then
    stop(&mut client);
    echo.join().unwrap();
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
    let remote_agent_path = await_fifo(&gate, &mut client);
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
    await_fifo(&gate, &mut client);
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
        .env("ET_SHELL", "/bin/sh")
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

fn spawn_tcp_echo_once(listener: TcpListener, expected: &'static [u8]) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        echo_once(&mut stream, expected);
    })
}

fn spawn_unix_echo(listener: UnixListener, expected: &'static [u8]) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        echo_once(&mut stream, expected);
    })
}

fn echo_once(stream: &mut (impl Read + Write), expected: &[u8]) {
    let mut payload = vec![0u8; expected.len()];
    stream.read_exact(&mut payload).unwrap();
    assert_eq!(payload, expected);
    stream.write_all(&payload).unwrap();
}

fn try_stream_round_trip(stream: &mut (impl Read + Write), payload: &[u8]) -> std::io::Result<()> {
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

fn assert_ready_tcp_round_trip(port: u16, payload: &[u8]) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    try_stream_round_trip(&mut stream, payload).unwrap();
}

fn assert_unix_round_trip(path: &std::path::Path, payload: &[u8]) {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    try_stream_round_trip(&mut stream, payload).unwrap();
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

fn await_fifo(path: &std::path::Path, child: &mut Child) -> String {
    let path = path.to_owned();
    let reader_path = path.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let _ = sender.send(fs::read_to_string(reader_path));
    });
    match receiver.recv_timeout(TIMEOUT) {
        Ok(result) => {
            reader.join().unwrap();
            result.unwrap()
        }
        Err(error) => {
            let status = child.try_wait().unwrap();
            if status.is_none() {
                child.kill().unwrap();
                let _ = child.wait().unwrap();
            }
            let _ = fs::OpenOptions::new().write(true).open(&path);
            reader.join().unwrap();
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("client readiness failed: {error}; status={status:?}; stderr={stderr}");
        }
    }
}

fn stop(child: &mut Child) {
    child.kill().unwrap();
    let _ = child.wait().unwrap();
}
