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

const TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn ssh_config_local_tunnel_relays_while_remote_forward_is_omitted() {
    let mut stack = Stack::start();
    let local_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_destination_port = local_destination.local_addr().unwrap().port();
    let local_echo = spawn_tcp_echo_once(local_destination, b"config-local");
    let local_source = stack.directory.join("ssh-config-local.sock");
    let reverse_source = stack.directory.join("ssh-config-remote.sock");
    let gate = stack.directory.join("ssh-config-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1\nuser tester\n\
         localforward {} [127.0.0.1]:{local_destination_port}\n\
         remoteforward {} [127.0.0.1]:{local_destination_port}\n",
        local_source.display(),
        reverse_source.display(),
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
    assert_unix_round_trip(&local_source, b"config-local");
    assert!(!reverse_source.exists());

    stop(&mut client);
    local_echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn ssh_config_destination_host_reaches_target_not_localhost_decoy() {
    let mut stack = Stack::start();
    let (target, decoy) = reserve_destination_and_decoy().unwrap();
    let target_port = target.local_addr().unwrap().port();
    decoy.set_nonblocking(true).unwrap();
    let target_echo = spawn_tcp_echo_once(target, b"configured-destination");
    let source = stack.directory.join("configured-destination.sock");
    let gate = stack.directory.join("configured-destination-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1\nuser tester\n\
         localforward {} [127.0.0.2]:{target_port}\n",
        source.display(),
    );
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"))
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
        .arg(format!("tester@127.0.0.1:{}", stack.port))
        .spawn()
        .unwrap();

    assert_eq!(await_fifo(&gate, &mut client), "ready");
    assert_unix_round_trip(&source, b"configured-destination");
    assert!(matches!(
        decoy.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));

    stop(&mut client);
    target_echo.join().unwrap();
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
    let usable_source = stack.directory.join("best-effort-source.sock");
    let gate = stack.directory.join("imported-bind-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1
user tester
gatewayports no
         localforward {occupied_port} [127.0.0.1]:{destination_port}
         localforward {} [127.0.0.1]:{destination_port}
",
        usable_source.display(),
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
    assert_unix_round_trip(&usable_source, b"usable-import");

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
        2,
        "the fake SSH rejects the private master before the imported bind warning: {output}"
    );
    drop(occupied);
    echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn exit_on_forward_failure_yes_aborts_imported_bind_conflict() {
    let mut stack = Stack::start();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let config = format!(
        "hostname 127.0.0.1\nuser tester\n\
         exitonforwardfailure yes\n\
         localforward {occupied_port} [127.0.0.1]:1\n"
    );
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &stack.directory)
        .env("ET_SSH_COUNT", &stack.ssh_count)
        .env("ET_SSH_CONFIG", config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .args(["--terminal-path"])
        .arg(&stack.terminal)
        .args(["--serverfifo"])
        .arg(&stack.router)
        .arg("-N")
        .arg(format!("tester@127.0.0.1:{}", stack.port))
        .spawn()
        .unwrap();

    let status = client
        .wait_timeout(TIMEOUT)
        .unwrap()
        .expect("strict imported bind conflict did not terminate the client");
    let mut error = String::new();
    client
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();
    assert!(!status.success());
    assert!(error.contains("Address already in use"), "{error}");

    drop(occupied);
    stack.shutdown();
}

#[test]
fn imported_remote_rows_are_omitted_while_local_row_stays_live() {
    let mut stack = Stack::start();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    let echo = spawn_tcp_echo_once(destination, b"usable-local-import");
    let local_source = stack.directory.join("imported-local.sock");
    let usable_source = stack.directory.join("omitted-remote.sock");
    let gate = stack.directory.join("imported-remote-bind-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1\nuser tester\n\
         localforward {} [127.0.0.1]:{destination_port}\n\
         remoteforward {occupied_port} [127.0.0.1]:{destination_port}\n\
         remoteforward {} [127.0.0.1]:{destination_port}\n",
        local_source.display(),
        usable_source.display(),
    );
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"))
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
        .arg(format!("tester@127.0.0.1:{}", stack.port))
        .spawn()
        .unwrap();

    assert_eq!(await_fifo(&gate, &mut client), "ready");
    assert_unix_round_trip(&local_source, b"usable-local-import");
    assert!(!usable_source.exists());

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
        "only the fake SSH's rejected private master should warn: {output}"
    );
    drop(occupied);
    echo.join().unwrap();
    stack.shutdown();
}

#[test]
fn native_jumphost_omits_imported_remote_rows() {
    let mut destination = Stack::start();
    let mut jump = Stack::start();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    let echo = spawn_tcp_echo_once(backend, b"native-jump-local");
    let local_source = destination.directory.join("native-jump-local.sock");
    let usable_source = destination.directory.join("native-jump-remote.sock");
    let gate = destination.directory.join("native-jump-report-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1\nuser tester\n\
         localforward {} [127.0.0.1]:{backend_port}\n\
         remoteforward {occupied_port} [127.0.0.1]:{backend_port}\n\
         remoteforward {} [127.0.0.1]:{backend_port}\n",
        local_source.display(),
        usable_source.display(),
    );
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &destination.directory)
        .env("ET_SSH_COUNT", &destination.ssh_count)
        .env("ET_SSH_CONFIG", config)
        .env("ET_SSH_READY", &gate)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["--logtostdout", "--terminal-path"])
        .arg(&destination.terminal)
        .args(["--serverfifo"])
        .arg(&destination.router)
        .args(["--jumphost", "jump.example", "--jport"])
        .arg(jump.port.to_string())
        .args(["--jserverfifo"])
        .arg(&jump.router)
        .arg("-N")
        .arg(format!("tester@127.0.0.1:{}", destination.port))
        .spawn()
        .unwrap();

    assert_eq!(await_fifo(&gate, &mut client), "ready");
    assert_unix_round_trip(&local_source, b"native-jump-local");
    assert!(!usable_source.exists());

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
        2,
        "the fake SSH rejects one private master for each SSH target: {output}"
    );
    drop(occupied);
    echo.join().unwrap();
    jump.shutdown();
    destination.shutdown();
}

#[test]
fn native_jumphost_explicit_remote_bind_failure_releases_final_sibling() {
    let mut destination = Stack::start();
    let mut jump = Stack::start();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let sibling_source = destination.directory.join("jump-sibling-source.sock");
    let sibling_destination = destination.directory.join("jump-sibling-destination.sock");
    let mut client = Command::new(env!("CARGO_BIN_EXE_et"))
        .env("PATH", &destination.directory)
        .env("ET_SSH_COUNT", &destination.ssh_count)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .args(["--terminal-path"])
        .arg(&destination.terminal)
        .args(["--serverfifo"])
        .arg(&destination.router)
        .args(["--jumphost", "jump.example", "--jport"])
        .arg(jump.port.to_string())
        .args(["--jserverfifo"])
        .arg(&jump.router)
        .args(["-N", "-r"])
        .arg(format!(
            "{}:{}",
            sibling_source.display(),
            sibling_destination.display()
        ))
        .arg("-r")
        .arg(format!("{occupied_port}:1"))
        .arg(format!("tester@127.0.0.1:{}", destination.port))
        .spawn()
        .unwrap();

    let status = client
        .wait_timeout(TIMEOUT)
        .unwrap()
        .expect("native jumphost reverse bind failure did not terminate the top-level client");
    let mut error = String::new();
    client
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();

    assert!(!status.success());
    assert!(error.contains("Address already in use"), "{error}");
    assert!(!sibling_source.exists());
    let rebound = UnixListener::bind(&sibling_source).unwrap();
    drop(rebound);
    jump.shutdown();
    destination.shutdown();
    drop(occupied);
}

#[test]
fn explicit_remote_bind_failure_aborts_and_releases_sibling_listener() {
    let mut stack = Stack::start();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let sibling_source = stack.directory.join("sibling-source.sock");
    let sibling_destination = stack.directory.join("sibling-destination.sock");
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
        .args(["-N", "-r"])
        .arg(format!(
            "{}:{}",
            sibling_source.display(),
            sibling_destination.display()
        ))
        .arg("-r")
        .arg(format!("{occupied_port}:1"))
        .arg(format!("tester@127.0.0.1:{}", stack.port))
        .spawn()
        .unwrap();

    let status = client
        .wait_timeout(TIMEOUT)
        .unwrap()
        .expect("explicit reverse bind failure did not terminate the client");
    let mut error = String::new();
    client
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut error)
        .unwrap();

    assert!(!status.success());
    assert!(error.contains("Address already in use"), "{error}");
    assert!(!sibling_source.exists());
    let rebound = UnixListener::bind(&sibling_source).unwrap();
    drop(rebound);
    stack.shutdown();
    drop(occupied);
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
        2,
        "the fake SSH's rejected private master and only the distinct same-source row should warn: {output}"
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
fn ssh_config_unix_local_tunnels_relay_and_remote_rows_are_omitted() {
    let mut stack = Stack::start();

    let local_unix_source = stack.directory.join("local-unix-source.sock");
    let local_tcp_destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_tcp_destination_port = local_tcp_destination.local_addr().unwrap().port();
    let local_tcp_echo = spawn_tcp_echo_once(local_tcp_destination, b"local-unix-source");

    let second_local_unix_source = stack.directory.join("second-local-unix-source.sock");
    let local_unix_destination_path = stack.directory.join("local-unix-destination.sock");
    let local_unix_destination = UnixListener::bind(&local_unix_destination_path).unwrap();
    let local_unix_echo = spawn_unix_echo(local_unix_destination, b"local-unix-destination");

    let remote_unix_source = stack.directory.join("remote-unix-source.sock");

    let gate = stack.directory.join("ssh-config-mixed-ready");
    mkfifo(&gate);
    let config = format!(
        "hostname 127.0.0.1\nuser tester\n\
         localforward {} [127.0.0.1]:{local_tcp_destination_port}\n\
         localforward {} {}\n\
         remoteforward {} [127.0.0.1]:9\n",
        local_unix_source.display(),
        second_local_unix_source.display(),
        local_unix_destination_path.display(),
        remote_unix_source.display(),
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
    assert_unix_round_trip(&second_local_unix_source, b"local-unix-destination");
    assert!(!remote_unix_source.exists());

    stop(&mut client);
    local_tcp_echo.join().unwrap();
    local_unix_echo.join().unwrap();
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
    if let Err(error) = ready_tcp_round_trip(reverse_source_port, b"reverse") {
        panic_tunnel_failure(error, &mut reverse_client, &mut stack);
    }
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
    if let Err(error) = try_stream_round_trip(&mut remote, b"agent") {
        panic_tunnel_failure(error, &mut client, &mut stack);
    }
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
    let address = listener.local_addr().unwrap();
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_cancelled = std::sync::Arc::clone(&cancelled);
    let (completed_tx, completed_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        // Accept multiple times so readiness probes do not exhaust a one-shot echo.
        loop {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut payload = vec![0u8; expected.len()];
            if stream.read_exact(&mut payload).is_err() {
                if worker_cancelled.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                continue;
            }
            assert_eq!(payload, expected);
            stream.write_all(&payload).unwrap();
            completed_tx.send(()).unwrap();
            return;
        }
    });
    thread::spawn(move || {
        if completed_rx.recv_timeout(TIMEOUT + TIMEOUT).is_err() {
            cancelled.store(true, std::sync::atomic::Ordering::Release);
            drop(TcpStream::connect(address));
            worker.join().unwrap();
            panic!("TCP echo did not receive its payload before the deadline");
        }
        worker.join().unwrap();
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
    ready_tcp_round_trip(port, payload).unwrap();
}

fn ready_tcp_round_trip(port: u16, payload: &[u8]) -> std::io::Result<()> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    try_stream_round_trip(&mut stream, payload)
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

fn reserve_destination_and_decoy() -> std::io::Result<(TcpListener, TcpListener)> {
    const MAX_ATTEMPTS: usize = 128;
    let target_address = Ipv4Addr::new(127, 0, 0, 2);
    for _ in 0..MAX_ATTEMPTS {
        let target = TcpListener::bind((target_address, 0))?;
        let port = target.local_addr()?.port();
        match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(decoy) => return Ok((target, decoy)),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!("could not reserve paired loopback listeners after {MAX_ATTEMPTS} attempts"),
    ))
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

fn panic_tunnel_failure(error: std::io::Error, child: &mut Child, stack: &mut Stack) -> ! {
    let status_before = child.try_wait().unwrap();
    if status_before.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let status_after = child.try_wait().unwrap();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let server = stack.failure_diagnostics();
    panic!(
        "tunnel round-trip failed: {error}; client status before={status_before:?} \
         after={status_after:?}; client stderr={stderr}; {server}"
    );
}
