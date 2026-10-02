#![cfg(unix)]
#![forbid(unsafe_code)]

mod reconnect_stack;
mod tunnel_support;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reconnect_stack::{mkfifo, shell_quote, Stack};
use tunnel_support::SingleCutProxy;
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(15);

struct Client(Child);

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn client_command(stack: &Stack, agent: Option<&Path>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_et"));
    command
        .env("PATH", &stack.directory)
        .env("HOME", &stack.directory)
        .env("TMPDIR", &stack.directory)
        .env("ET_SSH_COUNT", &stack.ssh_count)
        .env("ET_SHELL", "/bin/sh")
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(agent) = agent {
        command.env("SSH_AUTH_SOCK", agent);
    }
    command
}

fn start(stack: &Stack, agent: &Path, port: u16) -> Client {
    let gate = stack.directory.join("shell-gate");
    mkfifo(&gate);
    let remote_path = stack.directory.join("remote-agent");
    let shell_command = format!(
        "printf %s \"$SSH_AUTH_SOCK\" > {}; exec /bin/cat < {}",
        shell_quote(remote_path.to_str().unwrap()),
        shell_quote(gate.to_str().unwrap()),
    );
    Client(
        client_command(stack, Some(agent))
            .args([
                "--name",
                "agent-test",
                "--forward-ssh-agent",
                "--terminal-path",
            ])
            .arg(&stack.terminal)
            .arg("--serverfifo")
            .arg(&stack.router)
            .args(["--command", &shell_command])
            .arg(format!("tester@127.0.0.1:{port}"))
            .spawn()
            .unwrap(),
    )
}

fn attach(stack: &Stack, agent: Option<&Path>) -> Client {
    Client(
        client_command(stack, agent)
            .args(["--attach", "agent-test", "--no-terminal"])
            .spawn()
            .unwrap(),
    )
}

fn wait(client: &mut Client, description: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        if let Some(status) = client.0.try_wait().unwrap() {
            let mut error = String::new();
            client
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut error)
                .unwrap();
            panic!("client exited {status}: {error}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {description}");
}

fn paths(stack: &Stack, client: &mut Client) -> (PathBuf, PathBuf) {
    let remote_file = stack.directory.join("remote-agent");
    let saved_file = stack.directory.join(".et/sessions/agent-test");
    wait(client, "session record and remote agent path", || {
        fs::metadata(&remote_file).is_ok_and(|meta| meta.len() > 0) && saved_file.exists()
    });
    let remote = PathBuf::from(fs::read_to_string(remote_file).unwrap());
    let record = fs::read_to_string(saved_file).unwrap();
    let id = record
        .lines()
        .find_map(|line| line.strip_prefix("id="))
        .unwrap();
    let local = stack.directory.join(format!("et-agent-{id}/agent.sock"));
    (remote, local)
}

fn request(client: &mut Client, remote: &Path, agent: &UnixListener, answer: &[u8]) {
    let mut connection = UnixStream::connect(remote).unwrap();
    connection.set_read_timeout(Some(TIMEOUT)).unwrap();
    connection.write_all(b"agent-request").unwrap();
    let mut accepted = None;
    wait(client, "agent request acceptance", || {
        accepted = match agent.accept() {
            Ok((stream, _)) => Some(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(error) => panic!("agent accept: {error}"),
        };
        accepted.is_some()
    });
    let mut agent_stream = accepted.unwrap();
    agent_stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    let mut request = [0; 13];
    agent_stream.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"agent-request");
    agent_stream.write_all(answer).unwrap();
    let mut response = vec![0; answer.len()];
    connection.read_exact(&mut response).unwrap();
    assert_eq!(response, answer);
}

fn listener(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

#[test]
fn named_attach_retargets_to_new_agent_without_changing_remote_socket() {
    let mut stack = Stack::start();
    let old_path = stack.directory.join("old.sock");
    let new_path = stack.directory.join("new.sock");
    let old = listener(&old_path);
    let new = listener(&new_path);
    let mut first = start(&stack, &old_path, stack.port);
    let (remote, local) = paths(&stack, &mut first);
    let remote_inode = fs::metadata(&remote).unwrap().ino();
    assert_eq!(
        fs::metadata(&remote).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(local.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    request(&mut first, &remote, &old, b"old-identity");
    drop(first);

    // Possessing a local record is not enough: a failed authentication must
    // not retarget the endpoint used by the still-running remote session.
    let saved_file = stack.directory.join(".et/sessions/agent-test");
    let record = fs::read_to_string(&saved_file).unwrap();
    let passkey = record
        .lines()
        .find_map(|line| line.strip_prefix("passkey="))
        .unwrap();
    let replacement = if passkey.starts_with('A') { 'B' } else { 'A' };
    let invalid = record.replace(passkey, &format!("{replacement}{}", &passkey[1..]));
    fs::write(&saved_file, invalid).unwrap();
    let mut denied = attach(&stack, Some(&new_path));
    assert!(!denied
        .0
        .wait_timeout(TIMEOUT)
        .unwrap()
        .expect("rejected attach exits")
        .success());
    assert_eq!(fs::read_link(&local).unwrap(), old_path);
    fs::write(saved_file, record).unwrap();
    drop(denied);

    let mut second = attach(&stack, Some(&new_path));
    wait(&mut second, "proxy retarget to the new agent", || {
        fs::read_link(&local).ok().as_ref() == Some(&new_path)
    });
    request(&mut second, &remote, &new, b"new-and-different-identity");
    assert_eq!(
        old.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(fs::metadata(&remote).unwrap().ino(), remote_inode);
    assert_eq!(
        fs::read_to_string(stack.directory.join("remote-agent")).unwrap(),
        remote.to_str().unwrap()
    );
    drop(second);

    // Missing environment clears the previous agent instead of leaving it exposed.
    let mut no_agent = attach(&stack, None);
    wait(&mut no_agent, "proxy removal without an agent", || {
        fs::symlink_metadata(&local).is_err()
    });
    let mut rejected = UnixStream::connect(&remote).unwrap();
    rejected.set_read_timeout(Some(TIMEOUT)).unwrap();
    let _ = rejected.write_all(b"no-agent");
    let result = rejected.read(&mut [0]);
    assert!(
        matches!(result, Ok(0))
            || result.is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ))
    );
    assert_eq!(
        new.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(no_agent);

    // A removed local directory is also reestablished on the next attach.
    fs::remove_dir(local.parent().unwrap()).unwrap();
    let mut restored = attach(&stack, Some(&new_path));
    wait(&mut restored, "removed proxy directory restoration", || {
        fs::read_link(&local).ok().as_ref() == Some(&new_path)
    });
    request(&mut restored, &remote, &new, b"restored");
    assert_eq!(fs::metadata(&remote).unwrap().ino(), remote_inode);
    drop(restored);
    stack.shutdown();
}

#[test]
fn reconnect_reestablishes_the_agent_proxy_before_new_requests() {
    let mut stack = Stack::start();
    let transport = SingleCutProxy::start(stack.port);
    let agent_path = stack.directory.join("agent.sock");
    let agent = listener(&agent_path);
    let mut client = start(&stack, &agent_path, transport.port);
    let (remote, local) = paths(&stack, &mut client);
    let remote_inode = fs::metadata(&remote).unwrap().ino();
    request(&mut client, &remote, &agent, b"before-reconnect");
    transport.cut();
    fs::remove_file(&local).unwrap();
    fs::remove_dir(local.parent().unwrap()).unwrap();
    // The environment path can be stable even when ssh-agent is restarted.
    // Keep the old listener alive to detect any accidental reuse.
    fs::remove_file(&agent_path).unwrap();
    let replacement = listener(&agent_path);
    transport.resume();
    wait(&mut client, "proxy restoration after reconnect", || {
        fs::read_link(&local).ok().as_ref() == Some(&agent_path)
    });
    request(&mut client, &remote, &replacement, b"replacement-agent");
    assert_eq!(
        agent.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(fs::metadata(&remote).unwrap().ino(), remote_inode);
    drop(client);
    transport.join();
    stack.shutdown();
}
