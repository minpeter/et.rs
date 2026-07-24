use std::io::{self, Read};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wait_timeout::ChildExt;

use crate::bootstrap::{parse_id_passkey, Credentials, SshInvocation};
use crate::deadline::Deadline;
use crate::error::ClientError;

pub const MAX_SSH_STDOUT: usize = 1024 * 1024;
pub const DEFAULT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct SshOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
}

pub trait SshRunner {
    fn run(&self, invocation: &SshInvocation, deadline: Deadline)
        -> Result<SshOutput, ClientError>;
}

#[derive(Debug, Clone, Copy)]
pub struct SystemSsh {
    timeout: Duration,
}

impl Default for SystemSsh {
    fn default() -> Self {
        Self::with_timeout(DEFAULT_BOOTSTRAP_TIMEOUT)
    }
}

impl SystemSsh {
    pub const fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub fn deadline(self) -> Deadline {
        Deadline::after(self.timeout)
    }
}

impl SshRunner for SystemSsh {
    fn run(
        &self,
        invocation: &SshInvocation,
        deadline: Deadline,
    ) -> Result<SshOutput, ClientError> {
        if deadline.remaining().is_none() {
            return Err(ClientError::SshTimeout(invocation.operation));
        }
        let mut child = Command::new(&invocation.program)
            .args(&invocation.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(ClientError::SshSpawn)?;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate_and_reap(&mut child)?;
                return Err(ClientError::SshStdout(io::Error::other(
                    "ssh stdout pipe was not created",
                )));
            }
        };
        let (receiver, reader) = match spawn_reader(stdout) {
            Ok(reader) => reader,
            Err(error) => {
                terminate_and_reap(&mut child)?;
                return Err(ClientError::SshStdout(error));
            }
        };

        let remaining = match deadline.remaining() {
            Some(remaining) => remaining,
            None => {
                stop_child(&mut child, reader)?;
                return Err(ClientError::SshTimeout(invocation.operation));
            }
        };
        match receiver.recv_timeout(remaining) {
            Ok(Capture::Complete(stdout)) => {
                if let Err(error) = join_reader(reader) {
                    terminate_and_reap(&mut child)?;
                    return Err(error);
                }
                let status = wait_for_exit(&mut child, deadline, invocation.operation)?;
                Ok(SshOutput { status, stdout })
            }
            Ok(Capture::TooLarge) => {
                stop_child(&mut child, reader)?;
                Err(ClientError::SshOutputTooLarge(MAX_SSH_STDOUT))
            }
            Ok(Capture::Failed(error)) => {
                stop_child(&mut child, reader)?;
                Err(ClientError::SshStdout(error))
            }
            Err(RecvTimeoutError::Timeout) => {
                stop_child(&mut child, reader)?;
                Err(ClientError::SshTimeout(invocation.operation))
            }
            Err(RecvTimeoutError::Disconnected) => {
                stop_child(&mut child, reader)?;
                Err(ClientError::SshStdout(io::Error::other(
                    "ssh stdout reader stopped unexpectedly",
                )))
            }
        }
    }
}

pub fn run_checked<R: SshRunner + ?Sized>(
    runner: &R,
    invocation: &SshInvocation,
    deadline: Deadline,
) -> Result<Vec<u8>, ClientError> {
    let output = runner.run(invocation, deadline)?;
    if !output.status.success() {
        return Err(ClientError::SshNonZero(output.status.code()));
    }
    Ok(output.stdout)
}

pub fn run_bootstrap<R: SshRunner + ?Sized>(
    runner: &R,
    invocation: &SshInvocation,
    deadline: Deadline,
) -> Result<Credentials, ClientError> {
    parse_id_passkey(&run_checked(runner, invocation, deadline)?)
}

enum Capture {
    Complete(Vec<u8>),
    TooLarge,
    Failed(io::Error),
}

fn spawn_reader(mut stdout: ChildStdout) -> io::Result<(mpsc::Receiver<Capture>, JoinHandle<()>)> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::Builder::new()
        .name("ssh-stdout".to_string())
        .spawn(move || {
            let capture = capture_bounded(&mut stdout);
            drop(stdout);
            let _ = sender.send(capture);
        })?;
    Ok((receiver, reader))
}

fn capture_bounded(reader: &mut impl Read) -> Capture {
    let mut captured = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let available = MAX_SSH_STDOUT.saturating_sub(captured.len());
        let read_len = buffer.len().min(available.saturating_add(1));
        match reader.read(&mut buffer[..read_len]) {
            Ok(0) => return Capture::Complete(captured),
            Ok(count) if count > available => return Capture::TooLarge,
            Ok(count) => captured.extend_from_slice(&buffer[..count]),
            Err(error) => return Capture::Failed(error),
        }
    }
}

fn wait_for_exit(
    child: &mut Child,
    deadline: Deadline,
    operation: &'static str,
) -> Result<ExitStatus, ClientError> {
    let remaining = match deadline.remaining() {
        Some(remaining) => remaining,
        None => {
            terminate_and_reap(child)?;
            return Err(ClientError::SshTimeout(operation));
        }
    };
    match child.wait_timeout(remaining) {
        Ok(Some(status)) => Ok(status),
        Ok(None) => {
            terminate_and_reap(child)?;
            Err(ClientError::SshTimeout(operation))
        }
        Err(error) => {
            terminate_and_reap(child)?;
            Err(ClientError::SshWait(error))
        }
    }
}

fn stop_child(child: &mut Child, reader: JoinHandle<()>) -> Result<(), ClientError> {
    let terminate = terminate_and_reap(child);
    let joined = join_reader(reader);
    terminate.and(joined)
}

fn terminate_and_reap(child: &mut Child) -> Result<(), ClientError> {
    if child
        .try_wait()
        .map_err(ClientError::SshTerminate)?
        .is_some()
    {
        return Ok(());
    }
    let kill = child.kill();
    let waited = child.wait();
    match (kill, waited) {
        (_, Ok(_)) => Ok(()),
        (Err(error), _) | (_, Err(error)) => Err(ClientError::SshTerminate(error)),
    }
}

fn join_reader(reader: JoinHandle<()>) -> Result<(), ClientError> {
    reader
        .join()
        .map_err(|_| ClientError::SshStdout(io::Error::other("ssh stdout reader panicked")))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    struct FakeRunner(Result<SshOutput, io::Error>);

    impl SshRunner for FakeRunner {
        fn run(&self, _: &SshInvocation, _: Deadline) -> Result<SshOutput, ClientError> {
            match &self.0 {
                Ok(output) => Ok(SshOutput {
                    status: output.status,
                    stdout: output.stdout.clone(),
                }),
                Err(error) => Err(ClientError::SshSpawn(io::Error::new(
                    error.kind(),
                    error.to_string(),
                ))),
            }
        }
    }

    fn invocation(program: &str, args: &[&str]) -> SshInvocation {
        SshInvocation {
            program: program.into(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            operation: "testing bootstrap",
        }
    }

    fn status(program: &str) -> ExitStatus {
        Command::new(program).status().unwrap()
    }

    #[test]
    fn runner_seam_returns_credentials() {
        let runner = FakeRunner(Ok(SshOutput {
            status: status("true"),
            stdout: b"IDPASSKEY:abcdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".to_vec(),
        }));
        let invocation = invocation("ssh", &[]);
        assert_eq!(
            run_bootstrap(
                &runner,
                &invocation,
                Deadline::after(Duration::from_secs(1))
            )
            .unwrap()
            .id,
            "abcdefghijklmnop"
        );
    }

    #[test]
    fn nonzero_output_is_typed() {
        let runner = FakeRunner(Ok(SshOutput {
            status: status("false"),
            stdout: Vec::new(),
        }));
        let invocation = invocation("ssh", &[]);
        assert!(matches!(
            run_bootstrap(
                &runner,
                &invocation,
                Deadline::after(Duration::from_secs(1))
            ),
            Err(ClientError::SshNonZero(_))
        ));
    }

    #[test]
    fn system_runner_terminates_on_deadline() {
        let runner = SystemSsh::with_timeout(Duration::from_millis(50));
        let invocation = invocation("/bin/sh", &["-c", "exec /bin/sleep 30"]);
        let started = Instant::now();
        let result = runner.run(&invocation, runner.deadline());
        assert!(matches!(result, Err(ClientError::SshTimeout(_))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn system_runner_stops_output_flood_at_limit() {
        let runner = SystemSsh::with_timeout(Duration::from_secs(2));
        let invocation = invocation(
            "/bin/sh",
            &["-c", "while :; do printf 0123456789abcdef; done"],
        );
        let started = Instant::now();
        let result = runner.run(&invocation, runner.deadline());
        assert!(matches!(result, Err(ClientError::SshOutputTooLarge(_))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
