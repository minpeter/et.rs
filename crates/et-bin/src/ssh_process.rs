use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
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
        let mut command = Command::new(&invocation.program);
        command
            .args(&invocation.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        command.process_group(0);
        let mut child = command.spawn().map_err(ClientError::SshSpawn)?;
        let process_group = Pid::from_raw(child.id().cast_signed());
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate_and_reap(&mut child, process_group)?;
                return Err(ClientError::SshStdout(io::Error::other(
                    "ssh stdout pipe was not created",
                )));
            }
        };
        let (receiver, reader) = match spawn_reader(stdout) {
            Ok(reader) => reader,
            Err(error) => {
                terminate_and_reap(&mut child, process_group)?;
                return Err(ClientError::SshStdout(error));
            }
        };

        let remaining = match deadline.remaining() {
            Some(remaining) => remaining,
            None => {
                stop_child(&mut child, process_group, reader)?;
                return Err(ClientError::SshTimeout(invocation.operation));
            }
        };
        match receiver.recv_timeout(remaining) {
            Ok(Capture::Complete(stdout)) => {
                if let Err(error) = join_reader(reader) {
                    terminate_and_reap(&mut child, process_group)?;
                    return Err(error);
                }
                let status =
                    wait_for_exit(&mut child, process_group, deadline, invocation.operation)?;
                Ok(SshOutput { status, stdout })
            }
            Ok(Capture::TooLarge) => {
                stop_child(&mut child, process_group, reader)?;
                Err(ClientError::SshOutputTooLarge(MAX_SSH_STDOUT))
            }
            Ok(Capture::Failed(error)) => {
                stop_child(&mut child, process_group, reader)?;
                Err(ClientError::SshStdout(error))
            }
            Err(RecvTimeoutError::Timeout) => {
                stop_child(&mut child, process_group, reader)?;
                Err(ClientError::SshTimeout(invocation.operation))
            }
            Err(RecvTimeoutError::Disconnected) => {
                stop_child(&mut child, process_group, reader)?;
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
    process_group: Pid,
    deadline: Deadline,
    operation: &'static str,
) -> Result<ExitStatus, ClientError> {
    let remaining = match deadline.remaining() {
        Some(remaining) => remaining,
        None => {
            terminate_and_reap(child, process_group)?;
            return Err(ClientError::SshTimeout(operation));
        }
    };
    match child.wait_timeout(remaining) {
        Ok(Some(status)) => Ok(status),
        Ok(None) => {
            terminate_and_reap(child, process_group)?;
            Err(ClientError::SshTimeout(operation))
        }
        Err(error) => {
            terminate_and_reap(child, process_group)?;
            Err(ClientError::SshWait(error))
        }
    }
}

fn stop_child(
    child: &mut Child,
    process_group: Pid,
    reader: JoinHandle<()>,
) -> Result<(), ClientError> {
    drop(reader);
    terminate_and_reap(child, process_group)
}

fn terminate_and_reap(child: &mut Child, process_group: Pid) -> Result<(), ClientError> {
    let kill = match killpg(process_group, Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => {
            let _ = child.kill();
            Err(io::Error::from(error))
        }
    };
    let waited = child.wait();
    match (kill, waited) {
        (Ok(()), Ok(_)) => Ok(()),
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
    #[cfg(target_os = "linux")]
    use std::{
        fs::{self, File, OpenOptions},
        io::{BufRead, BufReader, Write},
        os::fd::AsFd,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(target_os = "linux")]
    use nix::{
        poll::{poll, PollFd, PollFlags},
        sys::stat::Mode,
        unistd::mkfifo,
    };
    #[cfg(target_os = "linux")]
    use rustix::process::{
        pidfd_open, pidfd_send_signal, Pid as RustixPid, PidfdFlags, Signal as RustixSignal,
    };

    use super::*;

    #[cfg(target_os = "linux")]
    const EVENT_WAIT_MILLIS: u16 = 1_000;

    #[cfg(target_os = "linux")]
    struct ProcessGroupTestDir(PathBuf);

    #[cfg(target_os = "linux")]
    impl ProcessGroupTestDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "et-rs-ssh-process-group-{}-{n}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn fifo(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
            path
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ProcessGroupTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    fn poll_readable(fd: &impl AsFd) -> bool {
        let mut events = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut events, EVENT_WAIT_MILLIS).unwrap();
        ready == 1 && events[0].revents().unwrap().contains(PollFlags::POLLIN)
    }

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

    #[cfg(target_os = "linux")]
    #[test]
    fn system_runner_times_out_and_kills_stdout_holding_descendant() {
        const SSH_TIMEOUT: Duration = Duration::from_secs(2);
        const SCRIPT: &str = r#"
(IFS= read -r _ < "$3") &
descendant=$!
printf '%s %s\n' "$$" "$descendant" > "$1"
IFS= read -r _ < "$2"
exit 0
"#;

        let dir = ProcessGroupTestDir::new();
        let pid_fifo = dir.fifo("pid");
        let ack_fifo = dir.fifo("ack");
        let hold_fifo = dir.fifo("hold");

        let _pid_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pid_fifo)
            .unwrap();
        let pid_pipe = File::open(&pid_fifo).unwrap();
        let _ack_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&ack_fifo)
            .unwrap();
        let mut ack_pipe = OpenOptions::new().write(true).open(&ack_fifo).unwrap();
        let hold_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&hold_fifo)
            .unwrap();

        let runner = SystemSsh::with_timeout(SSH_TIMEOUT);
        let invocation = invocation(
            "/bin/sh",
            &[
                "-c",
                SCRIPT,
                "ssh-process-group-test",
                pid_fifo.to_str().unwrap(),
                ack_fifo.to_str().unwrap(),
                hold_fifo.to_str().unwrap(),
            ],
        );
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let started = Instant::now();
            let result = runner.run(&invocation, runner.deadline());
            let _ = result_sender.send((result, started.elapsed()));
        });

        assert!(
            poll_readable(&pid_pipe),
            "SSH child did not report its process IDs"
        );
        let mut process_ids = String::new();
        assert_ne!(
            BufReader::new(pid_pipe)
                .read_line(&mut process_ids)
                .unwrap(),
            0
        );
        let mut process_ids = process_ids.split_whitespace();
        let direct_pid = process_ids.next().unwrap().parse::<i32>().unwrap();
        let descendant_pid = process_ids.next().unwrap().parse::<i32>().unwrap();
        assert_eq!(process_ids.next(), None);

        let direct_pidfd = pidfd_open(
            RustixPid::from_raw(direct_pid).unwrap(),
            PidfdFlags::empty(),
        )
        .unwrap();
        let descendant_pidfd = pidfd_open(
            RustixPid::from_raw(descendant_pid).unwrap(),
            PidfdFlags::empty(),
        )
        .unwrap();

        ack_pipe.write_all(b"exit\n").unwrap();
        drop(ack_pipe);
        assert!(
            poll_readable(&direct_pidfd),
            "direct SSH child did not exit before the timeout"
        );

        let (result, elapsed) = result_receiver
            .recv_timeout(SSH_TIMEOUT + Duration::from_secs(1))
            .expect("SystemSsh did not return within its cleanup bound");
        worker.join().unwrap();
        let descendant_exited = poll_readable(&descendant_pidfd);
        if !descendant_exited {
            pidfd_send_signal(&descendant_pidfd, RustixSignal::KILL).unwrap();
        }
        drop(hold_control);

        assert!(matches!(result, Err(ClientError::SshTimeout(_))));
        assert!(
            elapsed < SSH_TIMEOUT + Duration::from_secs(1),
            "SystemSsh returned after {elapsed:?}"
        );
        assert!(
            descendant_exited,
            "SSH descendant survived process-group cleanup"
        );
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
