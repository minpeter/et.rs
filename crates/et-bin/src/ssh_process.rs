use std::io::{self, Read};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wait_timeout::ChildExt;

use crate::bootstrap::{
    parse_id_passkey, parse_shell_probe, Credentials, InvocationCompletion, RemoteShell,
    SshInvocation,
};
use crate::deadline::Deadline;
use crate::error::ClientError;

pub const MAX_SSH_STDOUT: usize = 1024 * 1024;
// The remote registration phase is bounded at 45 seconds. Leave explicit
// budget for SSH configuration, authentication, propagation of a structured
// remote timeout, and cancellation cleanup.
pub const DEFAULT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct SshOutput {
    /// Exit status, or `None` when an invocation-specific completion marker
    /// arrived before the SSH process exited.
    pub status: Option<ExitStatus>,
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
        // ssh stays in our process group so it can prompt on the controlling
        // terminal (password, passphrase, host-key confirmation), matching
        // upstream `SubprocessToStringInteractive`. Moving it to its own group
        // would make terminal reads raise SIGTTIN and hang the bootstrap.
        // Cleanup therefore targets the process subtree plus anything still
        // holding the captured stdout pipe.
        let mut child = command.spawn().map_err(ClientError::SshSpawn)?;
        let child_pid = process_id(child.id());
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate_and_reap(&mut child, child_pid, None)?;
                return Err(ClientError::SshStdout(io::Error::other(
                    "ssh stdout pipe was not created",
                )));
            }
        };
        // Identify the stdout pipe so descendants that outlive ssh while still
        // holding it can be found even after they re-parent to init.
        let pipe = pipe_identity(&stdout);
        let (receiver, reader) = match spawn_reader(stdout, invocation.completion) {
            Ok(reader) => reader,
            Err(error) => {
                terminate_and_reap(&mut child, child_pid, pipe)?;
                return Err(ClientError::SshStdout(error));
            }
        };

        let remaining = match deadline.remaining() {
            Some(remaining) => remaining,
            None => {
                stop_child(&mut child, child_pid, pipe, reader)?;
                return Err(ClientError::SshTimeout(invocation.operation));
            }
        };
        match receiver.recv_timeout(remaining) {
            Ok(Capture::Complete(stdout)) => {
                if let Err(error) = join_reader(reader) {
                    terminate_and_reap(&mut child, child_pid, pipe)?;
                    return Err(error);
                }
                let status =
                    wait_for_exit(&mut child, child_pid, pipe, deadline, invocation.operation)?;
                Ok(SshOutput {
                    status: Some(status),
                    stdout,
                })
            }
            Ok(Capture::Marker(stdout)) => {
                // Preserve a direct child's status when it exited before a
                // pipe-holding descendant emitted the completion marker.
                let status = match child.try_wait() {
                    Ok(status) => status,
                    Err(error) => {
                        stop_child(&mut child, child_pid, pipe, reader)?;
                        return Err(ClientError::SshWait(error));
                    }
                };
                // The remote terminal is registered and detached; stop waiting
                // on a channel a detached child may keep open.
                stop_child(&mut child, child_pid, pipe, reader)?;
                Ok(SshOutput { status, stdout })
            }
            Ok(Capture::TooLarge) => {
                stop_child(&mut child, child_pid, pipe, reader)?;
                Err(ClientError::SshOutputTooLarge(MAX_SSH_STDOUT))
            }
            Ok(Capture::Failed(error)) => {
                stop_child(&mut child, child_pid, pipe, reader)?;
                Err(ClientError::SshStdout(error))
            }
            Err(RecvTimeoutError::Timeout) => {
                stop_child(&mut child, child_pid, pipe, reader)?;
                Err(ClientError::SshTimeout(invocation.operation))
            }
            Err(RecvTimeoutError::Disconnected) => {
                stop_child(&mut child, child_pid, pipe, reader)?;
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
    // A bootstrap that stopped at the marker has no meaningful status.
    if let Some(status) = output.status {
        if !status.success() {
            return Err(ClientError::SshNonZero(status.code()));
        }
    }
    Ok(output.stdout)
}

pub fn run_shell_probe<R: SshRunner + ?Sized>(
    runner: &R,
    invocation: &SshInvocation,
    deadline: Deadline,
) -> Result<RemoteShell, ClientError> {
    let output = runner.run(invocation, deadline)?;
    if let Some(status) = output.status {
        if !status.success() {
            return Err(ClientError::SshNonZero(status.code()));
        }
    }
    parse_shell_probe(&output.stdout)
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
    /// The invocation-specific completion marker arrived, so a descendant
    /// holding stdout open cannot delay completion.
    Marker(Vec<u8>),
    TooLarge,
    Failed(io::Error),
}

/// `IDPASSKEY:` plus `<16 id>/<32 passkey>`.
const MARKER: &[u8] = b"IDPASSKEY:";
const MARKER_TOTAL: usize = 10 + 16 + 1 + 32;

/// Position just past a complete marker, if one is present.
fn marker_end(captured: &[u8]) -> Option<usize> {
    captured
        .windows(MARKER.len())
        .position(|window| window == MARKER)
        .map(|start| start + MARKER_TOTAL)
        .filter(|end| *end <= captured.len())
}

fn shell_probe_end(captured: &[u8]) -> Option<usize> {
    let mut line_start = 0;
    for line_end in captured
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'\n').then_some(index + 1))
    {
        if parse_shell_probe(&captured[line_start..line_end]).is_ok() {
            return Some(line_end);
        }
        line_start = line_end;
    }
    None
}

fn completion_end(captured: &[u8], completion: InvocationCompletion) -> Option<usize> {
    match completion {
        InvocationCompletion::Exit => None,
        InvocationCompletion::Credentials => marker_end(captured),
        InvocationCompletion::ShellProbe => shell_probe_end(captured),
    }
}

fn spawn_reader(
    mut stdout: ChildStdout,
    completion: InvocationCompletion,
) -> io::Result<(mpsc::Receiver<Capture>, JoinHandle<()>)> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::Builder::new()
        .name("ssh-stdout".to_string())
        .spawn(move || {
            let capture = capture_bounded(&mut stdout, completion);
            drop(stdout);
            let _ = sender.send(capture);
        })?;
    Ok((receiver, reader))
}

fn capture_bounded(reader: &mut impl Read, completion: InvocationCompletion) -> Capture {
    let mut captured = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let available = MAX_SSH_STDOUT.saturating_sub(captured.len());
        let read_len = buffer.len().min(available.saturating_add(1));
        match reader.read(&mut buffer[..read_len]) {
            Ok(0) => return Capture::Complete(captured),
            Ok(count) if count > available => return Capture::TooLarge,
            Ok(count) => {
                captured.extend_from_slice(&buffer[..count]);
                // Waiting for EOF is not reliable everywhere: on Windows the
                // detached session process can inherit this pipe, so the
                // channel never closes even though the session is ready.
                if completion_end(&captured, completion).is_some() {
                    return Capture::Marker(captured);
                }
            }
            Err(error) => return Capture::Failed(error),
        }
    }
}

fn wait_for_exit(
    child: &mut Child,
    child_pid: ProcessId,
    pipe: Option<PipeIdentity>,
    deadline: Deadline,
    operation: &'static str,
) -> Result<ExitStatus, ClientError> {
    let remaining = match deadline.remaining() {
        Some(remaining) => remaining,
        None => {
            terminate_and_reap(child, child_pid, pipe)?;
            return Err(ClientError::SshTimeout(operation));
        }
    };
    match child.wait_timeout(remaining) {
        Ok(Some(status)) => Ok(status),
        Ok(None) => {
            terminate_and_reap(child, child_pid, pipe)?;
            Err(ClientError::SshTimeout(operation))
        }
        Err(error) => {
            terminate_and_reap(child, child_pid, pipe)?;
            Err(ClientError::SshWait(error))
        }
    }
}

fn stop_child(
    child: &mut Child,
    child_pid: ProcessId,
    pipe: Option<PipeIdentity>,
    reader: JoinHandle<()>,
) -> Result<(), ClientError> {
    drop(reader);
    terminate_and_reap(child, child_pid, pipe)
}

/// Identity of the captured stdout pipe, used to find every process that still
/// holds it. Only Linux exposes this through `/proc`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PipeIdentity {
    #[cfg(target_os = "linux")]
    device: u64,
    #[cfg(target_os = "linux")]
    inode: u64,
}

#[cfg(target_os = "linux")]
fn pipe_identity(stdout: &ChildStdout) -> Option<PipeIdentity> {
    use std::os::fd::AsFd;
    let stat = rustix::fs::fstat(stdout.as_fd()).ok()?;
    Some(PipeIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

#[cfg(not(target_os = "linux"))]
fn pipe_identity(_stdout: &ChildStdout) -> Option<PipeIdentity> {
    None
}

fn terminate_and_reap(
    child: &mut Child,
    child_pid: ProcessId,
    pipe: Option<PipeIdentity>,
) -> Result<(), ClientError> {
    // ssh may leave descendants (ProxyJump helpers, remote-command wrappers)
    // that outlive it and keep the captured stdout pipe open, so kill the
    // subtree and anything still holding that pipe.
    let mut targets = descendants(child_pid);
    if let Some(pipe) = pipe {
        for holder in pipe_holders(pipe) {
            if !targets.contains(&holder) {
                targets.push(holder);
            }
        }
    }
    targets.push(child_pid);
    let mut failure = None;
    for pid in targets {
        if let Err(error) = kill_process(pid) {
            failure = Some(error);
        }
    }
    let waited = child.wait();
    match (failure, waited) {
        (None, Ok(_)) => Ok(()),
        (Some(error), _) => Err(ClientError::SshTerminate(error)),
        (_, Err(error)) => Err(ClientError::SshTerminate(error)),
    }
}

/// Process identifier used for subtree cleanup.
#[cfg(unix)]
pub(crate) type ProcessId = nix::unistd::Pid;
#[cfg(windows)]
pub(crate) type ProcessId = u32;

#[cfg(unix)]
fn process_id(raw: u32) -> ProcessId {
    nix::unistd::Pid::from_raw(raw.cast_signed())
}

#[cfg(windows)]
fn process_id(raw: u32) -> ProcessId {
    raw
}

#[cfg(unix)]
fn kill_process(pid: ProcessId) -> io::Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    match kill(pid, Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

#[cfg(windows)]
fn kill_process(pid: ProcessId) -> io::Result<()> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    let mut system = System::new();
    let pid = Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    match system.process(pid) {
        // Already gone is success, like ESRCH on Unix.
        None => Ok(()),
        Some(process) if process.kill() => Ok(()),
        Some(_) => Err(io::Error::other("could not terminate the ssh process")),
    }
}

/// Descendants of `root`, deepest first.
fn descendants(root: ProcessId) -> Vec<ProcessId> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let mut children_of: std::collections::HashMap<u32, Vec<u32>> =
        std::collections::HashMap::new();
    for (pid, process) in system.processes() {
        if let Some(parent) = process.parent() {
            children_of
                .entry(parent.as_u32())
                .or_default()
                .push(pid.as_u32());
        }
    }
    let mut found = Vec::new();
    let mut queue = std::collections::VecDeque::from([raw_pid(root)]);
    while let Some(current) = queue.pop_front() {
        for child in children_of.remove(&current).unwrap_or_default() {
            found.push(child);
            queue.push_back(child);
        }
    }
    // Signal children before parents so nothing re-parents mid-cleanup.
    found.reverse();
    found.into_iter().map(process_id).collect()
}

#[cfg(unix)]
fn raw_pid(pid: ProcessId) -> u32 {
    u32::try_from(pid.as_raw()).unwrap_or(0)
}

#[cfg(windows)]
fn raw_pid(pid: ProcessId) -> u32 {
    pid
}

/// Processes (other than us) holding an open descriptor on `pipe`.
#[cfg(target_os = "linux")]
fn pipe_holders(pipe: PipeIdentity) -> Vec<ProcessId> {
    let mut holders = Vec::new();
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return holders;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(descriptors) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            let Ok(stat) = std::fs::metadata(descriptor.path()) else {
                continue;
            };
            use std::os::unix::fs::MetadataExt;
            if stat.dev() == pipe.device && stat.ino() == pipe.inode {
                holders.push(process_id(pid));
                break;
            }
        }
    }
    holders
}

#[cfg(not(target_os = "linux"))]
fn pipe_holders(_pipe: PipeIdentity) -> Vec<ProcessId> {
    Vec::new()
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

    #[cfg(unix)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code as u32)
    }

    struct ProbeRunner {
        status: i32,
        stdout: &'static [u8],
    }

    impl SshRunner for ProbeRunner {
        fn run(
            &self,
            _invocation: &SshInvocation,
            _deadline: Deadline,
        ) -> Result<SshOutput, ClientError> {
            Ok(SshOutput {
                status: Some(exit_status(self.status)),
                stdout: self.stdout.to_vec(),
            })
        }
    }

    #[test]
    fn shell_probe_detects_windows_cmd() {
        let runner = ProbeRunner {
            status: 0,
            stdout: b"__ET_COMSPEC__C:\\WINDOWS\\system32\\cmd.exe\r\n",
        };
        let invocation = SshInvocation {
            program: "ssh".into(),
            args: Vec::new(),
            operation: "probe",
            completion: InvocationCompletion::ShellProbe,
        };
        assert_eq!(
            run_shell_probe(
                &runner,
                &invocation,
                Deadline::after(Duration::from_secs(1)),
            )
            .unwrap(),
            RemoteShell::Cmd
        );
    }

    #[test]
    fn shell_probe_detects_posix_literal() {
        let runner = ProbeRunner {
            status: 0,
            stdout: b"__ET_COMSPEC__%ComSpec%\n",
        };
        let invocation = SshInvocation {
            program: "ssh".into(),
            args: Vec::new(),
            operation: "probe",
            completion: InvocationCompletion::ShellProbe,
        };
        assert_eq!(
            run_shell_probe(
                &runner,
                &invocation,
                Deadline::after(Duration::from_secs(1)),
            )
            .unwrap(),
            RemoteShell::Posix
        );
    }

    #[test]
    fn shell_probe_propagates_ssh_255() {
        let runner = ProbeRunner {
            status: 255,
            stdout: b"",
        };
        let invocation = SshInvocation {
            program: "ssh".into(),
            args: Vec::new(),
            operation: "probe",
            completion: InvocationCompletion::ShellProbe,
        };
        assert!(matches!(
            run_shell_probe(
                &runner,
                &invocation,
                Deadline::after(Duration::from_secs(1))
            ),
            Err(ClientError::SshNonZero(Some(255)))
        ));
    }

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
            completion: InvocationCompletion::Exit,
        }
    }

    fn status(program: &str) -> ExitStatus {
        Command::new(program).status().unwrap()
    }

    #[test]
    fn runner_seam_returns_credentials() {
        let runner = FakeRunner(Ok(SshOutput {
            status: Some(status("true")),
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
            status: Some(status("false")),
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
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let runner = SystemSsh::with_timeout(Duration::from_millis(50));
            let invocation = invocation("/bin/sh", &["-c", "exec /bin/sleep 30"]);
            let _ = sender.send(runner.run(&invocation, runner.deadline()));
        });
        let result = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("SSH deadline did not terminate its process within the test bound");
        assert!(matches!(result, Err(ClientError::SshTimeout(_))));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn shell_probe_preserves_naturally_completed_nonzero_status() {
        const SCRIPT: &str = r#"
(IFS= read -r _ < "$3"; printf '__ET_COMSPEC__C:\\Windows\\System32\\cmd.exe\n') &
descendant=$!
printf '%s %s\n' "$$" "$descendant" > "$1"
IFS= read -r _ < "$2"
exit 255
"#;

        let dir = ProcessGroupTestDir::new();
        let pid_fifo = dir.fifo("probe-status-pid");
        let exit_fifo = dir.fifo("probe-status-exit");
        let release_fifo = dir.fifo("probe-status-release");
        let _pid_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pid_fifo)
            .unwrap();
        let pid_pipe = File::open(&pid_fifo).unwrap();
        let _exit_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&exit_fifo)
            .unwrap();
        let mut exit_pipe = OpenOptions::new().write(true).open(&exit_fifo).unwrap();
        let _release_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&release_fifo)
            .unwrap();
        let mut release_pipe = OpenOptions::new().write(true).open(&release_fifo).unwrap();
        let runner = SystemSsh::with_timeout(Duration::from_secs(3));
        let mut invocation = invocation(
            "/bin/sh",
            &[
                "-c",
                SCRIPT,
                "shell-probe-status-test",
                pid_fifo.to_str().unwrap(),
                exit_fifo.to_str().unwrap(),
                release_fifo.to_str().unwrap(),
            ],
        );
        invocation.completion = InvocationCompletion::ShellProbe;
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let result = run_shell_probe(&runner, &invocation, runner.deadline());
            let _ = result_sender.send(result);
        });

        assert!(
            poll_readable(&pid_pipe),
            "probe processes were not reported"
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

        exit_pipe.write_all(b"exit\n").unwrap();
        drop(exit_pipe);
        assert!(
            poll_readable(&direct_pidfd),
            "direct SSH child did not exit before the sentinel"
        );
        release_pipe.write_all(b"emit\n").unwrap();
        drop(release_pipe);
        let result = result_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("probe did not complete after the descendant sentinel");
        worker.join().unwrap();
        let descendant_exited = poll_readable(&descendant_pidfd);
        if !descendant_exited {
            pidfd_send_signal(&descendant_pidfd, RustixSignal::KILL).unwrap();
        }

        assert!(
            descendant_exited,
            "stdout-holding descendant survived cleanup"
        );
        assert!(matches!(result, Err(ClientError::SshNonZero(Some(255)))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shell_probe_completes_when_descendant_holds_stdout_open() {
        const SCRIPT: &str = r#"
(IFS= read -r _ < "$1") &
printf '__ET_COMSPEC__C:\\Windows\\System32\\cmd.exe\n'
exit 0
"#;

        let dir = ProcessGroupTestDir::new();
        let hold_fifo = dir.fifo("probe-hold");
        let hold_control = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&hold_fifo)
            .unwrap();
        let runner = SystemSsh::with_timeout(Duration::from_secs(2));
        let mut invocation = invocation(
            "/bin/sh",
            &[
                "-c",
                SCRIPT,
                "shell-probe-test",
                hold_fifo.to_str().unwrap(),
            ],
        );
        invocation.completion = InvocationCompletion::ShellProbe;

        let result = run_shell_probe(&runner, &invocation, runner.deadline());
        drop(hold_control);

        assert_eq!(result.unwrap(), RemoteShell::Cmd);
    }

    #[test]
    fn shell_probe_matcher_ignores_complete_decoy_line() {
        let captured = b"audit: echo __ET_COMSPEC__%ComSpec%\n";

        assert_eq!(shell_probe_end(captured), None);
    }

    #[test]
    fn shell_probe_matcher_returns_end_of_valid_line_after_decoy() {
        let captured = b"audit: echo __ET_COMSPEC__%ComSpec%\n\
                         __ET_COMSPEC__C:\\Windows\\System32\\cmd.exe\n";

        assert_eq!(shell_probe_end(captured), Some(captured.len()));
    }

    #[test]
    fn shell_probe_matcher_rejects_partial_valid_line() {
        let captured = b"__ET_COMSPEC__C:\\Windows\\System32\\cmd.exe";

        assert_eq!(shell_probe_end(captured), None);
    }

    #[test]
    fn system_runner_stops_output_flood_at_limit() {
        let runner = SystemSsh::with_timeout(Duration::from_secs(10));
        let invocation = invocation("/bin/cat", &["/dev/zero"]);
        let result = runner.run(&invocation, runner.deadline());
        assert!(matches!(result, Err(ClientError::SshOutputTooLarge(_))));
    }
}
