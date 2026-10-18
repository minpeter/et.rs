//! Linux raw pipe (`et -T`) runtime: one poll(2) loop over the router, the
//! command's stdin, stdout and stderr pipes and its pidfd.
//!
//! The threaded runtime spends a thread per output pipe plus a child waiter
//! that probes `try_wait` every 20 ms; the pidfd reports the exit instead, so
//! an idle command never wakes `etterminal`. Output is read until the pipe
//! runs dry or a frame fills, then written as one router frame. Kernels
//! without `pidfd_open` keep the threaded runtime.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::process::{Child, ChildStdin};

use et_net::local::LocalStream;
use et_net::local_packet::{LocalPacketDecoder, TerminalBufferFrame};
use rustix::event::{poll, PollFd, PollFlags};
use rustix::io::Errno;
use rustix::process::{pidfd_open, Pid, PidfdFlags};

use super::{
    exit_code, read_ready_packet, take_input, write_pending, write_terminal_exit_status,
    MAX_OUTPUT_CHUNK, MAX_PENDING_INPUT,
};

/// Watch `child` through a pidfd; `None` keeps the threaded runtime.
pub(super) fn watch(child: &Child) -> Option<OwnedFd> {
    let pid = Pid::from_raw(i32::try_from(child.id()).ok()?)?;
    pidfd_open(pid, PidfdFlags::empty()).ok()
}

pub(super) fn run<F>(
    router: LocalStream,
    mut child: Child,
    pidfd: OwnedFd,
    started: F,
) -> Result<i32, String>
where
    F: FnOnce(&mut LocalStream) -> Result<(), String>,
{
    let pipes = (|| {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "pipe command has no stdin".to_owned())?;
        let stdout = OwnedFd::from(
            child
                .stdout
                .take()
                .ok_or_else(|| "pipe command has no stdout".to_owned())?,
        );
        let stderr = OwnedFd::from(
            child
                .stderr
                .take()
                .ok_or_else(|| "pipe command has no stderr".to_owned())?,
        );
        for fd in [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()] {
            set_nonblocking(fd)?;
        }
        Ok::<_, String>((stdin, stdout, stderr))
    })();
    let (stdin, stdout, stderr) = match pipes {
        Ok(pipes) => pipes,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let mut session = PipeSession {
        router,
        decoder: LocalPacketDecoder::new(),
        stdin: Some(stdin),
        pending: Vec::new(),
        outputs: [Some(stdout), Some(stderr)],
        next_output: 0,
        output: vec![0; MAX_OUTPUT_CHUNK],
        filled: 0,
        output_is_stderr: false,
        frame: None,
        pidfd: Some(pidfd),
        child_status: None,
    };
    let result = session
        .router
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure pipe router: {error}"))
        .and_then(|()| started(&mut session.router))
        .and_then(|()| session.pump(&mut child));
    if session.child_status.is_none() {
        // TERMINAL_CLOSE or an error: the command's own status is not the
        // session status.
        let _ = child.kill();
        let _ = child.wait();
    }
    match result? {
        Some(code) => {
            if let Err(error) = write_terminal_exit_status(&mut session.router, code) {
                et_cli::logging::info(format!("pipe exit status was not sent: {error}"));
            }
            Ok(code)
        }
        None => Ok(0),
    }
}

struct PipeSession {
    router: LocalStream,
    decoder: LocalPacketDecoder,
    stdin: Option<ChildStdin>,
    /// Input the command has not accepted yet.
    pending: Vec<u8>,
    /// stdout then stderr; `None` once at EOF.
    outputs: [Option<OwnedFd>; 2],
    /// Output stream served first on the next read, alternating under load.
    next_output: usize,
    output: Vec<u8>,
    filled: usize,
    output_is_stderr: bool,
    /// Frame in flight and its length; it always completes before more
    /// output is read.
    frame: Option<(TerminalBufferFrame, usize)>,
    pidfd: Option<OwnedFd>,
    child_status: Option<i32>,
}

const STDOUT: usize = 0;
const STDERR: usize = 1;

impl PipeSession {
    /// `Ok(Some(code))` when the command exited after stdout closed,
    /// `Ok(None)` for TERMINAL_CLOSE.
    fn pump(&mut self, child: &mut Child) -> Result<Option<i32>, String> {
        loop {
            let stdout_done = self.outputs[STDOUT].is_none();
            if stdout_done && self.pending.is_empty() {
                // A redirected last command (`cat >file`) EOFs stdout while
                // still reading: flush accepted input, then close stdin.
                self.stdin = None;
            }
            let backlog = self.backlog();
            if let Some(code) = self.child_status {
                if stdout_done && !backlog {
                    // Deliver stderr the command already wrote, without
                    // waiting on a descendant that may keep the pipe open.
                    if self.outputs[STDERR].is_some() {
                        self.read_output(STDERR)?;
                        if self.filled != 0 {
                            self.flush_output()?;
                            continue;
                        }
                    }
                    return Ok(Some(code));
                }
            }
            let accept_input =
                self.stdin.is_some() && !stdout_done && self.pending.len() < MAX_PENDING_INPUT;
            let mut router_flags = PollFlags::empty();
            if accept_input {
                router_flags |= PollFlags::IN;
            }
            if backlog {
                router_flags |= PollFlags::OUT;
            }
            let read_flags = if backlog {
                PollFlags::empty()
            } else {
                PollFlags::IN
            };
            let stdin_flags = if self.pending.is_empty() {
                PollFlags::empty()
            } else {
                PollFlags::OUT
            };
            let router = self.router.as_fd();
            let (stdin_fd, stdin_wanted) =
                slot(self.stdin.as_ref().map(AsFd::as_fd), stdin_flags, router);
            let (stdout_fd, stdout_wanted) = slot(
                self.outputs[STDOUT].as_ref().map(AsFd::as_fd),
                read_flags,
                router,
            );
            let (stderr_fd, stderr_wanted) = slot(
                self.outputs[STDERR].as_ref().map(AsFd::as_fd),
                read_flags,
                router,
            );
            let (child_fd, child_wanted) =
                slot(self.pidfd.as_ref().map(AsFd::as_fd), PollFlags::IN, router);
            let mut fds = [
                PollFd::from_borrowed_fd(router, router_flags),
                PollFd::from_borrowed_fd(stdin_fd, stdin_wanted),
                PollFd::from_borrowed_fd(stdout_fd, stdout_wanted),
                PollFd::from_borrowed_fd(stderr_fd, stderr_wanted),
                PollFd::from_borrowed_fd(child_fd, child_wanted),
            ];
            loop {
                match poll(&mut fds, None) {
                    Ok(_) => break,
                    Err(Errno::INTR) => {}
                    Err(error) => return Err(format!("could not poll pipe session: {error}")),
                }
            }
            let ready = |index: usize, wanted: PollFlags| {
                !wanted.is_empty() && !fds[index].revents().is_empty()
            };
            let router_ready = !fds[0].revents().is_empty();
            let router_lost = fds[0].revents().intersects(PollFlags::HUP | PollFlags::ERR);
            let stdin_ready = ready(1, stdin_wanted);
            let stdout_ready = ready(2, stdout_wanted);
            let stderr_ready = ready(3, stderr_wanted);
            let child_ready = ready(4, child_wanted);

            if child_ready {
                self.pidfd = None;
                self.child_status = match child.try_wait() {
                    Ok(Some(status)) => Some(exit_code(status)),
                    Ok(None) => None,
                    Err(error) => return Err(format!("could not wait for pipe command: {error}")),
                };
            }
            if (accept_input || router_lost) && router_ready {
                for _ in 0..32 {
                    if self.pending.len() >= MAX_PENDING_INPUT {
                        break;
                    }
                    let Some(packet) = read_ready_packet(&mut self.router, &mut self.decoder)?
                    else {
                        break;
                    };
                    if take_input(packet, &mut self.stdin, &mut self.pending)? {
                        return Ok(None);
                    }
                    self.decoder = LocalPacketDecoder::new();
                }
            }
            if stdin_ready {
                if let Some(input) = self.stdin.as_mut() {
                    write_pending(input, &mut self.pending)?;
                }
            }
            if !backlog {
                let order = if self.next_output == STDOUT {
                    [(STDOUT, stdout_ready), (STDERR, stderr_ready)]
                } else {
                    [(STDERR, stderr_ready), (STDOUT, stdout_ready)]
                };
                if let Some(&(index, _)) = order.iter().find(|(_, ready)| *ready) {
                    self.next_output = 1 - index;
                    self.read_output(index)?;
                }
            }
            if self.backlog() {
                self.flush_output()?;
            }
        }
    }

    fn backlog(&self) -> bool {
        self.frame.is_some() || self.filled != 0
    }

    /// Read one stream until it runs dry, hits EOF or fills a frame. A pipe
    /// read returns everything queued up to the request, so a short read
    /// already drained it and no `EAGAIN` probe follows.
    fn read_output(&mut self, index: usize) -> Result<(), String> {
        let Some(fd) = self.outputs[index].as_ref() else {
            return Ok(());
        };
        self.output_is_stderr = index == STDERR;
        while self.filled < MAX_OUTPUT_CHUNK {
            match rustix::io::read(fd, &mut self.output[self.filled..MAX_OUTPUT_CHUNK]) {
                Ok(0) => {
                    self.outputs[index] = None;
                    break;
                }
                Ok(count) => {
                    let requested = MAX_OUTPUT_CHUNK - self.filled;
                    self.filled += count;
                    if count < requested {
                        break;
                    }
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => break,
                Err(error) => return Err(format!("could not read pipe output: {error}")),
            }
        }
        Ok(())
    }

    /// Write the buffered output as one frame, resuming across `WouldBlock`.
    fn flush_output(&mut self) -> Result<(), String> {
        if self.frame.is_none() {
            if self.filled == 0 {
                return Ok(());
            }
            let frame = TerminalBufferFrame::new(self.filled, self.output_is_stderr)
                .map_err(|error| format!("could not forward pipe output: {error}"))?;
            self.frame = Some((frame, self.filled));
        }
        let Some((frame, length)) = self.frame.as_mut() else {
            return Ok(());
        };
        let output = &self.output[..*length];
        while !frame.is_complete() {
            match frame.write_some(&mut self.router, output) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(format!("could not forward pipe output: {error}")),
            }
        }
        self.frame = None;
        self.filled = 0;
        Ok(())
    }
}

/// A poll slot for `fd` when it has work, else the router with no requested
/// events: such a slot can only echo the router's HUP/ERR, which the router's
/// own slot already handles, so a fixed-size set never spins on an idle pipe.
fn slot<'fd>(
    fd: Option<BorrowedFd<'fd>>,
    flags: PollFlags,
    router: BorrowedFd<'fd>,
) -> (BorrowedFd<'fd>, PollFlags) {
    match fd {
        Some(fd) if !flags.is_empty() => (fd, flags),
        _ => (router, PollFlags::empty()),
    }
}

fn set_nonblocking(fd: BorrowedFd<'_>) -> Result<(), String> {
    let flags = rustix::fs::fcntl_getfl(fd)
        .map_err(|error| format!("could not read pipe flags: {error}"))?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|error| format!("could not set pipe nonblocking: {error}"))
}
