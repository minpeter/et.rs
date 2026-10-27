//! Linux `etterminal` PTY runtime: one thread multiplexes the router socket,
//! the PTY master and the shell's pidfd with poll(2).
//!
//! Upstream `UserTerminalHandler::run` is likewise a single `select()` loop
//! over the PTY master and the router socket, but it wakes every 10 ms and
//! probes `waitpid(WNOHANG)`. Here the shell's exit arrives as pidfd
//! readiness, so an idle session never wakes, and PTY output is read until
//! the master runs dry or a frame fills (one master read returns what the
//! line discipline holds, at most ~4 KiB) before one router frame is
//! written, instead of one frame per read. Kernels without `pidfd_open`
//! (< 5.3, or a sandbox that denies it) keep the threaded runtime.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use et_net::local::LocalStream;
use et_net::local_packet::{RouterFraming, RouterStreamDecoder, TerminalBufferFrame};
use et_server::idle_memory::{IdleRelease, ReleaseScope};
use portable_pty::{Child, ChildKiller, MasterPty};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use rustix::termios::{LocalModes, SpecialCodeIndex, Termios};

use super::{
    kill_process_group, reap_shell, reconnect_router_stream, terminal_close_completion,
    CompletionState, OutputShaper, PumpCompletion, RouterResume, WorkerEvent, MAX_OUTPUT_CHUNK,
};
use crate::terminal_protocol::{
    read_ready_packet, terminal_command, write_terminal_exit_status, TerminalCommand,
    TerminalPacketError,
};

/// Bound on finishing a frame that the drain timeout cut short, so the exit
/// status never lands inside a half-written frame.
const FRAME_FINISH_TIMEOUT: Duration = Duration::from_secs(1);
/// Longest pause in PTY output reads after input that interrupts the
/// foreground job; see [`Session::hold_output_for_interrupt`].
const INTERRUPT_HOLD: Duration = Duration::from_millis(10);
/// How often a held session checks whether the shell took the terminal back.
const INTERRUPT_HOLD_CHECK: Duration = Duration::from_millis(1);

/// A duplicated PTY master for the poll runtime.
pub(super) struct PollPty {
    master: filedescriptor::FileDescriptor,
}

impl PollPty {
    /// `None` keeps the threaded runtime: `pidfd_open` is unavailable or the
    /// master cannot be duplicated. Probed before the shell exists so the
    /// runtime choice never has to be undone after spawning.
    pub(super) fn open(master: &dyn MasterPty) -> Option<Self> {
        drop(pidfd_open(rustix::process::getpid(), PidfdFlags::empty()).ok()?);
        let raw = master.as_raw_fd()?;
        // `master` owns `raw` for this whole call; the duplicate is a new
        // close-on-exec descriptor for the same open file description.
        let master = filedescriptor::FileDescriptor::dup(&MasterRawFd(raw)).ok()?;
        Some(Self { master })
    }
}

struct MasterRawFd(RawFd);

impl AsRawFd for MasterRawFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run<F>(
    router: LocalStream,
    master: Box<dyn MasterPty + Send>,
    pty: PollPty,
    child: Box<dyn Child + Send + Sync>,
    motd: Option<Vec<u8>>,
    output_delay: Duration,
    framing: RouterFraming,
    resume: Option<RouterResume>,
    started: F,
) -> Result<i32, String>
where
    F: FnOnce(&mut LocalStream) -> Result<(), String>,
{
    let child_pid = child.process_id();
    let mut killer = child.clone_killer();
    let pidfd = match child_pid
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(Pid::from_raw)
        .ok_or_else(|| "terminal shell has no pid".to_owned())
        .and_then(|pid| {
            pidfd_open(pid, PidfdFlags::empty())
                .map_err(|error| format!("could not watch terminal shell: {error}"))
        }) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            abandon_child(child_pid, &mut *killer, Some(child));
            return Err(error);
        }
    };
    let mut session = Session {
        router,
        master,
        pty: pty.master,
        child: Some(child),
        pidfd: Some(pidfd),
        resume,
        decoder: RouterStreamDecoder::new(framing),
        input: Vec::new(),
        input_sent: 0,
        shaper: OutputShaper::new(motd.is_some()),
        prefix: motd.unwrap_or_default(),
        prefix_sent: 0,
        output: vec![0; MAX_OUTPUT_CHUNK],
        filled: 0,
        sent: 0,
        frame: None,
        scratch: Vec::new(),
        pty_eof: false,
        output_reported: false,
        completion: CompletionState::default(),
        progress: 0,
        output_start: Instant::now() + output_delay,
        interrupt_hold: None,
        // This loop is the terminal process's only thread.
        idle: IdleRelease::new(ReleaseScope::Process, Instant::now()),
    };
    let setup = session
        .configure()
        .and_then(|()| started(&mut session.router));
    let output_started = setup.is_ok();
    let result = setup.and_then(|()| session.pump());
    let graceful_drain = result.as_ref().is_ok_and(|completion| completion.drained);
    kill_process_group(child_pid);
    if let Ok(completion) = result.as_ref() {
        if completion.reaped && session.finish_started_frame() {
            if let Err(error) = write_terminal_exit_status(
                &mut session.router,
                i32::try_from(completion.status).unwrap_or(1),
            ) {
                et_cli::logging::info(format!("terminal exit status was not sent: {error}"));
            }
        }
    }
    if output_started && !graceful_drain {
        let _ = session.router.shutdown(std::net::Shutdown::Both);
    }
    abandon_child(child_pid, &mut *killer, session.child.take());
    let completion = result?;
    i32::try_from(completion.status)
        .map_err(|_| "terminal shell exit status is out of range".to_owned())
}

/// Kill whatever is left of the shell and reap it if it was never reaped.
fn abandon_child(
    child_pid: Option<u32>,
    killer: &mut dyn ChildKiller,
    child: Option<Box<dyn Child + Send + Sync>>,
) {
    let Some(child) = child else {
        return;
    };
    kill_process_group(child_pid);
    let _ = killer.kill();
    let _ = reap_shell(child);
}

struct Session {
    router: LocalStream,
    master: Box<dyn MasterPty + Send>,
    pty: filedescriptor::FileDescriptor,
    child: Option<Box<dyn Child + Send + Sync>>,
    pidfd: Option<OwnedFd>,
    resume: Option<RouterResume>,
    decoder: RouterStreamDecoder,
    /// Keystrokes the PTY has not accepted yet; router reads pause meanwhile.
    input: Vec<u8>,
    input_sent: usize,
    shaper: OutputShaper,
    /// Startup motd, framed ahead of any PTY output.
    prefix: Vec<u8>,
    prefix_sent: usize,
    /// Shaped PTY output; `sent..filled` is not yet on the router.
    output: Vec<u8>,
    filled: usize,
    sent: usize,
    /// Frame in flight: the frame, its output length and whether it carries
    /// motd bytes. A started frame always finishes before anything else.
    frame: Option<(TerminalBufferFrame, usize, bool)>,
    scratch: Vec<u8>,
    pty_eof: bool,
    output_reported: bool,
    completion: CompletionState,
    /// Router writes accepted; extends the post-exit drain while it moves.
    progress: usize,
    output_start: Instant,
    /// PTY output reads paused after an interrupt; see
    /// [`Session::hold_output_for_interrupt`].
    interrupt_hold: Option<InterruptHold>,
    /// Returns the allocator memory of a quiet session; see `idle_memory`.
    idle: IdleRelease,
}

/// Output reads stay paused until `until`, or until the terminal's
/// foreground process group is no longer `foreground`.
struct InterruptHold {
    until: Instant,
    foreground: Option<Pid>,
}

struct Ready {
    router: PollFlags,
    pty: PollFlags,
    child: PollFlags,
}

impl Ready {
    const IDLE: Self = Self {
        router: PollFlags::empty(),
        pty: PollFlags::empty(),
        child: PollFlags::empty(),
    };
}

impl Session {
    fn configure(&mut self) -> Result<(), String> {
        self.router
            .set_nonblocking(true)
            .map_err(|error| format!("could not configure terminal router: {error}"))?;
        let flags = rustix::fs::fcntl_getfl(&self.pty)
            .map_err(|error| format!("could not configure PTY: {error}"))?;
        rustix::fs::fcntl_setfl(&self.pty, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(|error| format!("could not configure PTY: {error}"))
    }

    fn pump(&mut self) -> Result<PumpCompletion, String> {
        loop {
            let backlog = self.output_backlog();
            let input_pending = self.input_sent < self.input.len();
            let resume_at = self.output_resume_at();
            let delayed = !self.pty_eof && resume_at.is_some();
            let read_pty = !self.pty_eof && !backlog && !delayed;
            let mut router_flags = PollFlags::empty();
            if !input_pending {
                router_flags |= PollFlags::IN;
            }
            if backlog {
                router_flags |= PollFlags::OUT;
            }
            let mut pty_flags = PollFlags::empty();
            if read_pty {
                pty_flags |= PollFlags::IN;
            }
            if input_pending {
                pty_flags |= PollFlags::OUT;
            }
            let mut deadline = self.completion.drain_deadline;
            if let Some(resume_at) = resume_at.filter(|_| delayed) {
                deadline = Some(deadline.map_or(resume_at, |d| d.min(resume_at)));
            }
            if let Some(release_at) = self.idle.deadline() {
                deadline = Some(deadline.map_or(release_at, |d| d.min(release_at)));
            }
            let ready = self.wait(router_flags, pty_flags, deadline)?;
            let active =
                !(ready.router.is_empty() && ready.pty.is_empty() && ready.child.is_empty());
            self.idle.after_wait(active, Instant::now());

            if ready
                .child
                .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            {
                let status = self.reap()?;
                if let Some(done) = self.completion.observe(WorkerEvent::Child(Ok(status)))? {
                    return Ok(done);
                }
            }
            let router_lost = ready.router.intersects(PollFlags::HUP | PollFlags::ERR);
            if router_lost || (!input_pending && ready.router.contains(PollFlags::IN)) {
                // A dead router still delivers what it queued (TERMINAL_CLOSE
                // included) before the read reports the disconnect.
                match self.read_router(router_lost) {
                    Ok(Some(done)) => return Ok(done),
                    Ok(None) => {}
                    Err(error) if router_disconnected(&error) => self.recover_router(error)?,
                    Err(error) => return Err(error),
                }
            }
            if input_pending
                && ready
                    .pty
                    .intersects(PollFlags::OUT | PollFlags::HUP | PollFlags::ERR)
            {
                self.flush_input();
            }
            // Input read above may have interrupted the job; its hold
            // already applies to this pass.
            if read_pty
                && self.interrupt_hold.is_none()
                && ready
                    .pty
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            {
                self.read_pty()?;
            }
            if self.output_backlog() {
                self.flush_output()?;
            }
            if self.pty_eof && !self.output_backlog() && !self.output_reported {
                self.output_reported = true;
                if let Some(done) = self.completion.observe(WorkerEvent::Output(Ok(())))? {
                    return Ok(done);
                }
            }
            if let Some(done) = self.completion.expired_status(self.progress) {
                return Ok(done);
            }
        }
    }

    /// One poll over the router, the PTY (only while it has work) and the
    /// shell's pidfd (until reaped). An idle PTY stays out of the set so a
    /// hung-up slave cannot spin the loop while output waits on the router.
    fn wait(
        &self,
        router: PollFlags,
        pty: PollFlags,
        deadline: Option<Instant>,
    ) -> Result<Ready, String> {
        loop {
            let timeout = deadline.map(|deadline| {
                Timespec::try_from(deadline.saturating_duration_since(Instant::now()))
                    .expect("PTY drain deadline fits timespec")
            });
            let timeout = timeout.as_ref();
            let result = match (pty.is_empty(), self.pidfd.as_ref()) {
                (false, Some(pidfd)) => {
                    let mut fds = [
                        PollFd::new(&self.router, router),
                        PollFd::new(&self.pty, pty),
                        PollFd::new(pidfd, PollFlags::IN),
                    ];
                    poll(&mut fds, timeout).map(|_| Ready {
                        router: fds[0].revents(),
                        pty: fds[1].revents(),
                        child: fds[2].revents(),
                    })
                }
                (false, None) => {
                    let mut fds = [
                        PollFd::new(&self.router, router),
                        PollFd::new(&self.pty, pty),
                    ];
                    poll(&mut fds, timeout).map(|_| Ready {
                        router: fds[0].revents(),
                        pty: fds[1].revents(),
                        ..Ready::IDLE
                    })
                }
                (true, Some(pidfd)) => {
                    let mut fds = [
                        PollFd::new(&self.router, router),
                        PollFd::new(pidfd, PollFlags::IN),
                    ];
                    poll(&mut fds, timeout).map(|_| Ready {
                        router: fds[0].revents(),
                        child: fds[1].revents(),
                        ..Ready::IDLE
                    })
                }
                (true, None) => {
                    let mut fds = [PollFd::new(&self.router, router)];
                    poll(&mut fds, timeout).map(|_| Ready {
                        router: fds[0].revents(),
                        ..Ready::IDLE
                    })
                }
            };
            match result {
                Ok(ready) => return Ok(ready),
                // poll() is never restarted by SA_RESTART.
                Err(Errno::INTR) => {}
                Err(error) => return Err(format!("could not poll terminal session: {error}")),
            }
        }
    }

    fn reap(&mut self) -> Result<u32, String> {
        self.pidfd = None;
        let child = self
            .child
            .take()
            .ok_or_else(|| "terminal shell is not owned".to_owned())?;
        reap_shell(child)
    }

    /// Apply router messages until the socket runs dry. Keystrokes the PTY
    /// cannot take yet pause reading, unless the router is already gone.
    fn read_router(&mut self, drain: bool) -> Result<Option<PumpCompletion>, String> {
        while drain || self.input_sent == self.input.len() {
            let Some(packet) = read_ready_packet(&mut self.router, &mut self.decoder)? else {
                return Ok(None);
            };
            match terminal_command(&packet) {
                Ok(TerminalCommand::Close) => return Ok(Some(terminal_close_completion())),
                Ok(TerminalCommand::Input(bytes)) => self.write_input(&bytes),
                // A dead pty is not fatal: the exit status still follows.
                Ok(TerminalCommand::Resize(size)) => {
                    let _ = self.master.resize(size);
                }
                Err(TerminalPacketError::Pty(_)) => {}
                Err(TerminalPacketError::Protocol(error)) => return Err(error),
            }
        }
        Ok(None)
    }

    fn write_input(&mut self, bytes: &[u8]) {
        self.hold_output_for_interrupt(bytes);
        if self.input_sent < self.input.len() {
            self.input.extend_from_slice(bytes);
            return;
        }
        match write_nonblocking(&self.pty, bytes) {
            Ok(written) if written == bytes.len() => {}
            Ok(written) => {
                self.input.clear();
                self.input.extend_from_slice(&bytes[written..]);
                self.input_sent = 0;
            }
            // A dead pty drops input, like the threaded runtime.
            Err(_) => {}
        }
    }

    fn flush_input(&mut self) {
        match write_nonblocking(&self.pty, &self.input[self.input_sent..]) {
            Ok(written) => self.input_sent += written,
            Err(_) => self.input_sent = self.input.len(),
        }
        if self.input_sent == self.input.len() {
            self.input.clear();
            self.input_sent = 0;
        }
    }

    /// Input that makes the line discipline signal the foreground job and
    /// flush the output it has not delivered pauses PTY output reads while
    /// output is pending, until the shell takes the terminal back or
    /// [`INTERRUPT_HOLD`] passes. Reading on would forward what the job keeps
    /// writing before the kernel applies the interrupt: while this loop keeps
    /// the PTY drained the job's writes never block, and the line discipline
    /// applies the signal and flush only between them, so after Ctrl+C a
    /// `yes` flood forwarded another 25 to 290 KB. Paused, the job fills the
    /// PTY and blocks, and the kernel discards that tail. Upstream
    /// `UserTerminalHandler` reads at most one chunk per `select()` pass and
    /// does not wake for router room, so its PTY stays full and the flush
    /// takes effect at once.
    fn hold_output_for_interrupt(&mut self, input: &[u8]) {
        if self.pty_eof {
            return;
        }
        let Ok(termios) = rustix::termios::tcgetattr(&self.pty) else {
            return;
        };
        if !interrupts_output(&termios, input) || !(self.output_backlog() || self.pty_readable()) {
            return;
        }
        self.interrupt_hold = Some(InterruptHold {
            until: Instant::now() + INTERRUPT_HOLD,
            foreground: rustix::termios::tcgetpgrp(&self.pty).ok(),
        });
    }

    /// When PTY output reads may resume, or `None` when they may run now:
    /// after the startup output delay and any interrupt hold.
    fn output_resume_at(&mut self) -> Option<Instant> {
        let now = Instant::now();
        if now < self.output_start {
            return Some(self.output_start);
        }
        let hold = self.interrupt_hold.as_ref()?;
        let shell_took_terminal = hold
            .foreground
            .is_some_and(|job| rustix::termios::tcgetpgrp(&self.pty).ok() != Some(job));
        if now >= hold.until || shell_took_terminal {
            self.interrupt_hold = None;
            return None;
        }
        Some(hold.until.min(now + INTERRUPT_HOLD_CHECK))
    }

    fn pty_readable(&self) -> bool {
        let mut fds = [PollFd::new(&self.pty, PollFlags::IN)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        matches!(poll(&mut fds, Some(&now)), Ok(1..))
    }

    /// Read and shape PTY output until the master runs dry (`EAGAIN`) or a
    /// frame fills. Only called with no output backlog.
    ///
    /// A short read does not mean the producer stopped: the line discipline
    /// is refilled by the flip-buffer worker while this loop reads, so a
    /// flood that outruns the worker arrives in reads of a few hundred bytes
    /// to a few KiB. Stopping at the first short read framed each of them
    /// separately: an unloaded host forwarding a 101 MB `cat` wrote about
    /// 46,000 router frames, mostly under 4 KiB, and etserver read each in
    /// three or four socket reads before encrypting and sending it. Reading
    /// on until `EAGAIN` frames the same output as about 6,800 frames, most
    /// a full [`MAX_OUTPUT_CHUNK`], for one extra read when output pauses.
    fn read_pty(&mut self) -> Result<(), String> {
        while self.filled < MAX_OUTPUT_CHUNK {
            let start = self.filled;
            match rustix::io::read(&self.pty, &mut self.output[start..MAX_OUTPUT_CHUNK]) {
                Ok(0) | Err(Errno::IO) => {
                    self.finish_output();
                    return Ok(());
                }
                Ok(count) => self.shape_in_place(start, count),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => return Ok(()),
                Err(error) => return Err(format!("could not read PTY output: {error}")),
            }
        }
        Ok(())
    }

    /// Shape `count` freshly read bytes at `start` in place. Plain output
    /// (the common case) is left exactly where the read put it.
    fn shape_in_place(&mut self, start: usize, count: usize) {
        let end = start + count;
        let shaped = if self.shaper.startup.is_none() {
            match self.shaper.filter.apply_slice(&self.output[start..end]) {
                std::borrow::Cow::Borrowed(_) => None,
                std::borrow::Cow::Owned(bytes) => Some(bytes),
            }
        } else {
            let read = self.output[start..end].to_vec();
            let mut shaped = Vec::with_capacity(read.len());
            self.shaper.push(&read, &mut shaped);
            Some(shaped)
        };
        match shaped {
            None => self.filled = end,
            Some(bytes) => {
                self.filled = start;
                self.append_output(&bytes);
            }
        }
    }

    fn finish_output(&mut self) {
        self.pty_eof = true;
        let mut tail = std::mem::take(&mut self.scratch);
        tail.clear();
        self.shaper.finish(&mut tail);
        self.append_output(&tail);
        self.scratch = tail;
    }

    fn append_output(&mut self, bytes: &[u8]) {
        let end = self.filled + bytes.len();
        if end > self.output.len() {
            self.output.resize(end, 0);
        }
        self.output[self.filled..end].copy_from_slice(bytes);
        self.filled = end;
    }

    fn output_backlog(&self) -> bool {
        self.frame.is_some() || self.prefix_sent < self.prefix.len() || self.sent < self.filled
    }

    /// Write queued output as frames until done or the router is full.
    fn flush_output(&mut self) -> Result<(), String> {
        loop {
            if self.frame.is_none() {
                let (length, motd) = if self.prefix_sent < self.prefix.len() {
                    (
                        (self.prefix.len() - self.prefix_sent).min(MAX_OUTPUT_CHUNK),
                        true,
                    )
                } else if self.sent < self.filled {
                    ((self.filled - self.sent).min(MAX_OUTPUT_CHUNK), false)
                } else {
                    self.sent = 0;
                    self.filled = 0;
                    self.prefix = Vec::new();
                    self.prefix_sent = 0;
                    return Ok(());
                };
                let frame = TerminalBufferFrame::new(length, false)
                    .map_err(|error| format!("could not forward PTY output: {error}"))?;
                self.frame = Some((frame, length, motd));
            }
            let Some((frame, length, motd)) = self.frame.as_mut() else {
                return Ok(());
            };
            let output = if *motd {
                &self.prefix[self.prefix_sent..self.prefix_sent + *length]
            } else {
                &self.output[self.sent..self.sent + *length]
            };
            match frame.write_some(&mut self.router, output) {
                Ok(_) => {
                    self.progress = self.progress.wrapping_add(1);
                    if frame.is_complete() {
                        if *motd {
                            self.prefix_sent += *length;
                        } else {
                            self.sent += *length;
                        }
                        self.frame = None;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if self.resume.is_some() && peer_gone(&error) => {
                    self.recover_router(format!("terminal router disconnected: {error}"))?;
                }
                Err(error) => return Err(format!("could not forward PTY output: {error}")),
            }
        }
    }

    /// Re-register a lost router when the session can resume; a frame that
    /// was cut short restarts whole on the new stream, which is read with
    /// the framing its registration negotiated.
    fn recover_router(&mut self, error: String) -> Result<(), String> {
        let Some(resume) = self.resume.as_ref() else {
            return Err(error);
        };
        let (router, framing) = reconnect_router_stream(resume)?;
        self.router = router;
        self.decoder = RouterStreamDecoder::new(framing);
        if let Some((frame, length, _)) = self.frame.as_mut() {
            *frame = TerminalBufferFrame::new(*length, false)
                .map_err(|error| format!("could not forward PTY output: {error}"))?;
        }
        Ok(())
    }

    /// Complete a frame the drain timeout interrupted mid-write. Returns
    /// whether the stream is at a frame boundary again.
    fn finish_started_frame(&mut self) -> bool {
        let Some((frame, length, motd)) = self.frame.as_mut() else {
            return true;
        };
        if !frame.is_started() {
            self.frame = None;
            return true;
        }
        let output = if *motd {
            &self.prefix[self.prefix_sent..self.prefix_sent + *length]
        } else {
            &self.output[self.sent..self.sent + *length]
        };
        let deadline = Instant::now() + FRAME_FINISH_TIMEOUT;
        while !frame.is_complete() {
            match frame.write_some(&mut self.router, output) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return false;
                    }
                    let timeout = Timespec::try_from(remaining).expect("one second fits timespec");
                    let mut fds = [PollFd::new(&self.router, PollFlags::OUT)];
                    let _ = poll(&mut fds, Some(&timeout));
                }
                Err(_) => return false,
            }
        }
        true
    }
}

/// Whether `input` makes the line discipline signal the foreground job and
/// flush its undelivered output: `ISIG` on, `NOFLSH` off, and an INTR, QUIT
/// or SUSP character that is not disabled.
fn interrupts_output(termios: &Termios, input: &[u8]) -> bool {
    if !termios.local_modes.contains(LocalModes::ISIG)
        || termios.local_modes.contains(LocalModes::NOFLSH)
    {
        return false;
    }
    let signals = [
        SpecialCodeIndex::VINTR,
        SpecialCodeIndex::VQUIT,
        SpecialCodeIndex::VSUSP,
    ]
    .map(|index| termios.special_codes[index]);
    // `_POSIX_VDISABLE` is NUL on Linux.
    input
        .iter()
        .any(|byte| *byte != 0 && signals.contains(byte))
}

fn write_nonblocking(pty: &filedescriptor::FileDescriptor, mut bytes: &[u8]) -> io::Result<usize> {
    let mut written = 0;
    while !bytes.is_empty() {
        match rustix::io::write(pty, bytes) {
            Ok(0) => break,
            Ok(count) => {
                written += count;
                bytes = &bytes[count..];
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(written)
}

fn router_disconnected(error: &str) -> bool {
    error == "terminal router disconnected" || error.starts_with("could not read terminal router")
}

fn peer_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}

#[cfg(test)]
#[path = "terminal_pty_poll_tests.rs"]
mod tests;
