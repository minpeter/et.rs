//! Per-pane PTY handler, mirroring upstream `htm/TerminalHandler.cpp`.
//!
//! Each pane owns an interactive shell on a PTY. Bounded channels isolate blocking
//! platform PTY I/O from the daemon's control loop. The screen owns recovery.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize};

const MAX_BUFFER_LINES: usize = 1024;
const MAX_BUFFER_CHARS: i64 = 128 * MAX_BUFFER_LINES as i64;
const READ_BUFFER: usize = 16 * 1024;

pub struct TerminalHandler {
    master: Box<dyn MasterPty + Send>,
    writer: mpsc::SyncSender<Vec<u8>>,
    child: Box<dyn Child + Send + Sync>,
    output: Receiver<Vec<u8>>,
    initial_cwd: PathBuf,
    running: bool,
    exit_deadline: Option<Instant>,
    buffer: VecDeque<String>,
    buffer_length: i64,
}

impl TerminalHandler {
    /// Spawn a non-login shell on a fresh PTY, as canonical control mode does.
    pub fn start() -> std::io::Result<Self> {
        Self::start_in(None)
    }

    pub fn start_in(cwd: Option<PathBuf>) -> std::io::Result<Self> {
        Self::start_in_size(cwd, 80, 24)
    }

    pub(crate) fn start_in_size(
        cwd: Option<PathBuf>,
        cols: u16,
        rows: u16,
    ) -> std::io::Result<Self> {
        let pty = portable_pty::native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(std::io::Error::other)?;
        let shell = default_shell();
        let mut command = CommandBuilder::new(&shell);
        let initial_cwd = cwd
            .or_else(|| std::env::var_os("HTM_INITIAL_CWD").map(PathBuf::from))
            .or_else(home_directory)
            .unwrap_or_else(|| PathBuf::from("/"));
        command.cwd(&initial_cwd);
        command.env("HTM_VERSION", env!("CARGO_PKG_VERSION"));
        command.env("TERM", "screen");
        command.env("PROMPT_EOL_MARK", "");
        let child = pty
            .slave
            .spawn_command(command)
            .map_err(std::io::Error::other)?;
        drop(pty.slave);
        let mut writer = pty.master.take_writer().map_err(std::io::Error::other)?;
        let (input, receive) = mpsc::sync_channel::<Vec<u8>>(16);
        std::thread::Builder::new()
            .name("htm-pane-input".into())
            .spawn(move || {
                while let Ok(data) = receive.recv() {
                    if writer
                        .write_all(&data)
                        .and_then(|()| writer.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        let mut reader = pty
            .master
            .try_clone_reader()
            .map_err(std::io::Error::other)?;
        let (sender, output) = mpsc::sync_channel(16);
        std::thread::Builder::new()
            .name("htm-pane".to_owned())
            .spawn(move || {
                let mut chunk = [0u8; READ_BUFFER];
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(count) => {
                            if sender.send(chunk[..count].to_vec()).is_err() {
                                return;
                            }
                        }
                    }
                }
            })?;
        Ok(Self {
            master: pty.master,
            writer: input,
            child,
            output,
            initial_cwd,
            running: true,
            exit_deadline: None,
            buffer: VecDeque::new(),
            buffer_length: 0,
        })
    }

    /// Drain a bounded batch of PTY output, retaining diagnostic history.
    pub fn poll_user_terminal(&mut self) -> Vec<u8> {
        if !self.running {
            return Vec::new();
        }
        let mut collected = Vec::new();
        let mut eof = false;
        while collected.len() < READ_BUFFER {
            match self.output.try_recv() {
                Ok(chunk) => collected.extend_from_slice(&chunk),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    eof = true;
                    break;
                }
            }
        }
        // ConPTY can keep its output pipe open after the child exits. Reap
        // independently of EOF, allowing a bounded final drain before dropping
        // the master (which closes the pseudo-console and unblocks its reader).
        if self.exit_deadline.is_none() && self.child.try_wait().ok().flatten().is_some() {
            self.exit_deadline = Some(Instant::now() + Duration::from_millis(250));
        }
        if let Some(deadline) = self.exit_deadline {
            if eof || Instant::now() >= deadline {
                self.running = false;
            }
        }
        if !collected.is_empty() {
            self.buffer_new_chars(&collected);
        }
        collected
    }

    fn buffer_new_chars(&mut self, chunk: &[u8]) {
        let text = String::from_utf8_lossy(chunk).into_owned();
        let tokens: Vec<String> = text.split('\n').map(str::to_owned).collect();
        for token in &tokens {
            self.buffer_length += token.len() as i64;
        }
        if self.buffer.is_empty() {
            self.buffer.extend(tokens);
        } else {
            let mut tokens = tokens.into_iter();
            if let (Some(last), Some(first)) = (self.buffer.back_mut(), tokens.next()) {
                last.push_str(&first);
            }
            self.buffer.extend(tokens);
        }
        while self.buffer.len() > MAX_BUFFER_LINES {
            if let Some(front) = self.buffer.pop_front() {
                self.buffer_length -= front.len() as i64;
            }
        }
        while self.buffer_length > MAX_BUFFER_CHARS {
            match self.buffer.pop_front() {
                Some(front) => self.buffer_length -= front.len() as i64,
                None => break,
            }
        }
    }

    pub fn append_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "pane input too large",
            ));
        }
        self.writer
            .try_send(data.to_vec())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::WouldBlock, error.to_string()))
    }

    pub fn cwd(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        if let Some(pid) = self.child.process_id() {
            if let Ok(cwd) = std::fs::read_link(format!("/proc/{pid}/cwd")) {
                return cwd;
            }
        }
        #[cfg(target_os = "macos")]
        if let Some(pid) = self.child.process_id() {
            use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
            let pid = Pid::from_u32(pid);
            let mut system = System::new();
            system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid]),
                false,
                ProcessRefreshKind::nothing().with_cwd(UpdateKind::Always),
            );
            if let Some(cwd) = system.process(pid).and_then(|p| p.cwd()) {
                return cwd.to_owned();
            }
        }
        self.initial_cwd.clone()
    }

    pub fn foreground_command(&self) -> String {
        #[cfg(unix)]
        {
            let name = |pid: u32| -> String {
                #[cfg(target_os = "macos")]
                let value = {
                    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
                    let pid = Pid::from_u32(pid);
                    let mut system = System::new();
                    system.refresh_processes_specifics(
                        ProcessesToUpdate::Some(&[pid]),
                        false,
                        ProcessRefreshKind::nothing(),
                    );
                    system
                        .process(pid)
                        .map(|p| p.name().to_string_lossy().into_owned())
                        .unwrap_or_default()
                };
                #[cfg(not(target_os = "macos"))]
                let value = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .unwrap_or_default()
                    .trim_end_matches('\n')
                    .to_owned();
                if matches!(value.as_str(), "pgrep" | "pkill" | "htmd" | "htm") {
                    String::new()
                } else {
                    value
                }
            };
            if let Some(pid) = self.master.process_group_leader().filter(|&p| p > 0) {
                let comm = name(pid as u32);
                if !comm.is_empty() {
                    return comm;
                }
            }
            self.child.process_id().map(name).unwrap_or_default()
        }
        #[cfg(windows)]
        {
            use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
            let Some(pid) = self.child.process_id() else {
                return String::new();
            };
            let root = Pid::from_u32(pid);
            let mut system = System::new();
            system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                false,
                ProcessRefreshKind::nothing(),
            );
            let name = |pid| {
                system
                    .process(pid)
                    .map(|p| {
                        let name = p.name().to_string_lossy().to_lowercase();
                        name.strip_suffix(".exe").unwrap_or(&name).to_owned()
                    })
                    .unwrap_or_default()
            };
            let mut stack = vec![root];
            let mut seen = std::collections::HashSet::new();
            let mut best = String::new();
            while let Some(pid) = stack.pop() {
                if !seen.insert(pid) {
                    continue;
                }
                let mut children: Vec<_> = system
                    .processes()
                    .iter()
                    .filter(|(_, p)| p.parent() == Some(pid))
                    .map(|(&pid, _)| pid)
                    .collect();
                children.sort();
                if children.is_empty() {
                    let comm = name(pid);
                    if !matches!(
                        comm.as_str(),
                        "" | "cmd"
                            | "powershell"
                            | "pwsh"
                            | "powershell_ise"
                            | "conhost"
                            | "openconsole"
                            | "wt"
                            | "windowsterminal"
                            | "htmd"
                            | "htm"
                    ) || (best.is_empty() && pid == root)
                    {
                        best = comm;
                    }
                } else {
                    stack.extend(children);
                }
            }
            if best.is_empty() {
                name(root)
            } else {
                best
            }
        }
    }

    pub fn process_id(&self) -> Option<u32> {
        self.child.process_id()
    }
    pub fn update_terminal_size(&self, cols: i32, rows: i32) {
        // Upstream assigns straight into `winsize` without validation.
        let _ = self.master.resize(PtySize {
            rows: (rows as u32 & 0xFFFF) as u16,
            cols: (cols as u32 & 0xFFFF) as u16,
            pixel_width: 0,
            pixel_height: 0,
        });
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while self.child.try_wait().ok().flatten().is_none() && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        self.running = false;
    }

    /// Bounded diagnostic history, not a control-mode replay stream.
    pub fn buffer(&self) -> &VecDeque<String> {
        &self.buffer
    }
}

/// Shell selection follows reviewed upstream HTM on each platform.
pub(crate) fn default_shell() -> String {
    if let Some(shell) = std::env::var("SHELL").ok().filter(|s| !s.is_empty()) {
        return shell;
    }
    #[cfg(unix)]
    {
        "/bin/sh".to_owned()
    }
    #[cfg(windows)]
    {
        std::env::var("COMSPEC")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "cmd.exe".to_owned())
    }
}

impl Drop for TerminalHandler {
    fn drop(&mut self) {
        if self.running {
            self.stop();
        }
        // Release a reader blocked on our bounded channel before the master
        // closes ConPTY, whose shutdown may otherwise wait for that reader.
        self.output = mpsc::channel().1;
    }
}

fn home_directory() -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    let name = "HOME";
    #[cfg(windows)]
    let name = "USERPROFILE";
    std::env::var_os(name)
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exited_child_drains_output_without_waiting_for_pty_eof() {
        let mut handler = TerminalHandler::start().unwrap();
        let (sender, output) = mpsc::sync_channel(2);
        handler.output = output;
        handler.child.kill().unwrap();
        handler.child.wait().unwrap();
        sender.send(b"final output".to_vec()).unwrap();
        assert_eq!(handler.poll_user_terminal(), b"final output");
        assert!(handler.is_running(), "allow late output during final drain");
        sender.send(b"late output".to_vec()).unwrap();
        assert_eq!(handler.poll_user_terminal(), b"late output");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while handler.is_running() && std::time::Instant::now() < deadline {
            handler.poll_user_terminal();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            !handler.is_running(),
            "child exit must not depend on PTY EOF"
        );
        drop(sender);
    }

    #[test]
    fn pty_is_created_at_client_dimensions() {
        let handler = TerminalHandler::start_in_size(None, 117, 31).unwrap();
        let size = handler.master.get_size().unwrap();
        assert_eq!((size.cols, size.rows), (117, 31));
    }

    #[test]
    fn buffer_appends_partial_lines_and_bounds_growth() {
        let mut handler = TerminalHandler {
            master: dummy_master(),
            writer: mpsc::sync_channel(1).0,
            child: dummy_child(),
            output: mpsc::channel().1,
            initial_cwd: PathBuf::from("/"),
            running: true,
            exit_deadline: None,
            buffer: VecDeque::new(),
            buffer_length: 0,
        };
        handler.buffer_new_chars(b"abc");
        handler.buffer_new_chars(b"def\nghi");
        assert_eq!(
            handler.buffer,
            VecDeque::from(["abcdef".to_owned(), "ghi".to_owned()])
        );

        for _ in 0..(MAX_BUFFER_LINES + 100) {
            handler.buffer_new_chars(b"x\n");
        }
        assert!(handler.buffer.len() <= MAX_BUFFER_LINES);
        assert!(handler.buffer_length <= MAX_BUFFER_CHARS);
    }

    fn dummy_master() -> Box<dyn MasterPty + Send> {
        portable_pty::native_pty_system()
            .openpty(PtySize::default())
            .unwrap()
            .master
    }

    fn dummy_child() -> Box<dyn Child + Send + Sync> {
        let pty = portable_pty::native_pty_system()
            .openpty(PtySize::default())
            .unwrap();
        #[cfg(unix)]
        let mut command = CommandBuilder::new("true");
        #[cfg(windows)]
        let mut command = {
            let mut command = CommandBuilder::new("cmd.exe");
            command.args(["/C", "exit 0"]);
            command
        };
        command.env("HTM_TEST", "1");
        pty.slave.spawn_command(command).unwrap()
    }
}
