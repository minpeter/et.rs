//! Per-pane PTY handler, mirroring upstream `htm/TerminalHandler.cpp`.
//!
//! Each pane owns a login shell on a PTY. Output is returned to the caller and
//! also retained in a line buffer that is replayed when a client reconnects.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, TryRecvError};

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize};

const MAX_BUFFER_LINES: usize = 1024;
const MAX_BUFFER_CHARS: i64 = 128 * MAX_BUFFER_LINES as i64;
const READ_BUFFER: usize = 16 * 1024;

pub struct TerminalHandler {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
    output: Receiver<Vec<u8>>,
    running: bool,
    buffer: VecDeque<String>,
    buffer_length: i64,
}

impl TerminalHandler {
    /// Spawn a login shell on a fresh PTY, like upstream's
    /// `forkpty` + `execl(shell, shell, "-l")` in the user's home directory.
    pub fn start() -> std::io::Result<Self> {
        let pty = portable_pty::native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(std::io::Error::other)?;
        let shell = default_shell();
        let mut command = CommandBuilder::new(&shell);
        #[cfg(unix)]
        command.arg("-l");
        if let Some(home) = home_directory() {
            command.cwd(home);
        }
        command.env("HTM_VERSION", env!("CARGO_PKG_VERSION"));
        let child = pty
            .slave
            .spawn_command(command)
            .map_err(std::io::Error::other)?;
        drop(pty.slave);
        let writer = pty.master.take_writer().map_err(std::io::Error::other)?;
        let mut reader = pty
            .master
            .try_clone_reader()
            .map_err(std::io::Error::other)?;
        let (sender, output) = mpsc::channel();
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
            writer,
            child,
            output,
            running: true,
            buffer: VecDeque::new(),
            buffer_length: 0,
        })
    }

    /// Drain whatever the PTY produced, updating the replay buffer and
    /// returning the raw bytes just read.
    pub fn poll_user_terminal(&mut self) -> Vec<u8> {
        if !self.running {
            return Vec::new();
        }
        let mut collected = Vec::new();
        loop {
            match self.output.try_recv() {
                Ok(chunk) => collected.extend_from_slice(&chunk),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // The shell exited and closed the PTY.
                    let _ = self.child.wait();
                    self.running = false;
                    break;
                }
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
        self.writer.write_all(data)?;
        self.writer.flush()
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
        let _ = self.child.wait();
        self.running = false;
    }

    /// Buffered output replayed to reconnecting clients.
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
    fn buffer_appends_partial_lines_and_bounds_growth() {
        let mut handler = TerminalHandler {
            master: dummy_master(),
            writer: Box::new(Vec::new()),
            child: dummy_child(),
            output: mpsc::channel().1,
            running: true,
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
