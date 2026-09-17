//! Nonblocking control-mode daemon over the existing protected IPC transport.
use crate::control::{self, ClientFlags};
use crate::framing::{self, Lines, MAX_QUEUE};
use crate::state::MultiplexerState;
pub use crate::transport::pipe_name;
use crate::transport::{Listener, Stream};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn diagnostic_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".diagnostic");
    name.into()
}

/// Read a bounded snapshot without attaching, replacing the UI, or starting a
/// daemon. Both endpoints use the same private/authenticated transport policy.
pub fn dump_panes(path: &Path) -> io::Result<String> {
    let mut stream = crate::transport::connect(&diagnostic_path(path))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut header = [0; 5];
    read_diagnostic(&mut stream, &mut header, deadline)?;
    let size = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    if size > MAX_QUEUE / 2 || header[0] > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid pane dump header",
        ));
    }
    let mut body = vec![0; size];
    read_diagnostic(&mut stream, &mut body, deadline)?;
    let text = String::from_utf8(body).map_err(io::Error::other)?;
    if header[0] == 1 {
        return Err(io::Error::other(text));
    }
    Ok(text)
}

fn read_diagnostic(stream: &mut Stream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => bytes = &mut bytes[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(io::ErrorKind::TimedOut.into())
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub struct HtmServer {
    listener: Listener,
    diagnostic: Listener,
    diagnostic_reply: Option<(Stream, VecDeque<u8>, Instant)>,
    endpoint: Option<Stream>,
    state: MultiplexerState,
    input: Lines,
    pending: VecDeque<u8>,
    flags: ClientFlags,
    sequence: u64,
    running: bool,
}

impl HtmServer {
    pub fn bind(path: &Path) -> io::Result<Self> {
        Ok(Self {
            listener: Listener::bind(path)?,
            diagnostic: Listener::bind(&diagnostic_path(path))?,
            diagnostic_reply: None,
            endpoint: None,
            state: MultiplexerState::new().map_err(io::Error::other)?,
            input: Lines::default(),
            pending: VecDeque::new(),
            flags: ClientFlags::default(),
            sequence: 0,
            running: true,
        })
    }
    pub fn run(&mut self) -> io::Result<()> {
        while self.running {
            if let Err(error) = self.poll_diagnostic() {
                self.diagnostic_reply = None;
                eprintln!("htmd: pane diagnostic: {error}");
            }
            match self.listener.accept() {
                Ok(stream) => {
                    self.close_endpoint();
                    stream.set_nonblocking(true)?;
                    self.endpoint = Some(stream);
                    self.input = Lines::default();
                    // Canonical recover() resets framing, not client flags or
                    // pane gates. Frontends explicitly refresh those settings.
                    self.sequence += 1;
                    self.queue(framing::reply(self.sequence, 0, Ok(Vec::new())));
                    self.state.attach_notifications();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => eprintln!("htmd: accepting client: {e}"),
            }
            if self.read_commands().is_err() {
                self.close_endpoint();
            }
            // Always drain panes while detached; capture state remains current.
            let output = self.state.poll(
                self.endpoint.is_none() || self.flags.no_output,
                self.flags.pause.is_some(),
                self.flags.pause == Some(0),
            );
            self.queue(output);
            let notifications = std::mem::take(&mut self.state.notifications);
            self.queue(notifications);
            if self.flush().is_err() {
                self.close_endpoint();
            }
            if self.state.panes.is_empty() {
                self.running = false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.state.stop_all();
        // Retire before EOF: htm -x treats EOF as the shutdown acknowledgement.
        self.listener.retire()?;
        self.diagnostic.retire()?;
        self.diagnostic_reply = None;
        self.close_endpoint();
        Ok(())
    }
    fn poll_diagnostic(&mut self) -> io::Result<()> {
        // At most one bounded snapshot is retained. A slow consumer cannot
        // delay control input, retain a PTY, or extend the daemon's lifetime.
        if self.diagnostic_reply.is_none() {
            match self.diagnostic.accept() {
                Ok(stream) => {
                    stream.set_nonblocking(true)?;
                    let (status, body) = match self.state.dump_panes() {
                        Ok(body) => (0, body),
                        Err(error) => (1, error),
                    };
                    let mut bytes = VecDeque::from([status]);
                    bytes.extend((body.len() as u32).to_be_bytes());
                    bytes.extend(body.bytes());
                    self.diagnostic_reply =
                        Some((stream, bytes, Instant::now() + Duration::from_secs(2)));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        let (stream, bytes, deadline) = self.diagnostic_reply.as_mut().unwrap();
        while !bytes.is_empty() && Instant::now() < *deadline {
            match stream.write(bytes.as_slices().0) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    bytes.drain(..n);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if bytes.is_empty() || Instant::now() >= *deadline {
            self.diagnostic_reply = None;
        }
        Ok(())
    }
    fn queue(&mut self, bytes: Vec<u8>) {
        if self.endpoint.is_none() {
            return;
        }
        if self.pending.len() + bytes.len() > MAX_QUEUE {
            // Never emit a truncated reply or silently corrupt the control stream.
            // A stalled UI is disconnected; its shells and screen survive.
            self.close_endpoint();
        } else {
            self.pending.extend(bytes);
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(stream) = self.endpoint.as_mut() {
            while !self.pending.is_empty() {
                match stream.write(self.pending.as_slices().0) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => {
                        self.pending.drain(..n);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }
    fn read_commands(&mut self) -> io::Result<()> {
        let Some(stream) = self.endpoint.as_mut() else {
            return Ok(());
        };
        let mut buffer = [0; 4096];
        let n = match stream.read(&mut buffer) {
            Ok(0) => {
                self.close_endpoint();
                return Ok(());
            }
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(())
            }
            Err(e) => return Err(e),
        };
        for line in self.input.feed(&buffer[..n])? {
            let commands = match framing::parse(&line) {
                Ok(commands) => commands,
                Err(error) => {
                    self.sequence += 1;
                    self.queue(framing::reply(self.sequence, 1, Err(error)));
                    continue;
                }
            };
            if commands.is_empty() {
                self.close_endpoint();
                break;
            }
            for words in commands {
                match words.first().map(String::as_str).unwrap_or_default() {
                    "" | "detach-client" | "detach" | "exit" => {
                        self.close_endpoint();
                        return Ok(());
                    }
                    "kill-server" => {
                        self.running = false;
                        return Ok(());
                    }
                    _ => {}
                }
                self.sequence += 1;
                let result =
                    control::execute(&mut self.state, &mut self.flags, &words).and_then(|body| {
                        if body.len() > MAX_QUEUE / 2 {
                            Err("reply exceeds control size limit".into())
                        } else {
                            Ok(body)
                        }
                    });
                let failed = result.is_err();
                self.queue(framing::reply(self.sequence, 1, result));
                let notifications = std::mem::take(&mut self.state.notifications);
                self.queue(notifications);
                if failed || self.state.panes.is_empty() || self.endpoint.is_none() {
                    break;
                }
            }
            if self.state.panes.is_empty() || self.endpoint.is_none() {
                break;
            }
        }
        Ok(())
    }
    fn close_endpoint(&mut self) {
        if self.endpoint.is_some() {
            self.state.detach();
            // Finish admitted records before the exit marker. Bound the drain
            // so takeover/detach cannot hang behind a wedged frontend.
            if self.pending.len() + 6 <= MAX_QUEUE {
                self.pending.extend(b"%exit\n");
            }
            let deadline = Instant::now() + Duration::from_millis(250);
            while !self.pending.is_empty() && Instant::now() < deadline {
                if self.flush().is_err() {
                    break;
                }
                if !self.pending.is_empty() {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        if let Some(stream) = self.endpoint.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        self.pending.clear();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_deadline_is_absolute_despite_fragmented_progress() {
        let (mut reader, mut writer) = Stream::pair().unwrap();
        let peer = std::thread::spawn(move || {
            for _ in 0..64 {
                if writer.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        assert_eq!(
            read_diagnostic(
                &mut reader,
                &mut [0; 64],
                Instant::now() + Duration::from_millis(30)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        drop(reader);
        peer.join().unwrap();
    }

    #[test]
    fn diagnostic_does_not_take_over_or_mutate_the_ui() {
        use std::os::unix::fs::DirBuilderExt;
        let directory = std::env::temp_dir().join(format!("htm-diagnostic-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("ipc");
        let mut server = HtmServer::bind(&path).unwrap();
        let (_ui, endpoint) = Stream::pair().unwrap();
        server.endpoint = Some(endpoint);
        server.flags.no_output = true;
        server.sequence = 17;
        server
            .state
            .options
            .insert(('g', 0, "@affinities".into()), "3,1 2".into());
        server
            .state
            .panes
            .get_mut(&0)
            .unwrap()
            .screen
            .process(b"diagnostic sentinel")
            .unwrap();
        let mut client = crate::transport::connect(&diagnostic_path(&path)).unwrap();
        server.poll_diagnostic().unwrap();
        let mut result = Vec::new();
        client.read_to_end(&mut result).unwrap();
        assert_eq!(result[0], 0);
        assert_eq!(
            u32::from_be_bytes(result[1..5].try_into().unwrap()) as usize,
            result.len() - 5
        );
        let text = std::str::from_utf8(&result[5..]).unwrap();
        assert!(text.starts_with("# affinities: [[1,3],[2]]\n"), "{text}");
        assert!(text.contains("diagnostic sentinel"), "{text}");
        assert!(server.endpoint.is_some());
        assert!(server.flags.no_output);
        assert_eq!(server.sequence, 17);
        assert_eq!(server.state.panes.len(), 1);
        drop(server);
        assert!(!diagnostic_path(&path).exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn detach_drains_pending_records_before_one_exit() {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("htm-drain-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let mut server = HtmServer::bind(&path.join("ipc")).unwrap();
        let (mut client, endpoint) = Stream::pair().unwrap();
        endpoint.set_nonblocking(true).unwrap();
        server.endpoint = Some(endpoint);
        server.pending.extend(b"%begin 1 1 1\nanswer\n%end 1 1 1\n");
        server.close_endpoint();
        let mut output = String::new();
        client.read_to_string(&mut output).unwrap();
        assert_eq!(output, "%begin 1 1 1\nanswer\n%end 1 1 1\n%exit\n");
        drop(server);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn empty_arguments_detach_without_executing_stale_input() {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("htm-empty-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let mut server = HtmServer::bind(&path.join("ipc")).unwrap();
        for command in [
            b"\nkill-server\n".as_slice(),
            b"''\nkill-server\n",
            b"  \t\nkill-server\n",
        ] {
            let (mut client, endpoint) = Stream::pair().unwrap();
            endpoint.set_nonblocking(true).unwrap();
            server.endpoint = Some(endpoint);
            client.write_all(command).unwrap();
            server.read_commands().unwrap();
            assert!(server.endpoint.is_none());
            assert!(server.running);
            assert_eq!(server.state.panes.len(), 1);
        }
        drop(server);
        std::fs::remove_dir_all(path).unwrap();
    }
}
