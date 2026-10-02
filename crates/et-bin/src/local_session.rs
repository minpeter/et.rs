//! Persistent ET transport owner for local mux passengers and `--ctl`.
//! No local connection may block transport progress: framing, descriptor
//! receipt, input and output are polled, capped, and independently expired.
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use et_cli::client::ClientArgs;
use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalExitStatus, TerminalPacketType as Kind};
use et_net::connection::{Connection, WritePacketError};
use et_net::forward::{is_forward_packet, Forwarder};
use prost::Message;

use crate::error::ClientError;
use crate::initial_connect::ReconnectOutcome;
use crate::local_control::{self, Action, Control};
use crate::local_ipc::{self as ipc, Decoder, FrameReader, Listener};
use crate::local_mux::{self as mux, ExitMarker};

const MAX_CLIENTS: usize = 16;
const MAX_PENDING: usize = 64;

pub fn enabled(args: &ClientArgs) -> bool {
    args.ctl || mux::master(args) || args.no_remote_command
}
fn error(error: impl std::fmt::Display) -> ClientError {
    ClientError::Terminal(error.to_string())
}

struct Peer {
    socket: UnixStream,
    reader: FrameReader,
    control: bool,
    hello: bool,
    output: Vec<u8>,
    closing: bool,
    started: Instant,
    pending_session: Option<(u32, String)>,
    fds: Vec<OwnedFd>,
    attached: bool,
}
impl Peer {
    fn new(socket: UnixStream, control: bool) -> Self {
        Self {
            socket,
            reader: FrameReader::new(control),
            control,
            hello: control,
            output: if control {
                Vec::new()
            } else {
                ipc::mux_frame(&ipc::words(&[mux::HELLO, 4]))
            },
            closing: false,
            started: Instant::now(),
            pending_session: None,
            fds: Vec::new(),
            attached: false,
        }
    }
    fn reply(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        if self.output.len() + bytes.len() > ipc::MAX_REPLY {
            return Err(ipc::invalid("local reply queue full"));
        }
        self.output.extend(bytes);
        Ok(())
    }
}

struct NonblockingFile {
    file: File,
    original: rustix::fs::OFlags,
}
impl NonblockingFile {
    fn new(fd: OwnedFd, original: rustix::fs::OFlags) -> io::Result<Self> {
        rustix::fs::fcntl_setfl(&fd, original | rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self {
            file: File::from(fd),
            original,
        })
    }
}
impl Drop for NonblockingFile {
    fn drop(&mut self) {
        let _ = rustix::fs::fcntl_setfl(&self.file, self.original);
    }
}

struct Passenger {
    peer: Option<u32>,
    input: NonblockingFile,
    output: NonblockingFile,
    _stderr: OwnedFd,
    orphaned: bool,
    failed: bool,
    read_input: bool,
    queued: Vec<u8>,
    marker: Option<ExitMarker>,
    status: Option<u32>,
    size: Option<(u16, u16)>,
}
impl Passenger {
    fn new(peer: Option<u32>, fds: Vec<OwnedFd>, command: bool) -> io::Result<Self> {
        let flags = fds
            .iter()
            .map(rustix::fs::fcntl_getfl)
            .collect::<Result<Vec<_>, _>>()?;
        if flags.len() != 3 {
            return Err(ipc::invalid("expected three passenger descriptors"));
        }
        let mut fds = fds.into_iter();
        // Snapshot flags before changing any descriptor: stdin and stdout may
        // share an open file description (a terminal or socketpair).
        let input = NonblockingFile::new(fds.next().unwrap(), flags[0])?;
        let output = NonblockingFile::new(fds.next().unwrap(), flags[1])?;
        let stderr = fds.next().unwrap();
        Ok(Self {
            peer,
            input,
            output,
            _stderr: stderr,
            orphaned: false,
            failed: false,
            read_input: true,
            queued: Vec::new(),
            marker: command.then(ExitMarker::new),
            status: None,
            size: None,
        })
    }
    fn receive(&mut self, bytes: &[u8]) -> io::Result<()> {
        let bytes = if let Some(marker) = self.marker.as_mut() {
            let (bytes, status) = marker.consume(bytes);
            self.status = status.or(self.status);
            bytes
        } else {
            bytes.to_vec()
        };
        if self.orphaned {
            return Ok(());
        }
        if self.queued.len() + bytes.len() > ipc::MAX_REPLY {
            return Err(ipc::invalid("passenger output limit exceeded"));
        }
        self.queued.extend(bytes);
        Ok(())
    }
    fn fail(&mut self) {
        self.failed = true;
        self.orphaned = true;
        self.read_input = false;
        self.queued.clear();
        // The shell remains busy until its command marker arrives, even if
        // the consumer closed stdout or exceeded the bounded output queue.
        if self.marker.is_none() {
            self.status = Some(255);
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        ipc::flush(&mut self.output.file, &mut self.queued)
    }
}

struct Runtime {
    mux: Option<Listener>,
    ctl: Option<Listener>,
    peers: BTreeMap<u32, Peer>,
    next_id: u32,
    control: Control,
    passenger: Option<Passenger>,
    pending: VecDeque<Packet>,
    stopping: Option<Instant>,
    idle: Instant,
    primary_finished: bool,
    primary_status: i32,
}

pub struct Prepared {
    mux: Option<Listener>,
    ctl: Option<Listener>,
}

/// Reserve the local names before SSH can create/adopt a remote session.
pub fn prepare(args: &ClientArgs) -> Result<Option<Prepared>, ClientError> {
    if !enabled(args) {
        return Ok(None);
    }
    if (args.no_pty && !args.no_remote_command)
        || args.stdio_forward.is_some()
        || args.remote_is_windows()
    {
        return Err(ClientError::Unsupported(
            "local mux/control sessions require a POSIX shell (no -T/-W)",
        ));
    }
    (|| {
        let mux_listener = if mux::master(args) {
            Some(Listener::bind(Path::new(
                args.control_path.as_deref().unwrap(),
            ))?)
        } else {
            None
        };
        let ctl_listener = if args.ctl {
            let name = args.session_name.as_deref().ok_or_else(|| {
                ipc::invalid("control session requires a generated or explicit name")
            })?;
            if !local_control::valid_name(name) {
                return Err(ipc::invalid("invalid control session name"));
            }
            let path = match args.ctl_socket.as_deref() {
                Some(path) => path.into(),
                None => local_control::control_dir()?.join(format!("{name}.sock")),
            };
            let listener = Listener::bind(&path)?;
            local_control::tombstone(name, None)?;
            Some(listener)
        } else {
            None
        };
        Ok::<_, io::Error>(Some(Prepared {
            mux: mux_listener,
            ctl: ctl_listener,
        }))
    })()
    .map_err(error)
}

impl Runtime {
    fn new(args: &ClientArgs, prepared: Prepared) -> io::Result<Self> {
        if args
            .command
            .as_ref()
            .is_some_and(|command| command.len() + 128 > MAX_PENDING * 16 * 1024)
        {
            return Err(ipc::invalid("initial command exceeds input queue limit"));
        }
        let mut runtime = Self {
            mux: prepared.mux,
            ctl: prepared.ctl,
            peers: BTreeMap::new(),
            next_id: 1,
            control: Control::new(args.host.as_deref().unwrap_or("")),
            passenger: None,
            pending: VecDeque::new(),
            stopping: None,
            idle: Instant::now(),
            primary_finished: args.ctl
                || args.no_remote_command
                || (args.background && args.command.is_none())
                || args.no_terminal,
            primary_status: 0,
        };
        if !runtime.primary_finished {
            let fds = vec![
                rustix::io::dup(io::stdin())?,
                rustix::io::dup(io::stdout())?,
                rustix::io::dup(io::stderr())?,
            ];
            runtime.passenger = Some(Passenger::new(None, fds, false)?);
        }
        if args.ctl {
            runtime.pending.push_back(Packet::new(
                Kind::TerminalInfo as u8,
                runtime.control.size.encode_to_vec(),
            ));
            if let Some(command) = args.command.as_deref() {
                runtime.input(format!("{command}\n").as_bytes());
            }
        } else if let Some(command) = args.command.as_deref() {
            // Only passengers use the subshell marker. The primary command
            // retains normal ET shell state and --noexit semantics.
            let suffix = if args.no_exit { "\n" } else { "; exit\n" };
            runtime.input(format!("{command}{suffix}").as_bytes());
        }
        Ok(runtime)
    }
    fn input(&mut self, bytes: &[u8]) {
        for bytes in bytes.chunks(16 * 1024) {
            self.pending.push_back(Packet::new(
                Kind::TerminalBuffer as u8,
                TerminalBuffer {
                    buffer: Some(bytes.to_vec()),
                    is_stderr: None,
                }
                .encode_to_vec(),
            ));
        }
    }
    fn accept(&mut self) -> io::Result<()> {
        for control in [false, true] {
            let listener = if control { &self.ctl } else { &self.mux };
            if let Some(listener) = listener {
                for _ in 0..MAX_CLIENTS {
                    let Some(socket) = listener.accept()? else {
                        break;
                    };
                    if self.peers.len() >= MAX_CLIENTS {
                        continue;
                    }
                    let id = self.next_id;
                    self.next_id = self
                        .next_id
                        .checked_add(1)
                        .ok_or_else(|| ipc::invalid("mux session ids exhausted"))?;
                    self.peers.insert(id, Peer::new(socket, control));
                }
            }
        }
        Ok(())
    }
    fn local(
        &mut self,
        forwarder: &mut Forwarder,
        connected: bool,
        no_shell: bool,
    ) -> io::Result<()> {
        self.accept()?;
        let ids: Vec<_> = self.peers.keys().copied().collect();
        for id in ids {
            let mut peer = self.peers.remove(&id).unwrap();
            let result = (|| {
                ipc::flush(&mut peer.socket, &mut peer.output)?;
                if peer.closing {
                    return Ok(!peer.output.is_empty() && peer.started.elapsed() < ipc::TIMEOUT);
                }
                if !peer.attached && peer.started.elapsed() > ipc::TIMEOUT {
                    return Ok(false);
                }
                if peer.attached {
                    let mut byte = [0];
                    return match peer.socket.read(&mut byte) {
                        Ok(0) => Ok(false),
                        Ok(_) => Err(ipc::invalid("unexpected attached mux data")),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(true),
                        Err(e) => Err(e),
                    };
                }
                if peer.pending_session.is_some() {
                    while peer.fds.len() < 3 {
                        let Some(fd) = ipc::receive_fd(&peer.socket)? else {
                            return Ok(true);
                        };
                        peer.fds.push(fd);
                    }
                    let (request, command) = peer.pending_session.take().unwrap();
                    if self.passenger.is_some() || no_shell || self.pending.len() + 16 > MAX_PENDING
                    {
                        peer.reply(mux::failure(request, "shared shell unavailable or busy"))?;
                        peer.fds.clear();
                        return Ok(true);
                    }
                    let passenger = Passenger::new(
                        Some(id),
                        std::mem::take(&mut peer.fds),
                        !command.is_empty(),
                    )?;
                    peer.reply(ipc::mux_frame(&ipc::words(&[mux::OPENED, request, id])))?;
                    peer.attached = true;
                    let input = passenger
                        .marker
                        .as_ref()
                        .map(|marker| marker.command(&command));
                    self.passenger = Some(passenger);
                    self.idle = Instant::now();
                    if let Some(input) = input {
                        self.input(input.as_bytes());
                    }
                    return Ok(true);
                }
                let Some(frame) = peer.reader.poll(&mut peer.socket)? else {
                    return Ok(true);
                };
                peer.started = Instant::now();
                if peer.control {
                    if matches!(frame[0], 1 | 2 | 7) && self.pending.len() + 16 > MAX_PENDING {
                        peer.reply(ipc::control_frame(65, b"input queue full; retry later"))?;
                        peer.closing = true;
                        return Ok(true);
                    }
                    match self.control.request(frame[0], &frame[5..], connected) {
                        Ok((reply, action)) => {
                            peer.reply(reply)?;
                            match action {
                                Action::None => {}
                                Action::Input(bytes) => self.input(&bytes),
                                Action::Resize(bytes) => self
                                    .pending
                                    .push_back(Packet::new(Kind::TerminalInfo as u8, bytes)),
                                Action::Kill => self.stop(),
                            }
                        }
                        Err(e) => peer.reply(ipc::control_frame(65, e.to_string().as_bytes()))?,
                    }
                    peer.closing = true;
                    return Ok(true);
                }
                let mut decoder = Decoder(&frame[4..]);
                let kind = decoder.u32()?;
                if !peer.hello {
                    if kind != mux::HELLO || decoder.u32()? != 4 {
                        return Err(ipc::invalid("unsupported mux version"));
                    }
                    while !decoder.0.is_empty() {
                        decoder.string()?;
                        decoder.string()?;
                    }
                    peer.hello = true;
                    return Ok(true);
                }
                let request = decoder.u32()?;
                let result = self.request(kind, request, &mut decoder, &mut peer, forwarder);
                if let Err(e) = result {
                    peer.reply(mux::failure(request, &e.to_string()))?;
                }
                Ok(true)
            })();
            if result.unwrap_or(false) {
                self.peers.insert(id, peer);
            } else if self.passenger.as_ref().is_some_and(|p| p.peer == Some(id)) {
                // Drain an orphan command's marker before permitting reuse.
                // Otherwise its late status could terminate the next bridge.
                if let Some(passenger) = self.passenger.as_mut().filter(|p| p.marker.is_some()) {
                    passenger.orphaned = true;
                    passenger.read_input = false;
                    passenger.queued.clear();
                } else {
                    self.passenger = None;
                    self.idle = Instant::now();
                }
            }
        }
        Ok(())
    }
    fn request(
        &mut self,
        kind: u32,
        request: u32,
        decoder: &mut Decoder<'_>,
        peer: &mut Peer,
        forwarder: &mut Forwarder,
    ) -> io::Result<()> {
        match kind {
            mux::ALIVE => peer.reply(ipc::mux_frame(&ipc::words(&[
                mux::ALIVE_REPLY,
                request,
                std::process::id(),
            ])))?,
            mux::TERMINATE => {
                peer.reply(ipc::mux_frame(&ipc::words(&[mux::OK, request])))?;
                self.stop();
            }
            mux::STOP => {
                peer.reply(ipc::mux_frame(&ipc::words(&[mux::OK, request])))?;
                self.mux = None;
            }
            mux::OPEN_FWD | mux::CLOSE_FWD => {
                let forward = mux::forward(decoder)?;
                if kind == mux::OPEN_FWD {
                    forwarder
                        .add_local_forward(forward)
                        .map_err(|e| ipc::invalid(&e.to_string()))?;
                } else {
                    forwarder
                        .cancel_local_forward(&forward)
                        .map_err(|e| ipc::invalid(&e.to_string()))?;
                }
                peer.reply(ipc::mux_frame(&ipc::words(&[mux::OK, request])))?;
            }
            mux::NEW_SESSION => {
                if self.pending.len() + 16 > MAX_PENDING {
                    return Err(ipc::invalid("input queue full; retry later"));
                }
                decoder.string()?;
                let tty = decoder.u32()?;
                let x11 = decoder.u32()?;
                let agent = decoder.u32()?;
                let subsystem = decoder.u32()?;
                decoder.u32()?;
                decoder.string()?;
                let command = decoder.text()?;
                while !decoder.0.is_empty() {
                    decoder.string()?;
                }
                if tty == 0 {
                    return Err(ipc::invalid("raw no-PTY mux passengers are unsupported"));
                }
                if x11 != 0 || agent != 0 || subsystem != 0 {
                    return Err(ipc::invalid(
                        "mux X11/agent/subsystem requests are unsupported",
                    ));
                }
                peer.pending_session = Some((request, command));
            }
            _ => return Err(ipc::invalid("unsupported mux request")),
        }
        Ok(())
    }
    fn stop(&mut self) {
        if self.stopping.is_none() {
            self.stopping = Some(Instant::now());
            // CTL_KILL and mux TERMINATE stop the local owner, not the remote
            // saved shell. This is TerminalClient::shutdown(), not --kill.
            self.pending.clear();
            if let Some(passenger) = self.passenger.as_mut() {
                passenger.read_input = false;
            }
        }
    }
    fn pump_passenger(&mut self) -> bool {
        let Some(passenger) = self.passenger.as_mut() else {
            return false;
        };
        let mut input = Vec::new();
        let queued = passenger.queued.len();
        let mut failed = passenger.flush().is_err();
        let output_progress = passenger.queued.len() < queued;
        if self.pending.len() < MAX_PENDING && self.stopping.is_none() {
            if let Ok(size) = rustix::termios::tcgetwinsize(&passenger.input.file) {
                let dimensions = (size.ws_row, size.ws_col);
                if passenger.size != Some(dimensions) {
                    passenger.size = Some(dimensions);
                    self.pending.push_back(Packet::new(
                        Kind::TerminalInfo as u8,
                        et_core::proto::TerminalInfo {
                            row: Some(i32::from(size.ws_row)),
                            column: Some(i32::from(size.ws_col)),
                            width: Some(i32::from(size.ws_xpixel)),
                            height: Some(i32::from(size.ws_ypixel)),
                            ..Default::default()
                        }
                        .encode_to_vec(),
                    ));
                }
            }
        }
        if passenger.read_input && passenger.status.is_none() && self.pending.len() < MAX_PENDING {
            let mut bytes = [0; 16 * 1024];
            match passenger.input.file.read(&mut bytes) {
                Ok(0) => passenger.read_input = false,
                Ok(count) => input.extend_from_slice(&bytes[..count]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => failed = true,
            }
        }
        if failed {
            passenger.fail();
        }
        let done = passenger.status.is_some() && passenger.queued.is_empty();
        if done {
            let passenger = self.passenger.take().unwrap();
            let status = if passenger.failed {
                255
            } else {
                passenger.status.unwrap_or(255)
            };
            if let Some(id) = passenger.peer {
                if let Some(peer) = self.peers.get_mut(&id) {
                    let _ = peer.reply(ipc::mux_frame(&ipc::words(&[mux::EXIT, id, status])));
                    peer.closing = true;
                }
            } else {
                self.primary_finished = true;
                self.primary_status = status as i32;
            }
            self.idle = Instant::now();
        }
        self.input(&input);
        output_progress || done || !input.is_empty()
    }
    fn output_blocked(&self, count: usize) -> bool {
        self.passenger
            .as_ref()
            .is_some_and(|p| !p.orphaned && p.queued.len() + count + 128 > ipc::MAX_REPLY)
    }
    fn output(&mut self, bytes: &[u8]) {
        self.control.output(bytes);
        if let Some(passenger) = self.passenger.as_mut() {
            if passenger.receive(bytes).is_err() {
                passenger.fail();
            }
        }
    }
}

pub fn run<F>(
    mut connection: Connection,
    args: &ClientArgs,
    session_id: &str,
    prepared: Prepared,
    mut forwarder: Forwarder,
    mut reconnect: F,
) -> Result<i32, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let mut runtime = Runtime::new(args, prepared).map_err(error)?;
    struct Raw(bool);
    impl Drop for Raw {
        fn drop(&mut self) {
            if self.0 {
                let _ = crossterm::terminal::disable_raw_mode();
            }
        }
    }
    let _raw = Raw(runtime.passenger.is_some()
        && io::stdin().is_terminal()
        && crossterm::terminal::enable_raw_mode().is_ok());
    crate::local_daemon::ready().map_err(error)?;
    let result = pump(
        &mut connection,
        args,
        &mut forwarder,
        &mut runtime,
        &mut reconnect,
    );
    if let Some(passenger) = runtime.passenger.as_mut() {
        if passenger.status.is_none() {
            passenger.status = Some(
                if passenger.peer.is_none()
                    || (passenger.marker.is_none() && runtime.stopping.is_none())
                {
                    result.as_ref().copied().unwrap_or(255) as u32
                } else {
                    255
                },
            );
        }
    }
    let drain_deadline = Instant::now() + ipc::TIMEOUT;
    while runtime.passenger.is_some() && Instant::now() < drain_deadline {
        runtime.pump_passenger();
        std::thread::sleep(Duration::from_millis(5));
    }
    for peer in runtime.peers.values_mut() {
        let _ = ipc::flush(&mut peer.socket, &mut peer.output);
    }
    if args.ctl {
        let reason = match &result {
            Ok(_) if runtime.stopping.is_some() => "shutdown was requested",
            Ok(_) => "the remote session ended (server no longer has it)",
            Err(_) => "the connection closed",
        };
        if let Some(name) = args.session_name.as_deref() {
            if result.is_ok() && runtime.stopping.is_none() && !args.no_persist {
                if let Err(error) = crate::session_store::remove_if_matches(name, session_id) {
                    eprintln!("et: could not clean up saved session: {error}");
                }
            }
            let _ = local_control::tombstone(name, Some(reason));
        }
    }
    result
}

fn pump<F>(
    connection: &mut Connection,
    args: &ClientArgs,
    forwarder: &mut Forwarder,
    runtime: &mut Runtime,
    reconnect: &mut F,
) -> Result<i32, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct Signals(Vec<signal_hook::SigId>);
    impl Drop for Signals {
        fn drop(&mut self) {
            for id in self.0.drain(..) {
                signal_hook::low_level::unregister(id);
            }
        }
    }
    let mut signals = Signals(Vec::new());
    for signal in [
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGINT,
    ] {
        signals
            .0
            .push(signal_hook::flag::register(signal, stopped.clone()).map_err(error)?);
    }
    let mut pending_forward = None;
    let mut pending_output: Option<Vec<u8>> = None;
    let mut last_received = Instant::now();
    let mut keepalive = Instant::now();
    let mut retry = Instant::now();
    loop {
        if stopped.load(std::sync::atomic::Ordering::Relaxed) && runtime.stopping.is_none() {
            runtime.stop();
            if args.close_on_hangup {
                runtime
                    .pending
                    .push_back(Packet::new(Kind::TerminalClose as u8, Vec::new()));
            }
        }
        runtime
            .local(forwarder, connection.connected(), args.no_remote_command)
            .map_err(error)?;
        let mut progressed = runtime.pump_passenger();
        if let Some(bytes) = pending_output.take() {
            // Local backpressure is not transport silence. Keep servicing IPC,
            // outgoing keepalives and forwarding while the consumer catches up.
            last_received = Instant::now();
            if runtime.output_blocked(bytes.len()) {
                pending_output = Some(bytes);
            } else {
                runtime.output(&bytes);
                progressed = true;
            }
        }
        if let Some(stopped) = runtime.stopping {
            let replies_flushed = runtime.peers.values().all(|p| p.output.is_empty());
            if (runtime.pending.is_empty() && !connection.write_pending() && replies_flushed)
                || stopped.elapsed() > ipc::TIMEOUT
            {
                return Ok(0);
            }
        } else if !args.ctl
            && mux::master(args)
            && runtime.mux.is_none()
            && runtime.passenger.is_none()
        {
            return Ok(runtime.primary_status);
        } else if !args.ctl
            && mux::master(args)
            && runtime.primary_finished
            && runtime.passenger.is_none()
            && !args.no_remote_command
            && !args.background
        {
            let persist = args.control_persist;
            if !persist.is_some_and(|p| p.enabled) {
                return Ok(runtime.primary_status);
            }
            if let Some(persist) = persist.filter(|p| p.seconds > 0) {
                if runtime.idle.elapsed() >= Duration::from_secs(persist.seconds) {
                    return Ok(runtime.primary_status);
                }
            }
        } else if !args.ctl && mux::master(args) && runtime.passenger.is_none() {
            if let Some(persist) = args.control_persist.filter(|p| p.enabled && p.seconds > 0) {
                if runtime.idle.elapsed() >= Duration::from_secs(persist.seconds) {
                    return Ok(runtime.primary_status);
                }
            }
        }
        if !connection.connected() {
            if runtime.stopping.is_none() && Instant::now() >= retry {
                match reconnect(connection) {
                    Ok(ReconnectOutcome::Recovered) => {
                        last_received = Instant::now();
                        keepalive = Instant::now();
                    }
                    Ok(ReconnectOutcome::SessionEnded) => return Ok(0),
                    Err(e) if e.is_transient_reconnect() => {
                        retry = Instant::now() + Duration::from_secs(1)
                    }
                    Err(e) => return Err(e),
                }
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        if let Some(packet) = pending_forward.take() {
            pending_forward = forwarder.try_receive(packet).map_err(error)?;
        }
        for _ in 0..32 {
            if pending_forward.is_some() || pending_output.is_some() {
                break;
            }
            match connection.try_read_packet() {
                Ok(Some(packet)) => {
                    progressed = true;
                    last_received = Instant::now();
                    if is_forward_packet(packet.header()) {
                        pending_forward = forwarder.try_receive(packet).map_err(error)?;
                    } else if packet.header() == Kind::KeepAlive as u8 {
                        if let Some(ack) = et_core::keepalive::decode_ack(packet.payload()) {
                            connection.acknowledge_delivery(ack);
                        }
                    } else if packet.header() == Kind::TerminalBuffer as u8 {
                        let bytes = TerminalBuffer::decode(packet.payload()).map_err(error)?;
                        let bytes = bytes.buffer.unwrap_or_default();
                        if bytes.len() + 128 > ipc::MAX_REPLY {
                            return Err(error("terminal output packet exceeds local queue limit"));
                        }
                        if runtime.output_blocked(bytes.len()) {
                            pending_output = Some(bytes);
                        } else {
                            runtime.output(&bytes);
                        }
                    } else if packet.header() == Kind::TerminalExitStatus as u8 {
                        let code = TerminalExitStatus::decode(packet.payload())
                            .map_err(error)?
                            .exitcode
                            .unwrap_or(0);
                        return Ok(code);
                    }
                }
                Ok(None) => break,
                Err(et_net::connection::ConnError::Io(_)) => break,
                Err(e) => return Err(error(e)),
            }
        }
        if !connection.connected() {
            continue;
        }
        if let Err(e) = connection.advance_write() {
            let e = e.into_inner();
            if !crate::client_terminal::connection_ended(&e) {
                return Err(error(e));
            }
            continue;
        }
        if !connection.write_pending() {
            if keepalive.elapsed() >= Duration::from_secs(args.keepalive.into())
                && runtime.stopping.is_none()
            {
                runtime.pending.push_front(Packet::new(
                    Kind::KeepAlive as u8,
                    connection.keepalive_ack().to_vec(),
                ));
                keepalive = Instant::now();
            }
            if runtime.pending.len() < MAX_PENDING && runtime.stopping.is_none() {
                if let Some(packet) = forwarder.try_outbound().map_err(error)? {
                    runtime.pending.push_back(packet);
                }
            }
            if let Some(packet) = runtime.pending.pop_front() {
                match connection.start_write_packet_owned(packet.header(), packet.payload()) {
                    Ok(()) => {}
                    Err(WritePacketError::ReplayOwned(e))
                        if crate::client_terminal::connection_ended(&e) => {}
                    Err(WritePacketError::BeforeReplay(e))
                        if crate::client_terminal::connection_ended(&e) =>
                    {
                        runtime.pending.push_front(packet);
                        connection.disconnect();
                    }
                    Err(e) => return Err(error(e.into_inner())),
                }
            }
        }
        if last_received.elapsed() > Duration::from_secs(u64::from(args.keepalive) * 3) {
            connection.disconnect();
        }
        // All batches above are bounded and service IPC on every turn. A
        // fixed sleep after progress throttles short PTY packets and partial
        // pipe writes; sleep only when input/output could not advance.
        if !progressed {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
#[path = "local_session_tests.rs"]
mod tests;
