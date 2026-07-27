#[cfg(unix)]
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use et_core::proto::TerminalPacketType;
#[cfg(unix)]
use et_net::connection::Connection;
#[cfg(unix)]
use et_net::forward::{is_forward_packet, Forwarder};
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};
#[cfg(unix)]
use rustix::time::Timespec;

#[cfg(unix)]
use crate::client_terminal::{
    connection_ended, display_packet, recover_transport, send_buffer, send_size, terminal_error,
    terminal_io, terminal_text,
};
#[cfg(unix)]
use crate::error::ClientError;
#[cfg(unix)]
use crate::initial_connect::ReconnectOutcome;

#[cfg(unix)]
const INPUT_CHUNK: usize = 16 * 1024;
#[cfg(unix)]
const MISSED_KEEPALIVES: u32 = 3;

/// Loop configuration resolved by [`crate::client_terminal::run`].
pub(crate) struct PumpOptions {
    pub(crate) read_stdin: bool,
    pub(crate) keepalive_seconds: u32,
    pub(crate) terminal_enabled: bool,
    pub(crate) auto_cursor_report: bool,
}

#[cfg(unix)]
pub fn pump<F>(
    connection: &mut Connection,
    wake: &mut UnixStream,
    options: PumpOptions,
    forwarder: &Forwarder,
    mut reconnect: F,
) -> Result<(), ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let PumpOptions {
        read_stdin,
        keepalive_seconds,
        terminal_enabled,
        auto_cursor_report,
    } = options;
    let stdin = io::stdin();
    let interval = Duration::from_secs(u64::from(keepalive_seconds.max(1)));
    let silence = interval.saturating_mul(MISSED_KEEPALIVES);
    let mut last_received = Instant::now();
    let mut next_keepalive = last_received + interval;
    let mut stream = connection.try_clone_stream().map_err(terminal_error)?;
    // A forwarding packet the worker had no room for. While it is held, no
    // further session packets are read (ordering) and the network fd is not
    // watched for readability (a readable socket would busy-loop the poll).
    let mut pending_forward: Option<et_core::packet::Packet> = None;
    let forward_wake = forwarder
        .wake()
        .map_err(|error| terminal_text(error.to_string()))?;
    // Test harness only: signal after the encrypted session and local forwarder
    // are live so -N tunnel probes do not race bootstrap.
    if let Ok(path) = std::env::var("ET_SSH_READY") {
        let _ = std::fs::write(path, b"ready");
    }
    loop {
        // Retry a held forwarding packet first: draining the forwarder's
        // outbound queue below is what frees worker capacity, so this makes
        // progress every iteration instead of deadlocking on a blocking send.
        if let Some(packet) = pending_forward.take() {
            pending_forward = forwarder
                .try_receive(packet)
                .map_err(|error| terminal_text(error.to_string()))?;
        }
        let network_flags = if pending_forward.is_none() {
            PollFlags::IN | PollFlags::HUP | PollFlags::ERR
        } else {
            PollFlags::HUP | PollFlags::ERR
        };
        let deadline = next_keepalive.min(last_received + silence);
        let (network, resize, forwarding, input) = {
            let mut descriptors = vec![
                PollFd::new(&stream, network_flags),
                PollFd::new(&*wake, PollFlags::IN | PollFlags::HUP),
                PollFd::new(forward_wake, PollFlags::IN | PollFlags::HUP),
            ];
            if read_stdin {
                descriptors.push(PollFd::new(
                    &stdin,
                    PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
                ));
            }
            // poll() is never auto-restarted by SA_RESTART, so any signal
            // delivered to this thread (e.g. SIGWINCH from a window resize,
            // SIGCONT after job control) interrupts it with EINTR. The 100ms
            // cap also lets the nonblocking read below detect closed sockets
            // when Darwin omits the expected readiness bit.
            loop {
                // Cap at 10ms while a forwarding packet is held so the retry
                // above runs even when nothing else becomes ready.
                let poll_cap = if pending_forward.is_some() {
                    Duration::from_millis(10)
                } else {
                    Duration::from_millis(100)
                };
                let poll_deadline = deadline.min(Instant::now() + poll_cap);
                let timeout =
                    Timespec::try_from(poll_deadline.saturating_duration_since(Instant::now()))
                        .map_err(|_| terminal_text("keepalive deadline exceeds poll range"))?;
                match poll(&mut descriptors, Some(&timeout)) {
                    Ok(_) => break,
                    Err(error) if error == rustix::io::Errno::INTR => {}
                    Err(error) => {
                        return Err(terminal_io(
                            "polling terminal streams",
                            io::Error::from(error),
                        ));
                    }
                }
            }
            (
                descriptors[0].revents(),
                descriptors[1].revents(),
                descriptors[2].revents(),
                descriptors
                    .get(3)
                    .map(PollFd::revents)
                    .unwrap_or(PollFlags::empty()),
            )
        };
        let mut reconnect_needed = network.intersects(PollFlags::HUP | PollFlags::ERR);
        if resize.intersects(PollFlags::IN | PollFlags::HUP) {
            drain(wake)?;
            match if terminal_enabled {
                send_size(connection)
            } else {
                Ok(())
            } {
                Ok(()) => {}
                Err(ClientError::Transport(error)) if connection_ended(&error) => {
                    reconnect_needed = true;
                }
                Err(error) => return Err(error),
            }
        }
        while pending_forward.is_none() {
            match connection.try_read_packet() {
                Ok(Some(packet)) => {
                    last_received = Instant::now();
                    if packet.header() == TerminalPacketType::KeepAlive as u8 {
                        if let Some(ack) = et_core::keepalive::decode_ack(packet.payload()) {
                            connection.acknowledge_delivery(ack);
                        }
                    }
                    if is_forward_packet(packet.header()) {
                        pending_forward = forwarder
                            .try_receive(packet)
                            .map_err(|error| terminal_text(error.to_string()))?;
                    } else if route_server_packet(packet, terminal_enabled)? && auto_cursor_report {
                        let _ =
                            send_buffer(connection, crate::client_terminal::CURSOR_REPORT_REPLY);
                    }
                }
                Ok(None) => break,
                Err(error) if connection_ended(&error) => {
                    reconnect_needed = true;
                    break;
                }
                Err(error) => return Err(terminal_error(error)),
            }
        }
        if forwarding.intersects(PollFlags::IN | PollFlags::HUP) {
            while let Some(packet) = forwarder
                .try_outbound()
                .map_err(|error| terminal_text(error.to_string()))?
            {
                match connection.write_packet(packet.header(), packet.payload()) {
                    Ok(()) => {}
                    Err(error) if connection_ended(&error) => {
                        reconnect_needed = true;
                        break;
                    }
                    Err(error) => return Err(terminal_error(error)),
                }
            }
        }
        let now = Instant::now();
        if now.saturating_duration_since(last_received) >= silence {
            reconnect_needed = true;
        }
        if reconnect_needed {
            if !recover(connection, &mut reconnect, &mut stream, terminal_enabled)? {
                return Ok(());
            }
            last_received = Instant::now();
            next_keepalive = last_received + interval;
            continue;
        }
        if input.contains(PollFlags::IN) {
            let mut bytes = [0u8; INPUT_CHUNK];
            let count = stdin
                .lock()
                .read(&mut bytes)
                .map_err(|error| terminal_io("reading terminal input", error))?;
            if count == 0 {
                return Ok(());
            }
            match send_buffer(connection, &bytes[..count]) {
                Ok(()) => {}
                Err(error) if connection_ended(&error) => {
                    if !recover(connection, &mut reconnect, &mut stream, terminal_enabled)? {
                        return Ok(());
                    }
                    last_received = Instant::now();
                    next_keepalive = last_received + interval;
                }
                Err(error) => return Err(terminal_error(error)),
            }
        }
        if input.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Ok(());
        }
        let now = Instant::now();
        if now >= next_keepalive {
            // The payload acknowledges everything read so far, so the server
            // can trim its replay backup; legacy servers ignore it.
            let ack = connection.keepalive_ack();
            if connection
                .write_packet(TerminalPacketType::KeepAlive as u8, &ack)
                .is_err()
                && !recover(connection, &mut reconnect, &mut stream, terminal_enabled)?
            {
                return Ok(());
            }
            next_keepalive = Instant::now() + interval;
        }
    }
}

/// Returns `true` when a cursor position report must be sent back.
#[cfg(unix)]
fn route_server_packet(
    packet: et_core::packet::Packet,
    terminal_enabled: bool,
) -> Result<bool, ClientError> {
    if terminal_enabled || packet.header() == TerminalPacketType::KeepAlive as u8 {
        return display_packet(packet);
    }
    if packet.header() == TerminalPacketType::TerminalBuffer as u8 {
        return Ok(false);
    }
    Err(terminal_text(
        "server sent an unsupported no-terminal packet",
    ))
}

#[cfg(unix)]
fn recover<F>(
    connection: &mut Connection,
    reconnect: &mut F,
    stream: &mut std::net::TcpStream,
    send_terminal_size: bool,
) -> Result<bool, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    if !recover_transport(connection, reconnect, send_terminal_size)? {
        return Ok(false);
    }
    *stream = connection.try_clone_stream().map_err(terminal_error)?;
    Ok(true)
}

#[cfg(unix)]
fn drain(wake: &mut UnixStream) -> Result<(), ClientError> {
    let mut buffer = [0u8; 64];
    loop {
        match wake.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(terminal_io("draining resize wakeup", error)),
        }
    }
}
