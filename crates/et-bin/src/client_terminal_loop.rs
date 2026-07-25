use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use et_core::proto::TerminalPacketType;
use et_net::connection::{ConnError, Connection};
use rustix::event::{poll, PollFd, PollFlags};
use rustix::time::Timespec;

use crate::client_terminal::{
    display_packet, send_buffer, send_size, terminal_error, terminal_io, terminal_text,
};
use crate::error::ClientError;
use crate::initial_connect::ReconnectOutcome;

const INPUT_CHUNK: usize = 16 * 1024;
const MISSED_KEEPALIVES: u32 = 3;

pub fn pump<F>(
    connection: &mut Connection,
    wake: &mut UnixStream,
    read_stdin: bool,
    keepalive_seconds: u32,
    mut reconnect: F,
) -> Result<(), ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    let stdin = io::stdin();
    let interval = Duration::from_secs(u64::from(keepalive_seconds.max(1)));
    let silence = interval.saturating_mul(MISSED_KEEPALIVES);
    let mut last_received = Instant::now();
    let mut next_keepalive = last_received + interval;
    let mut stream = connection.try_clone_stream().map_err(terminal_error)?;
    loop {
        let deadline = next_keepalive.min(last_received + silence);
        let timeout = Timespec::try_from(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| terminal_text("keepalive deadline exceeds poll range"))?;
        let (network, resize, input) = {
            let mut descriptors = vec![
                PollFd::new(&stream, PollFlags::IN | PollFlags::HUP | PollFlags::ERR),
                PollFd::new(&*wake, PollFlags::IN | PollFlags::HUP),
            ];
            if read_stdin {
                descriptors.push(PollFd::new(
                    &stdin,
                    PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
                ));
            }
            poll(&mut descriptors, Some(&timeout))
                .map_err(|error| terminal_io("polling terminal streams", io::Error::from(error)))?;
            (
                descriptors[0].revents(),
                descriptors[1].revents(),
                descriptors
                    .get(2)
                    .map(PollFd::revents)
                    .unwrap_or(PollFlags::empty()),
            )
        };
        let mut reconnect_needed = network.intersects(PollFlags::HUP | PollFlags::ERR);
        if resize.intersects(PollFlags::IN | PollFlags::HUP) {
            drain(wake)?;
            match send_size(connection) {
                Ok(()) => {}
                Err(ClientError::Transport(error)) if connection_ended(&error) => {
                    reconnect_needed = true;
                }
                Err(error) => return Err(error),
            }
        }
        if network.contains(PollFlags::IN) {
            loop {
                match connection.try_read_packet() {
                    Ok(Some(packet)) => {
                        last_received = Instant::now();
                        display_packet(packet)?;
                    }
                    Ok(None) => break,
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
            if !recover(connection, &mut reconnect, &mut stream)? {
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
                    if !recover(connection, &mut reconnect, &mut stream)? {
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
            if connection
                .write_packet(TerminalPacketType::KeepAlive as u8, &[])
                .is_err()
                && !recover(connection, &mut reconnect, &mut stream)?
            {
                return Ok(());
            }
            next_keepalive = Instant::now() + interval;
        }
    }
}

fn recover<F>(
    connection: &mut Connection,
    reconnect: &mut F,
    stream: &mut std::net::TcpStream,
) -> Result<bool, ClientError>
where
    F: FnMut(&mut Connection) -> Result<ReconnectOutcome, ClientError>,
{
    match reconnect(connection)? {
        ReconnectOutcome::Recovered => {
            *stream = connection.try_clone_stream().map_err(terminal_error)?;
            send_size(connection)?;
            Ok(true)
        }
        ReconnectOutcome::SessionEnded => Ok(false),
    }
}

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

pub(crate) fn connection_ended(error: &ConnError) -> bool {
    matches!(
        error,
        ConnError::Io(source)
            if matches!(
                source.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
            )
    )
}
