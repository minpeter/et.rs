use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use et_core::packet::Packet;
use et_core::proto::{TerminalPacketType, TerminalUserInfo};
use et_net::local_packet::LocalPacketDecoder;
use prost::Message;
use rustix::event::{poll, PollFd, PollFlags};

use crate::registry::{RegistrationError, Registry};
use crate::router::{RouterError, RouterEvent, RouterReject};
use crate::socket_path::OwnedRouterListener;

struct PendingConnection {
    stream: UnixStream,
    decoder: LocalPacketDecoder,
}

enum ReadOutcome {
    Pending,
    Packet(Packet),
    Reject,
}

pub(crate) fn run(
    listener: OwnedRouterListener,
    mut wake_reader: UnixStream,
    registry: Registry,
    events: Sender<RouterEvent>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), RouterError> {
    let mut pending = Vec::<PendingConnection>::new();
    loop {
        let mut poll_fds = Vec::with_capacity(pending.len() + 2);
        poll_fds.push(PollFd::new(listener.listener(), PollFlags::IN));
        poll_fds.push(PollFd::new(&wake_reader, PollFlags::IN));
        for connection in &pending {
            poll_fds.push(PollFd::new(
                &connection.stream,
                PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
            ));
        }
        match poll(&mut poll_fds, None) {
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(RouterError::Io(io::Error::from(error))),
        }
        let readiness: Vec<PollFlags> = poll_fds.iter().map(PollFd::revents).collect();
        drop(poll_fds);

        if readiness
            .get(1)
            .is_some_and(|flags| flags.intersects(PollFlags::IN | PollFlags::HUP))
        {
            drain_waker(&mut wake_reader)?;
            if shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
        }
        if readiness
            .first()
            .is_some_and(|flags| flags.contains(PollFlags::IN))
        {
            accept_ready(&listener, &mut pending)?;
        }
        let mut ready_indices: Vec<usize> = readiness
            .iter()
            .skip(2)
            .enumerate()
            .filter_map(|(index, flags)| {
                flags
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
                    .then_some(index)
            })
            .collect();
        ready_indices.reverse();
        for index in ready_indices {
            if index >= pending.len() {
                continue;
            }
            match read_ready(&mut pending[index])? {
                ReadOutcome::Pending => {}
                ReadOutcome::Packet(packet) => {
                    let connection = pending.swap_remove(index);
                    process_registration(packet, connection.stream, &registry, &events);
                }
                ReadOutcome::Reject => {
                    pending.swap_remove(index);
                    let _ = events.send(RouterEvent::Rejected(RouterReject::MalformedFrame));
                }
            }
        }
    }
}

fn accept_ready(
    listener: &OwnedRouterListener,
    pending: &mut Vec<PendingConnection>,
) -> Result<(), RouterError> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(true).map_err(RouterError::Io)?;
                pending.push(PendingConnection {
                    stream,
                    decoder: LocalPacketDecoder::new(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(RouterError::Io(error)),
        }
    }
}

fn read_ready(connection: &mut PendingConnection) -> Result<ReadOutcome, RouterError> {
    loop {
        let needed = connection.decoder.required_bytes().min(8192);
        if needed == 0 {
            return Ok(ReadOutcome::Reject);
        }
        let mut buffer = [0u8; 8192];
        match connection.stream.read(&mut buffer[..needed]) {
            Ok(0) => {
                let decoder = std::mem::take(&mut connection.decoder);
                return Ok(match decoder.finish() {
                    Ok(()) => ReadOutcome::Pending,
                    Err(_) => ReadOutcome::Reject,
                });
            }
            Ok(count) => match connection.decoder.feed(&buffer[..count]) {
                Ok(Some(packet)) => return Ok(ReadOutcome::Packet(packet)),
                Ok(None) => {}
                Err(_) => return Ok(ReadOutcome::Reject),
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(ReadOutcome::Pending);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(ReadOutcome::Reject),
        }
    }
}

fn process_registration(
    packet: Packet,
    stream: UnixStream,
    registry: &Registry,
    events: &Sender<RouterEvent>,
) {
    let result = if packet.is_encrypted() {
        Err(RouterReject::Encrypted)
    } else if packet.header() != TerminalPacketType::TerminalUserInfo as u8 {
        Err(RouterReject::WrongPacketType)
    } else {
        TerminalUserInfo::decode(packet.payload())
            .map_err(|_| RouterReject::MalformedUserInfo)
            .and_then(|info| {
                registry
                    .register(info, stream)
                    .map_err(|error| match error {
                        RegistrationError::Invalid => RouterReject::InvalidRegistration,
                        RegistrationError::Duplicate => RouterReject::Duplicate,
                        RegistrationError::Unavailable | RegistrationError::Timeout => {
                            RouterReject::RegistryUnavailable
                        }
                    })
            })
    };
    let event = match result {
        Ok(id) => RouterEvent::Registered { id },
        Err(error) => RouterEvent::Rejected(error),
    };
    let _ = events.send(event);
}

fn drain_waker(wake_reader: &mut UnixStream) -> Result<(), RouterError> {
    let mut buffer = [0u8; 64];
    loop {
        match wake_reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(RouterError::Io(error)),
        }
    }
}
