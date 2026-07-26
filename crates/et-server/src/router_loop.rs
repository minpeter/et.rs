use et_net::local::LocalStream;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use et_core::packet::Packet;
use et_net::local_packet::LocalPacketDecoder;
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};
#[cfg(unix)]
use rustix::net::{recv, RecvFlags};

use crate::registry::{RegistrationIdentity, Registry};
use crate::router::{RouterError, RouterEvent, RouterReject};
use crate::router_registration;
use crate::runtime_lifecycle::LifecycleEvent;
#[cfg(unix)]
use crate::socket_path::OwnedRouterListener;
#[cfg(windows)]
use crate::socket_path_windows::OwnedRouterListener;

struct PendingConnection {
    stream: LocalStream,
    decoder: LocalPacketDecoder,
}

struct WatchedRegistration {
    stream: LocalStream,
    identity: RegistrationIdentity,
}

enum ReadOutcome {
    Pending,
    Packet(Packet),
    Reject,
}

pub(crate) fn run(
    listener: OwnedRouterListener,
    wake_reader: LocalStream,
    registry: Registry,
    events: Sender<RouterEvent>,
    lifecycle: Option<Sender<LifecycleEvent>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), RouterError> {
    #[cfg(unix)]
    return run_poll(listener, wake_reader, registry, events, lifecycle, shutdown);
    #[cfg(windows)]
    return run_windows(listener, wake_reader, registry, events, lifecycle, shutdown);
}

#[cfg(unix)]
fn run_poll(
    listener: OwnedRouterListener,
    mut wake_reader: LocalStream,
    registry: Registry,
    events: Sender<RouterEvent>,
    lifecycle: Option<Sender<LifecycleEvent>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), RouterError> {
    let mut pending = Vec::<PendingConnection>::new();
    let mut watched = Vec::<WatchedRegistration>::new();
    let idle = rustix::time::Timespec::try_from(std::time::Duration::from_millis(100))
        .expect("100ms fits in timespec");
    loop {
        let pending_start = 2;
        let watched_start = pending_start + pending.len();
        let mut poll_fds = Vec::with_capacity(watched_start + watched.len());
        poll_fds.push(PollFd::new(listener.listener(), PollFlags::IN));
        poll_fds.push(PollFd::new(&wake_reader, PollFlags::IN));
        for connection in &pending {
            poll_fds.push(PollFd::new(
                &connection.stream,
                PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
            ));
        }
        for registration in &watched {
            poll_fds.push(PollFd::new(
                &registration.stream,
                PollFlags::HUP | PollFlags::ERR,
            ));
        }
        match poll(&mut poll_fds, Some(&idle)) {
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
        let mut watched_readiness = readiness[watched_start..].to_vec();
        for (flags, registration) in watched_readiness.iter_mut().zip(&watched) {
            let mut probe = [0u8; 1];
            match recv(
                &registration.stream,
                &mut probe,
                RecvFlags::PEEK | RecvFlags::DONTWAIT,
            ) {
                Ok((_, 0)) => *flags |= PollFlags::HUP,
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::AGAIN => {}
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(_) => *flags |= PollFlags::ERR,
            }
        }
        disconnect_ready(
            &watched_readiness,
            &mut watched,
            &registry,
            &events,
            lifecycle.as_ref(),
        )?;
        if readiness
            .first()
            .is_some_and(|flags| flags.contains(PollFlags::IN))
        {
            accept_ready(&listener, &mut pending)?;
        }
        let ready_pending: Vec<usize> = readiness[pending_start..watched_start]
            .iter()
            .enumerate()
            .filter_map(|(index, flags)| {
                flags
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
                    .then_some(index)
            })
            .rev()
            .collect();
        for index in ready_pending {
            match read_ready(&mut pending[index])? {
                ReadOutcome::Pending => {}
                ReadOutcome::Packet(packet) => {
                    let connection = pending.swap_remove(index);
                    match router_registration::process(packet, connection.stream, &registry) {
                        Ok(terminal) => {
                            let id = terminal.identity.id().to_owned();
                            terminal
                                .watcher
                                .set_nonblocking(true)
                                .map_err(RouterError::Io)?;
                            watched.push(WatchedRegistration {
                                stream: terminal.watcher,
                                identity: terminal.identity,
                            });
                            let _ = events.send(RouterEvent::Registered { id });
                        }
                        Err(error) => {
                            let _ = events.send(RouterEvent::Rejected(error));
                        }
                    }
                }
                ReadOutcome::Reject => {
                    pending.swap_remove(index);
                    let _ = events.send(RouterEvent::Rejected(RouterReject::MalformedFrame));
                }
            }
        }
    }
}

/// Windows router loop.
///
/// The listener, the pending registrations, and the registered watchers cannot
/// be polled together, so each is serviced without blocking on upstream's 10ms
/// `select()` cadence. Registration handling, rejection reasons, and disconnect
/// bookkeeping are identical to the readiness-driven loop.
#[cfg(windows)]
fn run_windows(
    listener: OwnedRouterListener,
    mut wake_reader: LocalStream,
    registry: Registry,
    events: Sender<RouterEvent>,
    lifecycle: Option<Sender<LifecycleEvent>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), RouterError> {
    const IDLE: std::time::Duration = std::time::Duration::from_millis(10);
    let mut pending = Vec::<PendingConnection>::new();
    let mut watched = Vec::<WatchedRegistration>::new();
    loop {
        if shutdown.load(Ordering::Acquire) {
            drain_waker(&mut wake_reader)?;
            return Ok(());
        }
        let mut progress = false;

        // Terminals that closed their connection release their registration.
        // The watcher shares the session socket, so this must never consume
        // bytes: `peek` reports EOF without stealing session data.
        let mut disconnected = Vec::new();
        for (index, registration) in watched.iter().enumerate() {
            let mut probe = [0u8; 1];
            match registration.stream.peek(&mut probe) {
                Ok(0) => disconnected.push(index),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => disconnected.push(index),
            }
        }
        for index in disconnected.into_iter().rev() {
            progress = true;
            let registration = watched.swap_remove(index);
            if registry
                .remove_if_current(&registration.identity)
                .map_err(|error| RouterError::Io(io::Error::other(error)))?
            {
                let id = registration.identity.id().to_owned();
                let _ = events.send(RouterEvent::Disconnected { id });
                if let Some(sender) = lifecycle.as_ref() {
                    let _ =
                        sender.send(LifecycleEvent::TerminalDisconnected(registration.identity));
                }
            }
        }

        let before = pending.len();
        accept_ready(&listener, &mut pending)?;
        if pending.len() != before {
            progress = true;
        }

        for index in (0..pending.len()).rev() {
            match read_ready(&mut pending[index])? {
                ReadOutcome::Pending => {}
                ReadOutcome::Packet(packet) => {
                    progress = true;
                    let connection = pending.swap_remove(index);
                    match router_registration::process(packet, connection.stream, &registry) {
                        Ok(terminal) => {
                            let id = terminal.identity.id().to_owned();
                            watched.push(WatchedRegistration {
                                stream: terminal.watcher,
                                identity: terminal.identity,
                            });
                            let _ = events.send(RouterEvent::Registered { id });
                        }
                        Err(error) => {
                            let _ = events.send(RouterEvent::Rejected(error));
                        }
                    }
                }
                ReadOutcome::Reject => {
                    progress = true;
                    pending.swap_remove(index);
                    let _ = events.send(RouterEvent::Rejected(RouterReject::MalformedFrame));
                }
            }
        }

        if !progress {
            std::thread::sleep(IDLE);
        }
    }
}

#[cfg(unix)]
fn disconnect_ready(
    readiness: &[PollFlags],
    watched: &mut Vec<WatchedRegistration>,
    registry: &Registry,
    events: &Sender<RouterEvent>,
    lifecycle: Option<&Sender<LifecycleEvent>>,
) -> Result<(), RouterError> {
    let ready: Vec<usize> = readiness
        .iter()
        .enumerate()
        .filter_map(|(index, flags)| {
            flags
                .intersects(PollFlags::HUP | PollFlags::ERR)
                .then_some(index)
        })
        .rev()
        .collect();
    for index in ready {
        let registration = watched.swap_remove(index);
        if registry
            .remove_if_current(&registration.identity)
            .map_err(|error| RouterError::Io(io::Error::other(error)))?
        {
            let id = registration.identity.id().to_owned();
            let _ = events.send(RouterEvent::Disconnected { id });
            if let Some(sender) = lifecycle {
                let _ = sender.send(LifecycleEvent::TerminalDisconnected(registration.identity));
            }
        }
    }
    Ok(())
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

fn drain_waker(wake_reader: &mut LocalStream) -> Result<(), RouterError> {
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
