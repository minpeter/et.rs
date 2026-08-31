use et_net::local::LocalStream;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_net::local_packet::{
    parse_status, status_packet, write_local_packet, LocalPacketDecoder, REGISTRATION_STATUS,
    STARTUP_STATUS,
};
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};
#[cfg(unix)]
use rustix::net::{recv, RecvFlags};

use crate::registry::{RegistrationIdentity, Registry};
use crate::registry_validation::PeerIdentity;
use crate::router::{
    RouterError, RouterEvent, RouterReject, MAX_PENDING_REGISTRATIONS, REGISTRATION_TIMEOUT,
};
use crate::router_registration;
use crate::runtime_lifecycle::LifecycleEvent;
#[cfg(unix)]
use crate::socket_path::OwnedRouterListener;
#[cfg(windows)]
use crate::socket_path_windows::OwnedRouterListener;

struct PendingConnection {
    stream: LocalStream,
    decoder: LocalPacketDecoder,
    accepted: Instant,
    peer: PeerIdentity,
    #[cfg(windows)]
    token: Vec<u8>,
    #[cfg(windows)]
    expected_token: String,
}

struct WatchedRegistration {
    stream: LocalStream,
    identity: RegistrationIdentity,
    startup: Option<LocalPacketDecoder>,
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
    events: SyncSender<RouterEvent>,
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
    events: SyncSender<RouterEvent>,
    lifecycle: Option<Sender<LifecycleEvent>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), RouterError> {
    let mut pending = Vec::<PendingConnection>::new();
    let mut watched = Vec::<WatchedRegistration>::new();
    let idle = rustix::time::Timespec::try_from(std::time::Duration::from_millis(100))
        .expect("100ms fits in timespec");
    loop {
        // Expire before constructing poll descriptors so readiness indices and
        // the pending vector always describe the same generation.
        expire_pending(&mut pending, &events);
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
            let mut flags = PollFlags::HUP | PollFlags::ERR;
            if registration.startup.is_some() {
                flags |= PollFlags::IN;
            }
            poll_fds.push(PollFd::new(&registration.stream, flags));
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
        service_watched(
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
            accept_ready(&listener, &mut pending, &events)?;
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
                    let mut status = connection.stream.try_clone().map_err(RouterError::Io)?;
                    match router_registration::process(
                        packet,
                        connection.stream,
                        &registry,
                        connection.peer,
                    ) {
                        Ok(terminal) => {
                            if terminal.startup_ack
                                && write_local_packet(
                                    &mut status,
                                    &status_packet(REGISTRATION_STATUS, Ok(())),
                                )
                                .is_err()
                            {
                                rollback_registration(&registry, &terminal.identity, &events)?;
                                continue;
                            }
                            let id = terminal.identity.id().to_owned();
                            terminal
                                .watcher
                                .set_nonblocking(true)
                                .map_err(RouterError::Io)?;
                            watched.push(WatchedRegistration {
                                stream: terminal.watcher,
                                identity: terminal.identity,
                                startup: terminal.startup_ack.then(LocalPacketDecoder::new),
                            });
                            emit(&events, RouterEvent::Registered { id });
                        }
                        Err(error) => {
                            let message = format!("registration rejected: {error:?}");
                            let _ = write_local_packet(
                                &mut status,
                                &status_packet(REGISTRATION_STATUS, Err(&message)),
                            );
                            emit(&events, RouterEvent::Rejected(error));
                        }
                    }
                }
                ReadOutcome::Reject => {
                    pending.swap_remove(index);
                    emit(&events, RouterEvent::Rejected(RouterReject::MalformedFrame));
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
    events: SyncSender<RouterEvent>,
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
        for index in (0..watched.len()).rev() {
            if watched[index].startup.is_some() {
                let outcome = {
                    let registration = &mut watched[index];
                    read_decoder(
                        &mut registration.stream,
                        registration.startup.as_mut().expect("startup checked"),
                    )?
                };
                match outcome {
                    ReadOutcome::Packet(packet) => {
                        progress = true;
                        let result = parse_status(&packet, STARTUP_STATUS)
                            .map_err(|error| error.to_string());
                        registry
                            .report_startup(&watched[index].identity, result)
                            .map_err(|error| RouterError::Io(io::Error::other(error)))?;
                        watched[index].startup = None;
                    }
                    ReadOutcome::Reject => {
                        progress = true;
                        let _ = registry.report_startup(
                            &watched[index].identity,
                            Err("malformed terminal startup status".to_owned()),
                        );
                        watched[index].startup = None;
                    }
                    ReadOutcome::Pending => {}
                }
            }
            let mut probe = [0u8; 1];
            let disconnected = match watched[index].stream.peek(&mut probe) {
                Ok(0) => true,
                Ok(_) => false,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => false,
                Err(_) => true,
            };
            if disconnected {
                progress = true;
                disconnect_watched(index, &mut watched, &registry, &events, lifecycle.as_ref())?;
            }
        }

        expire_pending(&mut pending, &events);
        let before = pending.len();
        accept_ready(&listener, &mut pending, &events)?;
        if pending.len() != before {
            progress = true;
        }

        for index in (0..pending.len()).rev() {
            match read_ready(&mut pending[index])? {
                ReadOutcome::Pending => {}
                ReadOutcome::Packet(packet) => {
                    progress = true;
                    let connection = pending.swap_remove(index);
                    let mut status = connection.stream.try_clone().map_err(RouterError::Io)?;
                    match router_registration::process(
                        packet,
                        connection.stream,
                        &registry,
                        connection.peer,
                    ) {
                        Ok(terminal) => {
                            if terminal.startup_ack
                                && write_local_packet(
                                    &mut status,
                                    &status_packet(REGISTRATION_STATUS, Ok(())),
                                )
                                .is_err()
                            {
                                rollback_registration(&registry, &terminal.identity, &events)?;
                                continue;
                            }
                            let id = terminal.identity.id().to_owned();
                            watched.push(WatchedRegistration {
                                stream: terminal.watcher,
                                identity: terminal.identity,
                                startup: terminal.startup_ack.then(LocalPacketDecoder::new),
                            });
                            emit(&events, RouterEvent::Registered { id });
                        }
                        Err(error) => {
                            let message = format!("registration rejected: {error:?}");
                            let _ = write_local_packet(
                                &mut status,
                                &status_packet(REGISTRATION_STATUS, Err(&message)),
                            );
                            emit(&events, RouterEvent::Rejected(error));
                        }
                    }
                }
                ReadOutcome::Reject => {
                    progress = true;
                    pending.swap_remove(index);
                    emit(&events, RouterEvent::Rejected(RouterReject::MalformedFrame));
                }
            }
        }

        if !progress {
            std::thread::sleep(IDLE);
        }
    }
}

#[cfg(unix)]
fn service_watched(
    readiness: &[PollFlags],
    watched: &mut Vec<WatchedRegistration>,
    registry: &Registry,
    events: &SyncSender<RouterEvent>,
    lifecycle: Option<&Sender<LifecycleEvent>>,
) -> Result<(), RouterError> {
    for index in (0..watched.len()).rev() {
        let flags = readiness.get(index).copied().unwrap_or(PollFlags::empty());
        if flags.contains(PollFlags::IN) && watched[index].startup.is_some() {
            match read_startup(&mut watched[index])? {
                ReadOutcome::Packet(packet) => {
                    let result =
                        parse_status(&packet, STARTUP_STATUS).map_err(|error| error.to_string());
                    registry
                        .report_startup(&watched[index].identity, result)
                        .map_err(|error| RouterError::Io(io::Error::other(error)))?;
                    watched[index].startup = None;
                }
                ReadOutcome::Reject => {
                    let _ = registry.report_startup(
                        &watched[index].identity,
                        Err("malformed terminal startup status".to_owned()),
                    );
                    watched[index].startup = None;
                }
                ReadOutcome::Pending => {}
            }
        }
        if flags.intersects(PollFlags::HUP | PollFlags::ERR) {
            disconnect_watched(index, watched, registry, events, lifecycle)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_startup(registration: &mut WatchedRegistration) -> Result<ReadOutcome, RouterError> {
    let decoder = registration
        .startup
        .as_mut()
        .expect("startup decoder checked by caller");
    read_decoder(&mut registration.stream, decoder)
}

fn disconnect_watched(
    index: usize,
    watched: &mut Vec<WatchedRegistration>,
    registry: &Registry,
    events: &SyncSender<RouterEvent>,
    lifecycle: Option<&Sender<LifecycleEvent>>,
) -> Result<(), RouterError> {
    let registration = watched.swap_remove(index);
    if registry
        .remove_if_current(&registration.identity)
        .map_err(|error| RouterError::Io(io::Error::other(error)))?
    {
        let id = registration.identity.id().to_owned();
        emit(events, RouterEvent::Disconnected { id });
        if let Some(sender) = lifecycle {
            let _ = sender.send(LifecycleEvent::TerminalDisconnected(registration.identity));
        }
    }
    Ok(())
}

fn accept_ready(
    listener: &OwnedRouterListener,
    pending: &mut Vec<PendingConnection>,
    events: &SyncSender<RouterEvent>,
) -> Result<(), RouterError> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let peer = PeerIdentity::from_stream(&stream).map_err(RouterError::Io)?;
                stream.set_nonblocking(true).map_err(RouterError::Io)?;
                if pending.len() >= MAX_PENDING_REGISTRATIONS {
                    emit_capacity();
                    emit(events, RouterEvent::Rejected(RouterReject::Capacity));
                    continue;
                }
                pending.push(PendingConnection {
                    stream,
                    decoder: LocalPacketDecoder::new(),
                    accepted: Instant::now(),
                    peer,
                    #[cfg(windows)]
                    token: Vec::with_capacity(et_net::local::TOKEN_LEN + 1),
                    #[cfg(windows)]
                    expected_token: listener.token().to_owned(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if matches!(error.raw_os_error(), Some(23 | 24)) => {
                emit_resource_error(&error);
                return Ok(());
            }
            Err(error) => return Err(RouterError::Io(error)),
        }
    }
}

fn read_ready(connection: &mut PendingConnection) -> Result<ReadOutcome, RouterError> {
    #[cfg(windows)]
    if connection.token.last() != Some(&b'\n') {
        loop {
            let mut byte = [0u8; 1];
            match connection.stream.read(&mut byte) {
                Ok(0) => return Ok(ReadOutcome::Reject),
                Ok(_) => {
                    connection.token.push(byte[0]);
                    if connection.token.len() > et_net::local::TOKEN_LEN + 1 {
                        return Ok(ReadOutcome::Reject);
                    }
                    if byte[0] == b'\n' {
                        let supplied = &connection.token[..connection.token.len() - 1];
                        if supplied != connection.expected_token.as_bytes() {
                            return Ok(ReadOutcome::Reject);
                        }
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(ReadOutcome::Pending)
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Ok(ReadOutcome::Reject),
            }
        }
    }
    read_decoder(&mut connection.stream, &mut connection.decoder)
}

fn read_decoder(
    stream: &mut LocalStream,
    decoder: &mut LocalPacketDecoder,
) -> Result<ReadOutcome, RouterError> {
    loop {
        let needed = decoder.required_bytes().min(8192);
        if needed == 0 {
            return Ok(ReadOutcome::Reject);
        }
        let mut buffer = [0u8; 8192];
        match stream.read(&mut buffer[..needed]) {
            Ok(0) => {
                let decoder = std::mem::take(decoder);
                return Ok(match decoder.finish() {
                    Ok(()) => ReadOutcome::Pending,
                    Err(_) => ReadOutcome::Reject,
                });
            }
            Ok(count) => match decoder.feed(&buffer[..count]) {
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

fn rollback_registration(
    registry: &Registry,
    identity: &RegistrationIdentity,
    events: &SyncSender<RouterEvent>,
) -> Result<(), RouterError> {
    registry
        .remove_if_current(identity)
        .map_err(|error| RouterError::Io(io::Error::other(error)))?;
    emit(
        events,
        RouterEvent::Rejected(RouterReject::RegistryUnavailable),
    );
    Ok(())
}

fn expire_pending(pending: &mut Vec<PendingConnection>, events: &SyncSender<RouterEvent>) {
    let now = Instant::now();
    let mut expired = 0;
    pending.retain(|connection| {
        let keep = now.duration_since(connection.accepted) < REGISTRATION_TIMEOUT;
        expired += usize::from(!keep);
        keep
    });
    for _ in 0..expired {
        emit(events, RouterEvent::Rejected(RouterReject::Timeout));
    }
}

fn emit(events: &SyncSender<RouterEvent>, event: RouterEvent) {
    let _ = events.try_send(event);
}

fn emit_capacity() {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    if let Ok(mut last) = LAST.lock() {
        let now = Instant::now();
        if last.is_none_or(|previous| now.duration_since(previous) >= Duration::from_secs(1)) {
            crate::diag::info("router registration capacity exhausted");
            *last = Some(now);
        }
    }
}

fn emit_resource_error(error: &io::Error) {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    if let Ok(mut last) = LAST.lock() {
        let now = Instant::now();
        if last.is_none_or(|previous| now.duration_since(previous) >= Duration::from_secs(1)) {
            crate::diag::info(format!("router accept resource exhaustion: {error}"));
            *last = Some(now);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn expired_hung_up_pending_is_removed_before_readiness_is_indexed() {
        let (stream, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        drop(peer);
        let mut pending = vec![PendingConnection {
            stream,
            decoder: LocalPacketDecoder::new(),
            accepted: Instant::now() - REGISTRATION_TIMEOUT,
            peer: PeerIdentity::Unix {
                uid: rustix::process::getuid().as_raw(),
                gid: rustix::process::getgid().as_raw(),
            },
        }];
        let (events, receiver) = std::sync::mpsc::sync_channel(1);
        expire_pending(&mut pending, &events);
        assert!(pending.is_empty());
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            RouterEvent::Rejected(RouterReject::Timeout)
        );
        // Poll descriptors are constructed only after this point, so no stale
        // readiness index can address the removed connection.
        assert_eq!(pending.len(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn stalled_startup_socket_remains_nonblocking_while_other_work_progresses() {
        use std::net::{Ipv4Addr, TcpListener, TcpStream};

        fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let connector = std::thread::spawn(move || TcpStream::connect(address).unwrap());
            let (server, _) = listener.accept().unwrap();
            (server, connector.join().unwrap())
        }

        let (mut stalled, _stalled_peer) = pair();
        stalled.set_nonblocking(true).unwrap();
        let mut stalled_decoder = LocalPacketDecoder::new();
        assert!(matches!(
            read_decoder(&mut stalled, &mut stalled_decoder).unwrap(),
            ReadOutcome::Pending
        ));

        let (mut ready, mut ready_peer) = pair();
        ready.set_nonblocking(true).unwrap();
        let packet = et_core::packet::Packet::new(STARTUP_STATUS, vec![0]);
        write_local_packet(&mut ready_peer, &packet).unwrap();
        let mut ready_decoder = LocalPacketDecoder::new();
        assert!(matches!(
            read_decoder(&mut ready, &mut ready_decoder).unwrap(),
            ReadOutcome::Packet(_)
        ));
    }
}
