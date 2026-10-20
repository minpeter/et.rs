use et_net::local::LocalStream;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_net::local_packet::{
    parse_status, registration_status_packet, write_local_packet, LocalPacketDecoder,
    MAX_REGISTRATION_LEN, MAX_STATUS_MESSAGE, STARTUP_STATUS,
};
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};
#[cfg(unix)]
use rustix::net::{recv, RecvFlags};

use crate::registry::{RegisteredTerminal, RegistrationIdentity, Registry};
use crate::registry_validation::PeerIdentity;
use crate::router::{
    RouterError, RouterEvent, RouterReject, MAX_PENDING_REGISTRATIONS, REGISTRATION_TIMEOUT,
};
use crate::router_registration;
use crate::runtime_lifecycle::{LifecycleEvent, LifecycleSender};
#[cfg(unix)]
use crate::socket_path::OwnedRouterListener;
#[cfg(windows)]
use crate::socket_path_windows::OwnedRouterListener;

/// Largest `STARTUP_STATUS` packet: [`et_net::local_packet::status_packet`]
/// carries a result byte and at most [`MAX_STATUS_MESSAGE`] message bytes.
const MAX_STARTUP_STATUS_LEN: usize = et_core::packet::HEADER_LEN + 1 + MAX_STATUS_MESSAGE;

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
    lifecycle: Option<LifecycleSender>,
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
    lifecycle: Option<LifecycleSender>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), RouterError> {
    let mut router = RouterPoll::new(listener, registry, events, lifecycle);
    loop {
        router.expire();
        let timeout = router.timeout().map(|duration| {
            rustix::time::Timespec::try_from(duration).expect("registration timeout fits timespec")
        });
        let mut poll_fds = vec![PollFd::new(&wake_reader, PollFlags::IN)];
        router.descriptors(&mut poll_fds);
        match poll(&mut poll_fds, timeout.as_ref()) {
            Ok(_) => {}
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(RouterError::Io(io::Error::from(error))),
        }
        let readiness: Vec<PollFlags> = poll_fds.iter().map(PollFd::revents).collect();
        drop(poll_fds);
        if readiness[0].intersects(PollFlags::IN | PollFlags::HUP) {
            drain_waker(&mut wake_reader)?;
            if shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
        }
        router.service(&readiness[1..])?;
    }
}

/// The Unix router's poll state: its listener, registrations still being
/// read, and registered terminals watched for hang-up. A standalone
/// [`crate::router::Router`] drives it from a thread of its own; the runtime
/// drives it from its control thread, next to the TCP listeners.
#[cfg(unix)]
pub(crate) struct RouterPoll {
    listener: OwnedRouterListener,
    registry: Registry,
    events: SyncSender<RouterEvent>,
    lifecycle: Option<LifecycleSender>,
    pending: Vec<PendingConnection>,
    watched: Vec<WatchedRegistration>,
}

#[cfg(unix)]
impl RouterPoll {
    pub(crate) fn new(
        listener: OwnedRouterListener,
        registry: Registry,
        events: SyncSender<RouterEvent>,
        lifecycle: Option<LifecycleSender>,
    ) -> Self {
        Self {
            listener,
            registry,
            events,
            lifecycle,
            pending: Vec::new(),
            watched: Vec::new(),
        }
    }

    /// Drop expired registrations. Called before [`Self::descriptors`], so
    /// readiness indices and the pending list always describe the same
    /// generation.
    pub(crate) fn expire(&mut self) {
        expire_pending(&mut self.pending, &self.events);
    }

    /// How long the router may sleep, see [`idle_timeout`].
    pub(crate) fn timeout(&self) -> Option<Duration> {
        idle_timeout(&self.pending)
    }

    /// Append the listener, the pending registrations and the watched
    /// terminals, in that order. Returns how many descriptors were added.
    pub(crate) fn descriptors<'a>(&'a self, poll_fds: &mut Vec<PollFd<'a>>) -> usize {
        poll_fds.push(PollFd::new(self.listener.listener(), PollFlags::IN));
        for connection in &self.pending {
            poll_fds.push(PollFd::new(
                &connection.stream,
                PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
            ));
        }
        for registration in &self.watched {
            let mut flags = PollFlags::HUP | PollFlags::ERR;
            if registration.startup.is_some() {
                flags |= PollFlags::IN;
            }
            poll_fds.push(PollFd::new(&registration.stream, flags));
        }
        1 + self.pending.len() + self.watched.len()
    }

    /// Act on the readiness of the descriptors [`Self::descriptors`] added.
    pub(crate) fn service(&mut self, readiness: &[PollFlags]) -> Result<(), RouterError> {
        let pending_start = 1;
        let watched_start = pending_start + self.pending.len();
        let mut watched_readiness = readiness[watched_start..].to_vec();
        for (flags, registration) in watched_readiness.iter_mut().zip(&self.watched) {
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
            &mut self.watched,
            &self.registry,
            &self.events,
            self.lifecycle.as_ref(),
        )?;
        if readiness
            .first()
            .is_some_and(|flags| flags.contains(PollFlags::IN))
        {
            accept_ready(&self.listener, &mut self.pending, &self.events)?;
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
            match read_ready(&mut self.pending[index])? {
                ReadOutcome::Pending => {}
                ReadOutcome::Packet(packet) => {
                    let connection = self.pending.swap_remove(index);
                    let Some(terminal) =
                        complete_registration(connection, packet, &self.registry, &self.events)?
                    else {
                        continue;
                    };
                    let id = terminal.identity.id().to_owned();
                    terminal
                        .watcher
                        .set_nonblocking(true)
                        .map_err(RouterError::Io)?;
                    let startup = startup_watch(&terminal);
                    self.watched.push(WatchedRegistration {
                        stream: terminal.watcher,
                        identity: terminal.identity,
                        startup,
                    });
                    emit(&self.events, RouterEvent::Registered { id });
                    if terminal.resumed {
                        notify_resumed(self.lifecycle.as_ref());
                    }
                }
                ReadOutcome::Reject => {
                    self.pending.swap_remove(index);
                    emit(
                        &self.events,
                        RouterEvent::Rejected(RouterReject::MalformedFrame),
                    );
                }
            }
        }
        Ok(())
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
    lifecycle: Option<LifecycleSender>,
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
                    let Some(terminal) =
                        complete_registration(connection, packet, &registry, &events)?
                    else {
                        continue;
                    };
                    let id = terminal.identity.id().to_owned();
                    let startup = startup_watch(&terminal);
                    watched.push(WatchedRegistration {
                        stream: terminal.watcher,
                        identity: terminal.identity,
                        startup,
                    });
                    emit(&events, RouterEvent::Registered { id });
                    if terminal.resumed {
                        notify_resumed(lifecycle.as_ref());
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
    lifecycle: Option<&LifecycleSender>,
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
    lifecycle: Option<&LifecycleSender>,
) -> Result<(), RouterError> {
    let registration = watched.swap_remove(index);
    if registry
        .remove_if_current(&registration.identity)
        .map_err(|error| RouterError::Io(io::Error::other(error)))?
    {
        let id = registration.identity.id().to_owned();
        emit(events, RouterEvent::Disconnected { id });
        if let Some(sender) = lifecycle {
            sender.send(LifecycleEvent::TerminalDisconnected(registration.identity));
        }
    }
    Ok(())
}

/// The runtime sweeps a resumed terminal's recovery grace; arm that sweep.
fn notify_resumed(lifecycle: Option<&LifecycleSender>) {
    if let Some(sender) = lifecycle {
        sender.send(LifecycleEvent::TerminalResumed);
    }
}

fn accept_ready(
    listener: &OwnedRouterListener,
    pending: &mut Vec<PendingConnection>,
    _events: &SyncSender<RouterEvent>,
) -> Result<(), RouterError> {
    while pending.len() < MAX_PENDING_REGISTRATIONS {
        match listener.accept() {
            Ok((stream, _)) => {
                let peer = PeerIdentity::from_stream(&stream).map_err(RouterError::Io)?;
                stream.set_nonblocking(true).map_err(RouterError::Io)?;
                pending.push(PendingConnection {
                    stream,
                    decoder: registration_decoder(),
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
            Err(error) if crate::runtime_accept::accept_resource_exhausted(&error) => {
                // The listener stays readable until descriptors free up. Pause
                // so this does not spin the accept loop.
                emit_resource_error(&error);
                std::thread::sleep(Duration::from_millis(10));
                return Ok(());
            }
            Err(error) => return Err(RouterError::Io(error)),
        }
    }
    Ok(())
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

/// Decoder for a pending registration: upstream `UserTerminalRouter` refuses
/// a registration packet over `MAX_REGISTRATION_LENGTH` without a reply.
fn registration_decoder() -> LocalPacketDecoder {
    LocalPacketDecoder::with_limit(MAX_REGISTRATION_LEN)
}

/// Decoder for the `STARTUP_STATUS` an et.rs terminal sends once its new
/// session starts. A live pty that re-registers after an etserver restart
/// never sends one, and its stream already carries output for the resumed
/// bridge: reading it here would steal and corrupt that output.
fn startup_watch(terminal: &RegisteredTerminal) -> Option<LocalPacketDecoder> {
    (terminal.startup_ack && !terminal.resumed)
        .then(|| LocalPacketDecoder::with_limit(MAX_STARTUP_STATUS_LEN))
}

/// Register a read `TERMINAL_USER_INFO` and answer the terminal.
///
/// A terminal that registered with the `fd = -6` sentinel gets a
/// `REGISTRATION_STATUS` either way; success names the framing the router
/// will write to it. Any other terminal gets nothing: upstream
/// `UserTerminalRouter::registerTerminal` closes a refused terminal without
/// writing, and ET C++ `etterminal` treats an unexpected packet as fatal.
/// Returns `None` once the registration was refused or rolled back.
fn complete_registration(
    connection: PendingConnection,
    packet: Packet,
    registry: &Registry,
    events: &SyncSender<RouterEvent>,
) -> Result<Option<RegisteredTerminal>, RouterError> {
    let mut status = connection.stream.try_clone().map_err(RouterError::Io)?;
    match router_registration::process(packet, connection.stream, registry, connection.peer) {
        Ok(terminal) => {
            if terminal.startup_ack
                && write_local_packet(
                    &mut status,
                    &registration_status_packet(Ok(terminal.router_framing)),
                )
                .is_err()
            {
                rollback_registration(registry, &terminal.identity, events)?;
                return Ok(None);
            }
            Ok(Some(terminal))
        }
        Err(rejection) => {
            if rejection.wants_status {
                let message = format!("registration rejected: {:?}", rejection.reason);
                let _ = write_local_packet(&mut status, &registration_status_packet(Err(&message)));
            }
            emit(events, RouterEvent::Rejected(rejection.reason));
            Ok(None)
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

/// How long the router may sleep: until the oldest pending registration
/// expires. Every other source wakes it through a descriptor, so with nothing
/// pending it sleeps until one does. Darwin can omit readiness for a closed
/// registration socket, so it keeps rechecking every 100ms.
#[cfg(unix)]
fn idle_timeout(pending: &[PendingConnection]) -> Option<Duration> {
    let now = Instant::now();
    let expiry = pending
        .iter()
        .map(|connection| {
            (connection.accepted + REGISTRATION_TIMEOUT).saturating_duration_since(now)
        })
        .min();
    if cfg!(target_os = "macos") {
        let recheck = Duration::from_millis(100);
        return Some(expiry.map_or(recheck, |expiry| expiry.min(recheck)));
    }
    expiry
}

fn emit(events: &SyncSender<RouterEvent>, event: RouterEvent) {
    let _ = events.try_send(event);
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
            decoder: registration_decoder(),
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
