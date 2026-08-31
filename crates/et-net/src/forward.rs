#[cfg(unix)]
use std::io::Read;
use std::io::{self};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{PortForwardSourceRequest, TerminalPacketType};

use crate::forward_endpoint::{Endpoint, ResolvedEndpoint};
use crate::forward_io::BoundSource;
use crate::forward_worker::{run, Command};

const CHANNEL_CAPACITY: usize = 256;
/// Maximum reverse listeners owned by one terminal session, after DNS fanout
/// and address deduplication.
const MAX_SESSION_LISTENERS: usize = 32;

#[derive(Debug)]
pub enum ForwardError {
    Unsupported,
    Io(std::io::Error),
    Protocol(&'static str),
    Unavailable,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(formatter, "port forwarding is not implemented"),
            Self::Io(error) => write!(formatter, "port forwarding I/O: {error}"),
            Self::Protocol(message) => write!(formatter, "port forwarding protocol: {message}"),
            Self::Unavailable => write!(formatter, "port forwarding worker is unavailable"),
        }
    }
}

impl std::error::Error for ForwardError {}

impl From<io::Error> for ForwardError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) type Outbound = Result<Packet, ForwardError>;

pub struct Forwarder {
    commands: mpsc::SyncSender<Command>,
    outbound: mpsc::Receiver<Outbound>,
    /// Readiness channel for outbound packets. Unix callers poll it exactly
    /// like upstream's `select()`; Windows callers drain [`Forwarder::try_outbound`]
    /// on the client loop's 10ms cadence instead, because a socket pair created
    /// this way is not selectable there.
    #[cfg(unix)]
    wake: UnixStream,
    worker: Option<JoinHandle<()>>,
}

impl Forwarder {
    pub fn start(sources: Vec<PortForwardSourceRequest>) -> Result<Self, ForwardError> {
        Self::start_with_user(sources, None).map(|(forwarder, _)| forwarder)
    }

    /// Bind all forwarding sources and return the forwarder together with the
    /// environment variables created for named-pipe requests, mirroring the
    /// upstream server (`PortForwardHandler::createSource` +
    /// `TerminalServer::runTerminal`). `owner` is the session user: UNIX
    /// listen/connect drop to that user (ET #784).
    pub fn start_with_user(
        sources: Vec<PortForwardSourceRequest>,
        owner: Option<(u32, u32)>,
    ) -> Result<(Self, ForwardEnvironment), ForwardError> {
        let (sources, environment) = bind_sources(sources, owner)?;
        let session_user = owner;
        let (commands_tx, commands_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (outbound_tx, outbound_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        #[cfg(unix)]
        let (wake, wake_writer) = {
            let (reader, writer) = UnixStream::pair()?;
            reader.set_nonblocking(true)?;
            (reader, writer)
        };
        #[cfg(unix)]
        let (listener_stop, listener_stop_reader) = UnixStream::pair()?;
        #[cfg(windows)]
        let listener_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[cfg(windows)]
        let listener_stop_reader = listener_stop.clone();
        let worker_commands = commands_tx.clone();
        let worker = std::thread::Builder::new()
            .name("et-forwarding".to_owned())
            .spawn(move || {
                run(
                    sources,
                    commands_rx,
                    worker_commands,
                    outbound_tx,
                    #[cfg(unix)]
                    wake_writer,
                    listener_stop_reader,
                    session_user,
                );
                #[cfg(unix)]
                drop(listener_stop);
                #[cfg(windows)]
                listener_stop.store(true, std::sync::atomic::Ordering::Release);
            })
            .map_err(ForwardError::Io)?;
        Ok((
            Self {
                commands: commands_tx,
                outbound: outbound_rx,
                #[cfg(unix)]
                wake,
                worker: Some(worker),
            },
            environment,
        ))
    }

    /// Pollable readiness handle for outbound forwarding packets (Unix only).
    #[cfg(unix)]
    pub fn wake(&self) -> Result<&UnixStream, ForwardError> {
        Ok(&self.wake)
    }

    /// Hand a forwarding packet to the worker, blocking when its command
    /// queue is full.
    ///
    /// Only safe for callers that never also drain [`Forwarder::try_outbound`]
    /// on the same thread (e.g. tests). Session loops must use
    /// [`Forwarder::try_receive`] instead: the worker can itself be blocked
    /// emitting outbound packets, which only the session loop drains, so a
    /// blocking send from the session loop closes a cycle and deadlocks the
    /// session permanently.
    pub fn receive(&self, packet: Packet) -> Result<(), ForwardError> {
        self.commands
            .send(Command::Packet(packet))
            .map_err(|_| ForwardError::Unavailable)
    }

    /// Hand a forwarding packet to the worker without blocking.
    ///
    /// Returns the packet back when the worker's command queue is full so the
    /// caller can drain outbound packets (which is what unblocks the worker)
    /// and retry later. Callers must not read further session packets while
    /// holding a returned packet, or forwarding data would be reordered.
    pub fn try_receive(&self, packet: Packet) -> Result<Option<Packet>, ForwardError> {
        match self.commands.try_send(Command::Packet(packet)) {
            Ok(()) => Ok(None),
            Err(mpsc::TrySendError::Full(Command::Packet(packet))) => Ok(Some(packet)),
            Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
                Err(ForwardError::Unavailable)
            }
        }
    }

    pub fn try_outbound(&self) -> Result<Option<Packet>, ForwardError> {
        #[cfg(unix)]
        drain_wake(&self.wake)?;
        match self.outbound.try_recv() {
            Ok(result) => result.map(Some),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(ForwardError::Unavailable),
        }
    }

    pub fn wait_outbound(&self, timeout: Duration) -> Result<Packet, ForwardError> {
        self.outbound
            .recv_timeout(timeout)
            .map_err(|_| ForwardError::Unavailable)?
    }

    pub fn shutdown(mut self) -> Result<(), ForwardError> {
        self.stop()
    }

    fn stop(&mut self) -> Result<(), ForwardError> {
        if let Some(worker) = self.worker.take() {
            let _ = self.commands.send(Command::Stop);
            worker.join().map_err(|_| ForwardError::Unavailable)?;
        }
        Ok(())
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Environment variables created for named-pipe forwards.
pub type ForwardEnvironment = Vec<(String, String)>;

enum PlannedSource {
    Endpoint {
        source: ResolvedEndpoint,
        destination: et_core::proto::SocketEndpoint,
    },
    #[cfg(unix)]
    Environment {
        variable: String,
        destination: et_core::proto::SocketEndpoint,
    },
}

fn bind_sources(
    sources: Vec<PortForwardSourceRequest>,
    owner: Option<(u32, u32)>,
) -> Result<(Vec<BoundSource>, ForwardEnvironment), ForwardError> {
    let mut plans = Vec::with_capacity(sources.len());
    let mut listener_count = 0usize;
    for request in sources {
        // The destination is passed through verbatim in the
        // PORT_FORWARD_DESTINATION_REQUEST and parsed by the remote side.
        let destination = request.destination.unwrap_or_default();
        let (plan, additional_listeners) = if let Some(variable) = request.environmentvariable {
            if request.source.is_some() {
                return Err(ForwardError::Protocol(
                    "Do not set a source when forwarding named pipes with environment variables",
                ));
            }
            #[cfg(unix)]
            {
                (
                    PlannedSource::Environment {
                        variable,
                        destination,
                    },
                    1,
                )
            }
            #[cfg(windows)]
            {
                let _ = (variable, destination, owner);
                return Err(ForwardError::Protocol(
                    "named-pipe forwarding is not supported on Windows",
                ));
            }
        } else {
            let source = Endpoint::parse(request.source)?.resolve_for_bind()?;
            let listener_count = source.listener_count();
            (
                PlannedSource::Endpoint {
                    source,
                    destination,
                },
                listener_count,
            )
        };
        listener_count = listener_count
            .checked_add(additional_listeners)
            .ok_or(ForwardError::Protocol("reverse listener limit exceeded"))?;
        if listener_count > MAX_SESSION_LISTENERS {
            return Err(ForwardError::Protocol("reverse listener limit exceeded"));
        }
        plans.push(plan);
    }

    let mut bound = Vec::with_capacity(listener_count);
    #[cfg_attr(windows, allow(unused_mut))]
    let mut environment = Vec::new();
    for plan in plans {
        match plan {
            PlannedSource::Endpoint {
                source,
                destination,
            } => {
                for listener in source.bind_with_user(owner)? {
                    bound.push(BoundSource {
                        listener,
                        destination: destination.clone(),
                    });
                }
            }
            #[cfg(unix)]
            PlannedSource::Environment {
                variable,
                destination,
            } => {
                let path = create_forward_pipe(owner)?;
                let source = Endpoint::Unix(path.clone()).resolve_for_bind()?;
                let mut listeners = source.bind_with_user(owner)?;
                environment.push((variable, path.to_string_lossy().into_owned()));
                for mut listener in listeners.drain(..) {
                    if let Some(directory) = path.parent() {
                        listener.also_remove_dir(directory.to_path_buf());
                    }
                    bound.push(BoundSource {
                        listener,
                        destination: destination.clone(),
                    });
                }
            }
        }
    }
    Ok((bound, environment))
}

/// Create the private directory for a named-pipe forward and return the
/// socket path inside it (upstream `et_forward_sock_XXXXXX/sock`).
#[cfg(unix)]
fn create_forward_pipe(owner: Option<(u32, u32)>) -> Result<std::path::PathBuf, ForwardError> {
    use std::os::unix::fs::DirBuilderExt;
    let (suffix, _) = et_core::keys::gen_id_passkey();
    let directory = std::env::temp_dir().join(format!("et_forward_sock_{suffix}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(ForwardError::Io)?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(&directory, Some(uid), Some(gid)).map_err(ForwardError::Io)?;
    }
    Ok(directory.join("sock"))
}

#[cfg(unix)]
fn drain_wake(mut wake: &UnixStream) -> Result<(), ForwardError> {
    let mut buffer = [0u8; 64];
    loop {
        match wake.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ForwardError::Io(error)),
        }
    }
}

pub fn is_forward_packet(header: u8) -> bool {
    header == TerminalPacketType::PortForwardDestinationRequest as u8
        || header == TerminalPacketType::PortForwardDestinationResponse as u8
        || header == TerminalPacketType::PortForwardData as u8
}
