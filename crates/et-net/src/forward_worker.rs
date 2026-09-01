use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::io::Write;
use std::io::{self};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicI32};
use std::sync::Arc;
use std::thread::JoinHandle;

use crossbeam_channel as channel;

use crate::forward::{ForwardError, Outbound};
use crate::forward_endpoint::ForwardStream;
use crate::forward_io::{
    abort_io, spawn_connector, spawn_io, spawn_listener, stop_io, ActiveIo, BoundSource,
    ListenerStop, WriteCommand,
};
use et_core::packet::Packet;
use et_core::proto::SocketEndpoint;

const MAX_ACTIVE_SOCKETS: usize = 256;
const MAX_DATA_PACKET: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Source,
    Destination,
}

pub(crate) enum Command {
    Packet(Packet),
    Accepted {
        client_fd: i32,
        destination: SocketEndpoint,
        stream: ForwardStream,
    },
    Connected {
        client_fd: i32,
        socket_id: i32,
        result: io::Result<ForwardStream>,
    },
    Read {
        role: Role,
        socket_id: i32,
        buffer: Vec<u8>,
    },
    Closed {
        role: Role,
        socket_id: i32,
    },
    IoFailed {
        role: Role,
        socket_id: i32,
        error: io::Error,
    },
    Stop,
}

pub(crate) struct WorkerChannels {
    pub(crate) receiver: channel::Receiver<Command>,
    pub(crate) sender: channel::Sender<Command>,
    pub(crate) outbound: channel::Sender<Outbound>,
    pub(crate) cancel: channel::Receiver<()>,
    pub(crate) abandoned: Arc<AtomicBool>,
}

pub(crate) fn run(
    sources: Vec<BoundSource>,
    channels: WorkerChannels,
    #[cfg(unix)] mut outbound_wake: UnixStream,
    listener_stop: ListenerStop,
    session_user: Option<(u32, u32)>,
) {
    let WorkerChannels {
        receiver: commands,
        sender: command_sender,
        outbound,
        cancel,
        abandoned,
    } = channels;
    #[cfg(unix)]
    let result = Worker::new(
        command_sender,
        outbound.clone(),
        outbound_wake.try_clone().ok(),
        cancel.clone(),
        abandoned,
    )
    .and_then(|mut worker| worker.run(sources, commands, listener_stop, session_user));
    #[cfg(windows)]
    let result = Worker::new(command_sender, outbound.clone(), cancel.clone(), abandoned)
        .and_then(|mut worker| worker.run(sources, commands, listener_stop, session_user));
    if let Err(error) = result {
        channel::select! {
            send(outbound, Err(error)) -> _ => {}
            recv(cancel) -> _ => {}
        }
        #[cfg(unix)]
        let _ = outbound_wake.write(&[1]);
    }
}

struct Worker {
    commands: channel::Sender<Command>,
    outbound: channel::Sender<Outbound>,
    cancel: channel::Receiver<()>,
    abandoned: Arc<AtomicBool>,
    #[cfg(unix)]
    outbound_wake: UnixStream,
    pending: HashMap<i32, ForwardStream>,
    connecting: HashSet<i32>,
    sources: HashMap<i32, ActiveIo>,
    destinations: HashMap<i32, ActiveIo>,
    threads: Vec<JoinHandle<()>>,
    next_socket_id: i32,
    session_user: Option<(u32, u32)>,
}

impl Worker {
    fn new(
        commands: channel::Sender<Command>,
        outbound: channel::Sender<Outbound>,
        #[cfg(unix)] outbound_wake: Option<UnixStream>,
        cancel: channel::Receiver<()>,
        abandoned: Arc<AtomicBool>,
    ) -> Result<Self, ForwardError> {
        #[cfg(unix)]
        let outbound_wake = {
            let wake = outbound_wake.ok_or(ForwardError::Unavailable)?;
            wake.set_nonblocking(true).map_err(ForwardError::Io)?;
            wake
        };
        Ok(Self {
            commands,
            outbound,
            cancel,
            abandoned,
            #[cfg(unix)]
            outbound_wake,
            pending: HashMap::new(),
            connecting: HashSet::new(),
            sources: HashMap::new(),
            destinations: HashMap::new(),
            threads: Vec::new(),
            next_socket_id: 1,
            session_user: None,
        })
    }

    fn run(
        &mut self,
        sources: Vec<BoundSource>,
        commands: channel::Receiver<Command>,
        listener_stop: ListenerStop,
        session_user: Option<(u32, u32)>,
    ) -> Result<(), ForwardError> {
        self.session_user = session_user;
        let next_client_fd = Arc::new(AtomicI32::new(1));
        for source in sources {
            #[cfg(unix)]
            let stop = listener_stop.try_clone().map_err(ForwardError::Io)?;
            #[cfg(windows)]
            let stop = listener_stop.clone();
            self.threads.push(spawn_listener(
                source,
                self.commands.clone(),
                self.cancel.clone(),
                stop,
                next_client_fd.clone(),
            ));
        }
        let mut hard_cancelled = false;
        let result = loop {
            let command = channel::select! {
                recv(self.cancel) -> _ => {
                    hard_cancelled = true;
                    break Ok(())
                },
                recv(commands) -> command => match command {
                    Ok(command) => command,
                    Err(_) => break Ok(()),
                },
            };
            let step = match command {
                Command::Packet(packet) => self.handle_packet(packet),
                Command::Accepted {
                    client_fd,
                    destination,
                    stream,
                } => self.accepted(client_fd, destination, stream),
                Command::Connected {
                    client_fd,
                    socket_id,
                    result,
                } => self.connected(client_fd, socket_id, result),
                Command::Read {
                    role,
                    socket_id,
                    buffer,
                } => self.send_data(role, socket_id, buffer, false, None),
                Command::Closed { role, socket_id } => {
                    self.remove(role, socket_id);
                    self.send_data(role, socket_id, Vec::new(), true, None)
                }
                Command::IoFailed {
                    role,
                    socket_id,
                    error,
                } => {
                    self.remove(role, socket_id);
                    self.send_data(role, socket_id, Vec::new(), true, Some(error.to_string()))
                }
                Command::Stop => break Ok(()),
            };
            if let Err(error) = step {
                break Err(error);
            }
        };
        drop(commands);
        #[cfg(unix)]
        let _ = listener_stop.shutdown(std::net::Shutdown::Both);
        #[cfg(windows)]
        listener_stop.store(true, std::sync::atomic::Ordering::Release);
        for (_, stream) in self.pending.drain() {
            stream.shutdown();
        }
        hard_cancelled |= !matches!(self.cancel.try_recv(), Err(channel::TryRecvError::Empty));
        for (_, io) in self.sources.drain().chain(self.destinations.drain()) {
            if hard_cancelled {
                abort_io(io);
            } else {
                stop_io(io);
            }
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        result
    }
}
#[path = "forward_worker_state.rs"]
mod state;

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    use crossbeam_channel as channel;
    use et_core::packet::Packet;
    use et_core::proto::{
        PortForwardDestinationRequest, PortForwardDestinationResponse, SocketEndpoint,
        TerminalPacketType,
    };
    use prost::Message;

    use super::{Command, Worker, MAX_ACTIVE_SOCKETS};

    const EVENT_TIMEOUT: Duration = Duration::from_secs(3);

    fn worker() -> (
        Worker,
        channel::Receiver<Command>,
        channel::Receiver<crate::forward::Outbound>,
        channel::Sender<()>,
    ) {
        let (commands, command_receiver) = channel::bounded(MAX_ACTIVE_SOCKETS + 1);
        let (outbound, outbound_receiver) = channel::bounded(MAX_ACTIVE_SOCKETS + 1);
        let (cancel, cancel_receiver) = channel::bounded(1);
        let (_wake_reader, wake_writer) = UnixStream::pair().unwrap();
        (
            Worker::new(
                commands,
                outbound,
                Some(wake_writer),
                cancel_receiver,
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap(),
            command_receiver,
            outbound_receiver,
            cancel,
        )
    }

    struct RemoveDirectory(std::path::PathBuf);

    impl Drop for RemoveDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_directory(name: &str) -> (std::path::PathBuf, RemoveDirectory) {
        let path =
            std::path::PathBuf::from(format!("/tmp/et-forward-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        (path.clone(), RemoveDirectory(path))
    }

    fn destination_request(fd: i32, path: &std::path::Path) -> Packet {
        Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(path.to_string_lossy().into_owned()),
                    port: None,
                }),
                fd: Some(fd),
            }
            .encode_to_vec(),
        )
    }

    fn response(packet: Packet) -> PortForwardDestinationResponse {
        assert_eq!(
            packet.header(),
            TerminalPacketType::PortForwardDestinationResponse as u8
        );
        PortForwardDestinationResponse::decode(packet.payload()).unwrap()
    }

    #[test]
    fn in_flight_connectors_count_toward_socket_limit_and_failure_releases_slot() {
        let (directory, _cleanup) = test_directory("connector-failure-test");
        let missing_socket = directory.join("missing.sock");
        let (mut worker, commands, outbound, _cancel) = worker();

        for fd in 1..=MAX_ACTIVE_SOCKETS as i32 {
            worker
                .handle_packet(destination_request(fd, &missing_socket))
                .unwrap();
        }
        assert_eq!(worker.threads.len(), MAX_ACTIVE_SOCKETS);
        assert_eq!(worker.total_sockets(), MAX_ACTIVE_SOCKETS);

        let rejected_fd = MAX_ACTIVE_SOCKETS as i32 + 1;
        worker
            .handle_packet(destination_request(rejected_fd, &missing_socket))
            .unwrap();
        assert_eq!(worker.threads.len(), MAX_ACTIVE_SOCKETS);
        let rejected = response(outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap());
        assert_eq!(rejected.clientfd, Some(rejected_fd));
        assert!(rejected.error.unwrap().contains("socket limit"));

        let completion = commands.recv_timeout(EVENT_TIMEOUT).unwrap();
        let Command::Connected {
            client_fd,
            socket_id,
            result,
        } = completion
        else {
            panic!("connector emitted an unexpected command");
        };
        assert!(result.is_err());
        worker.connected(client_fd, socket_id, result).unwrap();
        assert_eq!(worker.total_sockets(), MAX_ACTIVE_SOCKETS - 1);
        let _ = outbound.recv_timeout(EVENT_TIMEOUT).unwrap().unwrap();

        worker
            .handle_packet(destination_request(rejected_fd + 1, &missing_socket))
            .unwrap();
        assert_eq!(worker.threads.len(), MAX_ACTIVE_SOCKETS + 1);

        for thread in worker.threads.drain(..) {
            thread.join().unwrap();
        }
    }

    #[test]
    fn successful_connector_transfers_slot_to_active_destination() {
        let (directory, _cleanup) = test_directory("connector-success-test");
        let path = directory.join("destination.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let (mut worker, commands, _outbound, _cancel) = worker();
        let request = Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(path.to_string_lossy().into_owned()),
                    port: None,
                }),
                fd: Some(1),
            }
            .encode_to_vec(),
        );

        worker.handle_packet(request).unwrap();
        assert_eq!(worker.total_sockets(), 1);
        let Command::Connected {
            client_fd,
            socket_id,
            result,
        } = commands.recv_timeout(EVENT_TIMEOUT).unwrap()
        else {
            panic!("connector emitted an unexpected command");
        };
        assert!(
            result.is_ok(),
            "connector failed: {:?}",
            result.as_ref().err()
        );
        let (peer, _) = listener.accept().unwrap();
        worker.connected(client_fd, socket_id, result).unwrap();

        assert_eq!(worker.total_sockets(), 1);
        assert_eq!(worker.destinations.len(), 1);

        drop(peer);
        worker.remove(super::Role::Destination, socket_id);
        for thread in worker.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}
