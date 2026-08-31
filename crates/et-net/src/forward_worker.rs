use std::collections::HashMap;
#[cfg(unix)]
use std::io::Write;
use std::io::{self};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicI32;
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
    } = channels;
    #[cfg(unix)]
    let result = Worker::new(
        command_sender,
        outbound.clone(),
        outbound_wake.try_clone().ok(),
        cancel.clone(),
    )
    .and_then(|mut worker| worker.run(sources, commands, listener_stop, session_user));
    #[cfg(windows)]
    let result = Worker::new(command_sender, outbound.clone(), cancel.clone())
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
    #[cfg(unix)]
    outbound_wake: UnixStream,
    pending: HashMap<i32, ForwardStream>,
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
            #[cfg(unix)]
            outbound_wake,
            pending: HashMap::new(),
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
