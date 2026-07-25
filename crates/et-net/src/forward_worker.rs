use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicI32;
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;

use crate::forward::{ForwardError, Outbound};
use crate::forward_endpoint::{Endpoint, ForwardStream};
use crate::forward_io::{
    spawn_connector, spawn_io, spawn_listener, stop_io, ActiveIo, BoundSource, WriteCommand,
};
use et_core::packet::Packet;

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
        destination: Endpoint,
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

pub(crate) fn run(
    sources: Vec<BoundSource>,
    commands: mpsc::Receiver<Command>,
    command_sender: mpsc::SyncSender<Command>,
    outbound: mpsc::SyncSender<Outbound>,
    mut outbound_wake: UnixStream,
    listener_stop: UnixStream,
) {
    let result = Worker::new(
        command_sender,
        outbound.clone(),
        outbound_wake.try_clone().ok(),
    )
    .and_then(|mut worker| worker.run(sources, commands, listener_stop));
    if let Err(error) = result {
        let _ = outbound.send(Err(error));
        let _ = outbound_wake.write(&[1]);
    }
}

struct Worker {
    commands: mpsc::SyncSender<Command>,
    outbound: mpsc::SyncSender<Outbound>,
    outbound_wake: UnixStream,
    pending: HashMap<i32, ForwardStream>,
    sources: HashMap<i32, ActiveIo>,
    destinations: HashMap<i32, ActiveIo>,
    threads: Vec<JoinHandle<()>>,
    next_socket_id: i32,
}

impl Worker {
    fn new(
        commands: mpsc::SyncSender<Command>,
        outbound: mpsc::SyncSender<Outbound>,
        outbound_wake: Option<UnixStream>,
    ) -> Result<Self, ForwardError> {
        let outbound_wake = outbound_wake.ok_or(ForwardError::Unavailable)?;
        outbound_wake
            .set_nonblocking(true)
            .map_err(ForwardError::Io)?;
        Ok(Self {
            commands,
            outbound,
            outbound_wake,
            pending: HashMap::new(),
            sources: HashMap::new(),
            destinations: HashMap::new(),
            threads: Vec::new(),
            next_socket_id: 1,
        })
    }

    fn run(
        &mut self,
        sources: Vec<BoundSource>,
        commands: mpsc::Receiver<Command>,
        listener_stop: UnixStream,
    ) -> Result<(), ForwardError> {
        let next_client_fd = Arc::new(AtomicI32::new(1));
        for source in sources {
            self.threads.push(spawn_listener(
                source,
                self.commands.clone(),
                listener_stop.try_clone().map_err(ForwardError::Io)?,
                next_client_fd.clone(),
            ));
        }
        let result = loop {
            let command = match commands.recv() {
                Ok(command) => command,
                Err(_) => break Ok(()),
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
        let _ = listener_stop.shutdown(std::net::Shutdown::Both);
        for (_, stream) in self.pending.drain() {
            stream.shutdown();
        }
        for (_, io) in self.sources.drain().chain(self.destinations.drain()) {
            stop_io(io);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        result
    }
}
#[path = "forward_worker_state.rs"]
mod state;
