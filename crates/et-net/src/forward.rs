use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{PortForwardSourceRequest, TerminalPacketType};

use crate::forward_endpoint::Endpoint;
use crate::forward_io::BoundSource;
use crate::forward_worker::{run, Command};

const CHANNEL_CAPACITY: usize = 256;

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
    wake: UnixStream,
    worker: Option<JoinHandle<()>>,
}

impl Forwarder {
    pub fn start(sources: Vec<PortForwardSourceRequest>) -> Result<Self, ForwardError> {
        let sources = bind_sources(sources)?;
        let (commands_tx, commands_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (outbound_tx, outbound_rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (wake, wake_writer) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        let (listener_stop, listener_stop_reader) = UnixStream::pair()?;
        let worker_commands = commands_tx.clone();
        let worker = std::thread::Builder::new()
            .name("et-forwarding".to_owned())
            .spawn(move || {
                run(
                    sources,
                    commands_rx,
                    worker_commands,
                    outbound_tx,
                    wake_writer,
                    listener_stop_reader,
                );
                drop(listener_stop);
            })
            .map_err(ForwardError::Io)?;
        Ok(Self {
            commands: commands_tx,
            outbound: outbound_rx,
            wake,
            worker: Some(worker),
        })
    }

    pub fn wake(&self) -> Result<&UnixStream, ForwardError> {
        Ok(&self.wake)
    }

    pub fn receive(&self, packet: Packet) -> Result<(), ForwardError> {
        self.commands
            .send(Command::Packet(packet))
            .map_err(|_| ForwardError::Unavailable)
    }

    pub fn try_outbound(&self) -> Result<Option<Packet>, ForwardError> {
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

fn bind_sources(sources: Vec<PortForwardSourceRequest>) -> Result<Vec<BoundSource>, ForwardError> {
    let mut bound = Vec::with_capacity(sources.len());
    for request in sources {
        let source = Endpoint::parse(request.source)?;
        let destination = Endpoint::parse(request.destination)?;
        bound.push(BoundSource {
            listener: source.bind()?,
            destination,
        });
    }
    Ok(bound)
}

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
