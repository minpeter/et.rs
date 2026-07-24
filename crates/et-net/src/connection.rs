use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};

use et_core::backed_reader::{BackedReader, ReadError, ReadItem};
use et_core::backed_writer::{BackedWriter, RecoverError, WriterOutcome};
use et_core::crypto::{
    CryptoHandler, EncryptError, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT, KEY_LEN,
};
use et_core::packet::Packet;
use et_core::proto::{CatchupBuffer, SequenceHeader};

use crate::framing_io::{read_proto_limited, write_proto_limited};

pub const MAX_RECOVERY_PROTO_LEN: i64 = 80 * 1024 * 1024;

#[derive(Debug)]
pub enum ConnError {
    Io(io::Error),
    Read(ReadError),
    Recover(RecoverError),
    Encrypt(EncryptError),
    Backpressure,
    SequenceOutOfRange(i64),
    InvalidRecoverySequence(Option<i32>),
}

pub struct Connection {
    stream: TcpStream,
    writer: BackedWriter,
    reader: BackedReader,
}

impl Connection {
    pub fn new_client(stream: TcpStream, key: &[u8; KEY_LEN]) -> Self {
        Self::new(stream, key, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT)
    }

    pub fn new_server(stream: TcpStream, key: &[u8; KEY_LEN]) -> Self {
        Self::new(stream, key, DIR_SERVER_TO_CLIENT, DIR_CLIENT_TO_SERVER)
    }

    fn new(stream: TcpStream, key: &[u8; KEY_LEN], encrypt: u8, decrypt: u8) -> Self {
        Self {
            stream,
            writer: BackedWriter::new(CryptoHandler::new(key, encrypt), true),
            reader: BackedReader::new(CryptoHandler::new(key, decrypt), true),
        }
    }

    pub fn write_packet(&mut self, header: u8, payload: &[u8]) -> Result<(), ConnError> {
        self.refresh_connectivity()?;
        match self.writer.write_packet(header, payload)? {
            WriterOutcome::Send(frame) => {
                if let Err(error) = self.stream.write_all(&frame) {
                    self.disconnect();
                    return Err(ConnError::Io(error));
                }
                Ok(())
            }
            WriterOutcome::BufferedOnly => Ok(()),
            WriterOutcome::Skipped => Err(ConnError::Backpressure),
        }
    }

    pub fn read_packet(&mut self) -> Result<Packet, ConnError> {
        loop {
            match self.reader.pop() {
                Ok(ReadItem::Packet(packet)) => return Ok(packet),
                Ok(ReadItem::NeedMore) => {}
                Err(error) => {
                    self.disconnect();
                    return Err(ConnError::Read(error));
                }
            }
            let mut buffer = [0u8; 8192];
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    self.disconnect();
                    return Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                Ok(count) => self.reader.feed(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.disconnect();
                    return Err(ConnError::Io(error));
                }
            }
        }
    }

    pub fn try_read_packet(&mut self) -> Result<Option<Packet>, ConnError> {
        match crate::connection_nonblocking::try_read(&mut self.stream, &mut self.reader) {
            Ok(packet) => Ok(packet),
            Err(error) => {
                self.disconnect();
                Err(error)
            }
        }
    }

    pub fn write_terminal(&mut self, bytes: &[u8]) -> Result<(), ConnError> {
        self.write_packet(0, bytes)
    }

    pub fn read_terminal(&mut self) -> Result<Vec<u8>, ConnError> {
        self.read_packet().map(|packet| packet.payload().to_vec())
    }

    pub fn disconnect(&mut self) {
        self.writer.invalidate();
        self.reader.invalidate();
    }

    pub fn shutdown(&mut self) -> Result<(), ConnError> {
        self.disconnect();
        match self.stream.shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(ConnError::Io(error)),
        }
    }

    pub fn recover(&mut self, new_stream: TcpStream) -> Result<(), ConnError> {
        self.disconnect();
        let _ = self.stream.shutdown(Shutdown::Both);
        let result = self.exchange_recovery(&new_stream);
        match result {
            Ok(remote_catchup) => {
                self.reader.revive(remote_catchup.buffer);
                self.writer.revive();
                self.stream = new_stream;
                Ok(())
            }
            Err(error) => {
                let _ = new_stream.shutdown(Shutdown::Both);
                self.disconnect();
                Err(error)
            }
        }
    }

    pub fn try_clone_stream(&self) -> Result<TcpStream, ConnError> {
        self.stream.try_clone().map_err(ConnError::Io)
    }

    pub fn connected(&self) -> bool {
        self.writer.connected()
    }

    pub fn writer_sequence(&self) -> i64 {
        self.writer.sequence()
    }

    pub fn reader_sequence(&self) -> i64 {
        self.reader.sequence()
    }

    fn exchange_recovery(&self, stream: &TcpStream) -> Result<CatchupBuffer, ConnError> {
        let local_sequence = self.reader.sequence();
        let wire_sequence = i32::try_from(local_sequence)
            .map_err(|_| ConnError::SequenceOutOfRange(local_sequence))?;
        let mut stream = stream.try_clone()?;
        write_proto_limited(
            &mut stream,
            &SequenceHeader {
                sequence_number: Some(wire_sequence),
            },
            MAX_RECOVERY_PROTO_LEN,
        )?;
        let remote: SequenceHeader = read_proto_limited(&mut stream, MAX_RECOVERY_PROTO_LEN)?;
        let remote_sequence = match remote.sequence_number {
            Some(sequence) if sequence >= 0 => i64::from(sequence),
            value => return Err(ConnError::InvalidRecoverySequence(value)),
        };
        let catchup = CatchupBuffer {
            buffer: self.writer.recover(remote_sequence)?,
        };
        write_proto_limited(&mut stream, &catchup, MAX_RECOVERY_PROTO_LEN)?;
        read_proto_limited(&mut stream, MAX_RECOVERY_PROTO_LEN).map_err(ConnError::Io)
    }

    fn refresh_connectivity(&mut self) -> Result<(), ConnError> {
        if !self.writer.connected() {
            return Ok(());
        }
        if let Err(error) = self.stream.set_nonblocking(true) {
            self.disconnect();
            return Err(ConnError::Io(error));
        }
        let mut byte = [0u8; 1];
        let probe = self.stream.peek(&mut byte);
        if let Err(error) = self.stream.set_nonblocking(false) {
            self.disconnect();
            return Err(ConnError::Io(error));
        }
        match probe {
            Ok(0) => self.disconnect(),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
            {
                self.disconnect();
            }
            Err(error) => {
                self.disconnect();
                return Err(ConnError::Io(error));
            }
        }
        Ok(())
    }
}
