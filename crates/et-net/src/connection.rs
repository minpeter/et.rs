use std::io::{self, Read, Write};
use std::net::TcpStream;

use et_core::backed_reader::{BackedReader, ReadError, ReadItem};
use et_core::backed_writer::{BackedWriter, RecoverError, WriterOutcome};
use et_core::crypto::{
    CryptoHandler, EncryptError, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT, KEY_LEN,
};
use et_core::proto::{CatchupBuffer, SequenceHeader};

use crate::framing_io::{read_proto, write_proto};

#[derive(Debug)]
pub enum ConnError {
    Io(io::Error),
    Read(ReadError),
    Recover(RecoverError),
    Encrypt(EncryptError),
    Backpressure,
    SequenceOutOfRange(i64),
}

impl From<io::Error> for ConnError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ReadError> for ConnError {
    fn from(e: ReadError) -> Self {
        Self::Read(e)
    }
}
impl From<RecoverError> for ConnError {
    fn from(e: RecoverError) -> Self {
        Self::Recover(e)
    }
}
impl From<EncryptError> for ConnError {
    fn from(e: EncryptError) -> Self {
        Self::Encrypt(e)
    }
}
impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Read(e) => write!(f, "read: {e}"),
            Self::Recover(e) => write!(f, "recover: {e}"),
            Self::Encrypt(e) => write!(f, "encrypt: {e}"),
            Self::Backpressure => write!(f, "disconnected write buffer is full"),
            Self::SequenceOutOfRange(sequence) => {
                write!(f, "sequence number {sequence} exceeds the wire format")
            }
        }
    }
}
impl std::error::Error for ConnError {}

pub struct Connection {
    stream: TcpStream,
    writer: BackedWriter,
    reader: BackedReader,
}

impl Connection {
    pub fn new_client(stream: TcpStream, key: &[u8; KEY_LEN]) -> Self {
        let enc = CryptoHandler::new(key, DIR_CLIENT_TO_SERVER);
        let dec = CryptoHandler::new(key, DIR_SERVER_TO_CLIENT);
        Self {
            stream,
            writer: BackedWriter::new(enc, true),
            reader: BackedReader::new(dec, true),
        }
    }

    pub fn new_server(stream: TcpStream, key: &[u8; KEY_LEN]) -> Self {
        let enc = CryptoHandler::new(key, DIR_SERVER_TO_CLIENT);
        let dec = CryptoHandler::new(key, DIR_CLIENT_TO_SERVER);
        Self {
            stream,
            writer: BackedWriter::new(enc, true),
            reader: BackedReader::new(dec, true),
        }
    }

    pub fn write_terminal(&mut self, bytes: &[u8]) -> Result<(), ConnError> {
        match self.writer.write_packet(0, bytes)? {
            WriterOutcome::Send(frame) => {
                self.stream.write_all(&frame)?;
                Ok(())
            }
            WriterOutcome::BufferedOnly => Ok(()),
            WriterOutcome::Skipped => Err(ConnError::Backpressure),
        }
    }

    pub fn read_terminal(&mut self) -> Result<Vec<u8>, ConnError> {
        loop {
            match self.reader.pop()? {
                ReadItem::Packet(packet) => return Ok(packet.payload().to_vec()),
                ReadItem::NeedMore => {}
            }

            let mut buf = [0u8; 8192];
            match self.stream.read(&mut buf) {
                Ok(0) => return Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into())),
                Ok(n) => self.reader.feed(&buf[..n]),
                Err(e) => return Err(ConnError::Io(e)),
            }
        }
    }

    pub fn disconnect(&mut self) {
        self.writer.invalidate();
        self.reader.invalidate();
    }

    pub fn recover(&mut self, new_stream: TcpStream) -> Result<(), ConnError> {
        let local_seq = self.reader.sequence();
        let wire_sequence =
            i32::try_from(local_seq).map_err(|_| ConnError::SequenceOutOfRange(local_seq))?;
        let header = SequenceHeader {
            sequence_number: Some(wire_sequence),
        };
        write_proto(&mut new_stream.try_clone()?, &header)?;

        let remote_header: SequenceHeader = read_proto(&mut new_stream.try_clone()?)?;
        let catchup_packets = self
            .writer
            .recover(i64::from(remote_header.sequence_number.unwrap_or(0)))?;
        let catchup = CatchupBuffer {
            buffer: catchup_packets,
        };
        write_proto(&mut new_stream.try_clone()?, &catchup)?;

        let remote_catchup: CatchupBuffer = read_proto(&mut new_stream.try_clone()?)?;
        self.reader.revive(remote_catchup.buffer);
        self.writer.revive();
        self.stream = new_stream;
        Ok(())
    }

    pub fn writer_sequence(&self) -> i64 {
        self.writer.sequence()
    }

    pub fn reader_sequence(&self) -> i64 {
        self.reader.sequence()
    }
}
