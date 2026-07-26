use std::io::{self, Read};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use et_core::backed_reader::ReadItem;
use et_core::backed_writer::{MAX_BACKUP_PACKETS, MAX_DISCONNECT_PACKETS};
use et_core::packet::Packet;
use et_core::proto::{CatchupBuffer, SequenceHeader};
use prost::Message;

use super::{ConnError, Connection};
use crate::framing_io::{
    read_frame_limited_deadline, read_proto_limited_deadline, write_proto_limited_deadline,
};

pub const MAX_RECOVERY_PROTO_LEN: i64 = 80 * 1024 * 1024;
pub const DEFAULT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RECOVERY_HEADER_LEN: i64 = 64 * 1024;

impl Connection {
    pub fn recover(&mut self, new_stream: TcpStream) -> Result<(), ConnError> {
        self.recover_with_timeout(new_stream, DEFAULT_RECOVERY_TIMEOUT)
    }

    pub fn recover_with_timeout(
        &mut self,
        new_stream: TcpStream,
        timeout: Duration,
    ) -> Result<(), ConnError> {
        let candidate = self.recovery_candidate(new_stream, timeout)?;
        let _ = self.stream.shutdown(Shutdown::Both);
        *self = candidate;
        Ok(())
    }

    pub fn recovery_candidate(
        &self,
        new_stream: TcpStream,
        timeout: Duration,
    ) -> Result<Self, ConnError> {
        let mut candidate = Self {
            stream: new_stream,
            writer: self.writer.clone(),
            reader: self.reader.clone(),
        };
        candidate.disconnect();
        let deadline = recovery_deadline(timeout)?;
        match candidate.exchange_recovery(deadline) {
            Ok(remote_catchup) => {
                candidate.reader.revive(remote_catchup.buffer)?;
                candidate.writer.revive();
                candidate.set_io_timeout(None)?;
                Ok(candidate)
            }
            Err(error) => {
                let _ = candidate.stream.shutdown(Shutdown::Both);
                Err(error)
            }
        }
    }

    /// Wait for one live packet on the revived stream and requeue it for the
    /// session loop. Successfully decrypting a packet proves the peer holds
    /// the session key, which is the only recovery proof required: upstream
    /// C++ peers do not send a dedicated proof packet, so the first packet
    /// may be any regular session traffic and must not be inspected or
    /// discarded.
    pub fn authenticate_peer(&mut self, timeout: Duration) -> Result<(), ConnError> {
        let packet = self.read_live_packet_until(recovery_deadline(timeout)?)?;
        self.reader.unread(packet);
        self.set_io_timeout(None)?;
        Ok(())
    }

    fn exchange_recovery(&self, deadline: Instant) -> Result<CatchupBuffer, ConnError> {
        let local_sequence = self.reader.sequence();
        let wire_sequence = i32::try_from(local_sequence)
            .map_err(|_| ConnError::SequenceOutOfRange(local_sequence))?;
        let mut stream = self.stream.try_clone()?;
        write_proto_limited_deadline(
            &mut stream,
            &SequenceHeader {
                sequence_number: Some(wire_sequence),
            },
            MAX_RECOVERY_HEADER_LEN,
            deadline,
        )?;
        let remote: SequenceHeader =
            read_proto_limited_deadline(&mut stream, MAX_RECOVERY_HEADER_LEN, deadline)?;
        let remote_sequence = match remote.sequence_number {
            Some(sequence) if sequence >= 0 => i64::from(sequence),
            value => return Err(ConnError::InvalidRecoverySequence(value)),
        };
        let catchup = CatchupBuffer {
            buffer: self.writer.recover(remote_sequence)?,
        };
        write_proto_limited_deadline(&mut stream, &catchup, MAX_RECOVERY_PROTO_LEN, deadline)?;
        let encoded = read_frame_limited_deadline(&mut stream, MAX_RECOVERY_PROTO_LEN, deadline)?;
        validate_catchup_encoding(&encoded)?;
        CatchupBuffer::decode(&*encoded)
            .map_err(|error| ConnError::Io(io::Error::new(io::ErrorKind::InvalidData, error)))
    }

    fn read_live_packet_until(&mut self, deadline: Instant) -> Result<Packet, ConnError> {
        loop {
            match self.reader.pop_live() {
                Ok(ReadItem::Packet(packet)) => return Ok(packet),
                Ok(ReadItem::NeedMore) => {}
                Err(error) => {
                    self.disconnect();
                    return Err(ConnError::Read(error));
                }
            }
            constrain_recovery_io(&self.stream, deadline)?;
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
}

fn recovery_deadline(timeout: Duration) -> Result<Instant, ConnError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(recovery_timed_out)
}

fn constrain_recovery_io(stream: &TcpStream, deadline: Instant) -> Result<(), ConnError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(recovery_timed_out)?;
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    Ok(())
}

fn recovery_timed_out() -> ConnError {
    ConnError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "recovery deadline elapsed",
    ))
}

fn validate_catchup_encoding(encoded: &[u8]) -> Result<(), ConnError> {
    let mut offset = 0usize;
    let mut entries = 0usize;
    while offset < encoded.len() {
        if encoded[offset] != 0x0a {
            return Err(invalid_catchup("catchup contains an unsupported field"));
        }
        offset += 1;
        let (length, consumed) = decode_varint(&encoded[offset..])
            .ok_or_else(|| invalid_catchup("catchup contains an invalid length"))?;
        offset = offset
            .checked_add(consumed)
            .ok_or_else(|| invalid_catchup("catchup length overflow"))?;
        let length = usize::try_from(length)
            .map_err(|_| invalid_catchup("catchup entry length overflow"))?;
        if length == 0 {
            return Err(invalid_catchup("catchup contains an empty entry"));
        }
        entries += 1;
        if entries > MAX_BACKUP_PACKETS + MAX_DISCONNECT_PACKETS {
            return Err(invalid_catchup("catchup contains too many entries"));
        }
        offset = offset
            .checked_add(length)
            .filter(|end| *end <= encoded.len())
            .ok_or_else(|| invalid_catchup("catchup entry exceeds frame"))?;
    }
    Ok(())
}

fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().copied().take(10).enumerate() {
        if index == 9 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn invalid_catchup(message: &'static str) -> ConnError {
    ConnError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

#[cfg(test)]
#[path = "connection_recovery_tests.rs"]
mod tests;
