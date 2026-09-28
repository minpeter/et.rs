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
use crate::handshake::MAX_HANDSHAKE_PROTO_LEN;

pub const MAX_RECOVERY_PROTO_LEN: i64 = 80 * 1024 * 1024;
pub const DEFAULT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);

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

    /// Snapshot writer/reader state onto `new_stream` without network I/O.
    ///
    /// Used by the server session path so the connection mutex can be released
    /// for the duration of [`Self::run_recovery_handshake`].
    pub fn prepare_recovery_candidate(&self, new_stream: TcpStream) -> Self {
        let mut candidate = Self {
            stream: new_stream,
            writer: self.writer.clone(),
            reader: self.reader.clone(),
            live_write_timeout: self.live_write_timeout,
            read_peer_catchup_first: self.read_peer_catchup_first,
        };
        candidate.disconnect();
        candidate
    }

    /// Sequence exchange, catchup transfer, and stream revive on a prepared
    /// recovery candidate. Safe to run without holding the session mutex.
    pub fn run_recovery_handshake(&mut self, timeout: Duration) -> Result<(), ConnError> {
        self.run_recovery_handshake_planned(timeout, None)
    }

    /// Sequence exchange. `reset_salt` is set only when the authenticated
    /// handshake selected reset recovery. A `SequenceHeader.reset` that was
    /// not selected is rejected.
    pub fn run_recovery_handshake_planned(
        &mut self,
        timeout: Duration,
        reset_salt: Option<&[u8]>,
    ) -> Result<(), ConnError> {
        let deadline = recovery_deadline(timeout)?;
        match self.exchange_recovery(deadline, reset_salt) {
            Ok(remote_catchup) => {
                if let Some(salt) = reset_salt {
                    self.reader
                        .reset_epoch(salt)
                        .map_err(|_| ConnError::ResetSaltMismatch)?;
                    self.writer
                        .reset_epoch(salt)
                        .map_err(|_| ConnError::ResetSaltMismatch)?;
                } else {
                    self.reader.revive(remote_catchup.buffer)?;
                    self.writer.revive();
                }
                self.set_io_timeout(None)?;
                Ok(())
            }
            Err(error) => {
                let _ = self.stream.shutdown(Shutdown::Both);
                Err(error)
            }
        }
    }

    /// Reset recovery on the socket this connection already owns.
    ///
    /// A fresh process (`--attach`, or the first connect of a client that
    /// asked for reset) has no prior sequence history. Both sides echo the
    /// authenticated salt, exchange empty catchup, and rekey.
    pub fn reset_in_place(&mut self, salt: &[u8], timeout: Duration) -> Result<(), ConnError> {
        let deadline = recovery_deadline(timeout)?;
        self.exchange_recovery(deadline, Some(salt))?;
        self.reader
            .reset_epoch(salt)
            .map_err(|_| ConnError::ResetSaltMismatch)?;
        self.writer
            .reset_epoch(salt)
            .map_err(|_| ConnError::ResetSaltMismatch)?;
        self.set_io_timeout(None)?;
        Ok(())
    }

    pub fn recovery_candidate(
        &self,
        new_stream: TcpStream,
        timeout: Duration,
    ) -> Result<Self, ConnError> {
        let mut candidate = self.prepare_recovery_candidate(new_stream);
        candidate.run_recovery_handshake(timeout)?;
        Ok(candidate)
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

    fn exchange_recovery(
        &self,
        deadline: Instant,
        reset_salt: Option<&[u8]>,
    ) -> Result<CatchupBuffer, ConnError> {
        let (wire_sequence, reset) = if let Some(salt) = reset_salt {
            if salt.len() != et_core::crypto::EPOCH_SALT_BYTES {
                return Err(ConnError::ResetSaltMismatch);
            }
            (0, Some(salt.to_vec()))
        } else {
            let local_sequence = self.reader.sequence();
            let wire_sequence = i32::try_from(local_sequence)
                .map_err(|_| ConnError::SequenceOutOfRange(local_sequence))?;
            (wire_sequence, None)
        };
        let mut stream = self.stream.try_clone()?;
        write_proto_limited_deadline(
            &mut stream,
            &SequenceHeader {
                sequence_number: Some(wire_sequence),
                reset: reset.as_ref().map(|_| true),
                reset_salt: reset.clone(),
            },
            MAX_HANDSHAKE_PROTO_LEN,
            deadline,
        )?;
        let remote: SequenceHeader =
            read_proto_limited_deadline(&mut stream, MAX_HANDSHAKE_PROTO_LEN, deadline)?;
        let remote_reset = remote.reset.unwrap_or(false);
        let remote_salt = remote.reset_salt.clone().unwrap_or_default();
        if let Some(salt) = reset_salt {
            if !remote_reset || remote_salt.as_slice() != salt {
                return Err(ConnError::ResetSaltMismatch);
            }
        } else if remote_reset || !remote_salt.is_empty() {
            return Err(ConnError::UnexpectedReset);
        }
        let local_catchup = if reset_salt.is_some() {
            CatchupBuffer { buffer: Vec::new() }
        } else {
            let remote_sequence = match remote.sequence_number {
                Some(sequence) if sequence >= 0 => i64::from(sequence),
                value => return Err(ConnError::InvalidRecoverySequence(value)),
            };
            CatchupBuffer {
                buffer: self.writer.recover(remote_sequence)?,
            }
        };
        let encoded = if self.read_peer_catchup_first {
            let encoded =
                read_frame_limited_deadline(&mut stream, MAX_RECOVERY_PROTO_LEN, deadline)?;
            write_proto_limited_deadline(
                &mut stream,
                &local_catchup,
                MAX_RECOVERY_PROTO_LEN,
                deadline,
            )?;
            encoded
        } else {
            write_proto_limited_deadline(
                &mut stream,
                &local_catchup,
                MAX_RECOVERY_PROTO_LEN,
                deadline,
            )?;
            read_frame_limited_deadline(&mut stream, MAX_RECOVERY_PROTO_LEN, deadline)?
        };
        if reset_salt.is_some() {
            return Ok(CatchupBuffer { buffer: Vec::new() });
        }
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
