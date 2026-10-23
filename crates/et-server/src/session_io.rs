use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use et_core::backed_writer::{
    MAX_BACKUP_PACKETS, MAX_DISCONNECT_PACKETS, MAX_RECOVERY_BACKUP_BYTES,
};
use et_net::local::LocalStream;

use super::{ActiveSession, SessionError};

impl ActiveSession {
    pub(crate) fn take_wake_reader(&self) -> Result<LocalStream, SessionError> {
        self.wake_reader
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .take()
            .ok_or(SessionError::Unavailable)
    }

    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn try_clone_stream(&self) -> Result<(TcpStream, u64), SessionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        let generation = self.connection_generation.load(Ordering::Acquire);
        let stream = connection
            .try_clone_stream()
            .map_err(SessionError::Connection)?;
        Ok((stream, generation))
    }

    pub(crate) fn has_buffered_read(&self) -> bool {
        self.reader
            .lock()
            .is_ok_and(|reader| reader.has_buffered_read())
    }

    /// Read through the receive half: the output writer keeps the connection
    /// lock for its frames, and recovery swaps this handle only between reads.
    pub(crate) fn try_read_packet(&self) -> Result<Option<et_core::packet::Packet>, SessionError> {
        let packet = self
            .reader
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .try_read_packet()
            .map_err(SessionError::Connection)?;
        if !self.pipe_mode {
            if let (Some(flow), Some(packet)) = (self.output_flow(), packet.as_ref()) {
                if packet.header() == et_core::proto::TerminalPacketType::TerminalBuffer as u8 {
                    if let Some((bytes, _)) =
                        et_core::packet::decode_terminal_buffer(packet.payload())
                    {
                        flow.observe_input(bytes)?;
                    } else {
                        use prost::Message;
                        let input = et_core::proto::TerminalBuffer::decode(packet.payload())
                            .map_err(|error| {
                                SessionError::Io(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    error,
                                ))
                            })?;
                        if let Some(bytes) = input.buffer {
                            flow.observe_input(&bytes)?;
                        }
                    }
                }
            }
        }
        Ok(packet)
    }

    pub(crate) fn note_bridge_generation(&self, generation: u64) -> Result<(), SessionError> {
        let mut observed = self
            .bridge_generation
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if generation > *observed {
            *observed = generation;
            self.bridge_changed.notify_all();
        }
        Ok(())
    }

    pub(crate) fn wait_for_bridge_generation(
        &self,
        expected: u64,
        timeout: Duration,
    ) -> Result<(), SessionError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(SessionError::Unavailable)?;
        let mut observed = self
            .bridge_generation
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        while *observed < expected {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(SessionError::RecoverBusy)?;
            let (next, result) = self
                .bridge_changed
                .wait_timeout(observed, remaining)
                .map_err(|_| SessionError::Unavailable)?;
            observed = next;
            if result.timed_out() && *observed < expected {
                return Err(SessionError::RecoverBusy);
            }
        }
        Ok(())
    }

    pub(crate) fn connection_state(&self) -> Result<(bool, u64), SessionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        Ok((
            connection.connected(),
            self.connection_generation.load(Ordering::Acquire),
        ))
    }

    /// Soft-drop the encrypted client transport without killing the terminal.
    ///
    /// Used when the client TCP path dies (sleep, Wi-Fi, NAT) so terminal
    /// output keeps buffering and a returning client can recover the same
    /// session. Does not set the session shutdown flag or close the terminal.
    pub(crate) fn mark_client_disconnected(
        &self,
        expected_generation: u64,
    ) -> Result<bool, SessionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if self.connection_generation.load(Ordering::Acquire) != expected_generation {
            return Ok(false);
        }
        connection.disconnect();
        if let Some(state) = self.output_flow() {
            state.disconnected();
        }
        Ok(true)
    }

    /// Apply a client delivery acknowledgement to the replay backup.
    pub(crate) fn acknowledge_delivery(&self, sequence: i64) -> Result<(), SessionError> {
        self.connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .acknowledge_delivery(sequence);
        Ok(())
    }

    /// Apply a client keep-alive's delivery acknowledgement, if any, and
    /// build the echo's payload: this side's acknowledgement when it tells
    /// the client something new, otherwise upstream's empty payload (see
    /// [`et_core::keepalive::AckSchedule`]).
    pub(crate) fn keepalive_echo(
        &self,
        acknowledged: Option<i64>,
    ) -> Result<Vec<u8>, SessionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if let Some(sequence) = acknowledged {
            connection.acknowledge_delivery(sequence);
        }
        let ack = connection.next_keepalive_ack(et_core::keepalive::AckSide::Responder, false);
        Ok(et_core::keepalive::ack_bytes(&ack).to_vec())
    }

    pub(crate) fn can_buffer_write(&self, bytes: i64) -> Result<bool, SessionError> {
        if let Some(state) = self.output_flow() {
            let bytes = usize::try_from(bytes).map_err(|_| SessionError::Unavailable)?;
            return state.can_accept_terminal(bytes);
        }
        let hold = self
            .recover_hold
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        if hold.len() >= MAX_BACKUP_PACKETS + MAX_DISCONNECT_PACKETS {
            return Ok(false);
        }
        let held =
            i64::try_from(self.recover_hold_bytes.load(Ordering::Acquire)).unwrap_or(i64::MAX);
        let requested = held.checked_add(bytes).unwrap_or(i64::MAX);
        if requested > MAX_RECOVERY_BACKUP_BYTES {
            return Ok(false);
        }
        Ok(self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .can_buffer_write(requested))
    }

    pub(crate) fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Wake the terminal bridge. Never blocks: a full wake channel already
    /// holds a pending wake.
    pub(super) fn signal(&self) -> Result<(), SessionError> {
        let mut wake = self
            .wake_writer
            .lock()
            .map_err(|_| SessionError::Unavailable)?;
        loop {
            match wake.write(&[1]) {
                Ok(_) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(SessionError::Io(error)),
            }
        }
    }
}
