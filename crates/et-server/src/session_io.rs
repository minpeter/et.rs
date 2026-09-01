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

    pub(crate) fn try_read_packet(&self) -> Result<Option<et_core::packet::Packet>, SessionError> {
        if let Some(flow) = &self.flow_control {
            flow.set_reader_waiting(true);
        }
        let result = (|| {
            self.connection
                .lock()
                .map_err(|_| SessionError::Unavailable)?
                .try_read_packet()
                .map_err(SessionError::Connection)
        })();
        if let Some(flow) = &self.flow_control {
            flow.set_reader_waiting(false);
        }
        result
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
        if let Some(state) = &self.flow_control {
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

    /// Keep-alive payload acknowledging everything read from the client.
    pub(crate) fn keepalive_ack(
        &self,
    ) -> Result<[u8; et_core::keepalive::ACK_PAYLOAD_LEN], SessionError> {
        Ok(self
            .connection
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .keepalive_ack())
    }

    pub(crate) fn can_buffer_write(&self, bytes: i64) -> Result<bool, SessionError> {
        if let Some(state) = &self.flow_control {
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

    pub(super) fn signal(&self) -> Result<(), SessionError> {
        self.wake_writer
            .lock()
            .map_err(|_| SessionError::Unavailable)?
            .write_all(&[1])
            .map_err(SessionError::Io)
    }
}
