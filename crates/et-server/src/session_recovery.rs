use std::net::{Shutdown, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use et_core::proto::TerminalPacketType;
use et_net::connection::DEFAULT_RECOVERY_TIMEOUT;

use super::{ActiveSession, SessionError, RECOVERY_LOCK_TIMEOUT};

impl ActiveSession {
    /// Acquire the single-flight recover permit without speaking on the wire.
    ///
    /// Callers must send `ReturningClient` only after this succeeds, so a
    /// concurrent recover does not commit the peer to sequence exchange and
    /// then fail with `RecoverBusy`. The permit releases the flag on drop
    /// (including panic unwind).
    pub(crate) fn try_begin_recover(&self) -> Result<RecoverPermit<'_>, SessionError> {
        if self
            .recovering
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(SessionError::RecoverBusy);
        }
        Ok(RecoverPermit { session: self })
    }

    /// Prepare → network handshake off-lock → install → flush hold.
    ///
    /// The connection mutex is held only for soft-disconnect/snapshot and for
    /// installing the new stream, not for sequence exchange or peer auth.
    fn recover_body(&self, stream: TcpStream) -> Result<(), SessionError> {
        if let Some(flow) = &self.flow_control {
            flow.pause()?;
        }
        // Phase 1: soft-disconnect and snapshot under a short lock.
        let mut candidate = {
            let connection = lock_timeout(&self.connection, RECOVERY_LOCK_TIMEOUT)?;
            // Snapshot onto the new stream without closing or disconnecting
            // the live victim socket (ET #784 / ANT-2026-VAMER5RC). Terminal
            // output during the off-lock handshake is queued in
            // `recover_hold` because `recovering` is set. A failed recover
            // must leave the existing session intact.
            connection.prepare_recovery_candidate(stream)
        };

        // Phase 2: recovery network I/O without the session connection lock.
        candidate
            .run_recovery_handshake(DEFAULT_RECOVERY_TIMEOUT)
            .map_err(SessionError::Connection)?;
        // Any packet that decrypts with the session key authenticates the
        // returning client; it is requeued and handled by the session loop.
        candidate
            .authenticate_peer(DEFAULT_RECOVERY_TIMEOUT)
            .map_err(SessionError::Connection)?;
        if self.flow_control.is_some() {
            candidate
                .minimize_output_buffering()
                .map_err(SessionError::Connection)?;
        }
        let ack = candidate.keepalive_ack();
        candidate
            .write_packet(TerminalPacketType::KeepAlive as u8, &ack)
            .map_err(SessionError::Connection)?;
        let new_control = candidate
            .try_clone_stream()
            .map_err(SessionError::Connection)?;

        // Phase 3: install under a short lock.
        {
            let mut control = lock_timeout(&self.control, RECOVERY_LOCK_TIMEOUT)?;
            let mut connection = lock_timeout(&self.connection, RECOVERY_LOCK_TIMEOUT)?;
            let old_control = std::mem::replace(&mut *control, new_control);
            let _ = old_control.shutdown(Shutdown::Both);
            *connection = candidate;
            self.connection_generation.fetch_add(1, Ordering::Release);
        }

        // Phase 4: drain terminal output queued while the handshake ran.
        // Still under `recovering` so concurrent send_packet keeps queuing
        // until the permit drops; Drop flushes once more after clearing.
        self.flush_recover_hold()
    }

    fn flush_recover_hold(&self) -> Result<(), SessionError> {
        loop {
            let batch = {
                let mut hold = self
                    .recover_hold
                    .lock()
                    .map_err(|_| SessionError::Unavailable)?;
                if hold.is_empty() {
                    return Ok(());
                }
                std::mem::take(&mut *hold)
            };
            let mut connection = lock_timeout(&self.connection, RECOVERY_LOCK_TIMEOUT)?;
            let mut remaining = batch.into_iter();
            while let Some((header, payload)) = remaining.next() {
                if let Err(error) = connection.write_packet(header, &payload) {
                    // Release the connection lock before taking `recover_hold`
                    // (send_packet may hold hold → connection; reverse deadlocks).
                    drop(connection);
                    // Put the failed packet and unwritten tail back ahead of
                    // anything concurrent senders queued after we took `batch`.
                    let mut hold = self
                        .recover_hold
                        .lock()
                        .map_err(|_| SessionError::Unavailable)?;
                    let concurrent = std::mem::take(&mut *hold);
                    hold.push((header, payload));
                    hold.extend(remaining);
                    hold.extend(concurrent);
                    return Err(SessionError::Connection(error));
                }
            }
        }
    }
}

/// Single-flight recover permit. Dropping it (normally or on panic) always
/// clears [`ActiveSession::recovering`] and wakes the terminal bridge.
pub(crate) struct RecoverPermit<'a> {
    session: &'a ActiveSession,
}

impl RecoverPermit<'_> {
    /// Run the recovery handshake and install the new stream.
    pub(crate) fn complete(self, stream: TcpStream) -> Result<(), SessionError> {
        // `self` drops after this returns (or panics), clearing `recovering`
        // and flushing any straggler hold packets.
        self.session.recover_body(stream)
    }
}

impl Drop for RecoverPermit<'_> {
    fn drop(&mut self) {
        // Flush while still marked recovering so send_packet keeps queuing
        // rather than racing into a half-installed connection.
        let _ = self.session.flush_recover_hold();
        self.session.recovering.store(false, Ordering::Release);
        // Catch anything that observed `recovering` and queued after the first
        // flush but before the flag cleared (re-check is under the hold lock).
        let _ = self.session.flush_recover_hold();
        if let Some(state) = &self.session.flow_control {
            let connected = self
                .session
                .connection
                .lock()
                .is_ok_and(|connection| connection.connected());
            state.resume(connected);
        }
        // Wake the bridge even on failure so it re-checks connection state.
        let _ = self.session.signal();
    }
}

/// Acquire a [`Mutex`] with a deadline so recover cannot park forever behind a
/// bridge thread blocked in a live write.
fn lock_timeout<T>(mutex: &Mutex<T>, timeout: Duration) -> Result<MutexGuard<'_, T>, SessionError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(SessionError::RecoverBusy)?;
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err(SessionError::Unavailable),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(SessionError::RecoverBusy);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}
