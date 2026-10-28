use et_core::packet::Packet;
use et_net::connection::{ConnError, WritePacketError};

use super::FlowControl;
use crate::session::{ActiveSession, SessionError};

pub(crate) enum FlowWriteResult {
    Delivered,
    BeforeReplay(SessionError),
    ReplayOwned(SessionError),
    Fatal(SessionError),
}

pub(crate) fn write_packet(
    session: &ActiveSession,
    flow: &FlowControl,
    packet: &Packet,
) -> (FlowWriteResult, bool) {
    let _write_serial = match session.write_serial.lock() {
        Ok(guard) => guard,
        Err(_) => return (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    };
    let reserved = match session.connection.lock() {
        Ok(_connection) if flow.is_hard_stopped() => {
            return (FlowWriteResult::Fatal(SessionError::Unavailable), false);
        }
        Ok(mut connection) => {
            connection.reserve_write_packet(packet.header(), packet.payload().len())
        }
        Err(_) => return (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    };
    let reserved = match reserved {
        Ok(reserved) => reserved,
        Err(WritePacketError::BeforeReplay(ConnError::Io(error))) => {
            if let Ok(mut connection) = session.connection.lock() {
                connection.disconnect();
            }
            return (
                FlowWriteResult::BeforeReplay(SessionError::Connection(ConnError::Io(error))),
                false,
            );
        }
        Err(WritePacketError::BeforeReplay(error)) => {
            if let Ok(mut connection) = session.connection.lock() {
                connection.disconnect();
            }
            return (
                FlowWriteResult::Fatal(SessionError::Connection(error)),
                false,
            );
        }
        Err(WritePacketError::ReplayOwned(error)) => {
            if let Ok(mut connection) = session.connection.lock() {
                connection.disconnect();
            }
            return (
                FlowWriteResult::ReplayOwned(SessionError::Connection(error)),
                false,
            );
        }
    };
    let frame = reserved.encrypt(packet.payload());
    let (prepared, was_connected) = match session.connection.lock() {
        Ok(mut connection) => (
            connection.commit_write_packet(reserved, frame),
            connection.connected(),
        ),
        Err(_) => return (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    };
    #[cfg(test)]
    if let Some((reached, release)) = session.prepared_write_hook.lock().unwrap().take() {
        reached.send(()).unwrap();
        release
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
    }
    let result = match prepared.send() {
        Ok(()) => return (FlowWriteResult::Delivered, was_connected),
        Err(WritePacketError::BeforeReplay(ConnError::Io(error))) => {
            FlowWriteResult::BeforeReplay(SessionError::Connection(ConnError::Io(error)))
        }
        Err(WritePacketError::BeforeReplay(error)) => {
            FlowWriteResult::Fatal(SessionError::Connection(error))
        }
        Err(WritePacketError::ReplayOwned(error)) => {
            FlowWriteResult::ReplayOwned(SessionError::Connection(error))
        }
    };
    match session.connection.lock() {
        Ok(mut connection) => {
            connection.disconnect();
            (result, connection.connected())
        }
        Err(_) => (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    }
}

#[cfg(unix)]
pub(crate) enum NonblockingWrite {
    /// The frame waits for transport room until this live-write deadline.
    Pending(std::time::Instant),
    /// The transport has no room to start this packet's frame; nothing was
    /// written and the packet stays droppable. Wait for writability until
    /// this deadline, past which the frame starts and fails as a stuck one.
    NoRoom(std::time::Instant),
    Done(FlowWriteResult, bool),
}

/// Start `packet`'s frame, or advance it once `started`, without blocking.
/// Both steps hold `write_serial` and the connection lock, so a synchronous
/// writer finishes a still-pending frame before it assigns its own.
///
/// A frame starts only while the transport has room (see
/// [`et_net::connection::Connection::has_write_room`]), as upstream
/// `drainWriteBufferToClient` checks `isSocketWritable` before each packet:
/// the kernel then takes a whole frame of at most the unsent low-water mark,
/// and Ctrl+C can still drop everything behind it. `room_wait` is when queued
/// output started waiting for room; after a live-write timeout without room
/// the frame starts anyway with the deadline counted from then, so a stuck
/// transport still fails as it did when every frame started at once.
#[cfg(unix)]
pub(crate) fn write_nonblocking(
    session: &ActiveSession,
    flow: &FlowControl,
    packet: &Packet,
    started: bool,
    room_wait: &mut Option<std::time::Instant>,
) -> NonblockingWrite {
    let Ok(_write_serial) = session.write_serial.lock() else {
        return NonblockingWrite::Done(FlowWriteResult::Fatal(SessionError::Unavailable), false);
    };
    let Ok(mut connection) = session.connection.lock() else {
        return NonblockingWrite::Done(FlowWriteResult::Fatal(SessionError::Unavailable), false);
    };
    if flow.is_hard_stopped() {
        return NonblockingWrite::Done(FlowWriteResult::Fatal(SessionError::Unavailable), false);
    }
    let step = if started {
        connection.advance_write()
    } else {
        if connection.has_write_room() {
            *room_wait = None;
        } else {
            let now = std::time::Instant::now();
            let deadline = connection.live_write_deadline(*room_wait.get_or_insert(now));
            if now < deadline {
                return NonblockingWrite::NoRoom(deadline);
            }
        }
        let step = connection
            .start_write_packet_owned_unprobed(packet.header(), packet.payload())
            .map(|()| !connection.write_pending());
        if let Some(since) = room_wait.take() {
            connection.backdate_pending_write(since);
        }
        step
    };
    let result = match step {
        Ok(true) => FlowWriteResult::Delivered,
        Ok(false) => match connection.pending_write_deadline() {
            Some(deadline) => return NonblockingWrite::Pending(deadline),
            None => FlowWriteResult::Delivered,
        },
        Err(WritePacketError::BeforeReplay(ConnError::Io(error))) => {
            FlowWriteResult::BeforeReplay(SessionError::Connection(ConnError::Io(error)))
        }
        Err(WritePacketError::BeforeReplay(error)) => {
            FlowWriteResult::Fatal(SessionError::Connection(error))
        }
        Err(WritePacketError::ReplayOwned(error)) => {
            FlowWriteResult::ReplayOwned(SessionError::Connection(error))
        }
    };
    if !matches!(result, FlowWriteResult::Delivered) {
        connection.disconnect();
    }
    NonblockingWrite::Done(result, connection.connected())
}

pub(crate) fn finish_pending_packet(
    session: &ActiveSession,
    flow: &FlowControl,
) -> (FlowWriteResult, bool) {
    let _write_serial = match session.write_serial.lock() {
        Ok(guard) => guard,
        Err(_) => return (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    };
    let (finish, was_connected) = match session.connection.lock() {
        Ok(_connection) if flow.is_hard_stopped() => {
            return (FlowWriteResult::Fatal(SessionError::Unavailable), false);
        }
        Ok(mut connection) => (
            connection.finish_pending_live_detached(),
            connection.connected(),
        ),
        Err(_) => return (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    };
    let Some(finish) = finish else {
        return (FlowWriteResult::Delivered, was_connected);
    };
    let result = match finish() {
        Ok(()) => return (FlowWriteResult::Delivered, was_connected),
        Err(WritePacketError::BeforeReplay(ConnError::Io(error))) => {
            FlowWriteResult::BeforeReplay(SessionError::Connection(ConnError::Io(error)))
        }
        Err(WritePacketError::BeforeReplay(error)) => {
            FlowWriteResult::Fatal(SessionError::Connection(error))
        }
        Err(WritePacketError::ReplayOwned(error)) => {
            FlowWriteResult::ReplayOwned(SessionError::Connection(error))
        }
    };
    match session.connection.lock() {
        Ok(mut connection) => {
            connection.disconnect();
            (result, connection.connected())
        }
        Err(_) => (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    }
}

#[cfg(test)]
pub(crate) fn write_packet_with<F>(
    session: &ActiveSession,
    flow: &FlowControl,
    packet: &Packet,
    prepare: F,
) -> (FlowWriteResult, bool)
where
    F: FnOnce(
        &mut et_net::connection::Connection,
        &Packet,
    ) -> Result<et_net::connection::PreparedWrite, WritePacketError>,
{
    let _write_serial = match session.write_serial.lock() {
        Ok(guard) => guard,
        Err(_) => return (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    };
    let (prepared, was_connected) = match session.connection.lock() {
        Ok(_connection) if flow.is_hard_stopped() => {
            return (FlowWriteResult::Fatal(SessionError::Unavailable), false);
        }
        Ok(mut connection) => {
            let res = prepare(&mut connection, packet);
            (res, connection.connected())
        }
        Err(_) => return (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    };
    #[cfg(test)]
    if let Some((reached, release)) = session.prepared_write_hook.lock().unwrap().take() {
        reached.send(()).unwrap();
        release
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
    }
    let result = match prepared.and_then(et_net::connection::PreparedWrite::send) {
        Ok(()) => return (FlowWriteResult::Delivered, was_connected),
        Err(WritePacketError::BeforeReplay(ConnError::Io(error))) => {
            FlowWriteResult::BeforeReplay(SessionError::Connection(ConnError::Io(error)))
        }
        Err(WritePacketError::BeforeReplay(error)) => {
            FlowWriteResult::Fatal(SessionError::Connection(error))
        }
        Err(WritePacketError::ReplayOwned(error)) => {
            FlowWriteResult::ReplayOwned(SessionError::Connection(error))
        }
    };
    match session.connection.lock() {
        Ok(mut connection) => {
            if matches!(
                result,
                FlowWriteResult::BeforeReplay(_) | FlowWriteResult::ReplayOwned(_)
            ) {
                connection.disconnect();
            }
            (result, connection.connected())
        }
        Err(_) => (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    }
}
