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

#[cfg(unix)]
pub(crate) fn write_packet(
    session: &ActiveSession,
    flow: &FlowControl,
    packet: &Packet,
) -> (FlowWriteResult, bool) {
    write_packet_with(session, flow, packet, |connection, packet| {
        connection.prepare_write_packet(packet.header(), packet.payload())
    })
}

#[cfg(unix)]
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
    let prepared = match session.connection.lock() {
        Ok(_connection) if flow.is_hard_stopped() => {
            return (FlowWriteResult::Fatal(SessionError::Unavailable), false);
        }
        Ok(mut connection) => prepare(&mut connection, packet),
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
        Ok(()) => FlowWriteResult::Delivered,
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

#[cfg(windows)]
pub(crate) fn write_packet(
    session: &ActiveSession,
    flow: &FlowControl,
    packet: &Packet,
) -> (FlowWriteResult, bool) {
    let _write_serial = match session.write_serial.lock() {
        Ok(guard) => guard,
        Err(_) => return (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    };
    match session.connection.lock() {
        Ok(_) if flow.is_hard_stopped() => {
            (FlowWriteResult::Fatal(SessionError::Unavailable), false)
        }
        Ok(mut connection) => {
            let result = match connection.write_packet_owned(packet.header(), packet.payload()) {
                Ok(()) => FlowWriteResult::Delivered,
                Err(WritePacketError::BeforeReplay(ConnError::Io(error))) => {
                    connection.disconnect();
                    FlowWriteResult::BeforeReplay(SessionError::Connection(ConnError::Io(error)))
                }
                Err(WritePacketError::BeforeReplay(error)) => {
                    FlowWriteResult::Fatal(SessionError::Connection(error))
                }
                Err(WritePacketError::ReplayOwned(error)) => {
                    FlowWriteResult::ReplayOwned(SessionError::Connection(error))
                }
            };
            (result, connection.connected())
        }
        Err(_) => (FlowWriteResult::Fatal(SessionError::Unavailable), false),
    }
}
