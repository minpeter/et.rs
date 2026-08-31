use et_core::packet::Packet;

use super::FlowControl;
use crate::session::{ActiveSession, SessionError};

#[cfg(unix)]
pub(super) fn write_packet(
    session: &ActiveSession,
    flow: &FlowControl,
    packet: &Packet,
) -> (Result<(), SessionError>, bool) {
    let prepared = match session.connection.lock() {
        Ok(_connection) if flow.is_hard_stopped() => {
            return (Err(SessionError::Unavailable), false);
        }
        Ok(mut connection) => connection
            .prepare_write_packet(packet.header(), packet.payload())
            .map_err(SessionError::Connection),
        Err(_) => Err(SessionError::Unavailable),
    };
    let result = prepared.and_then(|prepared| prepared.send().map_err(SessionError::Connection));
    match session.connection.lock() {
        Ok(mut connection) => {
            if result.is_err() {
                connection.disconnect();
            }
            (result, connection.connected())
        }
        Err(_) => (Err(SessionError::Unavailable), false),
    }
}

#[cfg(windows)]
pub(super) fn write_packet(
    session: &ActiveSession,
    flow: &FlowControl,
    packet: &Packet,
) -> (Result<(), SessionError>, bool) {
    match session.connection.lock() {
        Ok(_) if flow.is_hard_stopped() => (Err(SessionError::Unavailable), false),
        Ok(mut connection) => {
            let result = connection
                .write_packet(packet.header(), packet.payload())
                .map_err(SessionError::Connection);
            (result, connection.connected())
        }
        Err(_) => (Err(SessionError::Unavailable), false),
    }
}
