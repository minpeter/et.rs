use et_net::local::LocalStream;

use et_core::packet::Packet;
use et_core::proto::{TerminalPacketType, TerminalUserInfo};
use prost::Message;

use crate::registry::{RegisteredTerminal, RegistrationError, Registry};
use crate::registry_validation::PeerIdentity;
use crate::router::RouterReject;

pub(crate) fn process(
    packet: Packet,
    stream: LocalStream,
    registry: &Registry,
    peer: PeerIdentity,
) -> Result<RegisteredTerminal, RouterReject> {
    if packet.is_encrypted() {
        return Err(RouterReject::Encrypted);
    }
    if packet.header() != TerminalPacketType::TerminalUserInfo as u8 {
        return Err(RouterReject::WrongPacketType);
    }
    let info =
        TerminalUserInfo::decode(packet.payload()).map_err(|_| RouterReject::MalformedUserInfo)?;
    registry.register(info, stream, peer).map_err(map_error)
}

fn map_error(error: RegistrationError) -> RouterReject {
    match error {
        RegistrationError::Invalid => RouterReject::InvalidRegistration,
        RegistrationError::Duplicate => RouterReject::Duplicate,
        RegistrationError::Unavailable | RegistrationError::Timeout | RegistrationError::Io(_) => {
            RouterReject::RegistryUnavailable
        }
    }
}
