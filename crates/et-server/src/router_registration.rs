use et_net::local::LocalStream;

use et_core::packet::Packet;
use et_core::proto::{TerminalPacketType, TerminalUserInfo};
use prost::Message;

use crate::registry::{RegisteredTerminal, RegistrationError, Registry};
use crate::registry_validation::PeerIdentity;
use crate::router::RouterReject;

/// A refused registration.
pub(crate) struct Rejection {
    pub(crate) reason: RouterReject,
    /// The terminal registered with the `fd = -6` sentinel, so it waits for
    /// an error `REGISTRATION_STATUS`. Any other terminal (ET C++ included)
    /// treats an unexpected packet as fatal and is closed silently, like
    /// upstream `UserTerminalRouter::registerTerminal`.
    pub(crate) wants_status: bool,
}

pub(crate) fn process(
    packet: Packet,
    stream: LocalStream,
    registry: &Registry,
    peer: PeerIdentity,
) -> Result<RegisteredTerminal, Rejection> {
    let silent = |reason| Rejection {
        reason,
        wants_status: false,
    };
    if packet.is_encrypted() {
        return Err(silent(RouterReject::Encrypted));
    }
    if packet.header() != TerminalPacketType::TerminalUserInfo as u8 {
        return Err(silent(RouterReject::WrongPacketType));
    }
    let info = TerminalUserInfo::decode(packet.payload())
        .map_err(|_| silent(RouterReject::MalformedUserInfo))?;
    let wants_status = info.fd == Some(-6);
    registry
        .register(info, stream, peer)
        .map_err(|error| Rejection {
            reason: map_error(error),
            wants_status,
        })
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
