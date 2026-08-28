use std::sync::mpsc::Receiver;
use std::sync::Arc;

use crate::registry::RegistrationIdentity;
use crate::runtime_error::RuntimeError;
use crate::runtime_state::RuntimeCore;
use crate::session::SessionConnection;

pub(crate) enum LifecycleEvent {
    TerminalDisconnected(RegistrationIdentity),
    Shutdown,
}

pub(crate) fn run(
    events: Receiver<LifecycleEvent>,
    core: Arc<RuntimeCore>,
) -> Result<(), RuntimeError> {
    let mut first_error = None;
    while let Ok(event) = events.recv() {
        match event {
            LifecycleEvent::TerminalDisconnected(identity) => {
                crate::diag::info(format!(
                    "terminal disconnected for registration id={}",
                    identity.id()
                ));
                match core.sessions.remove_registration(&identity) {
                    Ok(Some(removed)) => {
                        crate::diag::info(format!(
                            "id={}: removed session after terminal disconnect",
                            identity.id()
                        ));
                        if let Some(SessionConnection::Starting(stream)) = removed.connection {
                            if let Err(error) = core.raw_sockets.shutdown_registration(&identity) {
                                crate::diag::info(format!(
                                    "id={}: error shutting down raw sockets: {error}",
                                    identity.id()
                                ));
                                first_error.get_or_insert(error);
                            }
                            if let Err(error) = stream.shutdown(std::net::Shutdown::Both) {
                                crate::diag::info(format!(
                                    "id={}: error shutting down session connection: {error}",
                                    identity.id()
                                ));
                                first_error.get_or_insert(RuntimeError::Session(
                                    crate::session::SessionError::Io(error),
                                ));
                            }
                        }
                    }
                    Ok(None) => {
                        crate::diag::verbose(
                            1,
                            format!(
                                "id={}: terminal disconnect with no active session slot",
                                identity.id()
                            ),
                        );
                    }
                    Err(error) => {
                        crate::diag::info(format!(
                            "id={}: session table error on terminal disconnect: {error}",
                            identity.id()
                        ));
                        first_error.get_or_insert(RuntimeError::SessionTable(error));
                    }
                }
            }
            LifecycleEvent::Shutdown => return first_error.map_or(Ok(()), Err),
        }
    }
    first_error.map_or(Ok(()), Err)
}
