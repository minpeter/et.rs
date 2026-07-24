use std::sync::mpsc::Receiver;
use std::sync::Arc;

use crate::registry::RegistrationIdentity;
use crate::runtime_error::RuntimeError;
use crate::runtime_state::RuntimeCore;

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
                if let Err(error) = core.raw_sockets.shutdown_registration(&identity) {
                    first_error.get_or_insert(error);
                }
                match core.sessions.remove_registration(&identity) {
                    Ok(Some(removed)) => {
                        if let Some(connection) = removed.connection {
                            if let Err(error) = connection.shutdown() {
                                first_error.get_or_insert(RuntimeError::Session(error));
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        first_error.get_or_insert(RuntimeError::SessionTable(error));
                    }
                }
            }
            LifecycleEvent::Shutdown => return first_error.map_or(Ok(()), Err),
        }
    }
    first_error.map_or(Ok(()), Err)
}
