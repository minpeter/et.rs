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
                // Keep the active transport open long enough for the bridge to
                // drain terminal bytes already buffered at HUP, but cancel every
                // pre-slot, starting, and returning raw socket in this generation.
                if let Err(error) = core.raw_sockets.shutdown_inactive_registration(&identity) {
                    crate::diag::info(format!(
                        "id={}: error shutting down inactive raw sockets: {error}",
                        identity.id()
                    ));
                    first_error.get_or_insert(error);
                }
                #[cfg(test)]
                notify_raw_scan_complete(identity.id());
                let removed = core.sessions.remove_registration_with(&identity, |_| {});
                match removed {
                    Ok(Some(removed)) => {
                        crate::diag::info(format!(
                            "id={}: removed session after terminal disconnect",
                            identity.id()
                        ));
                        if let Some(SessionConnection::Starting(stream)) = removed.connection {
                            match stream.shutdown(std::net::Shutdown::Both) {
                                Ok(()) => {}
                                Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {}
                                Err(error) => {
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

#[cfg(test)]
fn raw_scan_hooks(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, std::sync::mpsc::SyncSender<()>>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::sync::mpsc::SyncSender<()>>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
pub(crate) fn install_raw_scan_hook(id: &str, complete: std::sync::mpsc::SyncSender<()>) {
    raw_scan_hooks()
        .lock()
        .unwrap()
        .insert(id.to_owned(), complete);
}

#[cfg(test)]
fn notify_raw_scan_complete(id: &str) {
    if let Some(complete) = raw_scan_hooks().lock().unwrap().remove(id) {
        let _ = complete.send(());
    }
}
