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

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct IdleMemoryAccounting {
    dirty_decay_ms: isize,
    muzzy_decay_ms: isize,
}

#[cfg(target_os = "linux")]
fn release_idle_memory() -> Result<IdleMemoryAccounting, tikv_jemalloc_ctl::Error> {
    use tikv_jemalloc_ctl::{Access, AsName};

    // Configure future arenas, then update all existing arenas through
    // jemalloc's MALLCTL_ARENAS_ALL pseudo-index (4096).
    b"arenas.dirty_decay_ms\0".name().write(0_isize)?;
    b"arenas.muzzy_decay_ms\0".name().write(0_isize)?;
    b"arena.4096.dirty_decay_ms\0".name().write(0_isize)?;
    b"arena.4096.muzzy_decay_ms\0".name().write(0_isize)?;
    Ok(IdleMemoryAccounting {
        dirty_decay_ms: b"arenas.dirty_decay_ms\0".name().read()?,
        muzzy_decay_ms: b"arenas.muzzy_decay_ms\0".name().read()?,
    })
}

pub(crate) fn run(
    events: Receiver<LifecycleEvent>,
    core: Arc<RuntimeCore>,
) -> Result<(), RuntimeError> {
    #[cfg(target_os = "linux")]
    if let Err(error) = release_idle_memory() {
        crate::diag::info(format!(
            "could not configure allocator idle-page release: {error}"
        ));
    }
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
                // The removed session and its replay queues are out of scope;
                // now return their freed allocator pages to the kernel.
                #[cfg(target_os = "linux")]
                if let Err(error) = release_idle_memory() {
                    crate::diag::info(format!(
                        "could not release allocator pages after id={}: {error}",
                        identity.id()
                    ));
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::release_idle_memory;

    const BURST_BYTES: usize = 64 * 1024 * 1024;
    const ACTIVE_SLACK_BOUND: usize = 4 * 1024 * 1024;

    fn allocator_bytes() -> (usize, usize, usize) {
        tikv_jemalloc_ctl::epoch::advance().unwrap();
        (
            tikv_jemalloc_ctl::stats::allocated::read().unwrap(),
            tikv_jemalloc_ctl::stats::active::read().unwrap(),
            tikv_jemalloc_ctl::stats::resident::read().unwrap(),
        )
    }

    #[test]
    fn idle_release_configures_immediate_decay_and_bounds_active_bytes() {
        assert_eq!(
            release_idle_memory().unwrap(),
            super::IdleMemoryAccounting {
                dirty_decay_ms: 0,
                muzzy_decay_ms: 0,
            }
        );
        let (baseline_allocated, baseline_active, baseline_resident) = allocator_bytes();

        let mut burst = Vec::new();
        while burst.len() * (64 * 1024) < BURST_BYTES {
            let mut allocation = vec![0_u8; 64 * 1024];
            for page in allocation.chunks_mut(4096) {
                page[0] = 1;
            }
            burst.push(allocation);
        }
        let (_, _, peak_resident) = allocator_bytes();
        drop(burst);

        assert_eq!(
            release_idle_memory().unwrap(),
            super::IdleMemoryAccounting {
                dirty_decay_ms: 0,
                muzzy_decay_ms: 0,
            }
        );
        let (idle_allocated, idle_active, idle_resident) = allocator_bytes();
        assert!(
            idle_active <= baseline_active + ACTIVE_SLACK_BOUND,
            "live allocator bytes did not return to their bound: baseline allocated={baseline_allocated} active={baseline_active} resident={baseline_resident}; peak resident={peak_resident}; idle allocated={idle_allocated} active={idle_active} resident={idle_resident}"
        );
    }
}
