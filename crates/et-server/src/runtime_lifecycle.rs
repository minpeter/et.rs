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
    applied_arenas: u32,
    dirty_decay_ms: isize,
    muzzy_decay_ms: isize,
}

/// Return pages freed by finished sessions to the kernel.
///
/// Two steps are both required. `arenas.*_decay_ms` governs arenas created
/// later, and each arena that already holds session buffers is updated through
/// its own index.
///
/// jemalloc's `MALLCTL_ARENAS_ALL` pseudo-index is deliberately not used: it is
/// rejected with `EFAULT` on some builds, which silently left this policy
/// unapplied at runtime while a future-arena read-back still looked correct.
/// `arenas.narenas` is an upper limit rather than a count of live arenas, so an
/// index that was never initialized also answers `EFAULT`; those arenas hold
/// nothing and inherit the future-arena setting when they are created, so they
/// are skipped instead of failing the release.
#[cfg(target_os = "linux")]
fn release_idle_memory() -> Result<IdleMemoryAccounting, tikv_jemalloc_ctl::Error> {
    use tikv_jemalloc_ctl::{Access, AsName};

    b"arenas.dirty_decay_ms\0".name().write(0_isize)?;
    b"arenas.muzzy_decay_ms\0".name().write(0_isize)?;
    let limit: u32 = b"arenas.narenas\0".name().read()?;
    let mut applied_arenas = 0;
    for index in 0..limit {
        let dirty = format!("arena.{index}.dirty_decay_ms\0");
        if dirty.as_bytes().name().write(0_isize).is_err() {
            continue;
        }
        let muzzy = format!("arena.{index}.muzzy_decay_ms\0");
        let _ = muzzy.as_bytes().name().write(0_isize);
        applied_arenas += 1;
    }
    Ok(IdleMemoryAccounting {
        applied_arenas,
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
#[global_allocator]
static TEST_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::release_idle_memory;

    const BURST_BYTES: usize = 64 * 1024 * 1024;
    const CHUNK: usize = 64 * 1024;

    fn active_bytes() -> usize {
        tikv_jemalloc_ctl::epoch::advance().unwrap();
        tikv_jemalloc_ctl::stats::active::read().unwrap()
    }

    /// A real server run applied this policy to zero arenas while still
    /// reading back a configured future-arena value, so the release looked
    /// successful and reclaimed nothing. Assert the live-arena count it
    /// actually reached.
    #[test]
    fn idle_release_reaches_at_least_one_live_arena() {
        let accounting = release_idle_memory().expect("release must succeed under jemalloc");
        assert_eq!(accounting.dirty_decay_ms, 0);
        assert_eq!(accounting.muzzy_decay_ms, 0);
        assert!(
            accounting.applied_arenas >= 1,
            "release applied to no live arena: {accounting:?}"
        );
    }

    #[test]
    fn active_bytes_return_toward_baseline_after_a_large_burst_is_dropped() {
        release_idle_memory().unwrap();
        let baseline = active_bytes();

        let mut burst = Vec::new();
        while burst.len() * CHUNK < BURST_BYTES {
            let mut allocation = vec![0_u8; CHUNK];
            for page in allocation.chunks_mut(4096) {
                page[0] = 1;
            }
            burst.push(allocation);
        }
        let peak = active_bytes();
        assert!(
            peak >= baseline + BURST_BYTES / 2,
            "burst did not raise active bytes: baseline {baseline}, peak {peak}"
        );
        drop(burst);

        release_idle_memory().unwrap();
        let settled = active_bytes();
        assert!(
            settled < baseline + BURST_BYTES / 4,
            "active bytes stayed near the high-water mark: baseline {baseline}, peak {peak}, settled {settled}"
        );
    }
}
