use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use et_net::local::LocalStream;

use crate::registry::{RegistrationError, RegistrationIdentity};
use crate::runtime_error::RuntimeError;
use crate::runtime_state::RuntimeCore;
use crate::session::SessionConnection;
use crate::session_slot::Slot;

pub(crate) enum LifecycleEvent {
    TerminalDisconnected(RegistrationIdentity),
    /// A terminal re-registered a live PTY: its recovery grace needs sweeps.
    TerminalResumed,
    /// The runtime is shutting down: close the router this thread drives.
    #[cfg(unix)]
    StopRouter,
    Shutdown,
}

/// Recovery grace is measured in minutes. While a resumed terminal is
/// registered, a one-second pass keeps expiry prompt without churning the
/// registry lock at 10 Hz.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

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

/// Active-session decay: dirty pages return to the kernel after 1 s (the
/// build-time default, see `.cargo/config.toml`, restated here so builds
/// without that config keep it), and purged pages skip jemalloc's lazy
/// `MADV_FREE` stage (`muzzy_decay_ms` 0, jemalloc's own default): lazily
/// freed pages stay resident until the kernel is under memory pressure.
#[cfg(target_os = "linux")]
fn restore_active_decay() {
    use tikv_jemalloc_ctl::{Access, AsName};

    const DIRTY_DECAY_MS: isize = 1000;
    const MUZZY_DECAY_MS: isize = 0;
    let _ = b"arenas.dirty_decay_ms\0".name().write(DIRTY_DECAY_MS);
    let _ = b"arenas.muzzy_decay_ms\0".name().write(MUZZY_DECAY_MS);
    if let Ok(limit) = b"arenas.narenas\0".name().read() {
        let limit: u32 = limit;
        for index in 0..limit {
            let dirty = format!("arena.{index}.dirty_decay_ms\0");
            if dirty.as_bytes().name().write(DIRTY_DECAY_MS).is_err() {
                continue;
            }
            let muzzy = format!("arena.{index}.muzzy_decay_ms\0");
            let _ = muzzy.as_bytes().name().write(MUZZY_DECAY_MS);
        }
    }
}

/// Sends lifecycle events to the runtime control thread and wakes its poll.
#[derive(Clone)]
pub(crate) struct LifecycleSender {
    events: Sender<LifecycleEvent>,
    wake: Arc<LocalStream>,
}

impl LifecycleSender {
    pub(crate) fn send(&self, event: LifecycleEvent) {
        if self.events.send(event).is_ok() {
            // Non-blocking: a full wake buffer already guarantees a wakeup.
            let _ = (&*self.wake).write(&[1]);
        }
    }
}

/// Terminal lifecycle handling, serviced by the runtime control thread next
/// to its TCP listeners instead of on a thread of its own.
pub(crate) struct Lifecycle {
    events: Receiver<LifecycleEvent>,
    wake: LocalStream,
    /// When the next resume-expiry sweep is due; `None` while no resumed
    /// terminal is registered, so an idle server never wakes for it.
    next_sweep: Option<Instant>,
    sweep_failed: bool,
    /// `StopRouter` arrived; the control loop closes its router.
    #[cfg(unix)]
    router_stop: bool,
    first_error: Option<RuntimeError>,
}

pub(crate) fn channel() -> std::io::Result<(LifecycleSender, Lifecycle)> {
    let (wake, signal) = et_net::local::wake_pair()?;
    wake.set_nonblocking(true)?;
    signal.set_nonblocking(true)?;
    let (events, receiver) = std::sync::mpsc::channel();
    Ok((
        LifecycleSender {
            events,
            wake: Arc::new(signal),
        },
        Lifecycle {
            events: receiver,
            wake,
            next_sweep: None,
            sweep_failed: false,
            #[cfg(unix)]
            router_stop: false,
            first_error: None,
        },
    ))
}

impl Lifecycle {
    pub(crate) fn start(&self) {
        #[cfg(target_os = "linux")]
        restore_active_decay();
    }

    /// Readable when events are queued.
    #[cfg(unix)]
    pub(crate) fn wake(&self) -> &LocalStream {
        &self.wake
    }

    /// When the next resume-expiry sweep is due, if any.
    #[cfg(unix)]
    pub(crate) fn next_sweep(&self) -> Option<Instant> {
        self.next_sweep
    }

    /// Whether `StopRouter` arrived since the last call.
    #[cfg(unix)]
    pub(crate) fn take_router_stop(&mut self) -> bool {
        std::mem::take(&mut self.router_stop)
    }

    /// Run a due sweep and apply every queued event. Returns `true` once the
    /// runtime asked for shutdown (or every sender is gone).
    pub(crate) fn service(&mut self, core: &RuntimeCore, woken: bool) -> bool {
        let now = Instant::now();
        if self.next_sweep.is_some_and(|due| now >= due) {
            match expire_unclaimed_resumes(core, now) {
                Ok(()) => self.sweep_failed = false,
                Err(error) if !self.sweep_failed => {
                    crate::diag::info(format!(
                        "could not expire unclaimed terminal resumes: {error}"
                    ));
                    self.sweep_failed = true;
                }
                Err(_) => {}
            }
            // Keep sweeping while a resumed terminal remains (or the registry
            // cannot tell); the router re-arms the sweep for the next one.
            self.next_sweep =
                (!matches!(core.registry.has_resumed(), Ok(false))).then(|| now + SWEEP_INTERVAL);
        }
        if woken {
            drain_wake(&mut self.wake);
        }
        loop {
            match self.events.try_recv() {
                Ok(LifecycleEvent::TerminalDisconnected(identity)) => {
                    terminal_disconnected(core, &identity, &mut self.first_error);
                }
                Ok(LifecycleEvent::TerminalResumed) => {
                    self.next_sweep.get_or_insert(now + SWEEP_INTERVAL);
                }
                #[cfg(unix)]
                Ok(LifecycleEvent::StopRouter) => self.router_stop = true,
                Ok(LifecycleEvent::Shutdown) | Err(TryRecvError::Disconnected) => return true,
                Err(TryRecvError::Empty) => return false,
            }
        }
    }

    pub(crate) fn finish(self) -> Result<(), RuntimeError> {
        self.first_error.map_or(Ok(()), Err)
    }
}

fn drain_wake(wake: &mut LocalStream) {
    let mut buffer = [0u8; 64];
    loop {
        match wake.read(&mut buffer) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

fn terminal_disconnected(
    core: &RuntimeCore,
    identity: &RegistrationIdentity,
    first_error: &mut Option<RuntimeError>,
) {
    crate::diag::info(format!(
        "terminal disconnected for registration id={}",
        identity.id()
    ));
    // Keep the active transport open long enough for the bridge to drain
    // terminal bytes already buffered at HUP, but cancel every pre-slot,
    // starting, and returning raw socket in this generation.
    if let Err(error) = core.raw_sockets.shutdown_inactive_registration(identity) {
        crate::diag::info(format!(
            "id={}: error shutting down inactive raw sockets: {error}",
            identity.id()
        ));
        first_error.get_or_insert(error);
    }
    #[cfg(test)]
    notify_raw_scan_complete(identity.id());
    match core.sessions.remove_registration_with(identity, |_| {}) {
        Ok(Some(removed)) => {
            crate::diag::info(format!(
                "id={}: removed session after terminal disconnect",
                identity.id()
            ));
            match removed.connection {
                Some(SessionConnection::Starting(stream)) => {
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
                // The bridge keeps draining to a connected client; without
                // one, nothing it holds can be recovered any more.
                Some(SessionConnection::Active(session)) => session.detach(),
                None => {}
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
    // The removed session and its replay queues are out of scope; now return
    // their freed allocator pages to the kernel.
    #[cfg(target_os = "linux")]
    {
        if let Err(error) = release_idle_memory() {
            crate::diag::info(format!(
                "could not release allocator pages after id={}: {error}",
                identity.id()
            ));
        }
        restore_active_decay();
    }
}

/// A live PTY can re-register after restart without its client ever returning.
/// Allow the promised recovery grace, then close it using the same override
/// precedence as the active bridge (in particular, Some(0) disables expiry).
pub(crate) fn expire_unclaimed_resumes(
    core: &RuntimeCore,
    now: Instant,
) -> Result<(), RuntimeError> {
    for (registration, registered_at) in core.registry.resumed()? {
        let seconds = registration
            .disconnect_timeout_seconds
            .unwrap_or(core.disconnect_timeout_seconds);
        if seconds <= 0
            || now.saturating_duration_since(registered_at)
                < Duration::from_secs(seconds as u64).max(et_core::RECOVERY_GRACE)
        {
            continue;
        }
        let identity = registration.identity();
        let mut terminal = {
            // Match claim()'s lock order: session table, then registry. Checking
            // and removing under this lock prevents a reconnect from claiming
            // a generation between our expiry decision and deregistration.
            let mut state = core.sessions.lock()?;
            if state.shutdown {
                return Ok(());
            }
            let current_slot = state
                .slots
                .get(&registration.id)
                .filter(|slot| identity.matches(slot.registration()));
            if current_slot.is_some_and(|slot| !matches!(slot, Slot::Registered(_))) {
                continue;
            }
            // Authentication is marked before claim(). Check it while the
            // table lock is held: authenticate() and claim() then linearize
            // on opposite sides of this decision, while passkey-less peers do
            // not keep a resumed terminal alive.
            if core.raw_sockets.has_authenticated_registration(&identity)? {
                continue;
            }
            let remove_slot = current_slot.is_some();
            let stream = match core.registry.clone_stream(&registration) {
                Ok(stream) => stream,
                Err(RegistrationError::Unavailable) => continue,
                Err(error) => return Err(error.into()),
            };
            if !core.registry.remove_if_current(&identity)? {
                continue;
            }
            if remove_slot {
                state.slots.remove(&registration.id);
                core.sessions.inner.changed.notify_all();
            }
            stream
        };
        core.raw_sockets.shutdown_inactive_registration(&identity)?;
        // This generation has no session writer. Keep the close bounded without
        // blocking the table lock or the rest of the lifecycle worker. A live
        // pty that re-registered already reads the router stream in its
        // registration's framing.
        let close = et_core::packet::Packet::new(
            et_core::proto::TerminalPacketType::TerminalClose as u8,
            Vec::new(),
        );
        let sent = terminal.set_nonblocking(true).and_then(|()| {
            et_net::local_packet::write_router_message_cancelled(
                &mut terminal,
                &close,
                registration.router_framing,
                &core.shutdown,
                Instant::now() + Duration::from_millis(100),
            )
        });
        if let Err(error) = sent {
            let _ = terminal.shutdown(std::net::Shutdown::Both);
            crate::diag::info(format!(
                "id={}: could not close expired resumed terminal: {error}",
                registration.id
            ));
        }
    }
    Ok(())
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
}
