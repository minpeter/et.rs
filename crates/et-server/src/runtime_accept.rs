use et_net::local::LocalStream;
use std::io::{self, Read};
use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};

use crate::runtime_error::RuntimeError;
use crate::runtime_handler;
use crate::runtime_lifecycle::Lifecycle;
use crate::runtime_state::RuntimeCore;
#[cfg(unix)]
use crate::{router::RouterError, router_loop::RouterPoll};

/// The terminal router, serviced on the runtime control thread (Unix).
#[cfg(unix)]
pub(crate) struct ControlRouter {
    pub(crate) poll: RouterPoll,
    /// Tells `Runtime::shutdown` the router stopped, and with what error.
    pub(crate) stopped: std::sync::mpsc::SyncSender<Result<(), RouterError>>,
}

#[cfg(unix)]
impl ControlRouter {
    /// Close the router (its listener and watched terminals) and report how
    /// it ended.
    fn stop(self, result: Result<(), RouterError>) {
        drop(self.poll);
        let _ = self.stopped.send(result);
    }
}

/// The runtime control thread: accepts on every TCP listener (one thread for
/// IPv4 and IPv6 alike), services terminal lifecycle events and resume
/// expiry between accepts and, on Unix, runs the terminal router. A shutdown
/// wake stops accepting; the router runs until the runtime stops it and
/// lifecycle work continues until the runtime's final `Shutdown` event.
pub(crate) fn run(
    listeners: Vec<TcpListener>,
    mut wake_reader: LocalStream,
    mut lifecycle: Lifecycle,
    core: Arc<RuntimeCore>,
    #[cfg(unix)] mut router: Option<ControlRouter>,
) -> Result<(), RuntimeError> {
    let mut first_error = None;
    // Configure the wakeup independently of the listeners: `drain` reads until
    // `WouldBlock`, which would block forever on a blocking socket and keep
    // `Runtime::shutdown` from joining this thread. Without a non-blocking
    // wakeup it is neither polled nor drained; shutdown is still observed via
    // the lifecycle wakeup.
    let wake_usable = match wake_reader.set_nonblocking(true) {
        Ok(()) => true,
        Err(source) => {
            first_error = Some(RuntimeError::Io {
                operation: "configure accept wakeup",
                source,
            });
            false
        }
    };
    let configured = listeners
        .iter()
        .try_for_each(|listener| listener.set_nonblocking(true));
    // Lifecycle cleanup must keep running even if the listeners cannot.
    let mut listeners = match configured {
        Ok(()) => listeners,
        Err(source) => {
            first_error.get_or_insert(RuntimeError::Io {
                operation: "configure TCP listener",
                source,
            });
            Vec::new()
        }
    };
    lifecycle.start();
    let mut ready = Vec::with_capacity(listeners.len());
    #[cfg(unix)]
    let mut router_ready = Vec::new();
    loop {
        // Windows cannot poll listeners together with the wake handles, so
        // every listener is tried without blocking on upstream's 10 ms
        // `select()` cadence.
        #[cfg(windows)]
        let lifecycle_woken = {
            ready.clear();
            ready.resize(listeners.len(), true);
            true
        };
        #[cfg(unix)]
        if let Some(router) = router.as_mut() {
            router.poll.expire();
        }
        #[cfg(unix)]
        let lifecycle_woken = match wait(
            &listeners,
            wake_usable.then_some(&wake_reader),
            &lifecycle,
            router.as_ref().map(|router| &router.poll),
            &mut ready,
            &mut router_ready,
        ) {
            Ok(woken) => woken,
            Err(error) => {
                first_error.get_or_insert(error);
                listeners.clear();
                ready.clear();
                router_ready.clear();
                true
            }
        };
        if core.shutdown.load(Ordering::Acquire) {
            if wake_usable {
                drain(&mut wake_reader);
            }
            listeners.clear();
        }
        let mut index = 0;
        listeners.retain(|listener| {
            let is_ready = ready.get(index).copied().unwrap_or(false);
            index += 1;
            if !is_ready {
                return true;
            }
            match accept_ready(listener, &core) {
                Ok(()) => true,
                Err(error) => {
                    // Like the dedicated accept thread it replaces: a failed
                    // listener stops and its error surfaces at shutdown.
                    first_error.get_or_insert(error);
                    false
                }
            }
        });
        // Like the dedicated router thread it replaces: the router acts only
        // on its own readiness (and, on Darwin, every recheck, which probes
        // watched terminals that can close without readiness); a failed
        // router stops and its error surfaces when the runtime shuts it down.
        #[cfg(unix)]
        if !router_ready.is_empty()
            && (cfg!(target_os = "macos") || router_ready.iter().any(|flags| !flags.is_empty()))
        {
            if let Some(mut control) = router.take() {
                match control.poll.service(&router_ready) {
                    Ok(()) => router = Some(control),
                    Err(error) => control.stop(Err(error)),
                }
            }
        }
        let stop = lifecycle.service(&core, lifecycle_woken);
        #[cfg(unix)]
        if lifecycle.take_router_stop() {
            if let Some(control) = router.take() {
                control.stop(Ok(()));
            }
        }
        if stop {
            break;
        }
        #[cfg(windows)]
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let lifecycle = lifecycle.finish();
    match first_error {
        Some(error) => Err(error),
        None => lifecycle,
    }
}

/// Block until a listener is ready, the runtime wakes us, a lifecycle event
/// arrives, the router has work or the next resume sweep (if one is armed) or
/// registration expiry is due. `wake_reader` is `None` when the runtime
/// wakeup could not be made non-blocking. Fills listener readiness into
/// `ready` and the router's into `router_ready` (empty without a router) and
/// returns whether the lifecycle wakeup fired.
#[cfg(unix)]
fn wait(
    listeners: &[TcpListener],
    wake_reader: Option<&LocalStream>,
    lifecycle: &Lifecycle,
    router: Option<&RouterPoll>,
    ready: &mut Vec<bool>,
    router_ready: &mut Vec<PollFlags>,
) -> Result<bool, RuntimeError> {
    let mut descriptors: Vec<PollFd<'_>> = listeners
        .iter()
        .map(|listener| PollFd::new(listener, PollFlags::IN))
        .chain(
            wake_reader
                .into_iter()
                .map(|wake_reader| PollFd::new(wake_reader, PollFlags::IN | PollFlags::HUP)),
        )
        .chain([PollFd::new(
            lifecycle.wake(),
            PollFlags::IN | PollFlags::HUP,
        )])
        .collect();
    let lifecycle_index = descriptors.len() - 1;
    let now = std::time::Instant::now();
    let mut deadline = lifecycle.next_sweep();
    if let Some(router) = router {
        router.descriptors(&mut descriptors);
        if let Some(expiry) = router.timeout() {
            deadline = Some(deadline.map_or(now + expiry, |deadline| deadline.min(now + expiry)));
        }
    }
    loop {
        // Recomputed on every retry so interrupted polls keep the deadline.
        let timeout = deadline.map(|deadline| poll_timeout(deadline, std::time::Instant::now()));
        match poll(&mut descriptors, timeout.as_ref()) {
            Ok(_) => break,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => {
                return Err(RuntimeError::Io {
                    operation: "poll TCP listener",
                    source: io::Error::from(error),
                });
            }
        }
    }
    ready.clear();
    ready.extend(
        descriptors[..listeners.len()]
            .iter()
            .map(|descriptor| descriptor.revents().contains(PollFlags::IN)),
    );
    router_ready.clear();
    router_ready.extend(
        descriptors[lifecycle_index + 1..]
            .iter()
            .map(PollFd::revents),
    );
    Ok(!descriptors[lifecycle_index].revents().is_empty())
}

/// Time left until `deadline` as a poll timeout; zero once it has passed.
#[cfg(unix)]
fn poll_timeout(deadline: std::time::Instant, now: std::time::Instant) -> rustix::event::Timespec {
    rustix::event::Timespec::try_from(deadline.saturating_duration_since(now))
        .expect("sweep and registration deadlines fit timespec")
}

fn accept_ready(listener: &TcpListener, core: &Arc<RuntimeCore>) -> Result<(), RuntimeError> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let Some(pre_auth_guard) = core.pre_auth_slots.clone().try_acquire() else {
                    crate::diag::verbose(1, "reject TCP connection: pre-auth capacity exhausted");
                    continue;
                };
                // Windows inherits the listener's non-blocking mode on accepted
                // sockets (Unix does not), and the handshake below is blocking.
                stream
                    .set_nonblocking(false)
                    .and_then(|()| stream.set_nodelay(true))
                    .map_err(|source| RuntimeError::Io {
                        operation: "configure accepted TCP stream",
                        source,
                    })?;
                let guard = core.raw_sockets.track(&stream)?;
                let worker_core = core.clone();
                let worker = thread::Builder::new()
                    .name("et-session-handler".to_owned())
                    .spawn(move || {
                        runtime_handler::handle(stream, worker_core, guard, pre_auth_guard)
                    });
                match worker {
                    Ok(worker) => core.handlers.push(worker)?,
                    Err(error) => {
                        // The closure is dropped here, releasing its socket and
                        // admission permit. Keep the listener supervised and
                        // observable rather than silently killing acceptance.
                        crate::diag::info(format!("could not start session handler: {error}"));
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        return Ok(());
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) if accept_resource_exhausted(&source) => {
                crate::diag::info(format!("TCP accept resource exhaustion: {source}"));
                std::thread::sleep(std::time::Duration::from_millis(100));
                return Ok(());
            }
            Err(source) => {
                return Err(RuntimeError::Io {
                    operation: "accept TCP connection",
                    source,
                });
            }
        }
    }
}

/// `accept` failed because descriptors or kernel memory ran out. A peer can
/// provoke these; they must not abort the listener (upstream #890 / c0e36f2).
pub(crate) fn accept_resource_exhausted(error: &io::Error) -> bool {
    let Some(code) = error.raw_os_error() else {
        return false;
    };
    #[cfg(windows)]
    {
        // ENOMEM, WSAEMFILE, WSAENOBUFS.
        matches!(code, 8 | 10024 | 10055)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // ENOMEM, ENFILE, EMFILE, ENOBUFS.
        matches!(code, 12 | 23 | 24 | 105)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        // ENOMEM, ENFILE, EMFILE, ENOBUFS.
        matches!(code, 12 | 23 | 24 | 55)
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    {
        matches!(code, 12 | 23 | 24)
    }
}

fn drain(wake_reader: &mut LocalStream) {
    let mut buffer = [0u8; 64];
    loop {
        match wake_reader.read(&mut buffer) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}
