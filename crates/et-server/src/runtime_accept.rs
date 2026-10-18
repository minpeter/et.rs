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

/// The runtime control thread: accepts on every TCP listener (one thread for
/// IPv4 and IPv6 alike) and services terminal lifecycle events and resume
/// expiry between accepts. A shutdown wake stops accepting; lifecycle work
/// continues until the runtime's final `Shutdown` event.
pub(crate) fn run(
    listeners: Vec<TcpListener>,
    mut wake_reader: LocalStream,
    mut lifecycle: Lifecycle,
    core: Arc<RuntimeCore>,
) -> Result<(), RuntimeError> {
    let mut first_error = None;
    // Configure the wakeup independently of the listeners: `drain` reads until
    // `WouldBlock`, which would block forever on a blocking socket and keep
    // `Runtime::shutdown` from joining this thread. Without a non-blocking
    // wakeup it is neither polled nor drained; shutdown is still observed via
    // the lifecycle wakeup or the next resume sweep.
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
        let lifecycle_woken = match wait(
            &listeners,
            wake_usable.then_some(&wake_reader),
            &lifecycle,
            &mut ready,
        ) {
            Ok(woken) => woken,
            Err(error) => {
                first_error.get_or_insert(error);
                listeners.clear();
                ready.clear();
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
        if lifecycle.service(&core, lifecycle_woken) {
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
/// arrives or the next resume sweep is due. `wake_reader` is `None` when the
/// runtime wakeup could not be made non-blocking. Fills listener readiness
/// into `ready` and returns whether the lifecycle wakeup fired.
#[cfg(unix)]
fn wait(
    listeners: &[TcpListener],
    wake_reader: Option<&LocalStream>,
    lifecycle: &Lifecycle,
    ready: &mut Vec<bool>,
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
    let deadline = lifecycle.next_sweep();
    loop {
        // Recomputed on every retry so interrupted polls keep the deadline.
        let timeout = poll_timeout(deadline, std::time::Instant::now());
        match poll(&mut descriptors, Some(&timeout)) {
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
    // The lifecycle wakeup is always the last descriptor.
    Ok(descriptors
        .last()
        .is_some_and(|descriptor| !descriptor.revents().is_empty()))
}

/// Time left until `deadline` as a poll timeout; zero once it has passed.
#[cfg(unix)]
fn poll_timeout(deadline: std::time::Instant, now: std::time::Instant) -> rustix::event::Timespec {
    rustix::event::Timespec::try_from(deadline.saturating_duration_since(now))
        .expect("one-second sweep interval fits timespec")
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
