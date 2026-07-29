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
use crate::runtime_state::RuntimeCore;

pub(crate) fn run(
    listener: TcpListener,
    mut wake_reader: LocalStream,
    core: Arc<RuntimeCore>,
) -> Result<(), RuntimeError> {
    listener
        .set_nonblocking(true)
        .map_err(|source| RuntimeError::Io {
            operation: "configure TCP listener",
            source,
        })?;
    wake_reader
        .set_nonblocking(true)
        .map_err(|source| RuntimeError::Io {
            operation: "configure accept wakeup",
            source,
        })?;
    loop {
        #[cfg(unix)]
        {
            let mut descriptors = [
                PollFd::new(&listener, PollFlags::IN),
                PollFd::new(&wake_reader, PollFlags::IN | PollFlags::HUP),
            ];
            match poll(&mut descriptors, None) {
                Ok(_) => {}
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(error) => {
                    return Err(RuntimeError::Io {
                        operation: "poll TCP listener",
                        source: io::Error::from(error),
                    });
                }
            }
            let listener_ready = descriptors[0].revents().contains(PollFlags::IN);
            let wake_ready = descriptors[1]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP);
            if wake_ready && core.shutdown.load(Ordering::Acquire) {
                drain(&mut wake_reader);
                return Ok(());
            }
            if listener_ready {
                accept_ready(&listener, &core)?;
            }
        }
        // Windows cannot poll the listener and the shutdown wake handle
        // together, so both are checked without blocking on upstream's 10ms
        // `select()` cadence.
        #[cfg(windows)]
        {
            if core.shutdown.load(Ordering::Acquire) {
                drain(&mut wake_reader);
                return Ok(());
            }
            accept_ready(&listener, &core)?;
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
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
                    })
                    .map_err(RuntimeError::Spawn)?;
                core.handlers.push(worker)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(RuntimeError::Io {
                    operation: "accept TCP connection",
                    source,
                });
            }
        }
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
