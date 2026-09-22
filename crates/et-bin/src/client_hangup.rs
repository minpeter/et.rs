//! Optional remote close when the local terminal hangs up.
//!
//! Upstream `#707` / `#837`: `--close-on-hangup` sends a wire `TERMINAL_CLOSE`
//! and leaves the client loop. The default stays the previous behavior (a
//! local hangup does not tell the server to end the session).

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use et_core::proto::TerminalPacketType;
use et_net::connection::Connection;

pub(crate) struct HangupClose {
    requested: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    /// Keeps the SIGHUP registration alive for the client loop. Dropping it
    /// restores the previous disposition.
    #[cfg(unix)]
    _registration: Option<signal_hook::SigId>,
}

impl HangupClose {
    pub(crate) fn disabled() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            completed: Arc::new(AtomicBool::new(false)),
            #[cfg(unix)]
            _registration: None,
        }
    }

    /// Arm Unix `SIGHUP` or the Windows console close/logoff/shutdown/break
    /// events. `Ctrl+C` is left alone so raw-mode input still reaches the
    /// remote shell.
    pub(crate) fn install() -> io::Result<Self> {
        let requested = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        #[cfg(unix)]
        let registration =
            signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&requested))?;
        #[cfg(windows)]
        install_console_handler(Arc::clone(&requested))?;
        Ok(Self {
            requested,
            completed,
            #[cfg(unix)]
            _registration: Some(registration),
        })
    }

    pub(crate) fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Test seam: ask the client loop to close without delivering a real signal.
    #[cfg(test)]
    pub(crate) fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
    }

    fn mark_completed(&self) {
        self.completed.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }
}

/// When a hangup close is pending, send wire `TERMINAL_CLOSE` (if the
/// transport is still up) and tell the client loop to exit.
///
/// Write failures are swallowed, matching upstream's try/catch around
/// `writePacket`: the local terminal is already going away.
pub(crate) fn take_hangup_close(connection: &mut Connection, hangup: &HangupClose) -> bool {
    if !hangup.requested() {
        return false;
    }
    if connection.connected() {
        let _ = connection.write_packet(TerminalPacketType::TerminalClose as u8, &[]);
    }
    hangup.mark_completed();
    true
}

/// Windows console close/logoff/shutdown must not return from the OS handler
/// immediately: the process is torn down when that handler returns. Tokio's
/// console handler parks those events until the process exits, which gives
/// the client loop time to emit `TERMINAL_CLOSE`. `CTRL_BREAK_EVENT` is
/// handled without that park; the loop observes it on the next 10ms tick.
/// `CTRL_C_EVENT` is not registered.
#[cfg(windows)]
fn install_console_handler(requested: Arc<AtomicBool>) -> io::Result<()> {
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("et-client-hangup".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = started_tx.send(Err(error));
                    return;
                }
            };
            let signals = runtime.block_on(async {
                Ok::<_, io::Error>((
                    tokio::signal::windows::ctrl_close()?,
                    tokio::signal::windows::ctrl_logoff()?,
                    tokio::signal::windows::ctrl_shutdown()?,
                    tokio::signal::windows::ctrl_break()?,
                ))
            });
            let (mut close, mut logoff, mut shutdown, mut ctrl_break) = match signals {
                Ok(signals) => {
                    let _ = started_tx.send(Ok(()));
                    signals
                }
                Err(error) => {
                    let _ = started_tx.send(Err(error));
                    return;
                }
            };
            runtime.block_on(async move {
                let event = tokio::select! {
                    event = close.recv() => event,
                    event = logoff.recv() => event,
                    event = shutdown.recv() => event,
                    event = ctrl_break.recv() => event,
                };
                if event.is_some() {
                    requested.store(true, Ordering::SeqCst);
                }
            });
        })
        .map_err(|error| io::Error::other(error))?;
    started_rx.recv().map_err(|error| io::Error::other(error))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use et_core::crypto::KEY_LEN;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || TcpStream::connect(address).unwrap());
        let (server, _) = listener.accept().unwrap();
        (client.join().unwrap(), server)
    }

    #[test]
    fn disabled_hangup_does_not_send_terminal_close() {
        let (stream, peer) = tcp_pair();
        peer.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut connection = Connection::new_client(stream, &[7u8; KEY_LEN]);
        let hangup = HangupClose::disabled();
        assert!(!take_hangup_close(&mut connection, &hangup));
        assert!(!hangup.completed());
        let mut receiver = Connection::new_server(peer, &[7u8; KEY_LEN]);
        assert!(receiver.read_packet().is_err());
    }

    #[test]
    fn requested_hangup_sends_empty_terminal_close_and_completes() {
        let (stream, peer) = tcp_pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut connection = Connection::new_client(stream, &[7u8; KEY_LEN]);
        let hangup = HangupClose::disabled();
        hangup.request();
        assert!(take_hangup_close(&mut connection, &hangup));
        assert!(hangup.completed());
        let mut receiver = Connection::new_server(peer, &[7u8; KEY_LEN]);
        let packet = receiver.read_packet().unwrap();
        assert_eq!(packet.header(), TerminalPacketType::TerminalClose as u8);
        assert_eq!(TerminalPacketType::TerminalClose as u8, 11);
        assert!(packet.payload().is_empty());
        assert_eq!(et_core::PROTOCOL_VERSION, 6);
    }

    #[test]
    fn disconnected_hangup_skips_the_write_and_still_completes() {
        let (stream, peer) = tcp_pair();
        peer.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut connection = Connection::new_client(stream, &[7u8; KEY_LEN]);
        connection.disconnect();
        let hangup = HangupClose::disabled();
        hangup.request();
        assert!(take_hangup_close(&mut connection, &hangup));
        assert!(hangup.completed());
        let mut receiver = Connection::new_server(peer, &[7u8; KEY_LEN]);
        assert!(receiver.read_packet().is_err());
    }
}
