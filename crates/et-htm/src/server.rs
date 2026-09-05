//! `htmd`: the HTM multiplexer daemon, mirroring upstream `HtmServer.cpp`
//! plus `IpcPairServer`.

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

pub use crate::transport::pipe_name;
use crate::transport::{self, Listener, Stream};

use crate::codes;
use crate::framing;
use crate::state::MultiplexerState;

pub struct HtmServer {
    listener: Listener,
    endpoint: Option<Stream>,
    state: MultiplexerState,
    running: bool,
}

impl HtmServer {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let listener = Listener::bind(path)?;
        Ok(Self {
            listener,
            endpoint: None,
            state: MultiplexerState::new().map_err(io::Error::other)?,
            running: true,
        })
    }

    pub fn run(&mut self) -> io::Result<()> {
        while self.running {
            // A new authenticated UI (including htm -x) must be serviced even
            // while the previous UI remains attached. poll_accept closes the
            // old endpoint only after accepting the replacement.
            if let Err(error) = self.poll_accept() {
                self.close_endpoint();
                eprintln!("htmd: accepting UI client: {error}");
            }
            if self.endpoint.is_none() {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            if let Err(error) = self.step() {
                if error.kind() == io::ErrorKind::Other {
                    return Err(error);
                }
                // Upstream drops the client on any protocol/IO failure and
                // keeps the multiplexer alive.
                self.close_endpoint();
            }
        }
        self.state.stop_all();
        self.listener.retire()?;
        self.close_endpoint();
        Ok(())
    }

    /// Accept a new UI client, replacing any existing one, then resend state.
    fn poll_accept(&mut self) -> io::Result<()> {
        match self.listener.accept() {
            Ok(stream) => {
                if self.endpoint.is_some() {
                    self.close_endpoint();
                }
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                self.endpoint = Some(stream);
                self.recover()
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Send the HTM-mode escape, the JSON state, and buffered pane output.
    fn recover(&mut self) -> io::Result<()> {
        let Some(mut endpoint) = self.endpoint.as_ref().and_then(|s| s.try_clone().ok()) else {
            return Ok(());
        };
        endpoint.write_all(codes::ENTER_HTM_MODE)?;
        endpoint.flush()?;
        std::thread::sleep(Duration::from_millis(10));
        framing::write_debug(&mut endpoint, "Initializing HTM, please wait...\n\r")?;
        framing::write_init_state(&mut endpoint, &self.state.to_json_string())?;
        self.state
            .send_terminal_buffers(&mut endpoint)
            .map_err(io::Error::other)?;
        framing::write_debug(
            &mut endpoint,
            "HTM initialized.\n\rPress escape in this terminal to disconnect.\n\rPress x in this terminal to shut down HTM\n\r",
        )
    }

    fn step(&mut self) -> io::Result<()> {
        let Some(endpoint) = self.endpoint.as_ref() else {
            return Ok(());
        };
        if transport::readable(endpoint)? {
            self.handle_message()?;
        }
        if let Some(mut endpoint) = self.endpoint.as_ref().and_then(|s| s.try_clone().ok()) {
            self.state.update(&mut endpoint).map_err(io::Error::other)?;
        }
        Ok(())
    }

    fn handle_message(&mut self) -> io::Result<()> {
        let Some(stream) = self.endpoint.as_ref().and_then(|s| s.try_clone().ok()) else {
            return Ok(());
        };
        // Message bodies are read to completion, so block for the remainder
        // once the header byte is available.
        let mut reader = stream;
        let mut header = [0u8; 1];
        if reader.read_exact(&mut header).is_err() {
            self.close_endpoint();
            return Ok(());
        }
        if header[0] == codes::SESSION_END {
            self.close_endpoint();
            return Ok(());
        }
        let length = framing::read_length(&mut reader)?;
        self.dispatch(header[0], length, &mut reader)
    }

    fn dispatch(&mut self, header: u8, length: i32, reader: &mut impl Read) -> io::Result<()> {
        match header {
            codes::INSERT_KEYS => {
                let pane = framing::read_uuid(reader)?;
                let payload = usize::try_from(length)
                    .unwrap_or(0)
                    .saturating_sub(codes::UUID_LENGTH);
                let encoded = framing::read_exact_vec(reader, payload)?;
                let data = framing::decode(&encoded)?;
                self.state
                    .append_data(&pane, &data)
                    .map_err(io::Error::other)
            }
            codes::INSERT_DEBUG_KEYS => {
                let data = framing::read_exact_vec(reader, usize::try_from(length).unwrap_or(0))?;
                match data.first() {
                    // x: shut down; ESC: disconnect the UI; d: dump state.
                    Some(b'x') => self.running = false,
                    Some(27) => self.close_endpoint(),
                    Some(b'd') => {
                        let json = self.state.to_json_string();
                        if let Some(mut endpoint) =
                            self.endpoint.as_ref().and_then(|s| s.try_clone().ok())
                        {
                            framing::write_debug(&mut endpoint, &format!("Current State: {json}"))?;
                        }
                    }
                    _ => {}
                }
                Ok(())
            }
            codes::NEW_TAB => {
                let tab = framing::read_uuid(reader)?;
                let pane = framing::read_uuid(reader)?;
                self.state.new_tab(&tab, &pane).map_err(io::Error::other)
            }
            codes::NEW_SPLIT => {
                let source = framing::read_uuid(reader)?;
                let pane = framing::read_uuid(reader)?;
                let mut vertical = [0u8; 1];
                reader.read_exact(&mut vertical)?;
                self.state
                    .new_split(&source, &pane, vertical[0] == b'1')
                    .map_err(io::Error::other)
            }
            codes::RESIZE_PANE => {
                let cols = framing::read_length(reader)?;
                let rows = framing::read_length(reader)?;
                let pane = framing::read_uuid(reader)?;
                self.state
                    .resize_pane(&pane, cols, rows)
                    .map_err(io::Error::other)
            }
            codes::CLIENT_CLOSE_PANE => {
                let pane = framing::read_uuid(reader)?;
                self.state.close_pane(&pane).map_err(io::Error::other)?;
                if self.state.num_panes() == 0 {
                    self.running = false;
                }
                Ok(())
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Got unknown packet header: {other}"),
            )),
        }
    }

    fn close_endpoint(&mut self) {
        if let Some(mut endpoint) = self.endpoint.take() {
            let _ = endpoint.write_all(&[codes::SESSION_END]);
            let _ = endpoint.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for HtmServer {
    fn drop(&mut self) {
        self.state.stop_all();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_matches_upstream_shape() {
        let path = pipe_name().unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("htm."));
        assert!(name.ends_with(".ipc"));
        assert!(name.contains(&rustix::process::getuid().as_raw().to_string()));
    }

    #[test]
    fn stale_socket_is_replaced_on_bind() {
        let directory = std::env::temp_dir().join(format!("htm-bind-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("htm.test.ipc");
        // A leftover file with no listener must not block startup.
        std::fs::write(&path, b"stale").unwrap();
        let server = HtmServer::bind(&path).unwrap();
        assert!(path.exists());
        drop(server);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
