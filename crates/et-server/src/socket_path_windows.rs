//! Router listener binding on Windows.
//!
//! Upstream has no Windows server at all, which is why hosting an ET session on
//! Windows previously meant running the Unix server inside WSL and getting a
//! WSL shell. Here the router is a loopback-only TCP listener whose address and
//! a fresh CSPRNG token are written to the `--serverfifo` path; terminals prove
//! they can read that user-private file by presenting the token. See
//! [`et_net::local`] for the wire details.

#![cfg(windows)]

use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use crate::path::{PathError, RouterPath};

pub(crate) struct OwnedRouterListener {
    listener: TcpListener,
    path: PathBuf,
    token: String,
}

impl OwnedRouterListener {
    pub(crate) fn bind(selected: &RouterPath) -> Result<Self, PathError> {
        selected.prepare()?;
        let path = selected.path().to_path_buf();
        prepare_endpoint_path(&path)?;
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|source| PathError::Io {
                operation: "bind router listener",
                path: path.clone(),
                source,
            })?;
        listener
            .set_nonblocking(true)
            .map_err(|source| PathError::Io {
                operation: "configure router listener",
                path: path.clone(),
                source,
            })?;
        let address = listener.local_addr().map_err(|source| PathError::Io {
            operation: "inspect router listener",
            path: path.clone(),
            source,
        })?;
        let token = et_net::local::new_token();
        fs::write(
            &path,
            format!("{address}\n{token}\net-registration-ack-v1\n"),
        )
        .map_err(|source| PathError::Io {
            operation: "write router endpoint file",
            path: path.clone(),
            source,
        })?;
        Ok(Self {
            listener,
            path,
            token,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn listener(&self) -> &TcpListener {
        &self.listener
    }

    /// Accept a terminal without blocking the sole router worker. Token bytes
    /// are authenticated incrementally by the bounded pending state machine.
    pub(crate) fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.listener.accept()?;
        if !peer.ip().is_loopback() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "router peer is not loopback",
            ));
        }
        stream.set_nodelay(true)?;
        Ok((stream, peer))
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }
}

impl Drop for OwnedRouterListener {
    fn drop(&mut self) {
        // Only remove an endpoint file that still describes this listener.
        if let Ok((_, token)) = et_net::local::read_endpoint(&self.path) {
            if token == self.token {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

fn prepare_endpoint_path(path: &Path) -> Result<(), PathError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(PathError::Io {
                operation: "inspect router path",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(PathError::Symlink(path.to_path_buf()));
    }
    if !metadata.file_type().is_file() {
        return Err(PathError::NotSocket(path.to_path_buf()));
    }
    // A live server still answering on the recorded address owns this path.
    if let Ok((address, _)) = et_net::local::read_endpoint(path) {
        if TcpStream::connect_timeout(&address, std::time::Duration::from_millis(250)).is_ok() {
            return Err(PathError::LiveSocket(path.to_path_buf()));
        }
    }
    fs::remove_file(path).map_err(|source| PathError::Io {
        operation: "remove stale router endpoint file",
        path: path.to_path_buf(),
        source,
    })
}
