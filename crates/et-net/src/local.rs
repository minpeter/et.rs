//! Local IPC between `etserver` and `etterminal`.
//!
//! On Unix this is upstream's arrangement exactly: a `SOCK_STREAM` Unix socket
//! at a filesystem path (`--serverfifo`), whose permissions restrict access to
//! the owner.
//!
//! Windows has no equivalent that can be polled next to TCP sockets, and
//! upstream simply does not build a server there (which is why running an ET
//! server on Windows meant running it inside WSL, giving a WSL shell instead of
//! a native one). Here the same role is filled by a loopback-only TCP listener
//! plus an *endpoint file* at the `--serverfifo` path:
//!
//! ```text
//! 127.0.0.1:49731
//! 6f1c...  (64 hex chars of CSPRNG token)
//! ```
//!
//! The listener refuses non-loopback peers, and every terminal must present the
//! token as its first line before the registration packet. The endpoint file
//! lives in a user-private directory, so only processes that can already read
//! the user's files can register a terminal.

use std::io;
use std::path::Path;

use socket2::SockRef;

/// Stream type used for local server/terminal IPC.
#[cfg(unix)]
pub type LocalStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type LocalStream = std::net::TcpStream;

/// Bound terminal-to-server buffering for opted-in flow-control sessions.
pub fn set_receive_buffer_size(stream: &LocalStream, bytes: usize) -> io::Result<()> {
    SockRef::from(stream).set_recv_buffer_size(bytes)
}

/// Length of the hex-encoded Windows registration token.
#[cfg(windows)]
pub const TOKEN_LEN: usize = 64;

/// Create a connected, non-blocking pair of local sockets `(reader, writer)`
/// used to wake blocked loops.
///
/// Unix uses `socketpair(2)` exactly like upstream; Windows uses a loopback TCP
/// pair so the handle can sit in the same readiness checks as every other
/// socket.
pub fn wake_pair() -> io::Result<(LocalStream, LocalStream)> {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::pair()
    }
    #[cfg(windows)]
    {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let writer = std::net::TcpStream::connect(address)?;
        let (reader, peer) = listener.accept()?;
        if !peer.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected wake peer",
            ));
        }
        reader.set_nodelay(true)?;
        writer.set_nodelay(true)?;
        Ok((reader, writer))
    }
}

/// Connect to a local endpoint described by `path`.
pub fn connect(path: &Path) -> io::Result<LocalStream> {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(path)
    }
    #[cfg(windows)]
    {
        use std::io::Write;
        let (address, token) = read_endpoint(path)?;
        let mut stream = std::net::TcpStream::connect(address)?;
        stream.set_nodelay(true)?;
        // The token proves this process can read the user-private endpoint
        // file, which is the Windows stand-in for Unix socket permissions.
        stream.write_all(token.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        Ok(stream)
    }
}

/// Read the `address` and `token` recorded in a Windows endpoint file.
#[cfg(windows)]
pub fn read_endpoint(path: &Path) -> io::Result<(std::net::SocketAddr, String)> {
    let text = std::fs::read_to_string(path)?;
    let mut lines = text.lines();
    let address = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "endpoint file has no address"))?
        .trim()
        .parse::<std::net::SocketAddr>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "endpoint address is malformed"))?;
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "endpoint address is not loopback",
        ));
    }
    let token = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "endpoint file has no token"))?
        .trim()
        .to_owned();
    if token.len() != TOKEN_LEN || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "endpoint token is malformed",
        ));
    }
    Ok((address, token))
}

/// Read and verify the token a Windows terminal sends before registering.
#[cfg(windows)]
pub fn accept_token(stream: &mut LocalStream, expected: &str) -> io::Result<()> {
    use std::io::Read;
    let mut received = Vec::with_capacity(TOKEN_LEN + 1);
    let mut byte = [0u8; 1];
    // Bounded read: the token is a fixed-length hex line.
    while received.len() <= TOKEN_LEN {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => received.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let matches = received.len() == expected.len()
        && received
            .iter()
            .zip(expected.as_bytes())
            .fold(0u8, |accumulator, (left, right)| {
                accumulator | (left ^ right)
            })
            == 0;
    if matches {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "terminal presented an invalid registration token",
        ))
    }
}

/// Generate a fresh registration token.
#[cfg(windows)]
pub fn new_token() -> String {
    use std::fmt::Write;
    let (left, right) = et_core::keys::gen_id_passkey();
    // Fold CSPRNG material into a fixed-length hex string.
    let mut token = String::with_capacity(TOKEN_LEN);
    for byte in left.bytes().chain(right.bytes()).take(TOKEN_LEN / 2) {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn token_is_fixed_length_hex() {
        let token = new_token();
        assert_eq!(token.len(), TOKEN_LEN);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(token, new_token());
    }

    #[test]
    fn endpoint_file_roundtrip_and_validation() {
        let directory = std::env::temp_dir().join(format!("et-endpoint-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("router");
        let token = new_token();
        std::fs::write(&path, format!("127.0.0.1:1234\n{token}\n")).unwrap();
        let (address, parsed) = read_endpoint(&path).unwrap();
        assert_eq!(address.port(), 1234);
        assert_eq!(parsed, token);

        std::fs::write(&path, "10.0.0.1:1234\nnope\n").unwrap();
        assert!(read_endpoint(&path).is_err());
        std::fs::write(&path, format!("127.0.0.1:1234\nshort\n")).unwrap();
        assert!(read_endpoint(&path).is_err());
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
