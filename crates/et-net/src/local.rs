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
#[cfg(unix)]
use std::io::Write;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

const REGISTRATION_ACK_CAPABILITY: &str = "et-registration-ack-v1";

use socket2::SockRef;

/// Terminal-side kernel queue bound for opted-in flow-control sessions.
pub const FLOW_CONTROL_SEND_BUFFER_BYTES: usize = 64 * 1024;

/// Stream type used for local server/terminal IPC.
#[cfg(unix)]
pub type LocalStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type LocalStream = std::net::TcpStream;

/// Bound terminal-to-server buffering on the sending endpoint.
///
/// On Unix this configures the `etterminal` Unix socket, matching upstream
/// PR #730. On Windows `LocalStream` is loopback TCP, where `SO_SNDBUF` is the
/// corresponding bound on the same terminal-side hop.
pub fn minimize_terminal_output_buffering(stream: &LocalStream) -> io::Result<()> {
    SockRef::from(stream).set_send_buffer_size(FLOW_CONTROL_SEND_BUFFER_BYTES)
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

/// Sidecar used to negotiate the local-only registration acknowledgement.
/// It does not alter the protocol-v6 network wire format.
#[cfg(unix)]
pub fn capability_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".cap");
    PathBuf::from(value)
}

/// Whether the selected router advertises registration acknowledgements.
pub fn supports_registration_ack(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return false;
        };
        std::fs::read_to_string(capability_path(path))
            .ok()
            .and_then(|value| parse_capability(&value))
            == Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        std::fs::read_to_string(path).is_ok_and(|value| {
            value.lines().nth(2).map(str::trim) == Some(REGISTRATION_ACK_CAPABILITY)
        })
    }
}

#[cfg(unix)]
pub fn write_registration_ack_capability(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        // The marker is not a secret. Root-mode routers are intentionally
        // reachable by unprivileged terminal users through a 0666 socket.
        .mode(0o644)
        .open(capability_path(path))?
        .write_all(
            format!(
                "{REGISTRATION_ACK_CAPABILITY} {} {}\n",
                metadata.dev(),
                metadata.ino()
            )
            .as_bytes(),
        )
}

#[cfg(unix)]
pub fn retire_registration_ack_capability(path: &Path, device: u64, inode: u64) -> io::Result<()> {
    let capability = capability_path(path);
    let mut retired = capability.as_os_str().to_owned();
    retired.push(format!(".retired-{device}-{inode}"));
    let retired = PathBuf::from(retired);
    match std::fs::rename(&capability, &retired) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let belongs_to_listener = std::fs::read_to_string(&retired)
        .ok()
        .and_then(|value| parse_capability(&value))
        == Some((device, inode));
    if belongs_to_listener {
        std::fs::remove_file(retired)
    } else if !capability.exists() {
        std::fs::rename(retired, capability)
    } else {
        // A current generation already published its marker. Never overwrite
        // it while retiring an unrelated generation.
        std::fs::remove_file(retired)
    }
}

#[cfg(unix)]
fn parse_capability(value: &str) -> Option<(u64, u64)> {
    let mut fields = value.split_whitespace();
    if fields.next() != Some(REGISTRATION_ACK_CAPABILITY) {
        return None;
    }
    let device = fields.next()?.parse().ok()?;
    let inode = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some((device, inode))
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

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    #[test]
    fn capability_is_bound_to_current_socket_inode() {
        let directory = std::env::temp_dir().join(format!(
            "et-capability-test-{}-{}",
            std::process::id(),
            et_core::keys::gen_id_passkey().0
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("router.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        write_registration_ack_capability(&path).unwrap();
        assert!(supports_registration_ack(&path));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(capability_path(&path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::write(
            capability_path(&path),
            format!("{REGISTRATION_ACK_CAPABILITY} 0 0\n"),
        )
        .unwrap();
        assert!(!supports_registration_ack(&path));
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        use std::os::unix::fs::MetadataExt;
        retire_registration_ack_capability(&path, metadata.dev() + 1, metadata.ino()).unwrap();
        assert!(
            capability_path(&path).exists(),
            "unrelated generation marker was deleted"
        );
        drop(replacement);
        std::fs::remove_dir_all(directory).unwrap();
    }
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
