use super::*;
use std::io::{Read, Write};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = private_base()
            .unwrap()
            .join(format!("et-htm-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn endpoint(&self) -> PathBuf {
        self.0.join("htm.ipc")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn invalid_token_receives_no_state_but_authenticated_client_connects() {
    // Given a real private endpoint and bound loopback listener.
    let directory = Directory::new();
    let path = directory.endpoint();
    let listener = Listener::bind(&path).unwrap();
    let (address, _) = et_net::local::read_endpoint(&path).unwrap();
    let mut intruder = Stream::connect(address).unwrap();
    intruder
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // When the peer presents an invalid token.
    intruder.write_all(b"wrong\n").unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    // Then no data can escape, and the listener remains usable.
    assert_eq!(intruder.read(&mut [0; 1]).unwrap(), 0);
    let mut client = connect(&path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut server = listener.accept().unwrap();
    server.write_all(b"authenticated").unwrap();
    let mut received = [0; 13];
    client.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"authenticated");
}

#[test]
fn lock_excludes_second_daemon_and_stale_endpoint_is_replaced() {
    // Given a crashed daemon's endpoint file.
    let directory = Directory::new();
    let path = directory.endpoint();
    std::fs::write(&path, b"stale").unwrap();
    // When the daemon takes the exclusive lifetime lock.
    let mut listener = Listener::bind(&path).unwrap();
    let first = std::fs::read(&path).unwrap();
    // Then a second bind neither replaces nor removes the live endpoint.
    let error = match Listener::bind(&path) {
        Ok(_) => panic!("duplicate bind"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    assert_eq!(std::fs::read(&path).unwrap(), first);
    listener.retire().unwrap();
    let replacement = Listener::bind(&path).unwrap();
    assert_ne!(std::fs::read(&path).unwrap(), first);
    drop(listener);
    assert!(
        connect(&path).is_ok(),
        "old generation removed the new endpoint"
    );
    drop(replacement);
}

#[test]
fn endpoints_outside_private_tree_and_remote_addresses_are_rejected() {
    // Given paths outside the user's private application directory.
    let directory = Directory::new();
    assert!(prepare_path(Path::new(r"C:\Windows\Temp\htm.ipc")).is_err());
    assert!(prepare_path(&directory.0.join("..").join("escape.ipc")).is_err());
    // When a private endpoint file advertises a remote address.
    let path = directory.endpoint();
    std::fs::write(
        &path,
        format!("192.0.2.1:1234\n{}\n", et_net::local::new_token()),
    )
    .unwrap();
    // Then connect rejects it before trying the network.
    assert_eq!(
        connect(&path).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn accepted_stream_uses_blocking_timeout_instead_of_inherited_would_block() {
    // Given an authenticated accepted stream with no remaining client bytes.
    let directory = Directory::new();
    let path = directory.endpoint();
    let listener = Listener::bind(&path).unwrap();
    let _client = connect(&path).unwrap();
    let mut accepted = listener.accept().unwrap();
    // When a blocking read's configured timeout expires. Timeouts are the
    // behavior under test here, not a sleep used to schedule another actor.
    accepted
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let error = accepted.read_exact(&mut [0]).unwrap_err();
    // Then Windows returns WSAETIMEDOUT, not inherited nonblocking WSAEWOULDBLOCK.
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}
