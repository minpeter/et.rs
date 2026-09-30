use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use super::unix::Proxy;

struct Session {
    id: String,
    directory: PathBuf,
}

impl Session {
    fn new() -> Self {
        let id = et_core::keys::gen_id_passkey().0;
        let directory = std::env::temp_dir().join(format!("et-agent-{id}"));
        Self { id, directory }
    }

    fn proxy(&self, pinned: Option<String>) -> Proxy {
        Proxy::open(&self.id, pinned, true).unwrap().unwrap()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn request(proxy: &Proxy, listener: &UnixListener, expected: u8) {
    let mut client = UnixStream::connect(proxy.path()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.write_all(b"request").unwrap();
    let (mut agent, _) = listener.accept().unwrap();
    agent
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = [0; 7];
    agent.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"request");
    agent.write_all(&[expected]).unwrap();
    let mut response = [0];
    client.read_exact(&mut response).unwrap();
    assert_eq!(response, [expected]);
}

#[test]
fn stable_endpoint_retargets_real_requests_and_leaves_old_agent_unused() {
    let session = Session::new();
    let proxy = session.proxy(None);
    let old_path = session.directory.join("old.sock");
    let new_path = session.directory.join("new.sock");
    let old = UnixListener::bind(&old_path).unwrap();
    let new = UnixListener::bind(&new_path).unwrap();
    old.set_nonblocking(true).unwrap();
    new.set_nonblocking(true).unwrap();
    let stable_path = proxy.path().to_owned();

    proxy.refresh(old_path.to_str()).unwrap();
    request(&proxy, &old, 13);
    proxy.refresh(new_path.to_str()).unwrap();
    assert_eq!(proxy.path(), stable_path);
    request(&proxy, &new, 29);
    assert_eq!(
        old.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        fs::metadata(&session.directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(fs::read_dir(&session.directory).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains(".tmp.")));

    // Process exit does not unlink the stable endpoint; attach reopens it.
    drop(proxy);
    let attached = session.proxy(None);
    attached.refresh(old_path.to_str()).unwrap();
    request(&attached, &old, 47);
    assert_eq!(attached.path(), stable_path);
    assert_eq!(
        new.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn explicit_socket_is_pinned_but_attach_uses_the_new_environment() {
    let session = Session::new();
    let first = session.proxy(Some("/tmp/explicit-agent.sock".into()));
    first.refresh(Some("/tmp/env-agent.sock")).unwrap();
    assert_eq!(
        fs::read_link(first.path()).unwrap(),
        PathBuf::from("/tmp/explicit-agent.sock")
    );
    first.refresh(None).unwrap();
    assert_eq!(
        fs::read_link(first.path()).unwrap(),
        PathBuf::from("/tmp/explicit-agent.sock")
    );
    drop(first);
    let attached = session.proxy(None);
    attached.refresh(Some("/tmp/new-agent.sock")).unwrap();
    assert_eq!(
        fs::read_link(attached.path()).unwrap(),
        PathBuf::from("/tmp/new-agent.sock")
    );
}

#[test]
fn missing_invalid_and_dead_targets_never_fall_back_to_the_old_agent() {
    let session = Session::new();
    let proxy = session.proxy(None);
    let old_path = session.directory.join("old.sock");
    let old = UnixListener::bind(&old_path).unwrap();
    old.set_nonblocking(true).unwrap();
    for missing in [None, Some("")] {
        proxy.refresh(old_path.to_str()).unwrap();
        proxy.refresh(missing).unwrap();
        assert!(fs::symlink_metadata(proxy.path()).is_err());
        assert!(UnixStream::connect(proxy.path()).is_err());
    }
    for invalid in [
        "relative.sock",
        "/tmp/bad\0sock",
        proxy.path().to_str().unwrap(),
    ] {
        proxy.refresh(old_path.to_str()).unwrap();
        assert!(proxy.refresh(Some(invalid)).is_err());
        assert!(fs::symlink_metadata(proxy.path()).is_err());
    }
    proxy.refresh(old_path.to_str()).unwrap();
    proxy
        .refresh(session.directory.join("absent.sock").to_str())
        .unwrap();
    assert!(UnixStream::connect(proxy.path()).is_err());
    assert_eq!(
        old.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    // Reestablishment is allowed after a target temporarily disappears.
    proxy.refresh(old_path.to_str()).unwrap();
    request(&proxy, &old, 83);
}

#[test]
fn unsafe_directory_and_non_symlink_proxy_are_not_modified() {
    let session = Session::new();
    let target = Session::new();
    fs::create_dir(&target.directory).unwrap();
    fs::set_permissions(&target.directory, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&target.directory, &session.directory).unwrap();
    assert!(Proxy::open(&session.id, None, true).is_err());
    assert_eq!(
        fs::metadata(&target.directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    fs::remove_file(&session.directory).unwrap();
    fs::create_dir(&session.directory).unwrap();
    fs::set_permissions(&session.directory, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(Proxy::open(&session.id, None, true).is_err());
    fs::set_permissions(&session.directory, fs::Permissions::from_mode(0o700)).unwrap();
    let proxy = session.proxy(None);
    fs::write(proxy.path(), "do not replace").unwrap();
    assert!(proxy.refresh(Some("/tmp/agent.sock")).is_err());
    assert!(proxy.refresh(None).is_err());
    assert_eq!(fs::read_to_string(proxy.path()).unwrap(), "do not replace");
    for invalid in ["../abcdefghijklmn", "", "short", "abcdefghijklmnop/child"] {
        assert!(Proxy::open(invalid, None, true).is_err());
    }
}

#[test]
fn missing_proxy_directory_is_recreated_for_attach() {
    let session = Session::new();
    let first = session.proxy(None);
    first.refresh(Some("/tmp/old-agent.sock")).unwrap();
    let path = first.path().to_owned();
    drop(first);
    fs::remove_dir_all(&session.directory).unwrap();
    assert!(Proxy::open(&session.id, None, false).unwrap().is_none());
    let attached = session.proxy(None);
    attached.refresh(Some("/tmp/new-agent.sock")).unwrap();
    assert_eq!(attached.path(), path);
    assert_eq!(
        fs::read_link(path).unwrap(),
        PathBuf::from("/tmp/new-agent.sock")
    );
}
