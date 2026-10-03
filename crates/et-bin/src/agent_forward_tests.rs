use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use super::unix::{validate_proxy_path, Policy, Proxy};

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
        let policy = if pinned.is_some() {
            Policy::Initial
        } else {
            Policy::Attach
        };
        let mut proxy = Proxy::open(&self.id, pinned.map(OsString::from), policy, true)
            .unwrap()
            .unwrap();
        proxy.mark_established();
        proxy
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

    proxy.refresh(Some(old_path.as_os_str())).unwrap();
    request(&proxy, &old, 13);
    proxy.refresh(Some(new_path.as_os_str())).unwrap();
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
    attached.refresh(Some(old_path.as_os_str())).unwrap();
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
    first
        .refresh(Some(OsStr::new("/tmp/env-agent.sock")))
        .unwrap();
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
    attached
        .refresh(Some(OsStr::new("/tmp/new-agent.sock")))
        .unwrap();
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
        proxy.refresh(Some(old_path.as_os_str())).unwrap();
        proxy.refresh(missing.map(OsStr::new)).unwrap();
        assert!(fs::symlink_metadata(proxy.path()).is_err());
        assert!(UnixStream::connect(proxy.path()).is_err());
    }
    for invalid in [
        "relative.sock",
        "/tmp/bad\0sock",
        proxy.path().to_str().unwrap(),
    ] {
        proxy.refresh(Some(old_path.as_os_str())).unwrap();
        proxy.refresh(Some(OsStr::new(invalid))).unwrap();
        assert!(fs::symlink_metadata(proxy.path()).is_err());
    }
    let pinned = session.proxy(Some("relative.sock".into()));
    assert!(pinned.refresh(None).is_err());
    proxy.refresh(Some(old_path.as_os_str())).unwrap();
    proxy
        .refresh(Some(session.directory.join("absent.sock").as_os_str()))
        .unwrap();
    assert!(UnixStream::connect(proxy.path()).is_err());
    assert_eq!(
        old.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    // Reestablishment is allowed after a target temporarily disappears.
    proxy.refresh(Some(old_path.as_os_str())).unwrap();
    request(&proxy, &old, 83);
}

#[test]
fn environment_targets_fail_closed_without_rejecting_attach() {
    let session = Session::new();
    let proxy = session.proxy(None);
    let old_path = session.directory.join("old.sock");
    proxy.refresh(Some(old_path.as_os_str())).unwrap();
    for invalid in [
        OsString::from("relative.sock"),
        OsString::from("/tmp/bad\0sock"),
        session
            .directory
            .join("./sub/../agent.sock")
            .into_os_string(),
    ] {
        proxy.refresh(Some(old_path.as_os_str())).unwrap();
        proxy.refresh(Some(&invalid)).unwrap();
        assert!(fs::symlink_metadata(proxy.path()).is_err());
    }
}

#[test]
fn initial_environment_target_is_validated_but_attach_remains_nonfatal() {
    let session = Session::new();
    let initial = Proxy::open(&session.id, None, Policy::Initial, true)
        .unwrap()
        .unwrap();
    for invalid in [
        OsString::from("relative.sock"),
        session.directory.join("./agent.sock").into_os_string(),
    ] {
        assert!(initial.refresh(Some(&invalid)).is_err());
        assert!(fs::symlink_metadata(initial.path()).is_err());
    }
    drop(initial);

    let attached = session.proxy(None);
    for invalid in [
        OsString::from("relative.sock"),
        session.directory.join("./agent.sock").into_os_string(),
    ] {
        attached.refresh(Some(&invalid)).unwrap();
        // The same fail-closed policy applies when reconnect refreshes again.
        attached.refresh(Some(&invalid)).unwrap();
        assert!(fs::symlink_metadata(attached.path()).is_err());
    }
}

#[test]
fn non_utf8_environment_target_is_preserved() {
    let session = Session::new();
    let proxy = session.proxy(None);
    let mut bytes = session.directory.as_os_str().as_encoded_bytes().to_vec();
    bytes.extend_from_slice(b"/agent-\xff.sock");
    let target = OsString::from_vec(bytes);
    proxy.refresh(Some(&target)).unwrap();
    assert_eq!(fs::read_link(proxy.path()).unwrap().as_os_str(), target);
}

#[test]
fn unestablished_proxy_is_removed_but_established_proxy_is_retained() {
    let unestablished = Session::new();
    let proxy = Proxy::open(&unestablished.id, None, Policy::Initial, true)
        .unwrap()
        .unwrap();
    proxy
        .refresh(Some(std::ffi::OsStr::new("/tmp/agent.sock")))
        .unwrap();
    drop(proxy);
    assert!(!unestablished.directory.exists());

    let established = Session::new();
    let proxy = established.proxy(None);
    proxy
        .refresh(Some(std::ffi::OsStr::new("/tmp/agent.sock")))
        .unwrap();
    drop(proxy);
    assert!(established.directory.exists());
}

#[test]
fn oversized_proxy_path_is_rejected_before_wire_use() {
    let path = PathBuf::from(format!("/{}", "x".repeat(256)));
    let error = validate_proxy_path(&path).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn unsafe_directory_and_non_symlink_proxy_are_not_modified() {
    let session = Session::new();
    let target = Session::new();
    fs::create_dir(&target.directory).unwrap();
    fs::set_permissions(&target.directory, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&target.directory, &session.directory).unwrap();
    assert!(Proxy::open(&session.id, None, Policy::Attach, true).is_err());
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
    assert!(Proxy::open(&session.id, None, Policy::Attach, true).is_err());
    fs::set_permissions(&session.directory, fs::Permissions::from_mode(0o700)).unwrap();
    let proxy = session.proxy(None);
    fs::write(proxy.path(), "do not replace").unwrap();
    assert!(proxy.refresh(Some(OsStr::new("/tmp/agent.sock"))).is_err());
    assert!(proxy.refresh(None).is_err());
    assert_eq!(fs::read_to_string(proxy.path()).unwrap(), "do not replace");
    for invalid in ["../abcdefghijklmn", "", "short", "abcdefghijklmnop/child"] {
        assert!(Proxy::open(invalid, None, Policy::Attach, true).is_err());
    }
}

#[test]
fn missing_proxy_directory_is_recreated_for_attach() {
    let session = Session::new();
    let first = session.proxy(None);
    first
        .refresh(Some(OsStr::new("/tmp/old-agent.sock")))
        .unwrap();
    let path = first.path().to_owned();
    drop(first);
    fs::remove_dir_all(&session.directory).unwrap();
    assert!(Proxy::open(&session.id, None, Policy::Attach, false)
        .unwrap()
        .is_none());
    let attached = session.proxy(None);
    attached
        .refresh(Some(OsStr::new("/tmp/new-agent.sock")))
        .unwrap();
    assert_eq!(attached.path(), path);
    assert_eq!(
        fs::read_link(path).unwrap(),
        PathBuf::from("/tmp/new-agent.sock")
    );
}
