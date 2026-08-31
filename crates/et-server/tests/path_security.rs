#![forbid(unsafe_code)]

mod support;

use std::fs::{self, File};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

use et_server::path::{select_router_path_for, PathError};
use et_server::{Registry, Router, RouterError};
use support::TestDir;

#[test]
fn selection_matches_root_xdg_home_and_absolute_override_rules() {
    let root = select_router_path_for(0, None, None, None).unwrap();
    assert_eq!(root.path(), Path::new("/var/run/etserver.idpasskey.fifo"));
    assert_eq!(root.socket_mode(), 0o666);

    let xdg = select_router_path_for(
        1000,
        None,
        Some(Path::new("/run/user/1000")),
        Some(Path::new("/home/alice")),
    )
    .unwrap();
    assert_eq!(
        xdg.path(),
        Path::new("/run/user/1000/etserver/etserver.idpasskey.fifo")
    );
    assert_eq!(xdg.socket_mode(), 0o600);

    let home = select_router_path_for(
        1000,
        None,
        Some(Path::new("relative")),
        Some(Path::new("/home/alice")),
    )
    .unwrap();
    assert_eq!(
        home.path(),
        Path::new("/home/alice/.local/share/etserver/etserver.idpasskey.fifo")
    );
    assert!(matches!(
        select_router_path_for(1000, Some(Path::new("relative")), None, None),
        Err(PathError::RelativeOverride(_))
    ));
}

#[test]
fn rejects_regular_symlink_and_live_socket_paths() {
    let dir = TestDir::new();
    let path = dir.socket();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();

    File::create(&path).unwrap();
    assert!(matches!(
        Router::start(selected.clone(), Registry::new()),
        Err(RouterError::Path(PathError::NotSocket(_)))
    ));
    fs::remove_file(&path).unwrap();

    symlink(dir.path().join("missing"), &path).unwrap();
    assert!(matches!(
        Router::start(selected.clone(), Registry::new()),
        Err(RouterError::Path(PathError::Symlink(_)))
    ));
    fs::remove_file(&path).unwrap();

    let live = UnixListener::bind(&path).unwrap();
    assert!(matches!(
        Router::start(selected, Registry::new()),
        Err(RouterError::Path(PathError::LiveSocket(_)))
    ));
    drop(live);
}

#[test]
fn stale_socket_is_replaced_with_secure_permissions_and_cleaned_up() {
    let dir = TestDir::new();
    let path = dir.socket();
    drop(UnixListener::bind(&path).unwrap());

    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, Registry::new()).unwrap();
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());

    router.shutdown().unwrap();
    assert!(!path.exists());
}

#[test]
fn cleanup_does_not_remove_a_replacement_inode() {
    let dir = TestDir::new();
    let path = dir.socket();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, Registry::new()).unwrap();

    fs::remove_file(&path).unwrap();
    fs::remove_file(et_net::local::capability_path(&path)).unwrap();
    File::create(&path).unwrap();
    et_net::local::write_registration_ack_capability(&path).unwrap();
    router.shutdown().unwrap();
    assert!(path.is_file());
    assert!(
        et_net::local::supports_registration_ack(&path),
        "old listener removed the replacement generation's marker"
    );
}

#[test]
fn root_compatible_socket_is_read_write_without_execute_bits() {
    let dir = TestDir::new();
    let path = dir.socket();
    let selected = select_router_path_for(0, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, Registry::new()).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o666);
    let capability = et_net::local::capability_path(&path);
    assert_eq!(
        fs::metadata(capability).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert!(et_net::local::supports_registration_ack(&path));
    router.shutdown().unwrap();
}

#[test]
fn rejects_writable_or_symlinked_override_directories() {
    let dir = TestDir::new();
    let path = dir.socket();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    assert!(matches!(
        Router::start(selected, Registry::new()),
        Err(RouterError::Path(PathError::UnsafeDirectory(_)))
    ));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let linked = dir.path().join("linked");
    symlink(&real, &linked).unwrap();
    let linked_socket = linked.join("router.sock");
    let selected = select_router_path_for(1000, Some(&linked_socket), None, None).unwrap();
    assert!(matches!(
        Router::start(selected, Registry::new()),
        Err(RouterError::Path(PathError::UnsafeDirectory(_)))
    ));
}

#[test]
fn home_default_creates_private_router_directory() {
    let home = TestDir::new();
    let selected = select_router_path_for(1000, None, None, Some(home.path())).unwrap();
    let path = selected.path().to_path_buf();
    let parent = path.parent().unwrap().to_path_buf();
    let mut router = Router::start(selected, Registry::new()).unwrap();

    assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    router.shutdown().unwrap();
    assert!(!path.exists());
}
