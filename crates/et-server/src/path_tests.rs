use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Registry, Router, RouterError};

use super::{select_router_path_for, DirectoryPlan, PathError, RouterPath};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "et-rs-root-router-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn trusted_root_parent_symlink_binds_but_explicit_parent_symlink_is_rejected() {
    let root = TestRoot::new();
    let target = root.0.join("run");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let linked = root.0.join("var-run");
    symlink(&target, &linked).unwrap();
    let socket = linked.join("router.sock");
    let trusted = RouterPath {
        path: socket.clone(),
        socket_mode: 0o666,
        plan: DirectoryPlan::RootDefault,
    };
    let mut router = Router::start(trusted, Registry::new()).unwrap();
    assert!(socket.exists());
    router.shutdown().unwrap();

    let explicit = select_router_path_for(0, Some(&socket), None, None).unwrap();
    assert!(matches!(
        Router::start(explicit, Registry::new()),
        Err(RouterError::Path(PathError::UnsafeDirectory(_)))
    ));
}

#[test]
fn xdg_etserver_refuses_a_replaceable_parent_and_a_planted_symlink() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root = TestRoot::new();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
    let selected = select_router_path_for(1000, None, Some(&root.0), None).unwrap();
    assert!(selected.prepare().is_err());

    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let victim = root.0.join("victim");
    fs::create_dir(&victim).unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&victim, root.0.join("etserver")).unwrap();
    let selected = select_router_path_for(1000, None, Some(&root.0), None).unwrap();
    assert!(selected.prepare().is_err());
    assert!(fs::read_dir(&victim).unwrap().next().is_none());
}

#[test]
fn home_etserver_checks_ancestors_and_stays_private() {
    use std::os::unix::fs::MetadataExt;

    let home = TestRoot::new();
    let selected = select_router_path_for(1000, None, None, Some(&home.0)).unwrap();
    selected.prepare().unwrap();
    let etserver = home.0.join(".local").join("share").join("etserver");
    assert_eq!(fs::metadata(&etserver).unwrap().mode() & 0o777, 0o700);
}
