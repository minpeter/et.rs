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
