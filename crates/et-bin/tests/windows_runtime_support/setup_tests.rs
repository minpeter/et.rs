use super::Stack;

#[test]
fn setup_failure_removes_the_acquired_directory() {
    // Given a setup hook reached after the fixture directory is created.
    let mut directory = None;
    // When setup fails before the server is spawned.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Stack::start_with_setup(|path| {
            directory = Some(path.to_path_buf());
            panic!("injected configuration setup failure");
        });
    }));
    let directory = directory.expect("setup hook did not run");
    let leaked = directory.exists();
    if leaked {
        std::fs::remove_dir_all(&directory).unwrap();
    }
    // Then the fixture, not this probe's fallback, owns failure cleanup.
    assert!(result.is_err());
    assert!(!leaked, "setup failure leaked {}", directory.display());
}
