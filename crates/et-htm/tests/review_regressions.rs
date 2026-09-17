use et_htm::{control, framing, state::MultiplexerState};

fn command(state: &mut MultiplexerState, line: &str) -> Result<Vec<u8>, String> {
    control::execute(state, &mut Default::default(), &framing::parse(line)?[0])
}

#[test]
fn format_expansion_and_list_aggregation_reject_oversize_before_delivery() {
    let mut state = MultiplexerState::new().unwrap();
    state
        .options
        .insert((' ', 1, "@large".into()), "x".repeat(65536));
    assert_eq!(
        command(&mut state, "display -p '#{@large}#{@large}'")
            .unwrap()
            .len(),
        131072
    );
    assert!(command(&mut state, "display -p '#{@large}#{@large}x'").is_err());
    assert!(command(
        &mut state,
        "display -p '#{?session_id,#{@large}#{@large}x,no}'"
    )
    .is_err());
    command(&mut state, "splitw").unwrap();
    command(&mut state, "splitw").unwrap();
    assert!(command(&mut state, "lsp -F '#{@large}'").is_err());
    assert_eq!(
        command(&mut state, "display -p '#{pane_id}'").unwrap(),
        b"%2"
    );
}

#[test]
fn resize_trap_cannot_interrupt_cross_window_ownership_transfer() {
    let mut state = MultiplexerState::new().unwrap();
    command(&mut state, "neww").unwrap();
    // Reproduce a real trapped guest without exhausting host memory.
    assert!(state
        .panes
        .get_mut(&1)
        .unwrap()
        .screen
        .process(b"\x1b[0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0m")
        .is_err());
    let _ = state.swap(0, 1);
    let mut owned: Vec<_> = state
        .windows
        .values()
        .flat_map(|w| w.layout.panes())
        .collect();
    owned.sort_unstable();
    assert_eq!(
        owned,
        vec![0, 1],
        "each pane must have exactly one window even on trap"
    );
    state.poll(true, false, false);
    assert!(
        !state.panes.contains_key(&1),
        "a poisoned idle screen must be reaped"
    );
    assert!(state.panes.contains_key(&0));
}

#[cfg(target_os = "linux")]
#[test]
fn automatic_rename_cannot_inject_control_records() {
    use std::time::{Duration, Instant};
    let directory = std::env::temp_dir().join(format!("htm-rename-review-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let program = directory.join("x\n%exit");
    std::os::unix::fs::symlink("/bin/sleep", &program).unwrap();
    let mut state = MultiplexerState::new().unwrap();
    state
        .panes
        .get_mut(&0)
        .unwrap()
        .terminal
        .append_data(format!("exec '{}' 5\n", program.display()).as_bytes())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        state.poll(true, false, false);
        if state.windows[&0].name.contains("%exit") {
            std::fs::remove_file(&program).unwrap();
            std::fs::remove_dir(&directory).unwrap();
            assert_eq!(state.windows[&0].name, "x\n%exit");
            let notifications = String::from_utf8_lossy(&state.notifications);
            assert!(
                !notifications.lines().any(|line| line == "%exit"),
                "{notifications}"
            );
            assert!(notifications.contains("x\\012%exit"), "{notifications}");
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::remove_file(&program).unwrap();
    std::fs::remove_dir(&directory).unwrap();
    panic!("shell process-name change not observed");
}
