use std::process::{Command, Stdio};

use super::{powershell, OwnedChild, PROCESS_CLEANUP};

#[test]
fn cleanup_continues_when_a_target_exits_between_has_exited_and_kill() {
    run_cleanup_probe("race");
}

#[test]
fn cleanup_reports_target_errors_after_processing_remaining_targets() {
    run_cleanup_probe("error");
}

fn run_cleanup_probe(scenario: &str) {
    let script = format!(
        "$ErrorActionPreference='Stop';\n{PROCESS_CLEANUP}\n{}\nTest-ProcessCleanup -Scenario '{scenario}'",
        include_str!("process_cleanup_probe.ps1")
    );
    let mut command = Command::new(powershell());
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null());
    let mut child = OwnedChild::spawn(&mut command);
    assert!(
        child.wait().success(),
        "native cleanup probe failed: {scenario}"
    );
}
