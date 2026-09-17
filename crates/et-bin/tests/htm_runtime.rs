//! Real HTM process/PTY control-mode contract, shared with native Windows QA.
#![forbid(unsafe_code)]
#[path = "htm_support/attached.rs"]
mod attached;
mod htm_support;
use htm_support::{Daemon, Relay};
use std::io::Write;

#[test]
fn frontend_bootstrap_diagnostics_and_gate_survive_takeover() {
    let mut daemon = Daemon::start();
    let mut ui = Relay::start(&daemon.path);
    let original = ui.state();
    assert_eq!(ui.command("display -p '#{version}'"), b"3.5a\n");
    assert!(
        String::from_utf8_lossy(&ui.command("list-commands")).contains("refresh-client [-C XxY]")
    );
    ui.command("refresh -C 81,27 -f no-output,pause-after=0 -A%0:off");
    ui.command("set -t$1 @affinities a_312c332032");
    let dump = et_htm::server::dump_panes(&daemon.path).unwrap();
    assert!(dump.starts_with("# affinities: [[1,3],[2]]\n"), "{dump}");
    assert!(dump.contains("pane %0 active=1 81x27"), "{dump}");
    assert_eq!(ui.state()["panes"], original["panes"]);
    let mut replacement = Relay::start(&daemon.path);
    ui.finish();
    assert_eq!(replacement.state()["panes"], original["panes"]);
    assert_eq!(
        replacement.command("show -gv @affinities"),
        b"a_312c332032\n"
    );
    replacement.command("refresh -f '!no-output,!pause-after' -A%0:continue");
    #[cfg(unix)]
    send(
        &mut replacement,
        "%0",
        b"printf 'FRONTEND_%s\\n' RESTORED\n",
    );
    #[cfg(windows)]
    {
        send(&mut replacement, "%0", b"\x1b[1;1R");
        send(&mut replacement, "%0", b"echo FRONTEND_RESTORED\r\n");
    }
    replacement.output_contains("%0", b"FRONTEND_RESTORED");
    assert!(et_htm::server::dump_panes(&daemon.path)
        .unwrap()
        .contains("FRONTEND_RESTORED"));
    writeln!(replacement.input, "kill-server").unwrap();
    replacement.finish();
    daemon.finish();
    assert!(et_htm::server::dump_panes(&daemon.path).is_err());
}

fn send(relay: &mut Relay, pane: &str, bytes: &[u8]) {
    let hex = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    relay.command(&format!("send-keys -t {pane} -H {hex}"));
}

#[test]
fn panes_resize_and_reattach_through_real_roles() {
    let mut daemon = Daemon::start();
    let mut relay = Relay::start(&daemon.path);
    let initial = relay.state();
    assert!(initial["panes"]["%0"].is_string());
    assert_eq!(
        relay.command("new-window -P -F '#{window_id} #{pane_id}'"),
        b"@1 %1\n"
    );
    #[cfg(windows)]
    {
        relay.output_contains("%1", b"\x1b[6n");
        send(&mut relay, "%1", b"\x1b[1;1R");
    }
    #[cfg(unix)]
    let command = b"HTM_QA=73; printf 'HTM_%s=%s\\n' VALUE \"$HTM_QA\"\n";
    #[cfg(windows)]
    let command = b"set HTM_QA=73\r\necho HTM_VALUE=%HTM_QA%\r\n";
    send(&mut relay, "%1", command);
    relay.output_contains("%1", b"HTM_VALUE=73");
    relay.command("resize-window -t @1 -x 113 -y 37");
    #[cfg(unix)]
    let geometry = b"printf 'HTM_SIZE='; stty size\n";
    #[cfg(windows)]
    let geometry = b"powershell.exe -NoProfile -Command \"Write-Output ('HTM_SIZE=' + [Console]::WindowHeight + ' ' + [Console]::WindowWidth)\"\r\n";
    send(&mut relay, "%1", geometry);
    relay.output_contains("%1", b"HTM_SIZE=37 113");
    relay.command("set -g @affinities '1,0;style=fs'");
    writeln!(relay.input, "detach-client").unwrap();
    relay.finish();
    let mut relay = Relay::start(&daemon.path);
    let restored = relay.state();
    assert_eq!(restored["panes"].as_object().unwrap().len(), 2);
    assert_eq!(restored["panes"]["%0"], initial["panes"]["%0"]);
    let capture = relay.command("capture-pane -p -t %1");
    assert!(String::from_utf8_lossy(&capture).contains("HTM_VALUE=73"));
    assert_eq!(relay.command("show -gv @affinities"), b"1,0;style=fs\n");
    #[cfg(unix)]
    let retained = b"printf 'HTM_%s=%s\\n' RETAINED \"$HTM_QA\"\n";
    #[cfg(windows)]
    let retained = b"echo HTM_RETAINED=%HTM_QA%\r\n";
    send(&mut relay, "%1", retained);
    relay.output_contains("%1", b"HTM_RETAINED=73");
    writeln!(relay.input, "kill-server").unwrap();
    relay.finish();
    daemon.finish();
}

#[test]
fn empty_line_detaches_and_stale_commands_do_not_execute() {
    let mut daemon = Daemon::start();
    let mut relay = Relay::start(&daemon.path);
    let initial = relay.state();
    relay.input.write_all(b"''\nkill-pane -t %0\n").unwrap();
    relay.finish();
    let mut relay = Relay::start(&daemon.path);
    assert_eq!(relay.state(), initial);
    writeln!(relay.input, "kill-server").unwrap();
    relay.finish();
    daemon.finish();
}

#[test]
fn auto_start_and_kill_other_sessions_replace_only_the_selected_daemon() {
    let mut other = Daemon::start();
    let mut other_relay = Relay::start(&other.path);
    let other_state = other_relay.state();
    writeln!(other_relay.input, "detach-client").unwrap();
    other_relay.finish();
    let endpoint = htm_support::Endpoint::new();
    let mut first = Relay::start(&endpoint.path);
    let before = first.state();
    writeln!(first.input, "detach-client").unwrap();
    first.finish();
    let mut reattached = Relay::start(&endpoint.path);
    assert_eq!(reattached.state(), before);
    writeln!(reattached.input, "detach-client").unwrap();
    reattached.finish();
    let mut replacement = Relay::restart(&endpoint.path);
    assert_ne!(replacement.state(), before);
    let mut other_relay = Relay::start(&other.path);
    assert_eq!(other_relay.state(), other_state);
    writeln!(replacement.input, "kill-server").unwrap();
    replacement.finish();
    writeln!(other_relay.input, "kill-server").unwrap();
    other_relay.finish();
    other.finish();
}

#[test]
fn command_lists_zero_targets_layout_and_final_pane_exit() {
    let mut daemon = Daemon::start();
    let mut relay = Relay::start(&daemon.path);
    relay.state();
    #[cfg(windows)]
    {
        // ConPTY waits for the frontend's cursor-position response before
        // starting cmd.exe. Its startup query may already have been drained
        // while detached or by state(), so supply the known initial position
        // as the frontend-bootstrap test does rather than awaiting a replay.
        send(&mut relay, "%0", b"\x1b[1;1R");
    }
    relay
        .input
        .write_all(b"display -p '#{version}'; split-window -h -t %0 -P -F '#{pane_id}'\r\n")
        .unwrap();
    assert_eq!(relay.reply(), b"3.5a\n");
    assert_eq!(relay.reply(), b"%1\n");
    let layout = relay.command("list-windows -F '#{window_id} #{window_layout}'");
    assert!(String::from_utf8_lossy(&layout).contains("8205,80x24,0,0{40x24,0,0,0,39x24,41,0,1}"));
    assert_eq!(
        relay.command("list-panes -t @0 -F '#{pane_id}'"),
        b"%0\n%1\n"
    );
    relay.command("kill-pane -t %1");
    #[cfg(unix)]
    send(&mut relay, "%0", b"printf 'HTM_%s' FINAL; exit\n");
    #[cfg(windows)]
    send(
        &mut relay,
        "%0",
        b"set HTM_LAST=FINAL\r\necho HTM_%HTM_LAST%\r\nexit\r\n",
    );
    relay.output_contains("%0", b"HTM_FINAL");
    relay.finish();
    daemon.finish();
}

#[cfg(windows)]
#[test]
fn autostart_survives_client_exit_inside_a_nonbreakaway_host_job() {
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_spawn::{Command, DropPolicy, Job, SpawnOptions, Stdio};
    let job = Job::create().unwrap();
    job.set_kill_on_close(true).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "auto_start_and_kill_other_sessions_replace_only_the_selected_daemon",
            "--exact",
            "--test-threads=1",
            "--nocapture",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn_with(
            SpawnOptions::new()
                .job(&job)
                .drop_policy(DropPolicy::Detach),
        )
        .unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    let result = receiver.recv_timeout(Duration::from_secs(45));
    if result.is_err() {
        job.terminate(1).unwrap();
    }
    worker.join().unwrap();
    let output = result.expect("host-job role scenario completion").unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
