//! Real HTM process/PTY contract, shared by Unix and native Windows QA.
#![forbid(unsafe_code)]

mod htm_support;

use et_htm::{codes, framing};
use htm_support::{Daemon, Relay};

#[test]
fn panes_resize_and_reattach_through_real_roles() {
    // Given an isolated foreground daemon and the actual stdin/stdout relay.
    let mut daemon = Daemon::start();
    let mut relay = Relay::start(&daemon.path);
    let initial = relay.state();
    let original = initial["panes"].as_object().unwrap().keys().next().unwrap();
    let pane = "11111111-1111-4111-8111-111111111111";
    let tab = "22222222-2222-4222-8222-222222222222";

    // When a new pane receives commands and a resize through HTM framing.
    framing::write_new_tab(&mut relay.input, tab, pane).unwrap();
    #[cfg(windows)]
    {
        // portable-pty requests an inherited cursor position. Act as the HTM
        // terminal emulator only after receiving that exact ConPTY query.
        relay.output_contains(pane, b"\x1b[6n");
        framing::write_insert_keys(&mut relay.input, pane, b"\x1b[1;1R").unwrap();
    }
    println!("HTM_PANE_CREATED id={pane}");
    #[cfg(unix)]
    let command = b"HTM_QA=73; printf 'HTM_%s=%s\\n' VALUE \"$HTM_QA\"\n";
    #[cfg(windows)]
    let command = b"set HTM_QA=73\r\necho HTM_VALUE=%HTM_QA%\r\n";
    framing::write_insert_keys(&mut relay.input, pane, command).unwrap();
    relay.output_contains(pane, b"HTM_VALUE=73");
    println!("HTM_SHELL_VALUE=73");
    framing::write_resize_pane(&mut relay.input, pane, 113, 37).unwrap();
    #[cfg(unix)]
    let geometry = b"printf 'HTM_SIZE='; stty size\n";
    #[cfg(windows)]
    let geometry = b"powershell.exe -NoProfile -Command \"Write-Output ('HTM_SIZE=' + [Console]::WindowHeight + ' ' + [Console]::WindowWidth)\"\r\n";
    framing::write_insert_keys(&mut relay.input, pane, geometry).unwrap();
    relay.output_contains(pane, b"HTM_SIZE=37 113");
    println!("HTM_SHELL_GEOMETRY=37x113");
    framing::write_debug_keys(&mut relay.input, &[27]).unwrap();
    relay.finish();

    // Then reattach preserves pane identity, replay, and the living shell state.
    let mut relay = Relay::start(&daemon.path);
    let restored = relay.state();
    assert_eq!(restored["panes"].as_object().unwrap().len(), 2);
    assert!(restored["panes"][original].is_object());
    assert_eq!(restored["tabs"][tab]["paneOrSplit"], pane);
    relay.output_contains(pane, b"HTM_VALUE=73");
    #[cfg(unix)]
    let retained = b"printf 'HTM_%s=%s\\n' RETAINED \"$HTM_QA\"\n";
    #[cfg(windows)]
    let retained = b"echo HTM_RETAINED=%HTM_QA%\r\n";
    framing::write_insert_keys(&mut relay.input, pane, retained).unwrap();
    relay.output_contains(pane, b"HTM_RETAINED=73");
    framing::write_client_close_pane(&mut relay.input, pane).unwrap();
    framing::write_debug_keys(&mut relay.input, b"x").unwrap();
    relay.finish();
    daemon.finish();
    println!(
        "HTM_QA_PASS pane-create input/output resize=113x37 replay shell-retained shutdown cleanup"
    );
}

#[test]
fn session_end_detaches_without_a_length_field() {
    use std::io::Write;
    // Given a running daemon and an initialized client.
    let mut daemon = Daemon::start();
    let mut relay = Relay::start(&daemon.path);
    let initial = relay.state();
    // When the client sends the upstream one-byte detach message.
    relay.input.write_all(&[codes::SESSION_END]).unwrap();
    relay.finish();
    // Then a fresh client reattaches to exactly the same pane.
    let mut relay = Relay::start(&daemon.path);
    assert_eq!(relay.state()["panes"], initial["panes"]);
    framing::write_debug_keys(&mut relay.input, b"x").unwrap();
    relay.finish();
    daemon.finish();
}

#[test]
fn auto_start_and_kill_other_sessions_replace_only_the_selected_daemon() {
    // Given an unrelated daemon and a never-bound isolated endpoint.
    let mut other = Daemon::start();
    let mut other_relay = Relay::start(&other.path);
    let other_state = other_relay.state();
    framing::write_debug_keys(&mut other_relay.input, &[27]).unwrap();
    other_relay.finish();
    let endpoint = htm_support::Endpoint::new();

    // When htm auto-starts its daemon, detaches, and then restarts it with -x.
    let mut first = Relay::start(&endpoint.path);
    let before = first.state();
    framing::write_debug_keys(&mut first.input, &[27]).unwrap();
    first.finish();
    // The auto-started daemon must outlive the htm process that launched it.
    let mut reattached = Relay::start(&endpoint.path);
    assert_eq!(reattached.state()["panes"], before["panes"]);
    framing::write_debug_keys(&mut reattached.input, &[27]).unwrap();
    reattached.finish();
    let mut replacement = Relay::restart(&endpoint.path);
    let after = replacement.state();

    // Then the selected daemon has fresh panes, while the other daemon survived.
    assert_ne!(after["panes"], before["panes"]);
    let mut other_relay = Relay::start(&other.path);
    assert_eq!(other_relay.state()["panes"], other_state["panes"]);
    framing::write_debug_keys(&mut replacement.input, b"x").unwrap();
    replacement.finish();
    framing::write_debug_keys(&mut other_relay.input, b"x").unwrap();
    other_relay.finish();
    other.finish();
    println!("HTM_AUTOSTART_PASS ready detach -x replacement unrelated-daemon-survived shutdown");
}

#[cfg(windows)]
#[test]
fn autostart_survives_client_exit_inside_a_nonbreakaway_host_job() {
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_spawn::{Command, DropPolicy, Job, SpawnOptions, Stdio};

    // Given a real supervisor job that does not permit child breakaway.
    // Kill-on-close preserves the host's authority to end this entire tree.
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
    // Assignment is atomic with process creation, not a race after spawning.
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

    // When the real role scenario starts, exits/reconnects, and replaces clients.
    let result = receiver.recv_timeout(Duration::from_secs(45));
    if result.is_err() {
        job.terminate(1).unwrap();
    }
    worker.join().unwrap();
    let output = result.expect("host-job role scenario completion").unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout));
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));

    // Then HTM survives client exit inside that still-living supervisor job.
    // No assertion claims survival after the supervising job itself is killed.
    assert!(output.status.success(), "host-job HTM role scenario failed");
}
