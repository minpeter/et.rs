#![forbid(unsafe_code)]

#[path = "reconnect_stack/mod.rs"]
mod reconnect_stack;
#[path = "reconnect_support/mod.rs"]
mod reconnect_support;

use std::fs;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use reconnect_stack::{mkfifo, shell_quote, Stack};
use reconnect_support::CutProxy;

const TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn real_client_recovers_same_shell_and_once_only_buffered_output() {
    let mut stack = Stack::start();
    let proxy = CutProxy::start(stack.port);
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 30,
            cols: 90,
            pixel_width: 900,
            pixel_height: 600,
        })
        .unwrap();
    let command = format!(
        "before=$(stty -g); {} --terminal-path {} --serverfifo {} \
         --keepalive=1 -p {} 127.0.0.1; code=$?; after=$(stty -g); restored=no; \
         [ \"$before\" = \"$after\" ] && restored=yes; \
         printf '\\nRECONNECT-TERMIOS:%s:CODE:%s:BEFORE:%s:AFTER:%s\\n' \
         \"$restored\" \"$code\" \"$before\" \"$after\"; exit \"$code\"",
        shell_quote(env!("CARGO_BIN_EXE_et")),
        shell_quote(stack.terminal.to_str().unwrap()),
        shell_quote(stack.router.to_str().unwrap()),
        proxy.port
    );
    let mut client = CommandBuilder::new("/bin/sh");
    client.args(["-c", &command]);
    client.env(
        "PATH",
        format!(
            "{}:{}",
            stack.directory.display(),
            std::env::var("PATH").unwrap()
        ),
    );
    client.env("TERM", "xterm-256color");
    client.env("ET_SSH_COUNT", &stack.ssh_count);
    let client_ready = stack.directory.join("client-ready");
    client.env("ET_SSH_READY", &client_ready);
    let mut child = pair.slave.spawn_command(client).unwrap();
    drop(pair.slave);
    let mut writer = pair.master.take_writer().unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let (output_tx, output_rx) = mpsc::sync_channel(64);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) if output_tx.send(chunk[..count].to_vec()).is_err() => break,
                Ok(_) => {}
            }
        }
    });

    let gate = stack.directory.join("gate.fifo");
    let ready = stack.directory.join("ready.fifo");
    let second_gate = stack.directory.join("second-gate.fifo");
    let second_ready = stack.directory.join("second-ready.fifo");
    mkfifo(&gate);
    mkfifo(&ready);
    mkfifo(&second_gate);
    mkfifo(&second_ready);
    wait_for_file(&client_ready, b"ready");
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let ready_reader = ready.clone();
    std::thread::spawn(move || {
        let result = fs::read_to_string(ready_reader);
        let _ = ready_tx.send(result);
    });
    let command = format!(
        "printf 'BEFORE-PID:%s\\n' \"$$\"; read gate < {}; \
         printf 'BUFFERED-ONCE\\n'; printf ready > {}",
        shell_quote(gate.to_str().unwrap()),
        shell_quote(ready.to_str().unwrap())
    );
    writer.write_all(command.as_bytes()).unwrap();
    writer.write_all(b"\n").unwrap();
    let (mut output, before_pid) = receive_number(&output_rx, Vec::new(), b"BEFORE-PID:");
    let keepalive_armed = Instant::now();
    assert!(proxy.wait_for_client_traffic_after(keepalive_armed) > 0);

    proxy.cut();
    write_fifo(gate, "go\n");
    assert_eq!(ready_rx.recv_timeout(TIMEOUT).unwrap().unwrap(), "ready");
    proxy.resume();
    output = receive_until(&output_rx, output, b"BUFFERED-ONCE\r\n");
    assert_eq!(count(&output, b"BUFFERED-ONCE\r\n"), 1);

    let (second_ready_tx, second_ready_rx) = mpsc::sync_channel(1);
    std::thread::spawn({
        let second_ready = second_ready.clone();
        move || {
            let _ = second_ready_tx.send(fs::read_to_string(second_ready));
        }
    });
    let second_command = format!(
        "printf 'SECOND-PID:%s\\n' \"$$\"; read gate < {}; \
         printf 'BUFFERED-TWICE\\n'; printf ready > {}",
        shell_quote(second_gate.to_str().unwrap()),
        shell_quote(second_ready.to_str().unwrap())
    );
    writer.write_all(second_command.as_bytes()).unwrap();
    writer.write_all(b"\n").unwrap();
    let (recovered_output, second_pid) = receive_number(&output_rx, output, b"SECOND-PID:");
    output = recovered_output;
    assert_eq!(before_pid, second_pid);
    proxy.cut();
    write_fifo(second_gate, "go\n");
    assert_eq!(
        second_ready_rx.recv_timeout(TIMEOUT).unwrap().unwrap(),
        "ready"
    );
    proxy.resume();
    output = receive_until(&output_rx, output, b"BUFFERED-TWICE\r\n");
    assert_eq!(count(&output, b"BUFFERED-TWICE\r\n"), 1);

    pair.master
        .resize(PtySize {
            rows: 44,
            cols: 111,
            pixel_width: 1110,
            pixel_height: 880,
        })
        .unwrap();
    writer
        .write_all(b"printf 'AFTER-PID:%s SIZE:%s\\n' \"$$\" \"$(stty size)\"; exit\n")
        .unwrap();
    output = receive_until(&output_rx, output, b"AFTER-PID:");
    while let Ok(chunk) = output_rx.recv_timeout(TIMEOUT) {
        output.extend(chunk);
    }
    let status = child.wait().unwrap();
    let text = String::from_utf8_lossy(&output);
    let errors: Vec<_> = text.lines().filter(|line| line.contains("et:")).collect();
    assert!(
        status.success(),
        "status={status:?} errors={errors:?} output={text}"
    );
    let after_pid = marker_number(&output, b"AFTER-PID:");
    assert_eq!(before_pid, after_pid);
    assert!(output.windows(11).any(|window| window == b"SIZE:44 111"));
    assert_eq!(count(&output, b"BUFFERED-ONCE\r\n"), 1);
    assert_eq!(count(&output, b"BUFFERED-TWICE\r\n"), 1);
    assert!(text.contains("RECONNECT-TERMIOS:"), "output={text}");
    assert!(text.contains(":CODE:0:"), "output={text}");
    assert!(termios_restored(&text), "output={text}");
    // One credential-free login-shell probe plus one credential bootstrap.
    // Reconnects stay on the encrypted ET transport and must not invoke SSH.
    assert_eq!(fs::read_to_string(&stack.ssh_count).unwrap(), "xx");
    proxy.join();
    stack.shutdown();
}

fn termios_restored(output: &str) -> bool {
    let Some((before, after)) = output
        .split_once(":BEFORE:")
        .and_then(|(_, modes)| modes.split_once(":AFTER:"))
    else {
        return false;
    };
    let after = after.trim_end_matches(['\r', '\n']);
    if before == after {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        before
            .split(':')
            .zip(after.split(':'))
            .all(|(left, right)| {
                if let (Some(left), Some(right)) =
                    (left.strip_prefix("lflag="), right.strip_prefix("lflag="))
                {
                    let left = u32::from_str_radix(left, 16).ok();
                    let right = u32::from_str_radix(right, 16).ok();
                    return left
                        .zip(right)
                        .is_some_and(|(left, right)| left & !0x2000_0000 == right & !0x2000_0000);
                }
                left == right
            })
    }
    #[cfg(not(target_os = "macos"))]
    false
}

fn receive_until(
    receiver: &mpsc::Receiver<Vec<u8>>,
    mut output: Vec<u8>,
    marker: &[u8],
) -> Vec<u8> {
    while !output.windows(marker.len()).any(|window| window == marker) {
        output.extend(receiver.recv_timeout(TIMEOUT).unwrap_or_else(|error| {
            panic!(
                "timed out waiting for {}: {error}; output={}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&output)
            )
        }));
    }
    output
}

fn marker_number(output: &[u8], marker: &[u8]) -> u32 {
    output
        .windows(marker.len())
        .enumerate()
        .filter(|(_, window)| *window == marker)
        .find_map(|(offset, _)| {
            String::from_utf8_lossy(&output[offset + marker.len()..])
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        })
        .unwrap()
}

fn receive_number(
    receiver: &mpsc::Receiver<Vec<u8>>,
    mut output: Vec<u8>,
    marker: &[u8],
) -> (Vec<u8>, u32) {
    loop {
        if let Some(value) = marker_number_optional(&output, marker) {
            return (output, value);
        }
        output.extend(receiver.recv_timeout(TIMEOUT).unwrap_or_else(|error| {
            panic!(
                "timed out waiting for {}: {error}; output={}",
                String::from_utf8_lossy(marker),
                String::from_utf8_lossy(&output)
            )
        }));
    }
}

fn marker_number_optional(output: &[u8], marker: &[u8]) -> Option<u32> {
    output
        .windows(marker.len())
        .enumerate()
        .filter(|(_, window)| *window == marker)
        .find_map(|(offset, _)| {
            String::from_utf8_lossy(&output[offset + marker.len()..])
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        })
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn write_fifo(path: std::path::PathBuf, value: &'static str) {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(fs::write(path, value));
    });
    receiver.recv_timeout(TIMEOUT).unwrap().unwrap();
}

fn wait_for_file(path: &std::path::Path, expected: &[u8]) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if fs::read(path).is_ok_and(|contents| contents == expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
