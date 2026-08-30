#![cfg(unix)]
#![forbid(unsafe_code)]

mod flow_control_tty_support;

use std::fs;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use flow_control_tty_support::{
    receive_bytes, receive_until, Stack, ThrottleProxy, MAX_PROMPT_LATENCY, SATURATION_BYTES,
    THROTTLE_BYTES_PER_SECOND,
};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

#[test]
fn flow_control_keeps_ctrl_c_and_prompt_responsive_on_a_slow_link() {
    let stack = Stack::start();
    let evidence = std::env::var_os("ET_FLOW_QA_EVIDENCE_DIR").map(std::path::PathBuf::from);
    if let Some(directory) = &evidence {
        fs::create_dir_all(directory).unwrap();
    }

    for mode in ["backpressure", "discard"] {
        let proxy = ThrottleProxy::start(stack.port);
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 800,
                pixel_height: 480,
            })
            .unwrap();
        let mut client = CommandBuilder::new(env!("CARGO_BIN_EXE_et"));
        client.args([
            "--flow-control",
            mode,
            "--terminal-path",
            stack.terminal.to_str().unwrap(),
            "--serverfifo",
            stack.router.to_str().unwrap(),
            "-p",
            &proxy.port.to_string(),
            "127.0.0.1",
        ]);
        client.env(
            "PATH",
            format!(
                "{}:{}",
                stack.directory.display(),
                std::env::var("PATH").unwrap()
            ),
        );
        client.env("TERM", "xterm-256color");
        let mut child = pair.slave.spawn_command(client).unwrap();
        drop(pair.slave);

        let mut writer = pair.master.take_writer().unwrap();
        let mut reader = pair.master.try_clone_reader().unwrap();
        let (sender, receiver) = mpsc::sync_channel(64);
        let reader_thread = thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(count) if sender.send(chunk[..count].to_vec()).is_err() => return,
                    Ok(_) => {}
                }
            }
        });

        writer
            .write_all(
                b"printf 'FLOW-%s\\n' START; while :; do printf \
                  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; done\n",
            )
            .unwrap();
        let output = match receive_until(
            &receiver,
            Vec::new(),
            b"FLOW-START\r\n",
            Duration::from_secs(10),
        ) {
            Ok(output) => output,
            Err(error) => {
                child.kill().unwrap();
                drop(writer);
                let _ = child.wait();
                reader_thread.join().unwrap();
                panic!("{mode}: waiting for FLOW-START: {error}");
            }
        };
        let mut output =
            match receive_bytes(&receiver, output, SATURATION_BYTES, Duration::from_secs(10)) {
                Ok(output) => output,
                Err(error) => {
                    child.kill().unwrap();
                    drop(writer);
                    let _ = child.wait();
                    reader_thread.join().unwrap();
                    panic!("{mode}: saturating throttled link: {error}");
                }
            };
        let interrupted = Instant::now();
        writer
            .write_all(b"\x03printf 'FLOW-%s\\n' PROMPT\n")
            .unwrap();
        output = match receive_until(&receiver, output, b"FLOW-PROMPT\r\n", MAX_PROMPT_LATENCY) {
            Ok(output) => output,
            Err(error) => {
                child.kill().unwrap();
                drop(writer);
                let _ = child.wait();
                reader_thread.join().unwrap();
                panic!("{mode}: waiting for Ctrl-C prompt: {error}");
            }
        };
        let latency = interrupted.elapsed();
        assert!(
            latency <= MAX_PROMPT_LATENCY,
            "{mode} Ctrl-C-to-prompt latency {latency:?} exceeded {MAX_PROMPT_LATENCY:?}"
        );

        child.kill().unwrap();
        drop(writer);
        while let Ok(chunk) = receiver.recv_timeout(Duration::from_millis(100)) {
            output.extend(chunk);
        }
        let _ = child.wait();
        reader_thread.join().unwrap();

        if let Some(directory) = &evidence {
            fs::write(directory.join(format!("{mode}.ansi")), &output).unwrap();
            fs::write(
                directory.join(format!("{mode}.json")),
                format!(
                    "{{\"mode\":\"{mode}\",\"rate_bytes_per_second\":{THROTTLE_BYTES_PER_SECOND},\
                     \"saturation_bytes\":{SATURATION_BYTES},\"ctrl_c_prompt_millis\":{},\
                     \"pass\":true}}\n",
                    latency.as_millis()
                ),
            )
            .unwrap();
        }
    }
}
