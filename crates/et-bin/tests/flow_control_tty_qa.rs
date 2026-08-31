#![cfg(unix)]
#![forbid(unsafe_code)]

mod flow_control_tty_support;

use std::fs;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use flow_control_tty_support::{
    receive_until, Stack, ThrottleProxy, MAX_PROMPT_LATENCY, SATURATION_BYTES,
    THROTTLE_BYTES_PER_SECOND,
};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

#[test]
fn flow_control_keeps_ctrl_c_and_prompt_responsive_on_a_slow_link() {
    let evidence = std::env::var_os("ET_FLOW_QA_EVIDENCE_DIR").map(std::path::PathBuf::from);
    if let Some(directory) = &evidence {
        fs::create_dir_all(directory).unwrap();
    }

    for mode in ["none", "backpressure", "discard"] {
        let stack = Stack::start();
        let bytes_per_second = THROTTLE_BYTES_PER_SECOND;
        let proxy = ThrottleProxy::start(stack.port, bytes_per_second, SATURATION_BYTES);
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
        // Keep the test harness from adding its own half-megabyte output
        // queue on top of the ET pipeline being measured.
        let (sender, receiver) = mpsc::sync_channel(32);
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

        writeln!(
            writer,
            "interrupted=; \
             trap 'interrupted=1; printf \"\\nFLOW-INTERRUPTED\\n\"' INT; \
             printf 'FLOW-%s\\n' START; \
             IFS= read -r flow_release; \
             i=0; while [ -z \"$interrupted\" ] && [ \"$i\" -lt 65536 ]; do \
             printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; \
             i=$((i + 1)); done; trap - INT"
        )
        .unwrap();
        let startup_timeout = Duration::from_secs(10);
        let output = match receive_until(&receiver, Vec::new(), b"FLOW-START\r\n", startup_timeout)
        {
            Ok(output) => output,
            Err(error) => {
                child.kill().unwrap();
                drop(writer);
                let _ = child.wait();
                reader_thread.join().unwrap();
                panic!("{mode}: waiting for FLOW-START: {error}");
            }
        };
        writer.write_all(b"FLOW-RELEASE\n").unwrap();
        writer.flush().unwrap();
        proxy
            .wait_saturated(Duration::from_secs(40))
            .unwrap_or_else(|error| panic!("{mode}: exact saturation event: {error}"));
        let mut output = output;
        while let Ok(chunk) = receiver.try_recv() {
            output.extend(chunk);
        }
        let interrupted = Instant::now();
        let prompt_timeout = MAX_PROMPT_LATENCY;
        let deadline = interrupted + prompt_timeout;
        writer.write_all(b"\x03").unwrap();
        writer.flush().unwrap();
        let interrupt = receive_until(
            &receiver,
            output.clone(),
            b"FLOW-INTERRUPTED\r\n",
            prompt_timeout,
        );
        let prompt = interrupt.and_then(|output| {
            writer
                .write_all(b"printf 'FLOW-%s\\n' PROMPT\n")
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)?;
            writer
                .flush()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(mpsc::RecvTimeoutError::Timeout)?;
            receive_until(&receiver, output, b"FLOW-PROMPT\r\n", remaining)
        });
        let latency = interrupted.elapsed();
        let latency_failed = prompt.is_err();
        if mode == "none" {
            // None is the unbounded baseline: latency may fail, but a fast
            // host/kernel is also allowed to drain enough for it to pass.
            if let Ok(prompt) = prompt {
                output = prompt;
            }
        } else {
            output = prompt.unwrap_or_else(|error| {
                panic!("{mode}: waiting for Ctrl-C prompt within {prompt_timeout:?}: {error}")
            });
            assert!(
                latency <= MAX_PROMPT_LATENCY,
                "{mode} Ctrl-C-to-prompt latency {latency:?} exceeded {MAX_PROMPT_LATENCY:?}"
            );
        }
        child.kill().unwrap();
        drop(writer);
        let _ = child.wait();
        while let Ok(chunk) = receiver.recv() {
            output.extend(chunk);
        }
        reader_thread.join().unwrap();
        proxy.finish().unwrap();

        if let Some(directory) = &evidence {
            fs::write(directory.join(format!("{mode}.ansi")), &output).unwrap();
            fs::write(
                directory.join(format!("{mode}.json")),
                format!(
                    "{{\"mode\":\"{mode}\",\"rate_bytes_per_second\":{bytes_per_second},\
                     \"saturation_bytes\":{SATURATION_BYTES},\"ctrl_c_prompt_millis\":{},\
                     \"latency_failed\":{},\"scenario_pass\":true}}\n",
                    latency.as_millis(),
                    latency_failed
                ),
            )
            .unwrap();
        }
    }
}
