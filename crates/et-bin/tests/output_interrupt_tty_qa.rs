#![cfg(unix)]
#![forbid(unsafe_code)]

mod flow_control_tty_support;

use std::fs;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use flow_control_tty_support::{
    Stack, ThrottleProxy, MAX_PROMPT_LATENCY, SATURATION_BYTES, THROTTLE_BYTES_PER_SECOND,
};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

struct Transcript {
    receiver: mpsc::Receiver<Vec<u8>>,
    bytes: Vec<u8>,
}

impl Transcript {
    fn until(&mut self, marker: &[u8], deadline: Instant) -> Result<(), String> {
        while !self.bytes.windows(marker.len()).any(|part| part == marker) {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| format!("terminal marker deadline expired: {marker:?}"))?;
            self.bytes.extend(
                self.receiver
                    .recv_timeout(remaining)
                    .map_err(|error| format!("waiting for terminal marker {marker:?}: {error}"))?,
            );
        }
        Ok(())
    }
}

#[test]
fn default_output_flood_interrupt_allows_a_subsequent_command() {
    // Given: native ET client/server processes and actual PTYs, with a slow
    // encrypted TCP path. The only SSH replacement is local bootstrap execution;
    // it does not emulate ET transport, terminal output, or Ctrl+C handling.
    let stack = Stack::start();
    let proxy = ThrottleProxy::start(stack.port, THROTTLE_BYTES_PER_SECOND, SATURATION_BYTES);
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 800,
            pixel_height: 480,
        })
        .unwrap();
    let mut writer = pair.master.take_writer().unwrap();
    let mut reader = pair.master.try_clone_reader().unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_et"));
    command.args([
        "--flow-control",
        "none",
        "--terminal-path",
        stack.terminal.to_str().unwrap(),
        "--serverfifo",
        stack.router.to_str().unwrap(),
        "-p",
        &proxy.port.to_string(),
        "127.0.0.1",
    ]);
    command.env(
        "PATH",
        format!(
            "{}:{}",
            stack.directory.display(),
            std::env::var("PATH").unwrap()
        ),
    );
    command.env("TERM", "xterm-256color");
    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);
    let (sender, receiver) = mpsc::sync_channel(32);
    let reader_thread = thread::spawn(move || -> io::Result<()> {
        let mut bytes = [0_u8; 8192];
        loop {
            match reader.read(&mut bytes) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    if sender.send(bytes[..count].to_vec()).is_err() {
                        return Ok(());
                    }
                }
                // Unix PTY masters report EIO when the last slave closes.
                Err(error) if error.raw_os_error() == Some(5) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    });
    let mut transcript = Transcript {
        receiver,
        bytes: Vec::new(),
    };
    let mut latency = Duration::ZERO;
    let result = (|| -> Result<(), String> {
        writeln!(
            writer,
            "interrupted=; trap 'interrupted=1; printf \"\\nET_INT%s\\n\" ERRUPTED' INT; \
             printf 'ET_FLOOD_%s\\n' START; IFS= read -r gate; \
             while [ -z \"$interrupted\" ]; do \
             printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; \
             done; trap - INT; printf 'ET_FLOOD_%s\\n' STOPPED"
        )
        .map_err(|error| error.to_string())?;
        writer.flush().map_err(|error| error.to_string())?;
        transcript.until(
            b"ET_FLOOD_START\r\n",
            Instant::now() + Duration::from_secs(10),
        )?;
        writer
            .write_all(b"RELEASE\n")
            .map_err(|error| error.to_string())?;
        writer.flush().map_err(|error| error.to_string())?;
        // Subscribe to the proxy's exact transfer event, not a guessed delay.
        // Rate limiting is the time behavior under test; no correctness sleeps.
        proxy
            .wait_saturated(Duration::from_secs(40))
            .map_err(|error| error.to_string())?;

        // When: send actual Ctrl+C through the client's raw input PTY.
        let interrupted = Instant::now();
        let deadline = interrupted + MAX_PROMPT_LATENCY;
        writer
            .write_all(b"\x03")
            .map_err(|error| error.to_string())?;
        writer.flush().map_err(|error| error.to_string())?;
        transcript.until(b"ET_INTERRUPTED\r\n", deadline)?;
        transcript.until(b"ET_FLOOD_STOPPED\r\n", deadline)?;
        writer
            .write_all(b"printf 'ET_CTRL_C_%s\\n' OK\n")
            .map_err(|error| error.to_string())?;
        writer.flush().map_err(|error| error.to_string())?;
        transcript.until(b"ET_CTRL_C_OK\r\n", deadline)?;
        latency = interrupted.elapsed();
        Ok(())
    })();

    // Cleanup is performed before any behavioral assertion, including failures.
    let killed = child.kill();
    drop(writer);
    let reaped = child.wait();
    let Transcript { receiver, bytes } = transcript;
    drop(receiver);
    let reader_result = reader_thread.join();
    let proxy_result = proxy.finish();
    let directory = stack.directory.clone();
    drop(stack);

    if let Some(evidence) = std::env::var_os("ET_INTERRUPT_QA_EVIDENCE_DIR") {
        let evidence = std::path::PathBuf::from(evidence);
        fs::create_dir_all(&evidence).unwrap();
        fs::write(evidence.join("default-output.ansi"), &bytes).unwrap();
        fs::write(
            evidence.join("default-output.txt"),
            format!(
                "surface=native Unix ET client/server + PTYs\nbootstrap=local SSH adapter\n\
             mode=none\nrate_bytes_per_second={}\nsaturation_bytes={}\n\
             ctrl_c_prompt_millis={}\nscenario={result:?}\n\
             client_kill={killed:?}\nclient_reaped={reaped:?}\n\
             proxy_cleanup={proxy_result:?}\nstack_removed={}\n",
                THROTTLE_BYTES_PER_SECOND,
                SATURATION_BYTES,
                latency.as_millis(),
                !directory.exists(),
            ),
        )
        .unwrap();
    }

    // Then: the actual terminal displays output from a subsequent command.
    killed.unwrap();
    reaped.unwrap();
    reader_result.unwrap().unwrap();
    proxy_result.unwrap();
    assert!(
        result.is_ok(),
        "native flood/Ctrl+C/subsequent command failed: {result:?}"
    );
    assert!(bytes
        .windows(b"ET_CTRL_C_OK\r\n".len())
        .any(|part| part == b"ET_CTRL_C_OK\r\n"));
    assert!(latency <= MAX_PROMPT_LATENCY);
}
