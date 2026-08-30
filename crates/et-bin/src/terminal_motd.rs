//! Session message-of-the-day output for new POSIX terminal sessions.
//!
//! `sshd` normally displays these files from its PAM session stack. Eternal
//! Terminal starts its PTY outside that stack, so the authenticated
//! `etterminal` process reads the same fixed files and sends them to the router
//! as terminal output before the login shell starts.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use et_core::packet::Packet;
use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::local::LocalStream;
use et_net::local_packet::write_local_packet;
use prost::Message;
use rustix::fs::{Mode, OFlags};

/// Largest output chunk per packet, matching the PTY output worker.
const MAX_OUTPUT_CHUNK: usize = 16 * 1024;
/// `pam_motd(8)` limits each message to 64 KiB.
const MAX_MOTD_MESSAGE: usize = 64 * 1024;
/// Bound aggregate startup output when many directory messages exist.
const MAX_MOTD_TOTAL: usize = 256 * 1024;
/// Bound directory enumeration as well as emitted bytes.
const MAX_MOTD_ENTRIES: usize = 1024;
/// Operator override naming one file to display instead of the defaults.
const OVERRIDE_VARIABLE: &str = "ET_MOTD_PATH";
/// `pam_motd(8)`'s default single files, highest priority first.
const DEFAULT_FILES: [&str; 3] = ["/etc/motd", "/run/motd", "/usr/lib/motd"];
/// `pam_motd(8)`'s default directories, highest priority first.
const DEFAULT_DIRS: [&str; 3] = ["/etc/motd.d", "/run/motd.d", "/usr/lib/motd.d"];

/// Emit the message of the day to the router, if there is one to show.
///
/// File-level failures are advisory and never fail the session. A router write
/// failure follows the same error path as any other terminal output failure.
pub fn emit(router: &mut LocalStream) -> Result<(), String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let override_path = std::env::var_os(OVERRIDE_VARIABLE)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    let files: Vec<PathBuf> = DEFAULT_FILES.iter().map(PathBuf::from).collect();
    let directories: Vec<PathBuf> = DEFAULT_DIRS.iter().map(PathBuf::from).collect();
    let Some(text) = load_from(
        &files,
        &directories,
        override_path.as_deref(),
        home.as_deref(),
    ) else {
        return Ok(());
    };
    write_output(router, &text)
}

fn load_from(
    files: &[PathBuf],
    directories: &[PathBuf],
    override_path: Option<&Path>,
    home: Option<&Path>,
) -> Option<Vec<u8>> {
    if home.is_some_and(|home| home.join(".hushlogin").exists()) {
        return None;
    }

    let mut output = Vec::new();
    if let Some(path) = override_path {
        let message = read_message(path)?;
        append_terminal_bytes(&mut output, &message);
    } else {
        for path in files {
            if let Some(message) = read_message(path) {
                append_terminal_bytes(&mut output, &message);
                break;
            }
        }
        for path in directory_messages(directories) {
            if output.len() >= MAX_MOTD_TOTAL {
                break;
            }
            if let Some(message) = read_message(&path) {
                append_terminal_bytes(&mut output, &message);
            }
        }
    }
    (!output.is_empty()).then_some(output)
}

/// Resolve directory overrides by basename, then return lexical display order.
fn directory_messages(directories: &[PathBuf]) -> Vec<PathBuf> {
    let mut messages: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for directory in directories {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if messages.contains_key(&name) {
                continue;
            }
            if messages.len() >= MAX_MOTD_ENTRIES {
                break;
            }
            messages.insert(name, entry.path());
        }
    }
    messages.into_values().collect()
}

/// Open without blocking on special files, then validate the opened object.
fn read_message(path: &Path) -> Option<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .ok()?;
    let file = File::from(descriptor);
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::with_capacity(MAX_MOTD_MESSAGE);
    file.take(u64::try_from(MAX_MOTD_MESSAGE).ok()?.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    bytes.truncate(MAX_MOTD_MESSAGE);
    Some(bytes)
}

/// Preserve existing CRLF and make lone LF render from column zero.
fn append_terminal_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    let mut previous = 0u8;
    for byte in bytes {
        if output.len() >= MAX_MOTD_TOTAL {
            return;
        }
        if *byte == b'\n' && previous != b'\r' {
            output.push(b'\r');
            if output.len() >= MAX_MOTD_TOTAL {
                return;
            }
        }
        output.push(*byte);
        previous = *byte;
    }
}

fn output_packet(chunk: &[u8]) -> Packet {
    let message = TerminalBuffer {
        buffer: Some(chunk.to_vec()),
    };
    Packet::new(
        TerminalPacketType::TerminalBuffer as u8,
        message.encode_to_vec(),
    )
}

fn write_output(router: &mut LocalStream, text: &[u8]) -> Result<(), String> {
    for chunk in text.chunks(MAX_OUTPUT_CHUNK) {
        write_local_packet(router, &output_packet(chunk))
            .map_err(|error| format!("could not forward message of the day: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    struct Sandbox(PathBuf);

    impl Sandbox {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "et-rs-motd-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).unwrap();
            path
        }

        fn directory(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            path
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn load_suppresses_everything_when_home_has_hushlogin() {
        let sandbox = Sandbox::new("hushlogin");
        let motd = sandbox.file("motd", b"banner\n");
        let home = Sandbox::new("hushlogin-home");
        home.file(".hushlogin", b"");

        assert_eq!(load_from(&[], &[], Some(&motd), Some(&home.0)), None);
    }

    #[test]
    fn load_skips_missing_empty_and_nonregular_override_files() {
        let sandbox = Sandbox::new("nonfatal");
        let empty = sandbox.file("empty", b"");
        let missing = sandbox.0.join("missing");
        let directory = sandbox.directory("directory");
        let fifo = sandbox.0.join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());

        for source in [empty, missing, directory, fifo, PathBuf::from("/dev/null")] {
            assert_eq!(load_from(&[], &[], Some(&source), None), None, "{source:?}");
        }
    }

    #[test]
    fn load_bounds_each_message_and_total_directory_output() {
        let sandbox = Sandbox::new("bounded");
        let directory = sandbox.directory("motd.d");
        for index in 0..5 {
            fs::write(
                directory.join(format!("{index:02}-message")),
                vec![b'x'; MAX_MOTD_MESSAGE * 3],
            )
            .unwrap();
        }

        let output = load_from(&[], std::slice::from_ref(&directory), None, None).unwrap();

        assert_eq!(output.len(), MAX_MOTD_TOTAL);
    }

    #[test]
    fn load_shows_only_the_first_readable_default_file() {
        let sandbox = Sandbox::new("defaults");
        let first = sandbox.file("first", b"first\n");
        let second = sandbox.file("second", b"second\n");

        assert_eq!(
            load_from(&[first, second.clone()], &[], None, None).unwrap(),
            b"first\r\n"
        );
        assert_eq!(
            load_from(&[sandbox.0.join("absent"), second], &[], None, None).unwrap(),
            b"second\r\n"
        );
    }

    #[test]
    fn load_orders_directory_union_and_honors_priority_overrides() {
        let sandbox = Sandbox::new("directories");
        let high = sandbox.directory("etc");
        let middle = sandbox.directory("run");
        let low = sandbox.directory("usr");
        fs::write(high.join("10-first"), b"first\n").unwrap();
        fs::write(high.join("20-shared"), b"high\n").unwrap();
        fs::write(middle.join("20-shared"), b"middle\n").unwrap();
        fs::write(low.join("20-shared"), b"low\n").unwrap();
        fs::write(low.join("30-last"), b"last\n").unwrap();
        fs::write(low.join("40-silenced"), b"must-not-appear\n").unwrap();
        symlink("/dev/null", high.join("40-silenced")).unwrap();

        assert_eq!(
            load_from(&[], &[high, middle, low], None, None).unwrap(),
            b"first\r\nhigh\r\nlast\r\n"
        );
    }

    #[test]
    fn load_preserves_raw_bytes_and_normalizes_only_lone_line_feeds() {
        let sandbox = Sandbox::new("raw-bytes");
        let motd = sandbox.file("motd", b"a\r\nb\n\x1b[31mc\x07\xff\xfe\n");

        assert_eq!(
            load_from(&[], &[], Some(&motd), None).unwrap(),
            b"a\r\nb\r\n\x1b[31mc\x07\xff\xfe\r\n"
        );
    }

    #[test]
    fn maximum_output_packet_fits_the_local_frame_bound() {
        let packet = output_packet(&vec![b'x'; MAX_OUTPUT_CHUNK]);

        assert!(packet.wire_len() <= et_net::local_packet::MAX_LOCAL_PACKET_LEN);
    }
}
