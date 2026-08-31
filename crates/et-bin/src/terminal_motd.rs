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
/// Ubuntu's generated message, displayed by a separate `pam_motd` invocation.
const DYNAMIC_FILES: [&str; 1] = ["/run/motd.dynamic"];
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
    let dynamic_files: Vec<PathBuf> = DYNAMIC_FILES.iter().map(PathBuf::from).collect();
    let text = if override_path.is_some() {
        load_from(
            &files,
            &directories,
            override_path.as_deref(),
            home.as_deref(),
        )
    } else {
        load_defaults_from(&dynamic_files, &files, &directories, home.as_deref())
    };
    let Some(text) = text else {
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

    if let Some(path) = override_path {
        let mut output = Vec::new();
        let message = read_message(path)?;
        append_terminal_bytes(&mut output, &message);
        return (!output.is_empty()).then_some(output);
    }
    load_defaults_from(&[], files, directories, home)
}

fn load_defaults_from(
    dynamic_files: &[PathBuf],
    files: &[PathBuf],
    directories: &[PathBuf],
    home: Option<&Path>,
) -> Option<Vec<u8>> {
    if home.is_some_and(|home| home.join(".hushlogin").exists()) {
        return None;
    }

    let mut output = Vec::new();
    append_first_message(&mut output, dynamic_files);
    append_first_message(&mut output, files);
    for candidates in directory_message_candidates(directories) {
        if output.len() >= MAX_MOTD_TOTAL {
            break;
        }
        if let Some(message) = candidates
            .iter()
            .find_map(|path| try_read_message(path).ok())
            .flatten()
        {
            append_terminal_bytes(&mut output, &message);
        }
    }
    (!output.is_empty()).then_some(output)
}

fn append_first_message(output: &mut Vec<u8>, paths: &[PathBuf]) {
    for path in paths {
        match try_read_message(path) {
            Err(()) => continue,
            Ok(Some(message)) => {
                append_terminal_bytes(output, &message);
                break;
            }
            Ok(None) => continue,
        }
    }
}

/// Group directory overrides by basename in lexical display order.
fn directory_message_candidates(directories: &[PathBuf]) -> Vec<Vec<PathBuf>> {
    let mut messages: BTreeMap<OsString, Vec<PathBuf>> = BTreeMap::new();
    for directory in directories {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let name = entry.file_name();
            if !messages.contains_key(&name) && messages.len() >= MAX_MOTD_ENTRIES {
                break;
            }
            messages.entry(name).or_default().push(entry.path());
        }
    }
    messages.into_values().collect()
}

/// Open without blocking on special files, then validate the opened object.
fn read_message(path: &Path) -> Option<Vec<u8>> {
    try_read_message(path).ok().flatten()
}

fn try_read_message(path: &Path) -> Result<Option<Vec<u8>>, ()> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let file = File::from(descriptor);
    if !file.metadata().map_err(|_| ())?.is_file() {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(MAX_MOTD_MESSAGE);
    file.take(
        u64::try_from(MAX_MOTD_MESSAGE)
            .map_err(|_| ())?
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|_| ())?;
    bytes.truncate(MAX_MOTD_MESSAGE);
    Ok(Some(bytes))
}

/// Preserve existing CRLF and make lone LF render from column zero.
fn append_terminal_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let body = if bytes.ends_with(b"\r\n") {
        body.strip_suffix(b"\r").unwrap_or(body)
    } else {
        body
    };
    let content_limit = MAX_MOTD_TOTAL.saturating_sub(2);
    let mut previous = 0u8;
    for byte in body {
        if *byte == b'\n' && previous != b'\r' {
            if output.len().saturating_add(2) > content_limit {
                break;
            }
            output.push(b'\r');
        } else if output.len() >= content_limit {
            break;
        }
        output.push(*byte);
        previous = *byte;
    }
    if output.len().saturating_add(2) <= MAX_MOTD_TOTAL {
        output.extend_from_slice(b"\r\n");
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
#[path = "terminal_motd_tests.rs"]
mod tests;
