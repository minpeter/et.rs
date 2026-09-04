//! OpenSSH-compatible previous-login output for new Linux terminal sessions.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use jiff::fmt::strtime;
#[cfg(test)]
use jiff::tz::Offset;
use jiff::tz::TimeZone;
use jiff::Timestamp;
use rustix::fs::{Mode, OFlags};

const DEFAULT_PATH: &str = "/var/log/lastlog";
const HOST_BYTES: usize = 256;
const OVERRIDE_VARIABLE: &str = "ET_LASTLOG_PATH";

#[derive(Clone, Copy)]
struct Layout {
    record_bytes: usize,
    timestamp_bytes: usize,
    host_offset: usize,
}

// glibc's x86_64 ABI keeps a 32-bit lastlog time for compatibility, while
// aarch64 uses its native 64-bit time_t. These are the two GNU/Linux
// architectures shipped by et.rs.
#[cfg(target_arch = "x86_64")]
const NATIVE_LAYOUT: Layout = Layout {
    record_bytes: 292,
    timestamp_bytes: 4,
    host_offset: 36,
};
#[cfg(target_arch = "aarch64")]
const NATIVE_LAYOUT: Layout = Layout {
    record_bytes: 296,
    timestamp_bytes: 8,
    host_offset: 40,
};

pub fn load() -> Option<Vec<u8>> {
    let path = std::env::var_os(OVERRIDE_VARIABLE)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PATH));
    let uid = rustix::process::geteuid().as_raw();
    let time_zone = TimeZone::try_system().ok()?;
    load_from_time_zone(&path, uid, &time_zone, NATIVE_LAYOUT)
}

#[cfg(test)]
fn load_from(path: &Path, uid: u32, utc_offset_seconds: i32) -> Option<Vec<u8>> {
    let offset = Offset::from_seconds(utc_offset_seconds).ok()?;
    load_from_time_zone(path, uid, &TimeZone::fixed(offset), NATIVE_LAYOUT)
}

fn load_from_time_zone(
    path: &Path,
    uid: u32,
    time_zone: &TimeZone,
    layout: Layout,
) -> Option<Vec<u8>> {
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

    let offset = u64::from(uid).checked_mul(u64::try_from(layout.record_bytes).ok()?)?;
    let mut record = vec![0u8; layout.record_bytes];
    file.read_exact_at(&mut record, offset).ok()?;
    let timestamp = match layout.timestamp_bytes {
        4 => i64::from(u32::from_ne_bytes(record.get(..4)?.try_into().ok()?)),
        8 => i64::from_ne_bytes(record.get(..8)?.try_into().ok()?),
        _ => return None,
    };
    if timestamp <= 0 {
        return None;
    }
    let host = sanitize_host(record.get(layout.host_offset..layout.host_offset + HOST_BYTES)?);
    format_line(timestamp, host, time_zone)
}

fn sanitize_host(bytes: &[u8]) -> Option<&str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let host = bytes.get(..end)?;
    if host.is_empty() || !host.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
        return None;
    }
    std::str::from_utf8(host).ok()
}

fn format_line(timestamp: i64, host: Option<&str>, time_zone: &TimeZone) -> Option<Vec<u8>> {
    let timestamp = Timestamp::from_second(timestamp).ok()?;
    let zoned = timestamp.to_zoned(time_zone.clone());
    let ctime = strtime::format("%a %b %e %T %Y", &zoned).ok()?;
    let mut output = format!("Last login: {ctime}").into_bytes();
    if let Some(host) = host {
        output.extend_from_slice(b" from ");
        output.extend_from_slice(host.as_bytes());
    }
    output.extend_from_slice(b"\r\n");
    Some(output)
}

#[cfg(test)]
#[path = "terminal_last_login_tests.rs"]
mod tests;
