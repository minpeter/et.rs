use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use super::*;

const RECORD_BYTES: usize = 292;
const TEST_UID: u32 = 2;
const TEST_TIMESTAMP: u32 = 1_788_475_267;

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "et-rs-last-login-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn record(&self, timestamp: u32, host: &[u8]) -> PathBuf {
        let path = self.0.join("lastlog");
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut record = [0u8; RECORD_BYTES];
        record[..4].copy_from_slice(&timestamp.to_ne_bytes());
        let host = &host[..host.len().min(256)];
        record[36..36 + host.len()].copy_from_slice(host);
        file.write_all_at(
            &record,
            u64::from(TEST_UID) * u64::try_from(RECORD_BYTES).unwrap(),
        )
        .unwrap();
        path
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn load_formats_host_record_with_fixed_offset() {
    let sandbox = Sandbox::new("host");
    let path = sandbox.record(TEST_TIMESTAMP, b"127.0.0.1");

    assert_eq!(
        load_from(&path, TEST_UID, 0).unwrap(),
        b"Last login: Thu Sep  3 22:41:07 2026 from 127.0.0.1\r\n"
    );
}

#[test]
fn load_omits_from_clause_when_host_is_empty() {
    let sandbox = Sandbox::new("empty-host");
    let path = sandbox.record(TEST_TIMESTAMP, b"");

    assert_eq!(
        load_from(&path, TEST_UID, 0).unwrap(),
        b"Last login: Thu Sep  3 22:41:07 2026\r\n"
    );
}

#[test]
fn load_applies_server_timezone_offset() {
    let sandbox = Sandbox::new("offset");
    let path = sandbox.record(TEST_TIMESTAMP, b"127.0.0.1");

    assert_eq!(
        load_from(&path, TEST_UID, 9 * 60 * 60).unwrap(),
        b"Last login: Fri Sep  4 07:41:07 2026 from 127.0.0.1\r\n"
    );
}

#[test]
fn load_omits_missing_source() {
    let sandbox = Sandbox::new("missing");

    assert_eq!(load_from(&sandbox.0.join("missing"), TEST_UID, 0), None);
}

#[test]
fn load_omits_zero_timestamp() {
    let sandbox = Sandbox::new("zero");
    let path = sandbox.record(0, b"127.0.0.1");

    assert_eq!(load_from(&path, TEST_UID, 0), None);
}

#[test]
fn load_omits_short_record() {
    let sandbox = Sandbox::new("short");
    let path = sandbox.0.join("lastlog");
    fs::write(&path, b"short").unwrap();

    assert_eq!(load_from(&path, TEST_UID, 0), None);
}

#[test]
fn load_omits_nonregular_source() {
    let sandbox = Sandbox::new("nonregular");
    let path = sandbox.0.join("directory");
    fs::create_dir(&path).unwrap();

    assert_eq!(load_from(&path, TEST_UID, 0), None);
}

#[test]
fn load_drops_host_clause_for_control_bytes() {
    let sandbox = Sandbox::new("control-host");
    let path = sandbox.record(TEST_TIMESTAMP, b"bad\r\n\x1b[31mhost");

    assert_eq!(
        load_from(&path, TEST_UID, 0).unwrap(),
        b"Last login: Thu Sep  3 22:41:07 2026\r\n"
    );
}

#[test]
fn load_preserves_ipv6_literal_host() {
    let sandbox = Sandbox::new("ipv6");
    let path = sandbox.record(TEST_TIMESTAMP, b"2001:db8::1");

    assert_eq!(
        load_from(&path, TEST_UID, 0).unwrap(),
        b"Last login: Thu Sep  3 22:41:07 2026 from 2001:db8::1\r\n"
    );
}

#[test]
fn load_bounds_full_host_field() {
    let sandbox = Sandbox::new("full-host");
    let host = [b'x'; 256];
    let path = sandbox.record(TEST_TIMESTAMP, &host);
    let output = load_from(&path, TEST_UID, 0).unwrap();

    assert_eq!(output.len(), 12 + 24 + 6 + 256 + 2);
    assert!(output.ends_with(b"\r\n"));
}

#[test]
fn aarch64_layout_decodes_independent_literal_fixture() {
    let sandbox = Sandbox::new("aarch64");
    let path = sandbox.0.join("lastlog");
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .unwrap();
    let mut record = [0u8; 296];
    record[..8].copy_from_slice(&i64::from(TEST_TIMESTAMP).to_ne_bytes());
    record[40..48].copy_from_slice(b"10.0.0.1");
    file.write_all_at(&record, u64::from(TEST_UID) * 296)
        .unwrap();
    let layout = Layout {
        record_bytes: 296,
        timestamp_bytes: 8,
        host_offset: 40,
    };
    let output = load_from_time_zone(&path, TEST_UID, &TimeZone::UTC, layout).unwrap();

    assert_eq!(
        output,
        b"Last login: Thu Sep  3 22:41:07 2026 from 10.0.0.1\r\n"
    );
}
