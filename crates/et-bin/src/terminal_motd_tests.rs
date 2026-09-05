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
    assert!(output.ends_with(b"\r\n"));
}

#[test]
fn load_preserves_framing_when_newline_messages_hit_total_bound() {
    let sandbox = Sandbox::new("bounded-newline");
    let directory = sandbox.directory("motd.d");
    for index in 0..5 {
        let mut message = vec![b'x'; MAX_MOTD_MESSAGE];
        *message.last_mut().unwrap() = b'\n';
        fs::write(directory.join(format!("{index:02}-message")), message).unwrap();
    }

    let output = load_from(&[], std::slice::from_ref(&directory), None, None).unwrap();

    assert_eq!(output.len(), MAX_MOTD_TOTAL);
    assert!(output.ends_with(b"\r\n"));
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

    let nonregular = sandbox.directory("nonregular");
    let fallback = sandbox.file("fallback", b"fallback\n");
    assert_eq!(
        load_from(&[nonregular, fallback], &[], None, None).unwrap(),
        b"fallback\r\n"
    );
}

#[test]
fn load_shows_dynamic_message_before_static_defaults() {
    let sandbox = Sandbox::new("dynamic-defaults");
    let dynamic = sandbox.file("motd.dynamic", b"dynamic\n");
    let static_message = sandbox.file("motd", b"static\n");

    assert_eq!(
        load_defaults_from(
            std::slice::from_ref(&dynamic),
            std::slice::from_ref(&static_message),
            &[],
            None,
        )
        .unwrap(),
        b"dynamic\r\nstatic\r\n"
    );
}

#[test]
fn load_preserves_source_spacing_including_final_blank_lines() {
    let sandbox = Sandbox::new("source-spacing");
    let dynamic = sandbox.file("motd.dynamic", b"dynamic\n\n");
    let static_message = sandbox.file("motd", b"static\n\n\n");

    assert_eq!(
        load_defaults_from(
            std::slice::from_ref(&dynamic),
            std::slice::from_ref(&static_message),
            &[],
            None,
        )
        .unwrap(),
        b"dynamic\r\n\r\nstatic\r\n\r\n\r\n"
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
fn load_falls_back_when_higher_priority_directory_entry_is_unreadable() {
    let sandbox = Sandbox::new("directory-fallback");
    let high = sandbox.directory("etc");
    let low = sandbox.directory("usr");
    fs::create_dir(high.join("20-shared")).unwrap();
    fs::write(low.join("20-shared"), b"fallback\n").unwrap();

    assert_eq!(
        load_from(&[], &[high, low], None, None).unwrap(),
        b"fallback\r\n"
    );
}

#[test]
fn load_terminates_message_without_trailing_newline() {
    let sandbox = Sandbox::new("unterminated-message");
    let motd = sandbox.file("motd", b"maintenance tonight");

    assert_eq!(
        load_from(&[], &[], Some(&motd), None).unwrap(),
        b"maintenance tonight\r\n"
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
