use super::*;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let name = et_core::crypto::random_bytes::<8>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = std::env::temp_dir().join(format!("et-ipc-test-{name}"));
        ipc::private_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn local_history_byte_and_record_cursors_eviction_and_independent_readers() {
    let mut bytes = local_control::History::new(7, false);
    bytes.append(b'<', b"abc");
    bytes.append(b'<', b"DEFGH");
    let result = bytes.read(1);
    assert_eq!(&result[..8], &8_i64.to_be_bytes());
    assert_eq!(&result[8..], b"\x01DEFGH");
    assert_eq!(&bytes.read(-1)[8..], b"\x00DEFGH");
    assert_eq!(&bytes.read(5)[8..], b"\x00FGH");
    assert_eq!(bytes.read(1), result);
    assert_eq!(
        &bytes.read(99)[..],
        &[8_i64.to_be_bytes().as_slice(), &[0]].concat()
    );
    let mut records = local_control::History::new(7, true);
    records.append(b'>', b"ab");
    records.append(b'<', b"123456");
    assert_eq!(
        records.read(0),
        [
            2_i64.to_be_bytes().as_slice(),
            &[1, b'<', 0, 0, 0, 6],
            b"123456"
        ]
        .concat()
    );
    assert_eq!(&records.read(2)[8..], &[0]);
}

#[test]
fn local_control_secret_redaction_and_resize_cannot_kill_session() {
    let mut control = Control::new("host\ninjected=1");
    let (_, action) = control.request(7, b"private-value", true).unwrap();
    assert!(matches!(action, Action::Input(bytes) if bytes == b"private-value"));
    let (_, action) = control
        .request(
            2,
            &et_core::proto::TerminalInfo {
                row: Some(31),
                column: Some(117),
                id: Some("credential".to_owned()),
                command: Some(1),
                commandversion: Some(1),
                ..Default::default()
            }
            .encode_to_vec(),
            true,
        )
        .unwrap();
    let Action::Resize(resize) = action else {
        panic!("missing resize");
    };
    let resize = et_core::proto::TerminalInfo::decode(resize.as_slice()).unwrap();
    assert_eq!(resize.row, Some(31));
    assert_eq!(resize.column, Some(117));
    assert!(resize.command.is_none());
    assert!(resize.id.is_none());
    let (transcript, _) = control.request(6, &(-1_i64).to_be_bytes(), true).unwrap();
    assert!(transcript.ends_with(b"<secret>"));
    assert!(!String::from_utf8_lossy(&transcript).contains("private-value"));
    assert!(control.request(3, &[0; 9], true).is_err());
}

#[test]
fn local_exit_marker_survives_every_packet_boundary_and_ignores_echo() {
    let prefix = b"echo __ET_PASSENGER_EXIT__:%d\\n\r\nPAYLOAD\r\n";
    let bytes = [prefix.as_slice(), b"__ET_PASSENGER_EXIT__:37\r\nprompt"].concat();
    for split in 0..=bytes.len() {
        let mut marker = ExitMarker::new();
        let (mut out, code) = marker.consume(&bytes[..split]);
        if code.is_none() {
            let (tail, code) = marker.consume(&bytes[split..]);
            out.extend(tail);
            assert_eq!(code, Some(37), "split={split}");
        } else {
            assert_eq!(code, Some(37));
        }
        assert_eq!(out, prefix, "split={split}");
    }
    let mut marker = ExitMarker::new();
    assert_eq!(
        marker.consume(b"__ET_PASSENGER_EXIT__:999\n"),
        (b"__ET_PASSENGER_EXIT__:999\n".to_vec(), None)
    );
}

#[test]
fn local_frames_are_bounded_and_do_not_consume_descriptor_messages() {
    let (mut tx, mut rx) = UnixStream::pair().unwrap();
    rx.set_nonblocking(true).unwrap();
    let mut reader = FrameReader::new(false);
    let frame = ipc::mux_frame(&ipc::words(&[mux::HELLO, 4]));
    for byte in &frame[..frame.len() - 1] {
        tx.write_all(&[*byte]).unwrap();
        assert!(reader.poll(&mut rx).unwrap().is_none());
    }
    tx.write_all(&frame[frame.len() - 1..]).unwrap();
    let file = File::open("/dev/null").unwrap();
    ipc::send_fd(&tx, &file).unwrap();
    assert_eq!(reader.poll(&mut rx).unwrap(), Some(frame));
    let received = ipc::receive_fd(&rx).unwrap().unwrap();
    assert!(rustix::io::fcntl_getfd(&received)
        .unwrap()
        .contains(rustix::io::FdFlags::CLOEXEC));
    tx.write_all(&((ipc::MAX_FRAME + 1) as u32).to_be_bytes())
        .unwrap();
    assert!(reader.poll(&mut rx).is_err());
}

#[test]
fn local_socket_ownership_permissions_stale_reuse_and_identity_cleanup() {
    let directory = Directory::new();
    let path = directory.0.join("socket");
    let old = Listener::bind(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let peer = ipc::connect(&path).unwrap();
    assert!(ipc::authorized(&peer).unwrap());
    drop(peer);
    assert!(Listener::bind(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    let replacement = Listener::bind(&path).unwrap();
    drop(old);
    assert!(path.exists(), "old owner deleted the replacement socket");
    drop(replacement);
    assert!(!path.exists());
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let recovered = Listener::bind(&path).unwrap();
    drop(recovered);
    let target = directory.0.join("precious");
    std::fs::write(&target, "untouched").unwrap();
    symlink(&target, &path).unwrap();
    assert!(Listener::bind(&path).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    std::fs::remove_file(&path).unwrap();
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Listener::bind(&path).is_err());
}

#[test]
fn local_tombstone_replaces_symlink_without_touching_target() {
    let directory = Directory::new();
    let target = directory.0.join("target");
    let gone = directory.0.join("gone");
    std::fs::write(&target, "untouched").unwrap();
    symlink(&target, &gone).unwrap();
    local_control::write_tombstone(&gone, Some("shutdown\nwas requested")).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    assert!(std::fs::read_to_string(&gone)
        .unwrap()
        .ends_with(" shutdown was requested\n"));
    assert_eq!(
        std::fs::metadata(&gone).unwrap().permissions().mode() & 0o777,
        0o600
    );
    local_control::write_tombstone(&gone, None).unwrap();
    assert!(!gone.exists());
}

#[test]
fn local_passenger_alias_flags_restore_and_orphan_cannot_poison_next_command() {
    let (peer, client) = UnixStream::pair().unwrap();
    let original = rustix::fs::fcntl_getfl(&client).unwrap();
    let mut passenger = Passenger::new(
        Some(8),
        vec![
            rustix::io::dup(&client).unwrap(),
            rustix::io::dup(&client).unwrap(),
            rustix::io::dup(&client).unwrap(),
        ],
        true,
    )
    .unwrap();
    assert!(rustix::fs::fcntl_getfl(&client)
        .unwrap()
        .contains(rustix::fs::OFlags::NONBLOCK));
    passenger.orphaned = true;
    passenger
        .receive(b"late output\n__ET_PASSENGER_EXIT__:23\n")
        .unwrap();
    assert!(passenger.queued.is_empty());
    assert_eq!(passenger.status, Some(23));
    drop(passenger);
    drop(peer);
    assert_eq!(rustix::fs::fcntl_getfl(&client).unwrap(), original);
}

#[test]
fn local_queries_never_spawn_background_daemon_or_generate_control_name() {
    for option in ["-G", "-V", "--list"] {
        let mut args = ClientArgs::try_parse_from(["et", "--ctl", "-f", option, "host"]).unwrap();
        assert!(crate::local_daemon::prepare(&mut args, &[])
            .unwrap()
            .is_none());
        assert!(args.session_name.is_none());
    }
    let mut args = ClientArgs::try_parse_from(["et", "-f", "--kill", "work"]).unwrap();
    assert!(crate::local_daemon::prepare(&mut args, &[])
        .unwrap()
        .is_none());
}
