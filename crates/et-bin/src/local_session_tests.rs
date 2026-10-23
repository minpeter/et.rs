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
    let template = ExitMarker::new();
    let command = template.command("true");
    let marker = command
        .split("\\n")
        .nth(1)
        .unwrap()
        .split("%d")
        .next()
        .unwrap();
    let prefix = format!("{command}\r\n__ET_PASSENGER_EXIT__:0\r\nPAYLOAD\r\n");
    let bytes = format!("{prefix}{marker}37\r\nprompt").into_bytes();
    for split in 0..=bytes.len() {
        let mut marker = template.clone();
        let (mut out, code) = marker.consume(&bytes[..split]);
        if code.is_none() {
            let (tail, code) = marker.consume(&bytes[split..]);
            out.extend(tail);
            assert_eq!(code, Some(37), "split={split}");
        } else {
            assert_eq!(code, Some(37));
        }
        assert_eq!(out, prefix.as_bytes(), "split={split}");
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
fn local_listener_authenticates_buffered_readiness_after_sender_closes() {
    let directory = Directory::new();
    let path = directory.0.join("ready");
    let listener = Listener::bind(&path).unwrap();
    let mut peer = ipc::connect(&path).unwrap();
    peer.write_all(&[0]).unwrap();
    drop(peer);
    let mut accepted = listener.accept().unwrap().unwrap();
    let status = crate::local_daemon::read_status(&mut accepted, ipc::TIMEOUT).unwrap();
    assert_eq!(status, [0]);
}

#[test]
fn local_readiness_partial_response_times_out_without_peer_close() {
    let directory = Directory::new();
    let path = directory.0.join("ready");
    let listener = Listener::bind(&path).unwrap();
    let mut peer = ipc::connect(&path).unwrap();
    peer.write_all(&[1, b'x']).unwrap();
    let mut accepted = listener.accept().unwrap().unwrap();
    let started = std::time::Instant::now();
    let timeout = Duration::from_millis(30);
    let error = crate::local_daemon::read_status(&mut accepted, timeout).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= timeout);
    drop(peer);
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
    let command = passenger.marker.as_ref().unwrap().command("true");
    let marker = command
        .split("\\n")
        .nth(1)
        .unwrap()
        .split("%d")
        .next()
        .unwrap();
    passenger
        .receive(format!("late output\n{marker}23\n").as_bytes())
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

#[test]
fn local_history_rejects_oversized_records_and_advances_cursors() {
    for records in [false, true] {
        let mut history = local_control::History::new(3, records);
        history.append(b'<', b"oversized");
        let cursor = if records { 1_i64 } else { 9 };
        assert_eq!(
            history.read(0),
            [cursor.to_be_bytes().as_slice(), &[1]].concat()
        );
        history.append(b'>', b"ok");
        assert!(history.read(-1).ends_with(b"ok"));
    }
}

#[test]
fn local_concurrent_stale_replacement_keeps_exactly_one_live_listener() {
    let directory = Directory::new();
    let path = directory.0.join("mux");
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                Listener::bind(&path)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .all(|e| e.kind() == io::ErrorKind::AddrInUse));
    assert!(ipc::connect(&path).is_ok());
    drop(results);
    assert!(!path.exists());
}

#[test]
fn local_initial_command_cannot_overfill_pending_queue() {
    let mut args = ClientArgs::try_parse_from(["et", "--ctl", "host"]).unwrap();
    args.command = Some("x".repeat(MAX_PENDING * 16 * 1024));
    assert!(Runtime::new(
        &args,
        Prepared {
            mux: None,
            ctl: None
        }
    )
    .is_err());
}

#[test]
fn passenger_progress_distinguishes_draining_from_idle_and_backpressure() {
    let args = ClientArgs::try_parse_from(["et", "--no-terminal", "host"]).unwrap();
    let mut runtime = Runtime::new(
        &args,
        Prepared {
            mux: None,
            ctl: None,
        },
    )
    .unwrap();
    let (writer, mut reader) = UnixStream::pair().unwrap();
    runtime.passenger = Some(
        Passenger::new(
            None,
            vec![
                File::open("/dev/null").unwrap().into(),
                writer.into(),
                File::open("/dev/null").unwrap().into(),
            ],
            false,
        )
        .unwrap(),
    );
    assert!(!runtime.pump_passenger());
    runtime.output(b"hello");
    assert!(runtime.pump_passenger());
    let mut bytes = [0; 5];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"hello");
    assert!(!runtime.pump_passenger());
    runtime.output(&vec![0; ipc::MAX_REPLY]);
    assert!(runtime.pump_passenger());
    for _ in 0..1024 {
        if !runtime.pump_passenger() {
            assert!(!runtime.passenger.as_ref().unwrap().queued.is_empty());
            return;
        }
    }
    panic!("a full consumer must stop reporting progress");
}

#[test]
fn local_reply_progress_distinguishes_draining_from_idle_and_backpressure() {
    let args = ClientArgs::try_parse_from(["et", "--no-terminal", "host"]).unwrap();
    let mut runtime = Runtime::new(
        &args,
        Prepared {
            mux: None,
            ctl: None,
        },
    )
    .unwrap();
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();
    let (writer, mut reader) = UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    runtime.peers.insert(1, Peer::new(writer, true));
    assert!(!runtime.local(&mut forwarder, true, false).unwrap());
    runtime
        .peers
        .get_mut(&1)
        .unwrap()
        .reply(b"hello".to_vec())
        .unwrap();
    assert!(runtime.local(&mut forwarder, true, false).unwrap());
    let mut bytes = [0; 5];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"hello");
    assert!(!runtime.local(&mut forwarder, true, false).unwrap());
    runtime
        .peers
        .get_mut(&1)
        .unwrap()
        .reply(vec![0; ipc::MAX_REPLY])
        .unwrap();
    assert!(runtime.local(&mut forwarder, true, false).unwrap());
    for _ in 0..1024 {
        if !runtime.local(&mut forwarder, true, false).unwrap() {
            assert!(!runtime.peers[&1].output.is_empty());
            return;
        }
    }
    panic!("a blocked local reply must stop reporting progress");
}

/// Forwarding data and keepalives the fake server reads until `until`.
fn read_upload(
    peer: &mut Connection,
    stream: &std::net::TcpStream,
    until: Instant,
) -> (usize, usize) {
    let (mut data, mut keepalives) = (0, 0);
    while Instant::now() < until {
        match peer.try_read_packet().unwrap() {
            Some(packet) if packet.header() == Kind::PortForwardData as u8 => {
                data += packet.payload().len();
            }
            Some(packet) if packet.header() == Kind::KeepAlive as u8 => keepalives += 1,
            Some(_) => {}
            None => {
                let mut descriptors = [PollFd::new(stream, PollFlags::IN)];
                let timeout = Timespec::try_from(Duration::from_millis(20)).unwrap();
                let _ = poll(&mut descriptors, Some(&timeout));
            }
        }
    }
    (data, keepalives)
}

#[test]
fn no_shell_pump_acknowledges_by_volume_and_bounds_unacknowledged_forwarding() {
    use et_core::proto::{PortForwardDestinationRequest, SocketEndpoint};
    use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};

    // Given: an `-N` session whose server has proven it acknowledges
    // delivery, and a forwarded application uploading far more than the
    // delivery bound (a legacy, unwindowed socket, so only the gate limits).
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = listener.accept().unwrap().0;
    let control = server.try_clone().unwrap();
    let readiness = server.try_clone().unwrap();
    let connection = Connection::new_client(client, &[23; 32]);
    let mut peer = Connection::new_server(server, &[23; 32]);
    let forwarder = Forwarder::start(Vec::new()).unwrap();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    forwarder
        .receive(Packet::new(
            Kind::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(Ipv4Addr::LOCALHOST.to_string()),
                    port: Some(i32::from(destination.local_addr().unwrap().port())),
                }),
                fd: Some(7),
                window: None,
            }
            .encode_to_vec(),
        ))
        .unwrap();
    let (mut application, _) = destination.accept().unwrap();
    let uploader = std::thread::spawn(move || {
        let _ = application.write_all(&vec![5; 32 * 1024 * 1024]);
    });
    peer.write_packet(Kind::KeepAlive as u8, &peer.keepalive_ack())
        .unwrap();
    let session = std::thread::spawn(move || {
        let mut connection = connection;
        let mut forwarder = forwarder;
        let args = ClientArgs::try_parse_from(["et", "-N", "-k", "5", "host"]).unwrap();
        let mut runtime = Runtime::new(
            &args,
            Prepared {
                mux: None,
                ctl: None,
            },
        )
        .unwrap();
        pump(
            &mut connection,
            &args,
            &mut forwarder,
            &mut runtime,
            &mut |_: &mut Connection| Ok(ReconnectOutcome::SessionEnded),
        )
    });

    // When: the server reads everything but stops acknowledging.
    let (stalled, keepalives) = read_upload(
        &mut peer,
        &readiness,
        Instant::now() + Duration::from_secs(2),
    );

    // Then: the client acknowledged by volume and paused its producers at
    // the bound instead of pushing the whole upload into replay.
    let bound = et_core::backed_writer::MAX_UNACKNOWLEDGED_BYTES as usize;
    assert!(
        keepalives >= 2,
        "only {keepalives} keepalives in {stalled} forwarded bytes"
    );
    assert!(
        (bound / 2..2 * bound).contains(&stalled),
        "{stalled} bytes forwarded past an unacknowledged bound of {bound}"
    );
    // An acknowledgement releases the gate again.
    peer.write_packet(Kind::KeepAlive as u8, &peer.keepalive_ack())
        .unwrap();
    let (resumed, _) = read_upload(
        &mut peer,
        &readiness,
        Instant::now() + Duration::from_secs(1),
    );
    assert!(
        resumed >= bound / 2,
        "only {resumed} bytes after the acknowledgement"
    );

    control.shutdown(Shutdown::Both).unwrap();
    assert_eq!(session.join().unwrap().unwrap(), 0);
    uploader.join().unwrap();
}
