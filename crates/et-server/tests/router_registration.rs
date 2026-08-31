#![forbid(unsafe_code)]

mod support;

use std::io::Write;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{TerminalPacketType, TerminalUserInfo};
use et_net::local_packet::{write_local_packet, MAX_LOCAL_PACKET_LEN};
use et_server::path::select_router_path_for;
use et_server::{Registry, Router, RouterEvent, RouterReject};
use prost::Message;
use support::TestDir;

const ID: &str = "abcdefghijklmnop";
const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";

fn peer_identity() -> (i64, i64) {
    (
        i64::from(rustix::process::geteuid().as_raw()),
        i64::from(rustix::process::getegid().as_raw()),
    )
}

fn info(
    id: Option<&str>,
    key: Option<&str>,
    uid: Option<i64>,
    gid: Option<i64>,
) -> TerminalUserInfo {
    TerminalUserInfo {
        id: id.map(str::to_owned),
        passkey: key.map(str::to_owned),
        uid,
        gid,
        fd: None,
    }
}

fn connect_packet(path: &std::path::Path, packet: &Packet) -> UnixStream {
    let mut stream = UnixStream::connect(path).unwrap();
    write_local_packet(&mut stream, packet).unwrap();
    stream
}

fn send_packet(path: &std::path::Path, packet: &Packet) {
    drop(connect_packet(path, packet));
}

fn expect_rejected(router: &Router, expected: RouterReject) {
    assert_eq!(
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        RouterEvent::Rejected(expected)
    );
}

#[test]
fn valid_plaintext_registration_is_retained() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry.clone()).unwrap();

    let (uid, gid) = peer_identity();
    let packet = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        info(Some(ID), Some(KEY), Some(uid), Some(gid)).encode_to_vec(),
    );
    let _terminal = connect_packet(&path, &packet);
    assert_eq!(
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        RouterEvent::Registered { id: ID.to_owned() }
    );

    let registered = registry.get(ID).unwrap().unwrap();
    assert_eq!(registered.uid, u32::try_from(uid).unwrap());
    assert_eq!(registered.gid, u32::try_from(gid).unwrap());
    assert_eq!(&registered.key, KEY.as_bytes());
    router.shutdown().unwrap();
}

#[test]
fn router_registration_rejects_forged_identity() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(0, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry.clone()).unwrap();
    let (forged_uid, forged_gid) = if rustix::process::geteuid().as_raw() == 0 {
        (1, 1)
    } else {
        (0, 0)
    };

    send_packet(
        &path,
        &Packet::new(
            TerminalPacketType::TerminalUserInfo as u8,
            info(Some(ID), Some(KEY), Some(forged_uid), Some(forged_gid)).encode_to_vec(),
        ),
    );

    expect_rejected(&router, RouterReject::InvalidRegistration);
    assert!(registry.is_empty().unwrap());
    router.shutdown().unwrap();
}

#[test]
fn encrypted_wrong_type_and_malformed_packets_leave_no_entries() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry.clone()).unwrap();
    let payload = info(Some(ID), Some(KEY), Some(1), Some(1)).encode_to_vec();

    send_packet(
        &path,
        &Packet::raw(
            true,
            TerminalPacketType::TerminalUserInfo as u8,
            payload.as_slice(),
        ),
    );
    expect_rejected(&router, RouterReject::Encrypted);
    send_packet(
        &path,
        &Packet::new(TerminalPacketType::TerminalInit as u8, payload),
    );
    expect_rejected(&router, RouterReject::WrongPacketType);
    send_packet(
        &path,
        &Packet::new(TerminalPacketType::TerminalUserInfo as u8, [0xff, 0xff]),
    );
    expect_rejected(&router, RouterReject::MalformedUserInfo);
    assert_eq!(registry.len().unwrap(), 0);
    router.shutdown().unwrap();
}

#[test]
fn missing_and_invalid_fields_are_rejected() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry.clone()).unwrap();
    let cases = [
        info(None, Some(KEY), Some(1), Some(1)),
        info(Some(ID), None, Some(1), Some(1)),
        info(Some("short"), Some(KEY), Some(1), Some(1)),
        info(Some("abcdefghijklmno!"), Some(KEY), Some(1), Some(1)),
        info(Some(ID), Some("short"), Some(1), Some(1)),
        info(
            Some(ID),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcde!"),
            Some(1),
            Some(1),
        ),
        info(Some(ID), Some(KEY), None, Some(1)),
        info(Some(ID), Some(KEY), Some(1), None),
        info(Some(ID), Some(KEY), Some(-1), Some(1)),
    ];

    for value in cases {
        send_packet(
            &path,
            &Packet::new(
                TerminalPacketType::TerminalUserInfo as u8,
                value.encode_to_vec(),
            ),
        );
        expect_rejected(&router, RouterReject::InvalidRegistration);
    }
    assert_eq!(registry.len().unwrap(), 0);
    router.shutdown().unwrap();
}

#[test]
fn duplicate_rejection_preserves_the_original_registration() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry.clone()).unwrap();

    let (uid, gid) = peer_identity();
    let first = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        info(Some(ID), Some(KEY), Some(uid), Some(gid)).encode_to_vec(),
    );
    let _terminal = connect_packet(&path, &first);
    assert_eq!(
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        RouterEvent::Registered { id: ID.to_owned() }
    );

    let duplicate = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        info(Some(ID), Some(KEY), Some(uid), Some(gid)).encode_to_vec(),
    );
    send_packet(&path, &duplicate);
    expect_rejected(&router, RouterReject::Duplicate);
    assert_eq!(
        registry.get(ID).unwrap().unwrap().uid,
        u32::try_from(uid).unwrap()
    );
    assert_eq!(registry.len().unwrap(), 1);
    router.shutdown().unwrap();
}

#[test]
fn terminal_disconnect_is_typed_and_same_id_can_register_again() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry.clone()).unwrap();
    let (uid, gid) = peer_identity();
    let packet = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        info(Some(ID), Some(KEY), Some(uid), Some(gid)).encode_to_vec(),
    );

    let terminal = connect_packet(&path, &packet);
    assert_eq!(
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        RouterEvent::Registered { id: ID.to_owned() }
    );
    drop(terminal);
    assert_eq!(
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        RouterEvent::Disconnected { id: ID.to_owned() }
    );
    registry
        .wait_until_absent(ID, Duration::from_secs(2))
        .unwrap();

    let _fresh_terminal = connect_packet(&path, &packet);
    assert_eq!(
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        RouterEvent::Registered { id: ID.to_owned() }
    );
    assert_eq!(registry.len().unwrap(), 1);
    router.shutdown().unwrap();
}

#[test]
fn malformed_local_frames_are_capped_and_classified() {
    let dir = TestDir::new();
    let path = dir.socket();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, Registry::new()).unwrap();

    for prefix in [
        (-1i64).to_ne_bytes(),
        (MAX_LOCAL_PACKET_LEN as i64 + 1).to_ne_bytes(),
    ] {
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.write_all(&prefix).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        expect_rejected(&router, RouterReject::MalformedFrame);
    }

    let mut stream = UnixStream::connect(&path).unwrap();
    stream.write_all(&[0; 7]).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    expect_rejected(&router, RouterReject::MalformedFrame);
    router.shutdown().unwrap();
}

#[test]
fn pending_registration_cap_releases_a_slot_after_peer_close() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry).unwrap();
    let mut idle: Vec<_> = (0..64)
        .map(|_| UnixStream::connect(&path).unwrap())
        .collect();

    let (uid, gid) = peer_identity();
    let packet = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        info(Some(ID), Some(KEY), Some(uid), Some(gid)).encode_to_vec(),
    );
    let _queued = connect_packet(&path, &packet);
    drop(idle.pop());

    expect_rejected(&router, RouterReject::MalformedFrame);
    assert_eq!(
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        RouterEvent::Registered { id: ID.to_owned() }
    );
    router.shutdown().unwrap();
}

#[test]
fn idle_pending_registration_expires_and_router_remains_live() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry).unwrap();
    let mut idle = UnixStream::connect(&path).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(7))).unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(std::io::Read::read(&mut idle, &mut byte).unwrap(), 0);

    let (uid, gid) = peer_identity();
    let packet = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        info(Some(ID), Some(KEY), Some(uid), Some(gid)).encode_to_vec(),
    );
    let _terminal = connect_packet(&path, &packet);
    assert_eq!(
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        RouterEvent::Registered { id: ID.to_owned() }
    );
    router.shutdown().unwrap();
}
