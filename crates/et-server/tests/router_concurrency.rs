#![forbid(unsafe_code)]

mod support;

use std::os::unix::net::UnixStream;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{TerminalPacketType, TerminalUserInfo};
use et_net::local_packet::write_local_packet;
use et_server::path::select_router_path_for;
use et_server::{Registry, Router, RouterEvent, RouterReject};
use prost::Message;
use support::TestDir;

const KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";

fn register(path: &std::path::Path, id: String, uid: i64, barrier: Arc<Barrier>) -> UnixStream {
    let mut stream = UnixStream::connect(path).unwrap();
    let info = TerminalUserInfo {
        id: Some(id),
        passkey: Some(KEY.to_owned()),
        uid: Some(uid),
        gid: Some(uid),
        fd: None,
    };
    let packet = Packet::new(
        TerminalPacketType::TerminalUserInfo as u8,
        info.encode_to_vec(),
    );
    barrier.wait();
    write_local_packet(&mut stream, &packet).unwrap();
    stream
}

#[test]
fn concurrent_distinct_registrations_are_all_retained() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry.clone()).unwrap();
    let ids = ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"];
    let barrier = Arc::new(Barrier::new(ids.len()));

    let workers: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let path = path.clone();
            let barrier = barrier.clone();
            let id = (*id).to_owned();
            thread::spawn(move || register(&path, id, index as i64, barrier))
        })
        .collect();
    let terminals: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    for _ in &ids {
        assert!(matches!(
            router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
            RouterEvent::Registered { .. }
        ));
    }
    assert_eq!(registry.len().unwrap(), ids.len());
    router.shutdown().unwrap();
    drop(terminals);
}

#[test]
fn concurrent_same_id_has_one_winner_and_never_overwrites_it() {
    let dir = TestDir::new();
    let path = dir.socket();
    let registry = Registry::new();
    let selected = select_router_path_for(1000, Some(&path), None, None).unwrap();
    let mut router = Router::start(selected, registry.clone()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    let id = "sameidentifier00";
    assert_eq!(id.len(), 16);
    for uid in [101, 202] {
        let path = path.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            register(&path, id.to_owned(), uid, barrier)
        }));
    }
    let terminals: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();

    let events = [
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
        router.recv_event_timeout(Duration::from_secs(2)).unwrap(),
    ];
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, RouterEvent::Registered { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == RouterEvent::Rejected(RouterReject::Duplicate))
            .count(),
        1
    );
    let winner = registry.get(id).unwrap().unwrap().uid;
    assert!(winner == 101 || winner == 202);
    assert_eq!(registry.len().unwrap(), 1);
    router.shutdown().unwrap();
    drop(terminals);
}

#[test]
fn shutdown_wakes_an_idle_router_without_timing_luck() {
    let dir = TestDir::new();
    let selected = select_router_path_for(1000, Some(&dir.socket()), None, None).unwrap();
    let router = Router::start(selected, Registry::new()).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut router = router;
        let result = router.shutdown();
        let _ = done_tx.send(result);
    });

    assert!(done_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .is_ok());
}
