#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::io;
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use et_core::keys::passkey_to_key;
use et_core::proto::{ConnectStatus, FlowControlMode, SequenceHeader, TerminalPacketType};
use et_net::connection::Connection;
use et_net::framing_io::{read_proto_limited, write_proto};
use runtime_support::{default_payload, initialize, TestRuntime, ID_A, KEY_A, TIMEOUT};

struct RecoveryGate {
    port: u16,
    snapshot: mpsc::Receiver<()>,
    release: mpsc::SyncSender<()>,
    stop: mpsc::Receiver<TcpStream>,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}

impl RecoveryGate {
    fn start(mut server: TcpStream) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (snapshot_tx, snapshot) = mpsc::sync_channel(0);
        let (release, release_rx) = mpsc::sync_channel(0);
        let (stop_tx, stop) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let (mut client, _) = listener.accept()?;
            stop_tx
                .send(server.try_clone()?)
                .map_err(|_| io::Error::other("proxy stop receiver closed"))?;
            let mut client_read = client.try_clone()?;
            let mut server_write = server.try_clone()?;
            let upstream = thread::spawn(move || io::copy(&mut client_read, &mut server_write));

            let sequence: SequenceHeader = read_proto_limited(&mut server, 4 * 1024)?;
            snapshot_tx
                .send(())
                .map_err(|_| io::Error::other("snapshot receiver closed"))?;
            release_rx
                .recv()
                .map_err(|_| io::Error::other("recovery release sender closed"))?;
            write_proto(&mut client, &sequence)?;
            io::copy(&mut server, &mut client)?;
            let _ = client.shutdown(Shutdown::Both);
            upstream
                .join()
                .map_err(|_| io::Error::other("recovery upload worker panicked"))??;
            Ok(())
        });
        Self {
            port,
            snapshot,
            release,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(&mut self) {
        let stream = self.stop.recv_timeout(TIMEOUT).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for RecoveryGate {
    fn drop(&mut self) {
        if let Ok(stream) = self.stop.try_recv() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn recovery_snapshot_holds_flow_output_and_control_for_new_connection() {
    let mut server = TestRuntime::start();
    let _terminal = server.register(ID_A, KEY_A);
    let (stream, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::NewClient as i32));
    let key = passkey_to_key(KEY_A).unwrap();
    let mut payload = default_payload();
    payload.flowcontrol = Some(FlowControlMode::Backpressure as i32);
    let (mut client, initial) = initialize(stream, &key, payload);
    assert_eq!(initial.error, None);

    let (returning, response) = server.handshake(ID_A);
    assert_eq!(response.status, Some(ConnectStatus::ReturningClient as i32));
    let mut gate = RecoveryGate::start(returning);
    let recovery_stream = TcpStream::connect((Ipv4Addr::LOCALHOST, gate.port)).unwrap();
    runtime_support::bound(&recovery_stream);
    let (client_tx, client_rx) = mpsc::sync_channel::<Connection>(0);
    let recovery = thread::spawn(move || {
        client.recover(recovery_stream).unwrap();
        client
            .write_packet(TerminalPacketType::KeepAlive as u8, &[])
            .unwrap();
        client_tx.send(client).unwrap();
    });

    gate.snapshot.recv_timeout(TIMEOUT).unwrap();
    server.handle.send_packet(ID_A, 41, b"output").unwrap();
    server
        .handle
        .send_packet(ID_A, TerminalPacketType::KeepAlive as u8, b"control")
        .unwrap();
    gate.release.send(()).unwrap();

    let mut client = client_rx.recv_timeout(TIMEOUT).unwrap();
    recovery.join().unwrap();
    let acknowledgement = client.read_packet().unwrap();
    assert_eq!(
        acknowledgement.header(),
        TerminalPacketType::KeepAlive as u8
    );
    let output = client.read_packet().unwrap();
    let control = client.read_packet().unwrap();
    assert_eq!(
        (output.header(), output.payload()),
        (41, b"output".as_slice())
    );
    assert_eq!(
        (control.header(), control.payload()),
        (TerminalPacketType::KeepAlive as u8, b"control".as_slice())
    );

    client.shutdown().unwrap();
    gate.finish();
    server.runtime.shutdown().unwrap();
}
