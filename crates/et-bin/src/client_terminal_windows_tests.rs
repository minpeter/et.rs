#![cfg(windows)]

use super::*;
use crate::initial_connect::ReconnectOutcome;
use et_core::proto::{PortForwardDestinationRequest, SocketEndpoint};
use prost::Message;
use std::io::Write;
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

thread_local! {
    static PENDING_WRITE: std::cell::RefCell<Option<mpsc::SyncSender<()>>> = const {
        std::cell::RefCell::new(None)
    };
    static INPUT: std::cell::RefCell<Option<mpsc::Receiver<Vec<u8>>>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(super) fn take_input() -> Option<mpsc::Receiver<Vec<u8>>> {
    INPUT.with(|input| input.borrow_mut().take())
}

pub(super) fn note_pending_write() {
    PENDING_WRITE.with(|observer| {
        if let Some(observer) = observer.borrow_mut().take() {
            observer.send(()).unwrap();
        }
    });
}

#[test]
fn pump_services_inbound_while_large_forwarding_write_is_stalled() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(4096)
        .unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let control = client.try_clone().unwrap();
    let mut connection = Connection::new_client(client, &[19; 32]);
    connection.shrink_transport_window_for_tests(4096).unwrap();
    let mut peer = Connection::new_server(server, &[19; 32]);
    peer.set_io_timeout(Some(Duration::from_secs(3))).unwrap();

    let mut forwarder = Forwarder::start(Vec::new()).unwrap();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    forwarder
        .receive(et_core::packet::Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(Ipv4Addr::LOCALHOST.to_string()),
                    port: Some(i32::from(destination.local_addr().unwrap().port())),
                }),
                fd: Some(42),
                window: None,
            }
            .encode_to_vec(),
        ))
        .unwrap();
    let (mut application, _) = destination.accept().unwrap();
    application
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    application.write_all(&vec![3; 1024 * 1024]).unwrap();

    let (pending_tx, pending_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        PENDING_WRITE.with(|observer| *observer.borrow_mut() = Some(pending_tx));
        let mut recoveries = 0;
        let result = pump(
            &mut connection,
            crate::client_terminal_loop::PumpOptions {
                read_stdin: false,
                keepalive_seconds: 30,
                flow_control: et_cli::client::FlowControlMode::None,
                terminal_enabled: false,
                auto_cursor_report: false,
                binary_stdio: false,
                terminal_modes: &mut TerminalModeState::default(),
                hangup: &crate::client_hangup::HangupClose::disabled(),
                remote_exit: &crate::client_terminal::RemoteExit::new(false),
                stdio_forward: false,
            },
            &mut forwarder,
            |_| {
                recoveries += 1;
                Ok(ReconnectOutcome::SessionEnded)
            },
        );
        done_tx
            .send((result, recoveries, connection.reader_sequence()))
            .unwrap();
    });

    // Do not infer saturation from elapsed time: wait for a retained frame
    // while the peer has never drained the tiny receive window.
    pending_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    peer.write_packet(255, b"dispatch-before-output-drain")
        .unwrap();
    let observed = done_rx.recv_timeout(Duration::from_secs(1));
    let _ = control.shutdown(Shutdown::Both);
    worker.join().unwrap();

    assert!(
        matches!(observed, Ok((Err(_), 1, 1))),
        "pump starved inbound dispatch behind forwarding output: {observed:?}"
    );
}

#[test]
fn pending_local_input_yields_to_forwarding_before_more_local_input() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut connection = Connection::new_client(client, &[19; 32]);
    connection.minimize_output_buffering().unwrap();
    let mut peer = Connection::new_server(server, &[19; 32]);
    peer.set_io_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut forwarder = Forwarder::start(Vec::new()).unwrap();
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    forwarder
        .receive(et_core::packet::Packet::new(
            TerminalPacketType::PortForwardDestinationRequest as u8,
            PortForwardDestinationRequest {
                destination: Some(SocketEndpoint {
                    name: Some(Ipv4Addr::LOCALHOST.to_string()),
                    port: Some(i32::from(destination.local_addr().unwrap().port())),
                }),
                fd: Some(42),
                window: None,
            }
            .encode_to_vec(),
        ))
        .unwrap();
    let (_application, _) = destination.accept().unwrap();
    let (input_tx, input_rx) = mpsc::sync_channel(2);
    // Oversized fixture chunks guarantee retained writes independently of
    // socket capacity; both producers stay ready across frame completion.
    input_tx.send(vec![0x31; 1024 * 1024]).unwrap();
    input_tx.send(vec![0x72; 1024 * 1024]).unwrap();
    let (pending_tx, pending_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        INPUT.with(|input| *input.borrow_mut() = Some(input_rx));
        PENDING_WRITE.with(|observer| *observer.borrow_mut() = Some(pending_tx));
        pump(
            &mut connection,
            crate::client_terminal_loop::PumpOptions {
                read_stdin: false,
                keepalive_seconds: 30,
                flow_control: et_cli::client::FlowControlMode::None,
                terminal_enabled: false,
                auto_cursor_report: false,
                binary_stdio: false,
                terminal_modes: &mut TerminalModeState::default(),
                hangup: &crate::client_hangup::HangupClose::disabled(),
                remote_exit: &crate::client_terminal::RemoteExit::new(false),
                stdio_forward: false,
            },
            &mut forwarder,
            |_| Ok(ReconnectOutcome::SessionEnded),
        )
    });
    pending_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    // Volume acknowledgements (one keep-alive per 512 KiB written) may sit
    // between producer frames; they are not a producer turn.
    let first = next_data_packet(&mut peer);
    let second = next_data_packet(&mut peer);
    peer.write_packet(255, b"stop-after-producer-order-check")
        .unwrap();
    // The stop packet reconnects and the test callback ends the session.
    // Packet order above is the fairness check; the pump must just finish.
    worker
        .join()
        .unwrap()
        .expect("stop packet should end the pump");
    assert_eq!(first.header(), TerminalPacketType::TerminalBuffer as u8);
    assert_eq!(
        et_core::proto::TerminalBuffer::decode(first.payload())
            .unwrap()
            .buffer
            .unwrap(),
        vec![0x31; 1024 * 1024]
    );
    assert_eq!(
        second.header(),
        TerminalPacketType::PortForwardDestinationResponse as u8,
        "forwarding must get a turn before the second queued input frame"
    );
}

#[test]
fn binary_stdio_redirected_eof_sends_one_eof_and_waits_for_remote_exit() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let control = client.try_clone().unwrap();
    let mut connection = Connection::new_client(client, &[19; 32]);
    let mut peer = Connection::new_server(server, &[19; 32]);
    peer.set_io_timeout(Some(Duration::from_secs(5))).unwrap();
    // Redirected stdin that delivers one chunk, then ends.
    let (input_tx, input_rx) = mpsc::sync_channel(1);
    input_tx.send(b"last line\n".to_vec()).unwrap();
    drop(input_tx);
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        INPUT.with(|input| *input.borrow_mut() = Some(input_rx));
        let result = pump(
            &mut connection,
            crate::client_terminal_loop::PumpOptions {
                read_stdin: false,
                keepalive_seconds: 30,
                flow_control: et_cli::client::FlowControlMode::None,
                terminal_enabled: false,
                auto_cursor_report: false,
                binary_stdio: true,
                terminal_modes: &mut TerminalModeState::default(),
                hangup: &crate::client_hangup::HangupClose::disabled(),
                remote_exit: &crate::client_terminal::RemoteExit::new(true),
                stdio_forward: false,
            },
            &mut Forwarder::start(Vec::new()).unwrap(),
            |_| panic!("healthy transport must not recover"),
        );
        done_tx
            .send(result.map_err(|error| error.to_string()))
            .unwrap();
    });
    let data = next_data_packet(&mut peer);
    assert_eq!(
        et_core::proto::TerminalBuffer::decode(data.payload())
            .unwrap()
            .buffer
            .unwrap(),
        b"last line\n"
    );
    let eof = next_data_packet(&mut peer);
    assert_eq!(eof.header(), TerminalPacketType::TerminalBuffer as u8);
    assert_eq!(eof.payload(), [0x0a, 0x00]);
    let after_eof = done_rx.recv_timeout(Duration::from_millis(200));
    peer.write_packet(
        TerminalPacketType::TerminalExitStatus as u8,
        &et_core::proto::TerminalExitStatus { exitcode: Some(3) }.encode_to_vec(),
    )
    .unwrap();
    let completed = done_rx.recv_timeout(Duration::from_secs(3));
    let _ = control.shutdown(Shutdown::Both);
    worker.join().unwrap();
    assert!(after_eof.is_err(), "stdin EOF ended the -T session");
    assert_eq!(completed.unwrap(), Ok(3));
}

fn next_data_packet(peer: &mut Connection) -> et_core::packet::Packet {
    loop {
        let packet = peer.read_packet().unwrap();
        if packet.header() != TerminalPacketType::KeepAlive as u8 {
            return packet;
        }
    }
}
