#![cfg(windows)]

use super::*;
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
        matches!(observed, Ok((Err(_), 0, 1))),
        "pump starved inbound dispatch behind forwarding output: {observed:?}"
    );
}
