#![cfg(unix)]
#![forbid(unsafe_code)]

mod runtime_support;
mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use et_core::keys::passkey_to_key;
use et_core::proto::{PortForwardSourceRequest, SocketEndpoint};
use et_net::connection::{Connection, PreparedWrite};
use et_net::forward::{is_forward_packet, Forwarder};
use et_net::local_packet::read_local_packet;
use runtime_support::{default_payload, initialize, TestRuntime, ID_A, KEY_A};
use rustix::event::{poll, PollFd, PollFlags};
use rustix::time::Timespec;

const TRANSFER_SIZE: usize = 6 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);

#[test]
fn large_full_duplex_forward_survives_mutual_queue_saturation() {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo = thread::spawn(move || {
        let (mut stream, _) = echo_listener.accept().unwrap();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            stream.write_all(&buffer[..count]).unwrap();
        }
    });

    let mut server = TestRuntime::start();
    let mut terminal = server.register(ID_A, KEY_A);
    let (stream, _) = server.handshake(ID_A);
    let key = passkey_to_key(KEY_A).unwrap();
    let (mut connection, response) = initialize(stream, &key, default_payload());
    assert_eq!(response.error, None);
    connection.minimize_output_buffering().unwrap();
    let _initial = read_local_packet(&mut terminal).unwrap();

    let source_port = reserve_port();
    let forwarder = Forwarder::start(vec![PortForwardSourceRequest {
        source: Some(SocketEndpoint {
            name: Some(Ipv4Addr::LOCALHOST.to_string()),
            port: Some(i32::from(source_port)),
        }),
        destination: Some(SocketEndpoint {
            name: Some(Ipv4Addr::LOCALHOST.to_string()),
            port: Some(i32::from(echo_port)),
        }),
        environmentvariable: None,
    }])
    .unwrap();

    let stop_stream = connection.try_clone_stream().unwrap();
    let (pump_done_tx, pump_done_rx) = mpsc::sync_channel(1);
    let pump = thread::spawn(move || {
        let result = run_blocking_on_held_packet_pump(connection, forwarder);
        let _ = pump_done_tx.send(result);
    });

    let mut application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    application.set_read_timeout(Some(DEADLINE)).unwrap();
    application.set_write_timeout(Some(DEADLINE)).unwrap();
    let payload: Vec<u8> = (0..TRANSFER_SIZE)
        .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
        .collect();
    let expected = payload.clone();
    let mut writer = application.try_clone().unwrap();
    let (write_done_tx, write_done_rx) = mpsc::sync_channel(1);
    let application_writer = thread::spawn(move || {
        let result = writer.write_all(&payload);
        let _ = write_done_tx.send(result);
    });
    let (read_done_tx, read_done_rx) = mpsc::sync_channel(1);
    let application_reader = thread::spawn(move || {
        let mut received = vec![0_u8; expected.len()];
        let result = application
            .read_exact(&mut received)
            .map(|()| received == expected);
        let _ = read_done_tx.send(result);
    });

    let write_result = write_done_rx.recv_timeout(DEADLINE);
    let read_result = read_done_rx.recv_timeout(DEADLINE);
    let success = matches!(write_result, Ok(Ok(()))) && matches!(read_result, Ok(Ok(true)));

    let _ = stop_stream.shutdown(Shutdown::Both);
    drop(terminal);
    application_writer.join().unwrap();
    application_reader.join().unwrap();
    let pump_result = pump_done_rx.recv_timeout(DEADLINE);
    pump.join().unwrap();
    echo.join().unwrap();
    server.runtime.shutdown().unwrap();

    assert!(
        success,
        "6 MiB full-duplex forwarding did not complete byte-exact: write={write_result:?}, read={read_result:?}, pump={pump_result:?}"
    );
}

// This deliberately mirrors the shipping session-pump behavior: once the
// forwarder's bounded command queue returns a packet, transport readability is
// disabled until that packet can be admitted. The real server pump on the
// other endpoint must continue reading while its own packet is held, otherwise
// the two saturated endpoints wait on each other forever.
fn run_blocking_on_held_packet_pump(
    mut connection: Connection,
    forwarder: Forwarder,
) -> Result<(), String> {
    let stream = connection
        .try_clone_stream()
        .map_err(|error| error.to_string())?;
    // The server session has an independent bounded transport writer. Mirror
    // that here so this pump can keep dispatching until real socket pressure
    // fills the queue, without serializing reads behind each socket write.
    let (write_tx, write_rx) = mpsc::sync_channel::<PreparedWrite>(256);
    thread::spawn(move || {
        while let Ok(prepared) = write_rx.recv() {
            if prepared.send().is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + DEADLINE;
    let mut pending = None;
    loop {
        if let Some(packet) = pending.take() {
            pending = forwarder
                .try_receive(packet)
                .map_err(|error| error.to_string())?;
        }
        let network_flags = if pending.is_none() {
            PollFlags::IN | PollFlags::HUP | PollFlags::ERR
        } else {
            PollFlags::HUP | PollFlags::ERR
        };
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "client pump deadline elapsed".to_owned())?;
        let timeout = Timespec::try_from(remaining).map_err(|error| error.to_string())?;
        let mut descriptors = [
            PollFd::new(&stream, network_flags),
            PollFd::new(
                forwarder.wake().map_err(|error| error.to_string())?,
                PollFlags::IN | PollFlags::HUP,
            ),
        ];
        poll(&mut descriptors, Some(&timeout)).map_err(|error| error.to_string())?;
        let network = descriptors[0].revents();
        let forwarding = descriptors[1].revents();
        if network.intersects(PollFlags::HUP | PollFlags::ERR) {
            return Ok(());
        }
        if pending.is_none() && network.contains(PollFlags::IN) {
            while pending.is_none() {
                let Some(packet) = connection
                    .try_read_packet()
                    .map_err(|error| error.to_string())?
                else {
                    break;
                };
                if is_forward_packet(packet.header()) {
                    pending = forwarder
                        .try_receive(packet)
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        if forwarding.intersects(PollFlags::IN | PollFlags::HUP) {
            while let Some(packet) = forwarder
                .try_outbound()
                .map_err(|error| error.to_string())?
            {
                let prepared = connection
                    .prepare_write_packet(packet.header(), packet.payload())
                    .map_err(|error| error.into_inner().to_string())?;
                write_tx.send(prepared).map_err(|error| error.to_string())?;
            }
        }
    }
}

fn reserve_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
