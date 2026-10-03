use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use et_core::packet::Packet;
use et_core::proto::{PortForwardSourceRequest, SocketEndpoint, TerminalPacketType};
use et_net::connection::Connection;
use et_net::forward::{is_forward_packet, Forwarder};

use crate::windows_runtime_support::{Stack, TIMEOUT};

const TRANSFER_SIZE: usize = 16 * 1024 * 1024;
const PUMP_TICK: Duration = Duration::from_millis(1);
const DEADLINE: Duration = Duration::from_secs(120);

pub fn run() {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let (echo_tx, echo_rx) = mpsc::sync_channel(1);
    let echo = thread::spawn(move || {
        let _ = echo_tx.send(echo_exactly(echo_listener));
    });

    let mut stack = Stack::start();
    let connection = stack.connect();
    let source_port = reserve_port();
    let forwarder = Forwarder::start(vec![PortForwardSourceRequest {
        source: Some(endpoint(source_port)),
        destination: Some(endpoint(echo_port)),
        environmentvariable: None,
    }])
    .unwrap();

    let stop_stream = connection.try_clone_stream().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let pump_stop = stop.clone();
    let (pump_tx, pump_rx) = mpsc::sync_channel(1);
    let pump_thread = thread::spawn(move || {
        let result = pump(connection, forwarder, &pump_stop);
        let _ = pump_tx.send(result);
    });

    let mut application =
        TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, source_port).into(), TIMEOUT).unwrap();
    application.set_read_timeout(Some(DEADLINE)).unwrap();
    application.set_write_timeout(Some(DEADLINE)).unwrap();
    let payload: Vec<u8> = (0..TRANSFER_SIZE)
        .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
        .collect();
    let writer_payload = payload.clone();
    let mut writer_stream = application.try_clone().unwrap();
    let (writer_tx, writer_rx) = mpsc::sync_channel(1);
    let writer = thread::spawn(move || {
        let result = writer_stream.write_all(&writer_payload);
        let _ = writer_tx.send(result);
    });

    let mut received = vec![0_u8; TRANSFER_SIZE];
    let read_result = application.read_exact(&mut received);
    let write_result = writer_rx.recv_timeout(DEADLINE);
    writer.join().unwrap();
    let bytes_match = received == payload;

    // Ordinary forwards fully close when the source sends FIN. Drain every
    // echoed byte first, then half-close and require the destination EOF to
    // travel back through the real server and encrypted transport.
    let shutdown_result = application.shutdown(Shutdown::Write);
    let mut trailing = [0_u8; 1];
    let eof_result = application.read(&mut trailing);
    // Keep relaying until the peer close reaches the destination too.
    let echo_result = echo_rx.recv_timeout(TIMEOUT);

    stop.store(true, Ordering::Release);
    let pump_result = pump_rx.recv_timeout(TIMEOUT);
    pump_thread.join().unwrap();
    echo.join().unwrap();
    stack.wait_terminal(true);
    let _ = stop_stream.shutdown(Shutdown::Both);
    stack.finish();

    assert!(
        read_result.is_ok(),
        "16 MiB echo read failed: {read_result:?}"
    );
    assert!(
        matches!(write_result, Ok(Ok(()))),
        "16 MiB upload failed: {write_result:?}"
    );
    assert!(bytes_match, "16 MiB echo was not byte-exact");
    assert!(
        shutdown_result.is_ok(),
        "source FIN failed: {shutdown_result:?}"
    );
    assert_eq!(eof_result.unwrap(), 0, "expected EOF after byte-exact echo");
    assert!(
        matches!(echo_result, Ok(Ok(()))),
        "echo endpoint failed: {echo_result:?}"
    );
    assert!(
        matches!(pump_result, Ok(Ok(()))),
        "transport pump failed: {pump_result:?}"
    );
    println!("ISSUE134_TRANSFER upload={TRANSFER_SIZE} download={TRANSFER_SIZE} eof=true");
}

fn pump(mut connection: Connection, forwarder: Forwarder, stop: &AtomicBool) -> Result<(), String> {
    connection
        .minimize_output_buffering()
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + DEADLINE;
    let mut inbound = None;
    let mut outbound: VecDeque<Packet> = VecDeque::new();
    loop {
        if stop.load(Ordering::Acquire) {
            connection
                .finish_pending_write()
                .map_err(|error| error.into_inner().to_string())?;
            connection
                .write_packet(TerminalPacketType::TerminalClose as u8, &[])
                .map_err(|error| error.to_string())?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("native Windows forwarding pump deadline elapsed".to_owned());
        }

        if let Some(packet) = inbound.take() {
            inbound = forwarder
                .try_receive(packet)
                .map_err(|error| error.to_string())?;
        }
        for _ in outbound.len()..256 {
            let Some(packet) = forwarder
                .try_outbound()
                .map_err(|error| error.to_string())?
            else {
                break;
            };
            outbound.push_back(packet);
        }

        if connection.write_pending() {
            connection
                .advance_write()
                .map_err(|error| error.into_inner().to_string())?;
        } else if let Some(packet) = outbound.pop_front() {
            connection
                .start_write_packet_owned(packet.header(), packet.payload())
                .map_err(|error| error.into_inner().to_string())?;
        }

        if inbound.is_none() {
            for _ in 0..64 {
                if inbound.is_some() {
                    break;
                }
                let packet = match connection.try_read_packet() {
                    Ok(Some(packet)) => packet,
                    Ok(None) => break,
                    Err(_) if stop.load(Ordering::Acquire) => return Ok(()),
                    Err(error) => return Err(error.to_string()),
                };
                if is_forward_packet(packet.header()) {
                    inbound = forwarder
                        .try_receive(packet)
                        .map_err(|error| error.to_string())?;
                } else if packet.header() == TerminalPacketType::KeepAlive as u8 {
                    if let Some(ack) = et_core::keepalive::decode_ack(packet.payload()) {
                        connection.acknowledge_delivery(ack);
                    }
                    outbound.push_back(Packet::new(
                        TerminalPacketType::KeepAlive as u8,
                        connection.keepalive_ack().to_vec(),
                    ));
                }
                // ConPTY output is legitimate but irrelevant to this tunnel.
            }
        }
        thread::sleep(PUMP_TICK);
    }
}

fn echo_exactly(listener: TcpListener) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + DEADLINE;
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("echo accept deadline elapsed".to_owned());
                }
                thread::sleep(PUMP_TICK);
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(DEADLINE))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(DEADLINE))
        .map_err(|error| error.to_string())?;
    let mut total = 0_usize;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        stream
            .write_all(&buffer[..count])
            .map_err(|error| error.to_string())?;
        total += count;
    }
    (total == TRANSFER_SIZE)
        .then_some(())
        .ok_or_else(|| format!("echo endpoint received {total}, expected {TRANSFER_SIZE}"))
}

fn endpoint(port: u16) -> SocketEndpoint {
    SocketEndpoint {
        name: Some(Ipv4Addr::LOCALHOST.to_string()),
        port: Some(i32::from(port)),
    }
}

fn reserve_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
