#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use et_core::proto::{PortForwardSourceRequest, SocketEndpoint};
use et_net::forward::Forwarder;

const TIMEOUT: Duration = Duration::from_secs(3);

#[test]
fn two_forwarders_relay_a_real_tcp_round_trip() {
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    let echo = thread::spawn(move || {
        let (mut stream, _) = destination.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).unwrap();
        stream.write_all(&payload).unwrap();
    });
    let source_port = reserve_port();
    let source = Forwarder::start(vec![request(source_port, destination_port)]).unwrap();
    let destination = Forwarder::start(Vec::new()).unwrap();
    let mut application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    application.set_read_timeout(Some(TIMEOUT)).unwrap();

    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    application.write_all(b"hello").unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    let mut echoed = [0u8; 5];
    application.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hello");

    drop(application);
    source.shutdown().unwrap();
    destination.shutdown().unwrap();
    echo.join().unwrap();
}

#[test]
fn refused_destination_closes_the_accepted_source() {
    let destination_port = reserve_port();
    let source_port = reserve_port();
    let source = Forwarder::start(vec![request(source_port, destination_port)]).unwrap();
    let destination = Forwarder::start(Vec::new()).unwrap();
    let mut application = TcpStream::connect((Ipv4Addr::LOCALHOST, source_port)).unwrap();
    application.set_read_timeout(Some(TIMEOUT)).unwrap();
    destination
        .receive(source.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    source
        .receive(destination.wait_outbound(TIMEOUT).unwrap())
        .unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(application.read(&mut byte).unwrap(), 0);
    source.shutdown().unwrap();
    destination.shutdown().unwrap();
}

fn reserve_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn request(source: u16, destination: u16) -> PortForwardSourceRequest {
    PortForwardSourceRequest {
        source: Some(SocketEndpoint {
            name: Some("127.0.0.1".to_owned()),
            port: Some(i32::from(source)),
        }),
        destination: Some(SocketEndpoint {
            name: Some("127.0.0.1".to_owned()),
            port: Some(i32::from(destination)),
        }),
        environmentvariable: None,
    }
}
