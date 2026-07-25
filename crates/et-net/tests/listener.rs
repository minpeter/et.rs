#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};

use et_net::listener::bind_tcp;

#[test]
fn wildcard_bind_is_dual_stack_when_ipv6_is_available() {
    let ipv6_available = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok();
    let listeners = bind_tcp(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap();

    assert!(listeners.ipv4().is_some());
    assert_eq!(listeners.ipv6().is_some(), ipv6_available);
    let port = listeners.port();

    let client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let (accepted, _) = listeners.ipv4().unwrap().accept().unwrap();
    drop((client, accepted));

    if let Some(listener) = listeners.ipv6() {
        let client = TcpStream::connect((Ipv6Addr::LOCALHOST, port)).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        drop((client, accepted));
    }
}

#[test]
fn explicit_ipv6_listener_is_v6_only() {
    if TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_err() {
        return;
    }

    let listeners = bind_tcp(IpAddr::V6(Ipv6Addr::LOCALHOST), 0).unwrap();
    assert!(listeners.ipv4().is_none());
    assert!(listeners.ipv6().is_some());
    let socket = socket2::Socket::from(listeners.ipv6().unwrap().try_clone().unwrap());
    assert!(socket.only_v6().unwrap());
}

#[test]
fn occupied_address_is_a_typed_bind_error() {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = occupied.local_addr().unwrap().port();
    assert!(bind_tcp(IpAddr::V4(Ipv4Addr::LOCALHOST), port).is_err());
}
