//! Upstream #916: a destination whose `socket()` fails with EMFILE must fail
//! that destination, not the forwarder. This lowers the process-wide
//! `RLIMIT_NOFILE`, so it lives alone in its own test binary.
#![cfg(unix)]
#![forbid(unsafe_code)]

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::time::Duration;

use et_core::packet::Packet;
use et_core::proto::{
    PortForwardDestinationRequest, PortForwardDestinationResponse, SocketEndpoint,
    TerminalPacketType,
};
use et_net::forward::Forwarder;
use prost::Message;
use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

const TIMEOUT: Duration = Duration::from_secs(5);

struct RestoreLimit(Rlimit);

impl Drop for RestoreLimit {
    fn drop(&mut self) {
        let _ = setrlimit(Resource::Nofile, self.0);
    }
}

fn request(path: &std::path::Path, fd: i32) -> Packet {
    Packet::new(
        TerminalPacketType::PortForwardDestinationRequest as u8,
        PortForwardDestinationRequest {
            destination: Some(SocketEndpoint {
                name: Some(path.to_string_lossy().into_owned()),
                port: None,
            }),
            fd: Some(fd),
            window: None,
        }
        .encode_to_vec(),
    )
}

fn response(forwarder: &Forwarder) -> PortForwardDestinationResponse {
    let packet = forwarder.wait_outbound(TIMEOUT).unwrap();
    assert_eq!(
        packet.header(),
        TerminalPacketType::PortForwardDestinationResponse as u8
    );
    PortForwardDestinationResponse::decode(packet.payload()).unwrap()
}

#[test]
fn unix_destination_survives_descriptor_exhaustion() {
    let directory = std::env::temp_dir().join(format!("et-forward-emfile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("agent.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let forwarder = Forwarder::start(Vec::new()).unwrap();

    // A first destination proves the worker thread is up and has its own
    // descriptors before the cap, so only the next destination can hit it.
    forwarder.receive(request(&path, 299)).unwrap();
    let warm = response(&forwarder);
    assert_eq!(warm.error, None);
    let _warm_peer = listener.accept().unwrap();

    let original = getrlimit(Resource::Nofile);
    // Every descriptor below the lowest free one is in use, so capping the
    // soft limit there makes the destination's socket() fail with EMFILE.
    let lowest_free = std::fs::File::open("/dev/null").unwrap().as_raw_fd();
    let failed = {
        let _restore = RestoreLimit(original);
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(u64::try_from(lowest_free).unwrap()),
                maximum: original.maximum,
            },
        )
        .unwrap();
        forwarder.receive(request(&path, 300)).unwrap();
        response(&forwarder)
    };
    assert_eq!(failed.clientfd, Some(300));
    assert_eq!(failed.socketid, None);
    let error = failed.error.expect("EMFILE must be reported as an error");
    assert!(
        error.contains(
            &std::io::Error::from_raw_os_error(rustix::io::Errno::MFILE.raw_os_error()).to_string()
        ),
        "unexpected error: {error}"
    );

    // Once descriptors are available again, the same forwarder and
    // destination connect.
    forwarder.receive(request(&path, 301)).unwrap();
    let retry = response(&forwarder);
    assert_eq!(retry.clientfd, Some(301));
    assert_eq!(retry.error, None);
    assert!(retry.socketid.is_some_and(|id| id > 0));
    let _peer = listener.accept().unwrap();

    forwarder.shutdown().unwrap();
    let _ = std::fs::remove_dir_all(&directory);
}
