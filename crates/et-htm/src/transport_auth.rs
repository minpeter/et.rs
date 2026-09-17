//! Bounded nonblocking token admission, also exercised with TCP on Linux.
use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

pub(super) struct Pending {
    stream: TcpStream,
    bytes: [u8; 65],
    len: usize,
    deadline: Instant,
}

pub(super) fn accept(
    listener: &TcpListener,
    pending: &mut Vec<Pending>,
    token: &str,
) -> io::Result<TcpStream> {
    pending.retain(|p| Instant::now() < p.deadline);
    match listener.accept() {
        Ok((stream, peer)) if peer.ip().is_loopback() && pending.len() < 16 => {
            stream.set_nonblocking(true)?;
            pending.push(Pending {
                stream,
                bytes: [0; 65],
                len: 0,
                deadline: Instant::now() + Duration::from_secs(1),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error),
    }
    let mut index = 0;
    while index < pending.len() {
        let p = &mut pending[index];
        match p.stream.read(&mut p.bytes[p.len..]) {
            Ok(0) => {
                pending.remove(index);
                continue;
            }
            Ok(n) => p.len += n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                index += 1;
                continue;
            }
            Err(_) => {
                pending.remove(index);
                continue;
            }
        }
        if p.len == p.bytes.len() || p.bytes[..p.len].contains(&b'\n') {
            let valid = p.len == 65
                && p.bytes[64] == b'\n'
                && token.len() == 64
                && p.bytes[..64]
                    .iter()
                    .zip(token.as_bytes())
                    .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                    == 0;
            let p = pending.remove(index);
            if valid {
                // Preserve the transport's blocking-stream contract. The daemon
                // switches it to nonblocking before any control/diagnostic I/O.
                p.stream.set_nonblocking(false)?;
                p.stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                p.stream.set_nodelay(true)?;
                return Ok(p.stream);
            }
        } else {
            index += 1;
        }
    }
    Err(io::ErrorKind::WouldBlock.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn slow_auth_does_not_block_another_client_or_consume_its_command() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let token = "ab".repeat(32);
        let mut pending = Vec::new();
        let mut slow = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        slow.write_all(b"a").unwrap();
        let started = Instant::now();
        assert_eq!(
            accept(&listener, &mut pending, &token).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .write_all(format!("{token}\nhello").as_bytes())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut authenticated = loop {
            match accept(&listener, &mut pending, &token) {
                Ok(stream) => break stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("{error}"),
            }
        };
        let mut command = [0; 5];
        authenticated.read_exact(&mut command).unwrap();
        assert_eq!(&command, b"hello");
        assert_eq!(pending.len(), 1);
        // Advance the pending entry's deadline, not the wall clock. A byte
        // arriving now must not reset its original authentication deadline.
        pending[0].deadline = Instant::now();
        slow.write_all(b"b").unwrap();
        assert!(accept(&listener, &mut pending, &token).is_err());
        assert!(pending.is_empty());
    }

    #[test]
    fn wrong_token_is_rejected_and_pending_admissions_are_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let token = "ab".repeat(32);
        let mut pending = Vec::new();
        let mut wrong = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        wrong.write_all(b"wr").unwrap();
        assert!(accept(&listener, &mut pending, &token).is_err());
        assert_eq!(pending.len(), 1, "partial tokens must stay pending");
        wrong.write_all(b"ong\n").unwrap();
        // Also reject a full-length incorrect token without leaking output.
        let mut bad = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        bad.write_all(format!("{}\n", "cd".repeat(32)).as_bytes())
            .unwrap();
        assert!(accept(&listener, &mut pending, &token).is_err());
        for stream in [&mut wrong, &mut bad] {
            stream.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                // A write completing does not guarantee that a single server
                // poll has received it (notably on Darwin). Keep driving the
                // same admission loop the daemon uses while awaiting EOF.
                assert_eq!(
                    accept(&listener, &mut pending, &token).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                match stream.read(&mut [0]) {
                    Ok(0) => break,
                    Ok(_) => panic!("unauthenticated peer received output"),
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("invalid token was not disconnected: {error}"),
                }
            }
        }
        let mut held = Vec::new();
        for _ in 0..17 {
            held.push(TcpStream::connect(listener.local_addr().unwrap()).unwrap());
            assert!(accept(&listener, &mut pending, &token).is_err());
        }
        assert_eq!(pending.len(), 16);
    }
}
