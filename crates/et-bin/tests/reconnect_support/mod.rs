use std::io;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const TIMEOUT: Duration = Duration::from_secs(10);

pub struct CutProxy {
    pub port: u16,
    cut: mpsc::SyncSender<()>,
    waiting: mpsc::Receiver<()>,
    resume: mpsc::SyncSender<()>,
    traffic: mpsc::Receiver<(Instant, usize)>,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}

impl CutProxy {
    pub fn start(backend_port: u16) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cut_tx, cut_rx) = mpsc::sync_channel(1);
        let (waiting_tx, waiting_rx) = mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = mpsc::sync_channel(1);
        let (traffic_tx, traffic_rx) = mpsc::sync_channel(64);
        let worker = thread::spawn(move || {
            let (first, _) = listener.accept()?;
            let backend = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let first_relays = relay(&first, &backend, traffic_tx.clone())?;
            cut_rx
                .recv_timeout(TIMEOUT)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let _ = first.shutdown(Shutdown::Both);
            let _ = backend.shutdown(Shutdown::Both);
            join_relays(first_relays)?;

            let (second, _) = listener.accept()?;
            waiting_tx
                .send(())
                .map_err(|error| io::Error::other(error.to_string()))?;
            resume_rx
                .recv_timeout(TIMEOUT)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let recovered = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let second_relays = relay(&second, &recovered, traffic_tx.clone())?;
            cut_rx
                .recv_timeout(TIMEOUT)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let _ = second.shutdown(Shutdown::Both);
            let _ = recovered.shutdown(Shutdown::Both);
            join_relays(second_relays)?;

            let (third, _) = listener.accept()?;
            waiting_tx
                .send(())
                .map_err(|error| io::Error::other(error.to_string()))?;
            resume_rx
                .recv_timeout(TIMEOUT)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let third_backend = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let third_relays = relay(&third, &third_backend, traffic_tx.clone())?;
            join_relays(third_relays)?;

            let (final_client, _) = listener.accept()?;
            let final_backend = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let final_relays = relay(&final_client, &final_backend, traffic_tx)?;
            join_relays(final_relays)
        });
        Self {
            port,
            cut: cut_tx,
            waiting: waiting_rx,
            resume: resume_tx,
            traffic: traffic_rx,
            worker: Some(worker),
        }
    }

    pub fn cut(&self) {
        self.cut.send(()).unwrap();
        self.waiting.recv_timeout(TIMEOUT).unwrap();
    }

    pub fn resume(&self) {
        self.resume.send(()).unwrap();
    }

    pub fn wait_for_client_traffic_after(&self, armed: Instant) -> usize {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (observed, bytes) = self.traffic.recv_timeout(remaining).unwrap();
            if observed >= armed {
                return bytes;
            }
        }
    }

    pub fn join(mut self) {
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}

type Relays = (
    thread::JoinHandle<io::Result<u64>>,
    thread::JoinHandle<io::Result<u64>>,
);

fn relay(
    client: &TcpStream,
    backend: &TcpStream,
    traffic: mpsc::SyncSender<(Instant, usize)>,
) -> io::Result<Relays> {
    let mut client_reader = client.try_clone()?;
    let mut client_writer = client.try_clone()?;
    let mut backend_reader = backend.try_clone()?;
    let mut backend_writer = backend.try_clone()?;
    Ok((
        thread::spawn(move || copy_client(&mut client_reader, &mut backend_writer, &traffic)),
        thread::spawn(move || io::copy(&mut backend_reader, &mut client_writer)),
    ))
}

fn copy_client(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    traffic: &mpsc::SyncSender<(Instant, usize)>,
) -> io::Result<u64> {
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(total);
        }
        writer.write_all(&buffer[..count])?;
        total += count as u64;
        let _ = traffic.send((Instant::now(), count));
    }
}

fn join_relays((first, second): Relays) -> io::Result<()> {
    for worker in [first, second] {
        match worker.join() {
            Ok(Ok(_)) => {}
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(io::Error::other("relay worker panicked")),
        }
    }
    Ok(())
}
