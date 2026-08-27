use std::io;
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

pub struct SingleCutProxy {
    pub port: u16,
    cut: mpsc::SyncSender<()>,
    waiting: mpsc::Receiver<()>,
    resume: mpsc::SyncSender<()>,
    stop: mpsc::SyncSender<()>,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}

impl SingleCutProxy {
    pub fn start(backend_port: u16) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cut_tx, cut_rx) = mpsc::sync_channel(1);
        let (waiting_tx, waiting_rx) = mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = mpsc::sync_channel(1);
        let (stop_tx, stop_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let (first, _) = listener.accept()?;
            let backend = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let first_relays = relay(&first, &backend)?;
            cut_rx
                .recv_timeout(TIMEOUT)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let _ = first.shutdown(Shutdown::Both);
            let _ = backend.shutdown(Shutdown::Both);
            join(first_relays)?;

            let (second, _) = listener.accept()?;
            waiting_tx
                .send(())
                .map_err(|error| io::Error::other(error.to_string()))?;
            resume_rx
                .recv_timeout(TIMEOUT)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let recovered = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port))?;
            let relays = relay(&second, &recovered)?;
            stop_rx
                .recv_timeout(TIMEOUT)
                .map_err(|error| io::Error::other(error.to_string()))?;
            let _ = second.shutdown(Shutdown::Both);
            let _ = recovered.shutdown(Shutdown::Both);
            join(relays)
        });
        Self {
            port,
            cut: cut_tx,
            waiting: waiting_rx,
            resume: resume_tx,
            stop: stop_tx,
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

    pub fn join(mut self) {
        let _ = self.stop.send(());
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}

type Relays = (
    thread::JoinHandle<io::Result<u64>>,
    thread::JoinHandle<io::Result<u64>>,
);

fn relay(client: &TcpStream, backend: &TcpStream) -> io::Result<Relays> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut backend_read = backend.try_clone()?;
    let mut backend_write = backend.try_clone()?;
    Ok((
        thread::spawn(move || io::copy(&mut client_read, &mut backend_write)),
        thread::spawn(move || io::copy(&mut backend_read, &mut client_write)),
    ))
}

fn join(relays: Relays) -> io::Result<()> {
    for worker in [relays.0, relays.1] {
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
