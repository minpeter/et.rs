//! Windows HTM is a byte relay, including when stdin/stdout are redirected by
//! the HTM-capable terminal emulator. Console input cannot be polled with a
//! Winsock socket, so one process-lifetime thread owns the blocking stdin read.
//! The role's main thread returns on daemon EOF even if stdin remains open;
//! process exit releases that reader, without waiting for another keystroke.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use crate::transport::{self, Stream};

pub struct Stdin(pub std::io::Stdin);

impl Read for Stdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(buffer)
    }
}

pub fn connect(path: &Path) -> io::Result<Stream> {
    let mut last_error = io::Error::from(io::ErrorKind::NotFound);
    for attempt in 0..5 {
        match transport::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = error,
        }
        if attempt < 4 {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Err(last_error)
}

pub fn run(
    stream: &mut Stream,
    mut input: impl Read + Send + 'static,
    output: &mut impl Write,
) -> io::Result<()> {
    let mut writer = stream.try_clone()?;
    let (errors, input_error) = mpsc::channel();
    std::thread::Builder::new()
        .name("htm-stdin".to_owned())
        .spawn(move || {
            let error = match io::copy(&mut input, &mut writer) {
                Ok(_) => io::Error::new(io::ErrorKind::UnexpectedEof, "stdin has closed abruptly"),
                Err(error) => error,
            };
            if errors.send(error).is_ok() {
                // Wake the output reader so an input error is reported promptly.
                if let Err(error) = writer.shutdown(Shutdown::Both) {
                    eprintln!("htm: closing input stream: {error}");
                }
            }
        })?;
    let result = (|| {
        let mut buffer = [0; 16 * 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    // Do not guess frame boundaries from read() chunk sizes.
                    // SESSION_END is relayed too; htmd follows it with EOF.
                    output.write_all(&buffer[..count])?;
                    output.flush()?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    })();
    match input_error.try_recv() {
        Ok(error) => Err(error),
        Err(_) => result,
    }
}
