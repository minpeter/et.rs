//! Bounded Windows bridge. The console gateway preserves tmux DCS through
//! ConPTY, while redirected output remains the ordinary control byte stream.
use crate::transport::Stream;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::time::Duration;

pub struct Stdin(pub std::io::Stdin);
impl Read for Stdin {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(buffer)
    }
}

fn emit(writer: &mut impl Write, bytes: &[u8], console: bool) -> io::Result<()> {
    if console {
        for chunk in bytes.chunks(15) {
            writer.write_all(b"\x1b[?777")?;
            for byte in chunk {
                write!(writer, ";{byte}")?;
            }
            writer.write_all(b"q")?;
        }
    } else {
        writer.write_all(bytes)?;
    }
    writer.flush()
}

pub fn run(
    stream: &mut Stream,
    mut input: impl Read + Send + 'static,
    mut output: impl Write + Send + 'static,
    console: bool,
) -> io::Result<()> {
    let mut writer = stream.try_clone()?;
    writer.set_write_timeout(Some(Duration::from_secs(1)))?;
    std::thread::Builder::new()
        .name("htm-stdin".into())
        .spawn(move || {
            let result = (|| -> io::Result<()> {
                let mut lines = crate::framing::Lines::default();
                let mut buffer = [0; 4096];
                loop {
                    let n = input.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    for line in lines.feed(&buffer[..n])? {
                        writeln!(writer, "{line}")?;
                        if line.trim().is_empty()
                            || crate::framing::parse(&line).is_ok_and(|commands| {
                                commands.iter().any(|words| {
                                    matches!(
                                        words.first().map(String::as_str),
                                        None | Some("detach-client" | "detach" | "exit")
                                    )
                                })
                            })
                        {
                            return Ok(());
                        }
                    }
                }
                Ok(())
            })();
            let _ = writer.shutdown(if result.is_ok() {
                std::net::Shutdown::Write
            } else {
                std::net::Shutdown::Both
            });
        })?;
    // At most 16 * 16KiB, plus the writer's one in-flight chunk. A blocked
    // console must not stop the main thread observing daemon EOF.
    let (send, receive) = mpsc::sync_channel::<Vec<u8>>(16);
    let (done, completion) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("htm-stdout".into())
        .spawn(move || {
            let result = (|| -> io::Result<()> {
                emit(&mut output, crate::codes::ENTER_HTM_MODE, console)?;
                while let Ok(bytes) = receive.recv() {
                    emit(&mut output, &bytes, console)?;
                }
                emit(&mut output, crate::codes::LEAVE_HTM_MODE, console)
            })();
            let _ = done.send(result);
        })?;
    let result = (|| -> io::Result<()> {
        let mut buffer = [0; 16 * 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    if send.try_send(buffer[..n].to_vec()).is_err() {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    })();
    drop(send);
    let _ = stream.shutdown(std::net::Shutdown::Both);
    match completion.recv_timeout(Duration::from_millis(250)) {
        Ok(write) => result.and(write),
        Err(_) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_gateway_and_redirected_output_differ() {
        let mut bytes = Vec::new();
        emit(&mut bytes, crate::codes::ENTER_HTM_MODE, true).unwrap();
        assert_eq!(bytes, b"\x1b[?777;27;80;49;48;48;48;112q");
        bytes.clear();
        emit(&mut bytes, crate::codes::ENTER_HTM_MODE, false).unwrap();
        assert_eq!(bytes, b"\x1bP1000p");
    }
}
