//! Bounded, nonblocking Unix bridge. Daemon EOF remains observable when the
//! terminal stops reading; final output and ST are drained for a bounded time.
use crate::framing::{Lines, MAX_QUEUE};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub fn run(
    stream: &mut UnixStream,
    input: &mut (impl Read + AsFd),
    output: &mut (impl Write + AsFd),
) -> io::Result<()> {
    let input_flags = fcntl_getfl(&*input)?;
    let output_flags = fcntl_getfl(&*output)?;
    fcntl_setfl(&*input, input_flags | OFlags::NONBLOCK)?;
    if let Err(error) = fcntl_setfl(&*output, output_flags | OFlags::NONBLOCK) {
        fcntl_setfl(&*input, input_flags)?;
        return Err(error.into());
    }
    let result = relay(stream, input, output);
    if result.is_err() {
        let _ = output.write(crate::codes::LEAVE_HTM_MODE);
    }
    // Do not leave control commands for `htm; exec $SHELL` to consume.
    if rustix::termios::isatty(&*input) {
        let _ = rustix::termios::tcflush(&*input, rustix::termios::QueueSelector::IFlush);
    }
    let restore_in = fcntl_setfl(&*input, input_flags).map_err(io::Error::from);
    let restore_out = fcntl_setfl(&*output, output_flags).map_err(io::Error::from);
    result.and(restore_in).and(restore_out)
}

fn relay(
    stream: &mut UnixStream,
    input: &mut (impl Read + AsFd),
    output: &mut (impl Write + AsFd),
) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let mut to_daemon = VecDeque::new();
    let mut to_terminal = VecDeque::from(crate::codes::ENTER_HTM_MODE.to_vec());
    let mut lines = Lines::default();
    let mut stopping = None;
    let mut input_closed = false;
    let mut daemon_closed = false;
    let mut buffer = [0; 4096];
    loop {
        if daemon_closed && stopping.is_none() {
            stopping = Some(Instant::now());
        }
        if let Some(start) = stopping {
            if (to_terminal.is_empty() && to_daemon.is_empty())
                || start.elapsed() >= Duration::from_millis(250)
            {
                // Best effort, never turn a dead terminal into a stuck bridge.
                let _ = output.write(crate::codes::LEAVE_HTM_MODE);
                let _ = output.flush();
                return Ok(());
            }
        }
        let mut polls = [
            PollFd::new(
                &*stream,
                PollFlags::IN
                    | if to_daemon.is_empty() {
                        PollFlags::empty()
                    } else {
                        PollFlags::OUT
                    },
            ),
            PollFd::new(
                &*input,
                if !input_closed && stopping.is_none() && to_daemon.len() < MAX_QUEUE - buffer.len()
                {
                    PollFlags::IN
                } else {
                    PollFlags::empty()
                },
            ),
            PollFd::new(
                &*output,
                if to_terminal.is_empty() {
                    PollFlags::empty()
                } else {
                    PollFlags::OUT
                },
            ),
        ];
        match poll(
            &mut polls,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            }),
        ) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
        let events = [polls[0].revents(), polls[1].revents(), polls[2].revents()];
        if events[1].intersects(PollFlags::IN | PollFlags::HUP) && !input_closed {
            match input.read(&mut buffer) {
                Ok(0) => input_closed = true,
                Ok(n) => {
                    // Detect detach locally; a wedged daemon cannot prevent exit.
                    for line in lines.feed(&buffer[..n])? {
                        let detach = line.trim().is_empty()
                            || crate::framing::parse(&line).is_ok_and(|commands| {
                                commands.iter().any(|words| {
                                    matches!(
                                        words.first().map(String::as_str),
                                        None | Some("detach-client" | "detach" | "exit")
                                    )
                                })
                            });
                        if to_daemon.len() + line.len() + 1 > MAX_QUEUE {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "command queue full",
                            ));
                        }
                        to_daemon.extend(line.bytes());
                        to_daemon.push_back(b'\n');
                        if detach {
                            stopping = Some(Instant::now());
                            input_closed = true;
                            break;
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        if !to_daemon.is_empty() {
            drain(stream, &mut to_daemon)?;
        }
        if input_closed && to_daemon.is_empty() && stopping.is_none() {
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
        if events[0].intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) && !daemon_closed {
            match stream.read(&mut buffer) {
                Ok(0) => daemon_closed = true,
                Ok(n) => {
                    if to_terminal.len() + n <= MAX_QUEUE {
                        to_terminal.extend(&buffer[..n]);
                    } else {
                        stopping = Some(Instant::now());
                        daemon_closed = true;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        if events[2].contains(PollFlags::OUT) {
            drain(output, &mut to_terminal)?;
        }
        if events[2].intersects(PollFlags::HUP | PollFlags::ERR) {
            return Ok(());
        }
    }
}

fn drain(writer: &mut impl Write, queue: &mut VecDeque<u8>) -> io::Result<()> {
    while !queue.is_empty() {
        match writer.write(queue.as_slices().0) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                queue.drain(..n);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub struct Stdin(pub std::io::Stdin);
impl Read for Stdin {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(bytes)
    }
}
impl AsFd for Stdin {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_data_is_drained_before_st_on_hup() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let (mut input, _stdin) = UnixStream::pair().unwrap();
        let (mut output, mut terminal) = UnixStream::pair().unwrap();
        daemon.write_all(b"%output %0 final\\012\n%exit\n").unwrap();
        drop(daemon);
        run(&mut client, &mut input, &mut output).unwrap();
        drop(output);
        let mut bytes = Vec::new();
        terminal.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"\x1bP1000p%output %0 final\\012\n%exit\n\x1b\\");
    }

    #[test]
    fn wedged_terminal_does_not_hide_daemon_eof() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let (mut input, _stdin) = UnixStream::pair().unwrap();
        let (mut output, _terminal) = UnixStream::pair().unwrap();
        output.set_nonblocking(true).unwrap();
        while output.write(&[b'x'; 16384]).is_ok() {}
        daemon.write_all(b"%exit\n").unwrap();
        drop(daemon);
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            send.send(run(&mut client, &mut input, &mut output))
                .unwrap();
        });
        receive
            .recv_timeout(Duration::from_secs(2))
            .expect("blocked stdout prevented exit")
            .unwrap();
        worker.join().unwrap();
    }
}
