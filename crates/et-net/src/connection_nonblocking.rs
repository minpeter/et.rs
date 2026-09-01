use std::io;
#[cfg(windows)]
use std::io::Read;
use std::net::TcpStream;

use et_core::backed_reader::{BackedReader, ReadItem};
use et_core::packet::Packet;

use crate::connection::ConnError;

pub(crate) fn try_read(
    stream: &mut TcpStream,
    reader: &mut BackedReader,
) -> Result<Option<Packet>, ConnError> {
    match reader.pop()? {
        ReadItem::Packet(packet) => return Ok(Some(packet)),
        ReadItem::NeedMore => {}
    }
    let mut buffer = [0u8; 8192];
    #[cfg(unix)]
    let read = rustix::net::recv(stream, &mut buffer, rustix::net::RecvFlags::DONTWAIT)
        .map(|(count, _)| count)
        .map_err(io::Error::from);
    #[cfg(windows)]
    let read = {
        stream.set_nonblocking(true)?;
        let read = stream.read(&mut buffer);
        stream.set_nonblocking(false)?;
        read
    };
    match read {
        Ok(0) => Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into())),
        Ok(count) => {
            reader.feed(&buffer[..count]);
            match reader.pop()? {
                ReadItem::Packet(packet) => Ok(Some(packet)),
                ReadItem::NeedMore => Ok(None),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
        Err(error) => Err(ConnError::Io(error)),
    }
}
