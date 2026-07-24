use std::io::{self, Read};
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
    stream.set_nonblocking(true)?;
    let mut buffer = [0u8; 8192];
    let read = stream.read(&mut buffer);
    stream.set_nonblocking(false)?;
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
