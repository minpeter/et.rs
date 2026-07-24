use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use et_core::packet::Packet;
use et_core::proto::{TermInit, TerminalBuffer, TerminalInfo, TerminalPacketType};
use et_net::local_packet::{read_local_packet, LocalPacketDecoder};
use portable_pty::{MasterPty, PtySize};
use prost::Message;

const MAX_ENVIRONMENT: usize = 128;
const MAX_ENV_VALUE: usize = 4096;
const READ_BUFFER: usize = 16 * 1024;

pub fn read_initial_environment(router: &mut UnixStream) -> Result<Vec<(String, String)>, String> {
    let packet = read_local_packet(router)
        .map_err(|error| format!("could not read terminal initialization: {error}"))?;
    if packet.is_encrypted() || packet.header() != TerminalPacketType::TerminalInit as u8 {
        return Err("expected plaintext TERMINAL_INIT packet".to_owned());
    }
    let init = TermInit::decode(packet.payload())
        .map_err(|_| "TERMINAL_INIT protobuf is malformed".to_owned())?;
    if init.environmentnames.len() != init.environmentvalues.len()
        || init.environmentnames.len() > MAX_ENVIRONMENT
    {
        return Err("TERMINAL_INIT environment lists are invalid".to_owned());
    }
    init.environmentnames
        .into_iter()
        .zip(init.environmentvalues)
        .map(|(name, value)| {
            if !valid_environment_name(&name) || value.len() > MAX_ENV_VALUE || value.contains('\0')
            {
                return Err("TERMINAL_INIT contains an invalid environment entry".to_owned());
            }
            Ok((name, value))
        })
        .collect()
}

pub fn read_ready_packet(
    router: &mut UnixStream,
    decoder: &mut LocalPacketDecoder,
) -> Result<Option<Packet>, String> {
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        let wanted = decoder.required_bytes().min(buffer.len());
        match router.read(&mut buffer[..wanted]) {
            Ok(0) => return Err("terminal router disconnected".to_owned()),
            Ok(count) => {
                if let Some(packet) = decoder
                    .feed(&buffer[..count])
                    .map_err(|error| format!("malformed terminal packet: {error}"))?
                {
                    return Ok(Some(packet));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("could not read terminal router: {error}")),
        }
    }
}

pub fn handle_packet(
    packet: Packet,
    master: &dyn MasterPty,
    writer: &mut dyn Write,
) -> Result<(), String> {
    if packet.is_encrypted() {
        return Err("encrypted local terminal packet rejected".to_owned());
    }
    match packet.header() {
        header if header == TerminalPacketType::TerminalBuffer as u8 => {
            let message = TerminalBuffer::decode(packet.payload())
                .map_err(|_| "TERMINAL_BUFFER protobuf is malformed".to_owned())?;
            let bytes = message
                .buffer
                .ok_or_else(|| "TERMINAL_BUFFER is missing bytes".to_owned())?;
            writer
                .write_all(&bytes)
                .and_then(|()| writer.flush())
                .map_err(|error| format!("could not write PTY input: {error}"))
        }
        header if header == TerminalPacketType::TerminalInfo as u8 => {
            let info = TerminalInfo::decode(packet.payload())
                .map_err(|_| "TERMINAL_INFO protobuf is malformed".to_owned())?;
            master
                .resize(valid_size(info)?)
                .map_err(|error| format!("could not resize PTY: {error}"))
        }
        _ => Err("unsupported local terminal packet type".to_owned()),
    }
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_size(info: TerminalInfo) -> Result<PtySize, String> {
    fn dimension(value: Option<i32>, max: u16, name: &str) -> Result<u16, String> {
        let value = value.ok_or_else(|| format!("TERMINAL_INFO is missing {name}"))?;
        let value = u16::try_from(value).map_err(|_| format!("invalid terminal {name}"))?;
        if value == 0 || value > max {
            return Err(format!("invalid terminal {name}"));
        }
        Ok(value)
    }
    fn pixels(value: Option<i32>, name: &str) -> Result<u16, String> {
        let value = value.unwrap_or(0);
        let value = u16::try_from(value).map_err(|_| format!("invalid terminal {name}"))?;
        if value > 10_000 {
            return Err(format!("invalid terminal {name}"));
        }
        Ok(value)
    }
    Ok(PtySize {
        rows: dimension(info.row, 1000, "rows")?,
        cols: dimension(info.column, 1000, "columns")?,
        pixel_width: pixels(info.width, "pixel width")?,
        pixel_height: pixels(info.height, "pixel height")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use et_core::packet::Packet;
    use et_net::local_packet::write_local_packet;

    #[test]
    fn resize_rejects_zero_negative_and_oversized_dimensions() {
        for info in [
            TerminalInfo {
                row: Some(0),
                column: Some(80),
                ..Default::default()
            },
            TerminalInfo {
                row: Some(24),
                column: Some(-1),
                ..Default::default()
            },
            TerminalInfo {
                row: Some(24),
                column: Some(80),
                width: Some(10_001),
                ..Default::default()
            },
        ] {
            assert!(valid_size(info).is_err());
        }
    }

    #[test]
    fn resize_accepts_upstream_terminal_geometry() {
        let size = valid_size(TerminalInfo {
            row: Some(40),
            column: Some(100),
            width: Some(800),
            height: Some(600),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(size.rows, 40);
        assert_eq!(size.cols, 100);
        assert_eq!(size.pixel_width, 800);
        assert_eq!(size.pixel_height, 600);
    }

    #[test]
    fn initialization_rejects_wrong_type_malformed_and_invalid_environment() {
        let wrong_type = Packet::new(
            TerminalPacketType::TerminalBuffer as u8,
            TerminalBuffer {
                buffer: Some(Vec::new()),
            }
            .encode_to_vec(),
        );
        assert!(read_environment_packet(wrong_type).is_err());
        assert!(read_environment_packet(Packet::new(
            TerminalPacketType::TerminalInit as u8,
            vec![0xff]
        ))
        .is_err());
        for init in [
            TermInit {
                environmentnames: vec!["A".to_owned()],
                environmentvalues: Vec::new(),
            },
            TermInit {
                environmentnames: vec!["BAD-NAME".to_owned()],
                environmentvalues: vec!["value".to_owned()],
            },
            TermInit {
                environmentnames: vec!["VALID".to_owned()],
                environmentvalues: vec!["bad\0value".to_owned()],
            },
            TermInit {
                environmentnames: vec!["VALID".to_owned()],
                environmentvalues: vec!["x".repeat(MAX_ENV_VALUE + 1)],
            },
        ] {
            let packet = Packet::new(TerminalPacketType::TerminalInit as u8, init.encode_to_vec());
            assert!(read_environment_packet(packet).is_err());
        }
    }

    fn read_environment_packet(packet: Packet) -> Result<Vec<(String, String)>, String> {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        write_local_packet(&mut writer, &packet).unwrap();
        read_initial_environment(&mut reader)
    }
}
