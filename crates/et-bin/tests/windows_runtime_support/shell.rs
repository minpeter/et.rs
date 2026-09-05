use et_core::proto::{TerminalBuffer, TerminalPacketType};
use et_net::connection::Connection;
use prost::Message;

use super::TIMEOUT;

pub struct Shell {
    pub pid: u32,
    pub descendant: u32,
    state: String,
}

impl Shell {
    pub fn start(client: &mut Connection) -> Self {
        // portable-pty uses PSEUDOCONSOLE_INHERIT_CURSOR. Act as the terminal
        // emulator: answer its exact DSR event before submitting shell input.
        assert_eq!(read_marker(client, "\x1b[", 'n'), "6");
        Self::send(client, "\x1b[1;1R");
        // Sentinels are assembled by the shell: input echo cannot satisfy them.
        // The descendant blocks on a kernel event, not a correctness sleep.
        Self::send(client, concat!(
            "$etState=[guid]::NewGuid().ToString('N'); ",
            "$etChild=Start-Process -FilePath ($PSHOME+'\\powershell.exe') ",
            "-ArgumentList '-NoProfile -Command \"([Threading.ManualResetEvent]::new($false)).WaitOne()\"' ",
            "-WindowStyle Hidden -PassThru; ",
            "[Console]::WriteLine(('ET'+'-INITIAL:')+$PID+':'+$etChild.Id+':'+$etState+';')\r\n"
        ));
        let value = read_marker(client, "ET-INITIAL:", ';');
        let fields: Vec<_> = value.split(':').collect();
        assert_eq!(fields.len(), 3, "invalid shell identity: {value}");
        let shell = Self {
            pid: fields[0].parse().unwrap(),
            descendant: fields[1].parse().unwrap(),
            state: fields[2].to_owned(),
        };
        assert_ne!(shell.pid, shell.descendant);
        assert_eq!(shell.state.len(), 32);
        assert!(shell.state.bytes().all(|byte| byte.is_ascii_hexdigit()));
        println!("CONPTY_INITIAL {value}");
        shell
    }

    pub fn assert_recovered(&self, client: &mut Connection) {
        Self::send(
            client,
            "[Console]::WriteLine(('ET'+'-RECOVERED:')+$PID+':'+$etChild.Id+':'+$etState+';')\r\n",
        );
        let value = read_marker(client, "ET-RECOVERED:", ';');
        assert_eq!(
            value,
            format!("{}:{}:{}", self.pid, self.descendant, self.state)
        );
        println!("CONPTY_RECOVERED {value}");
    }

    pub fn send(client: &mut Connection, command: &str) {
        client.set_io_timeout(Some(TIMEOUT)).unwrap();
        client
            .write_packet(
                TerminalPacketType::TerminalBuffer as u8,
                &TerminalBuffer {
                    buffer: Some(command.as_bytes().to_vec()),
                }
                .encode_to_vec(),
            )
            .unwrap();
    }
}

fn read_marker(client: &mut Connection, marker: &str, delimiter: char) -> String {
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut output = Vec::new();
    loop {
        let packet = client.read_packet_until(deadline).unwrap_or_else(|error| {
            panic!(
                "missing {marker}: {error}; ConPTY output={:?}",
                String::from_utf8_lossy(&output)
            )
        });
        match packet.header() {
            header if header == TerminalPacketType::TerminalBuffer as u8 => {
                output.extend(
                    TerminalBuffer::decode(packet.payload())
                        .unwrap()
                        .buffer
                        .unwrap(),
                );
            }
            header if header == TerminalPacketType::KeepAlive as u8 => {}
            header => panic!("unexpected server packet {header}"),
        }
        assert!(
            output.len() <= 1024 * 1024,
            "shell output exceeded test bound"
        );
        let text = String::from_utf8_lossy(&output);
        if let Some((_, tail)) = text.split_once(marker) {
            if let Some((value, _)) = tail.split_once(delimiter) {
                return value.to_owned();
            }
        }
    }
}
