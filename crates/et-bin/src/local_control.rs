//! Canonical #819 byte cursors, transcript record cursors and tombstones.
use std::collections::VecDeque;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use et_core::proto::TerminalInfo;
use prost::Message;

use crate::local_ipc::{control_frame, invalid};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct History {
    chunks: VecDeque<(u8, Vec<u8>)>,
    base: i64,
    head: i64,
    retained: usize,
    capacity: usize,
    records: bool,
}
impl History {
    pub fn new(capacity: usize, records: bool) -> Self {
        Self {
            chunks: VecDeque::new(),
            base: 0,
            head: 0,
            retained: 0,
            capacity,
            records,
        }
    }
    pub fn append(&mut self, direction: u8, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.head += if self.records { 1 } else { bytes.len() as i64 };
        self.retained += bytes.len();
        self.chunks.push_back((direction, bytes.to_vec()));
        while self.retained > self.capacity && self.chunks.len() > 1 {
            let (_, bytes) = self.chunks.pop_front().unwrap();
            self.retained -= bytes.len();
            self.base += if self.records { 1 } else { bytes.len() as i64 };
        }
    }
    pub fn read(&self, cursor: i64) -> Vec<u8> {
        let cursor = if cursor < 0 { self.base } else { cursor };
        let mut output = self.head.to_be_bytes().to_vec();
        output.push(u8::from(cursor < self.base));
        let cursor = cursor.max(self.base);
        let mut start = self.base;
        for (direction, bytes) in &self.chunks {
            let end = start + if self.records { 1 } else { bytes.len() as i64 };
            if cursor < end {
                if self.records {
                    output.push(*direction);
                    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                    output.extend_from_slice(bytes);
                } else {
                    output
                        .extend_from_slice(&bytes[cursor.saturating_sub(start).max(0) as usize..]);
                }
            }
            start = end;
        }
        output
    }
}

pub struct Control {
    output: History,
    transcript: History,
    pub size: TerminalInfo,
    created: u64,
    activity: u64,
    host: String,
}
pub enum Action {
    None,
    Input(Vec<u8>),
    Resize(Vec<u8>),
    Kill,
}
impl Control {
    pub fn new(host: &str) -> Self {
        Self {
            output: History::new(2 * 1024 * 1024, false),
            transcript: History::new(512 * 1024, true),
            size: TerminalInfo {
                row: Some(24),
                column: Some(132),
                ..Default::default()
            },
            created: now(),
            activity: now(),
            host: host.replace(['\r', '\n'], ""),
        }
    }
    pub fn output(&mut self, bytes: &[u8]) {
        self.output.append(b'<', bytes);
        self.transcript.append(b'<', bytes);
        self.activity = now();
    }
    pub fn request(
        &mut self,
        opcode: u8,
        payload: &[u8],
        connected: bool,
    ) -> io::Result<(Vec<u8>, Action)> {
        let (code, body, action) = match opcode {
            1 | 7 => {
                self.transcript.append(b'>', if opcode == 7 { b"<secret>" } else { payload });
                self.activity = now();
                (64, Vec::new(), Action::Input(payload.to_vec()))
            }
            2 => {
                let size = TerminalInfo::decode(payload).map_err(|_| invalid("bad TerminalInfo"))?;
                // A resize must never smuggle a session-kill command or credentials.
                self.size = TerminalInfo { row: size.row, column: size.column, width: size.width, height: size.height, ..Default::default() };
                (64, Vec::new(), Action::Resize(self.size.encode_to_vec()))
            }
            3 | 6 => {
                let cursor = i64::from_be_bytes(payload.try_into().map_err(|_| invalid("cursor must contain eight bytes"))?);
                let (code, body) = if opcode == 3 { (66, self.output.read(cursor)) } else { (68, self.transcript.read(cursor)) };
                (code, body, Action::None)
            }
            4 if payload.is_empty() => (67, format!("alive=1\nconnected={}\nhost={}\npid={}\nrows={}\ncols={}\nheadCursor={}\ncreated={}\nlastActivity={}\n", u8::from(connected), self.host, std::process::id(), self.size.row.unwrap_or(24), self.size.column.unwrap_or(132), self.output.head, self.created, self.activity).into_bytes(), Action::None),
            5 if payload.is_empty() => (64, Vec::new(), Action::Kill),
            _ => return Err(invalid("unknown opcode or invalid payload")),
        };
        Ok((control_frame(code, &body), action))
    }
}

pub fn control_dir() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| invalid("HOME is not set"))?;
    let root = PathBuf::from(home).join(".et");
    crate::local_ipc::private_dir(&root)?;
    let directory = root.join("control");
    crate::local_ipc::private_dir(&directory)?;
    Ok(directory)
}
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}
pub fn tombstone(name: &str, reason: Option<&str>) -> io::Result<()> {
    if !valid_name(name) {
        return Err(invalid("invalid control session name"));
    }
    write_tombstone(&control_dir()?.join(format!("{name}.gone")), reason)
}
pub fn write_tombstone(path: &Path, reason: Option<&str>) -> io::Result<()> {
    // Never follow a stale/symlink tombstone. The enclosing directory is private.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(reason) = reason {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        writeln!(file, "{} {}", now(), reason.replace(['\r', '\n'], " "))?;
    }
    Ok(())
}
