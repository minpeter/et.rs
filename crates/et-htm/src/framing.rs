//! Bounded tmux control command framing. IPC carries no terminal DCS markers.

use std::io;

pub const MAX_COMMAND: usize = 64 * 1024;
pub const MAX_QUEUE: usize = 256 * 1024;

#[derive(Default)]
pub struct Lines {
    pending: Vec<u8>,
    cr: bool,
}

impl Lines {
    pub fn feed(&mut self, bytes: &[u8]) -> io::Result<Vec<String>> {
        let mut lines = Vec::new();
        for &byte in bytes {
            if byte == b'\n' && self.cr {
                self.cr = false;
                continue;
            }
            self.cr = byte == b'\r';
            if matches!(byte, b'\r' | b'\n') {
                lines.push(
                    String::from_utf8(std::mem::take(&mut self.pending)).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "command is not UTF-8")
                    })?,
                );
            } else {
                if self.pending.len() == MAX_COMMAND {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "command too long",
                    ));
                }
                self.pending.push(byte);
            }
        }
        Ok(lines)
    }
}

/// Match canonical's separate command-list and argument unescaping passes.
pub fn parse(line: &str) -> Result<Vec<Vec<String>>, String> {
    let mut commands = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut separated = false;
    for ch in line.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
        } else if quote == Some(ch) {
            quote = None;
            word.push(ch);
        } else if quote.is_some() {
            word.push(ch);
        } else if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            word.push(ch);
        } else if ch == ';' {
            separated = true;
            if !word.trim_ascii().is_empty() {
                commands.push(word.trim_ascii().to_owned());
            }
            word.clear();
        } else {
            word.push(ch);
        }
    }
    if !separated {
        commands = vec![line.to_owned()];
    } else if !word.trim_ascii().is_empty() {
        commands.push(word.trim_ascii().to_owned());
    }
    if commands.is_empty() {
        commands.push(line.to_owned());
    }
    Ok(commands
        .into_iter()
        .map(|command| {
            let mut words = Vec::new();
            let mut word = String::new();
            let mut quote = None;
            let mut escaped = false;
            for ch in command.chars() {
                if escaped {
                    word.push(ch);
                    escaped = false;
                } else if ch == '\\' && quote != Some('\'') {
                    escaped = true;
                } else if quote == Some(ch) {
                    quote = None;
                } else if quote.is_some() {
                    word.push(ch);
                } else if matches!(ch, '\'' | '"') {
                    quote = Some(ch);
                } else if ch.is_ascii_whitespace() {
                    if !word.is_empty() {
                        words.push(std::mem::take(&mut word));
                    }
                } else {
                    word.push(ch);
                }
            }
            if !word.is_empty() {
                words.push(word);
            }
            words
        })
        .collect())
}

pub fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &byte in bytes {
        if byte < 32 || byte == b'\\' {
            out.extend_from_slice(&[
                b'\\',
                b'0' + (byte >> 6),
                b'0' + ((byte >> 3) & 7),
                b'0' + (byte & 7),
            ]);
        } else {
            out.push(byte);
        }
    }
    out
}

pub fn reply(sequence: u64, flags: u8, result: Result<Vec<u8>, String>) -> Vec<u8> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut out = format!("%begin {time} {sequence} {flags}\n").into_bytes();
    let (body, end) = match result {
        Ok(body) => (body, "end"),
        Err(error) => (escape(error.as_bytes()), "error"),
    };
    out.extend_from_slice(&body);
    if !body.is_empty() && !body.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(format!("%{end} {time} {sequence} {flags}\n").as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_crlf_and_bound() {
        let mut lines = Lines::default();
        assert_eq!(lines.feed(b"list-panes\r").unwrap(), ["list-panes"]);
        assert_eq!(lines.feed(b"\nfoo\n\n").unwrap(), ["foo", ""]);
        assert!(lines.feed(&vec![b'x'; MAX_COMMAND]).unwrap().is_empty());
        assert!(lines.feed(b"x").is_err());
    }
    #[test]
    fn quoting_and_lists() {
        assert_eq!(
            parse("send -l 'a;b' \"\"; display 'x y'").unwrap(),
            vec![vec!["send", "-l", "a;b"], vec!["display", "x y"]]
        );
        assert_eq!(parse("send 'x").unwrap(), vec![vec!["send", "x"]]);
        assert_eq!(escape(b"a\0\n\x1b\\\xff"), b"a\\000\\012\\033\\134\xff");
    }
}
