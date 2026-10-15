//! Interrupt recognition and loss-aware filtering of unsent terminal bytes.

pub const FLUSH_THRESHOLD: usize = 64 * 1024;

/// Client input may split a tmux control-mode command across transport packets.
#[derive(Default)]
pub struct InterruptInput {
    carry: Vec<u8>,
    overlong: bool,
}

impl InterruptInput {
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        let mut interrupt = bytes.iter().any(|byte| matches!(byte, 3 | 26 | 28));
        for &byte in bytes {
            if matches!(byte, b'\n' | b'\r') {
                interrupt |= !self.overlong && command_requests_interrupt(&self.carry);
                self.carry.clear();
                self.overlong = false;
            } else if !self.overlong {
                if self.carry.len() == 4096 {
                    self.carry.clear();
                    self.overlong = true;
                } else {
                    self.carry.push(byte);
                }
            }
        }
        interrupt || (!self.overlong && command_requests_interrupt(&self.carry))
    }
}

fn command_requests_interrupt(bytes: &[u8]) -> bool {
    let Ok(line) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut tokens = line.split_ascii_whitespace();
    if !matches!(tokens.next(), Some("send-keys" | "send")) {
        return false;
    }
    let mut hex = false;
    let mut literal = false;
    while let Some(token) = tokens.next() {
        if let Some(flags) = token.strip_prefix('-') {
            if flags.contains('H') {
                hex = true;
                literal = false;
            } else if flags.contains('l') {
                literal = true;
                hex = false;
            }
            if flags.chars().any(|flag| matches!(flag, 't' | 'c' | 'N')) {
                tokens.next();
            }
            continue;
        }
        if literal {
            continue;
        }
        let number = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"));
        if hex || number.is_some() {
            let number = number.unwrap_or(token);
            if (1..=2).contains(&number.len())
                && matches!(u8::from_str_radix(number, 16), Ok(3 | 26 | 28))
            {
                return true;
            }
        } else if ["C-c", "^C", "C-z", "^Z", "C-\\", "C-|"]
            .iter()
            .any(|key| token.eq_ignore_ascii_case(key))
        {
            return true;
        }
    }
    false
}

const TMUX_DCS: &[u8] = b"\x1bP1000p";

fn is_tmux_control_token(token: &[u8]) -> bool {
    let token = token.strip_prefix(TMUX_DCS).unwrap_or(token);
    matches!(
        token,
        b"%begin"
            | b"%end"
            | b"%error"
            | b"%output"
            | b"%extended-output"
            | b"%exit"
            | b"%layout-change"
            | b"%window-add"
            | b"%window-close"
            | b"%window-renamed"
            | b"%pane-mode-changed"
            | b"%window-pane-changed"
            | b"%unlinked-window-add"
            | b"%unlinked-window-close"
            | b"%unlinked-window-renamed"
            | b"%session-changed"
            | b"%session-renamed"
            | b"%session-window-changed"
            | b"%sessions-changed"
            | b"%client-detached"
            | b"%client-session-changed"
            | b"%subscription-changed"
            | b"%message"
            | b"%config-error"
            | b"%continue"
            | b"%pause"
            | b"%paste-buffer-changed"
            | b"%paste-buffer-deleted"
    )
}

fn line_first_token(line: &[u8]) -> &[u8] {
    let token = line
        .split(|byte| byte.is_ascii_whitespace())
        .next()
        .unwrap_or_default();
    token.strip_prefix(TMUX_DCS).unwrap_or(token)
}

/// State of the prefix already handed to the transport/console writer.
/// Never truncate a line whose prefix a tmux client has already received.
#[derive(Clone, Default)]
pub struct TerminalStream {
    token: Vec<u8>,
    token_done: bool,
    midline: bool,
    control: bool,
    block: bool,
    escape: bool,
}

impl TerminalStream {
    pub fn observe(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.control && !self.block && self.escape && byte == b'\\' {
                self.control = false;
                self.token.clear();
                self.token_done = false;
                self.midline = false;
                self.escape = false;
                continue;
            }
            self.escape = byte == b'\x1b';
            if byte == b'\n' {
                let token = self.token.strip_prefix(TMUX_DCS).unwrap_or(&self.token);
                if is_tmux_control_token(token) {
                    self.control = true;
                }
                match token {
                    b"%begin" => self.block = true,
                    b"%end" | b"%error" => self.block = false,
                    _ => {}
                }
                self.token.clear();
                self.token_done = false;
                self.midline = false;
            } else {
                self.midline = true;
                if byte.is_ascii_whitespace() {
                    if !self.token_done && is_tmux_control_token(&self.token) {
                        self.control = true;
                    }
                    self.token_done = true;
                }
                if !self.token_done && self.token.len() < 32 {
                    self.token.push(byte);
                    if self.token == TMUX_DCS {
                        self.control = true;
                        self.token.clear();
                        self.midline = false;
                    }
                }
            }
        }
    }

    /// Filter a contiguous unsent suffix; the caller owns any trailing skip.
    pub fn filter(&self, bytes: &[u8]) -> FilteredOutput {
        self.partition(bytes, false)
    }

    /// Make command responses available before pane floods without losing bytes.
    pub fn promote_control(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if !self.control
            && !bytes
                .split(|byte| *byte == b'\n')
                .any(|line| is_tmux_control_token(line_first_token(line)))
        {
            return None;
        }
        // The incomplete suffix is an ordering barrier, including response
        // blocks whose lines are complete but whose %end has not arrived yet.
        let mut observed = self.clone();
        let mut offset = 0;
        let mut complete = 0;
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            observed.observe(line);
            offset += line.len();
            if line.ends_with(b"\n") && !observed.block {
                complete = offset;
            }
        }
        let mut result = self.partition(&bytes[..complete], true);
        if result.kept.is_empty() || result.droppable.is_empty() {
            return None;
        }
        result.kept.extend(result.droppable);
        result.kept.extend_from_slice(&bytes[complete..]);
        Some(result.kept)
    }
    fn partition(&self, bytes: &[u8], retain_droppable: bool) -> FilteredOutput {
        let mut state = self.clone();
        let mut kept = Vec::new();
        let mut droppable = Vec::new();
        let mut skip_until_newline = false;
        // A control-mode line that was already partly sent must be finished,
        // including later non-`%` lines, or the client sees a fragment and
        // leaves tmux mode. Walk the backlog in a loop: the server decides
        // how many lines are buffered, so this must not recurse per line.
        let mut index = 0;
        if state.control
            && state.midline
            && !bytes.is_empty()
            && bytes[0] != b'%'
            && bytes[0] != b'\n'
        {
            while index < bytes.len() && bytes[index] != b'%' && bytes[index] != b'\n' {
                match bytes[index..].iter().position(|byte| *byte == b'\n') {
                    None => {
                        kept.extend_from_slice(&bytes[index..]);
                        state.observe(&bytes[index..]);
                        index = bytes.len();
                    }
                    Some(newline) => {
                        let end = index + newline + 1;
                        kept.extend_from_slice(&bytes[index..end]);
                        state.observe(&bytes[index..end]);
                        index = end;
                    }
                }
            }
        }
        for line in bytes[index..].split_inclusive(|byte| *byte == b'\n') {
            let token = line_first_token(line);
            let pane = matches!(token, b"%output" | b"%extended-output");
            let control_token =
                is_tmux_control_token(token) || (state.control && token.starts_with(b"%"));
            let dcs_terminator = state.control
                && !state.block
                && (token.starts_with(b"\x1b\\") || (state.escape && line.starts_with(b"\\")));
            let keep = state.block
                || (state.control && state.midline)
                || (control_token && !pane)
                || dcs_terminator
                || (state.control && token.is_empty());
            if keep {
                kept.extend_from_slice(line);
            } else {
                if retain_droppable {
                    droppable.extend_from_slice(line);
                }
                if pane && !line.ends_with(b"\n") {
                    skip_until_newline = true;
                }
            }
            state.observe(line);
        }
        FilteredOutput {
            dropped: bytes.len() - kept.len(),
            kept,
            skip_until_newline,
            droppable,
        }
    }
}

pub struct FilteredOutput {
    pub kept: Vec<u8>,
    pub dropped: usize,
    pub skip_until_newline: bool,
    droppable: Vec<u8>,
}
