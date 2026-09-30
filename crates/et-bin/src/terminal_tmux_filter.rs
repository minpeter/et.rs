//! PTY-only counterpart of upstream `TmuxCcInjectionFilter` (#857).
//! Never decode terminal bytes as text. Only a leading tmux -CC DCS enables
//! filtering; response bodies and all bytes outside control mode are preserved.

const DCS: &[u8] = b"\x1bP1000p";
const ST: &[u8] = b"\x1b\\";

#[derive(Clone, Copy)]
enum AfterLine {
    None,
    Begin,
    End,
    Exit,
}

#[derive(Clone, Copy)]
enum Line {
    Prefix,
    Pass(AfterLine),
    Drop,
}

pub(super) struct TmuxCcFilter {
    control: bool,
    response: bool,
    introducer_line: bool,
    line_start: bool,
    line: Line,
    escape: bool,
    // Only a DCS/ST prefix or a possible %begin/%end/%error/%exit token.
    // At most seven bytes, never an entire notification, response, or wall.
    pending: Vec<u8>,
}

impl Default for TmuxCcFilter {
    fn default() -> Self {
        Self {
            control: false,
            response: false,
            introducer_line: false,
            line_start: true,
            line: Line::Prefix,
            escape: false,
            pending: Vec::with_capacity(DCS.len()),
        }
    }
}

impl TmuxCcFilter {
    pub(super) fn apply(&mut self, chunk: &[u8]) -> Vec<u8> {
        // A wall write can end without a newline before tmux's next write.
        // Do not apply this heuristic inside a %begin response: arbitrary
        // response bytes, including a split '%' or ESC, belong to the client.
        if self.control
            && !self.response
            && matches!(self.line, Line::Drop)
            && (chunk.starts_with(b"%") || chunk.starts_with(b"\x1b"))
        {
            self.line = Line::Prefix;
            self.escape = false;
        }
        let mut output = Vec::with_capacity(chunk.len());
        for &byte in chunk {
            if !self.control {
                if self.line_start && (!self.pending.is_empty() || byte == DCS[0]) {
                    self.pending.push(byte);
                    if self.pending == DCS {
                        output.extend_from_slice(DCS);
                        self.pending.clear();
                        self.control = true;
                        self.introducer_line = true;
                    } else if !DCS.starts_with(&self.pending) {
                        output.append(&mut self.pending);
                        self.line_start = byte == b'\n';
                    }
                } else {
                    output.push(byte);
                    self.line_start = byte == b'\n';
                }
                continue;
            }
            match self.line {
                Line::Prefix => {
                    self.pending.push(byte);
                    if self.pending == ST {
                        output.extend_from_slice(ST);
                        self.leave_control();
                        continue;
                    }
                    if ST.starts_with(&self.pending) || self.pending == b"%" {
                        continue;
                    }
                    self.line = if is_notification(&self.pending) {
                        if byte.is_ascii_whitespace() {
                            let token = &self.pending[..self.pending.len() - 1];
                            Line::Pass(match token {
                                b"%begin" => AfterLine::Begin,
                                b"%end" | b"%error" => AfterLine::End,
                                b"%exit" => AfterLine::Exit,
                                _ => AfterLine::None,
                            })
                        } else if [b"%begin".as_slice(), b"%end", b"%error", b"%exit"]
                            .iter()
                            .any(|token| token.starts_with(&self.pending))
                        {
                            continue;
                        } else {
                            Line::Pass(AfterLine::None)
                        }
                    } else if self.response {
                        Line::Pass(AfterLine::None)
                    } else if self.introducer_line && self.pending == b"\r" {
                        continue;
                    } else if self.introducer_line
                        && (self.pending == b"\n" || self.pending == b"\r\n")
                    {
                        Line::Pass(AfterLine::None)
                    } else {
                        Line::Drop
                    };
                    if matches!(self.line, Line::Pass(_)) {
                        output.append(&mut self.pending);
                    } else {
                        self.pending.clear();
                    }
                }
                Line::Pass(_) => {
                    output.push(byte);
                    // Preserve opaque response bytes. Elsewhere ST ends control
                    // mode even without a newline, including after a fragment.
                    if !self.response && self.escape && byte == b'\\' {
                        self.leave_control();
                        continue;
                    }
                }
                Line::Drop => {
                    if self.escape && byte == b'\\' {
                        output.extend_from_slice(ST);
                        self.leave_control();
                        continue;
                    }
                }
            }
            self.escape = byte == b'\x1b';
            if byte == b'\n' {
                match self.line {
                    Line::Pass(AfterLine::Begin) => self.response = true,
                    Line::Pass(AfterLine::End) => self.response = false,
                    Line::Pass(AfterLine::Exit) => self.leave_control(),
                    _ => {}
                }
                self.line = Line::Prefix;
                self.introducer_line = false;
                self.line_start = true;
            }
        }
        output
    }

    fn leave_control(&mut self) {
        self.control = false;
        self.response = false;
        self.introducer_line = false;
        self.line_start = true;
        self.line = Line::Prefix;
        self.escape = false;
        self.pending.clear();
    }

    pub(super) fn finish(&mut self) -> Vec<u8> {
        if !self.control || self.response || is_notification(&self.pending) {
            std::mem::take(&mut self.pending)
        } else {
            self.pending.clear();
            Vec::new()
        }
    }
}

fn is_notification(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'%') && bytes.get(1).is_some_and(u8::is_ascii_alphabetic)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filtered(chunks: &[&[u8]]) -> Vec<u8> {
        let mut filter = TmuxCcFilter::default();
        let mut output = Vec::new();
        for chunk in chunks {
            output.extend(filter.apply(chunk));
            assert!(filter.pending.len() <= 7);
        }
        output.extend(filter.finish());
        output
    }

    fn assert_every_split(input: &[u8], expected: &[u8]) {
        assert_eq!(filtered(&input.chunks(1).collect::<Vec<_>>()), expected);
        for split in 0..=input.len() {
            assert_eq!(
                filtered(&[&input[..split], &input[split..]]),
                expected,
                "split={split}"
            );
        }
    }

    #[test]
    fn ordinary_binary_prompts_and_embedded_markers_are_byte_exact() {
        for input in [
            b"prompt without newline".as_slice(),
            b"\0\xff\x80\r\n%begin 1 2 3\nBroadcast ordinary text\r\n",
            b"embedded \x1bP1000p%output %1 hi\nordinary\n",
            b"\x1bP1000",
        ] {
            assert_every_split(input, input);
        }
        let mut filter = TmuxCcFilter::default();
        assert_eq!(filter.apply(b"prompt> "), b"prompt> ");
    }

    #[test]
    fn filters_wall_only_in_control_mode_and_keeps_response_bodies() {
        let input = b"%begin shell echo\n\x1bP1000p%begin 1 2 3\n\0\xffresponse%body\r\n%end 1 2 3\nBroadcast message from journald\r\n\x07emergency\r\n\n%output %0 escaped\\012\n%window-add @2\n%begin 4 5 6\nplain error body\n%error 4 5 6\nwall\n%exit\n\x1b\\prompt> \xff";
        let expected = b"%begin shell echo\n\x1bP1000p%begin 1 2 3\n\0\xffresponse%body\r\n%end 1 2 3\n%output %0 escaped\\012\n%window-add @2\n%begin 4 5 6\nplain error body\n%error 4 5 6\n%exit\n\x1b\\prompt> \xff";
        assert_every_split(input, expected);
    }

    #[test]
    fn terminator_unlatches_even_after_wall_and_before_coalesced_prompt() {
        assert_every_split(
            b"\x1bP1000p%output %0 hi\nwall\x1b\\prompt\nordinary",
            b"\x1bP1000p%output %0 hi\n\x1b\\prompt\nordinary",
        );
        assert_eq!(
            filtered(&[
                b"\x1bP1000p%output %0 hi\nwall fragment",
                b"%window-add @1\n",
                b"\x1b",
                b"\\prompt"
            ]),
            b"\x1bP1000p%output %0 hi\n%window-add @1\n\x1b\\prompt"
        );
    }

    #[test]
    fn partial_response_and_notification_are_preserved_at_eof() {
        assert_every_split(
            b"\x1bP1000p%begin 1 2 3\nbody\0\xff",
            b"\x1bP1000p%begin 1 2 3\nbody\0\xff",
        );
        assert_every_split(b"\x1bP1000p%output %0 tail", b"\x1bP1000p%output %0 tail");
        assert_every_split(b"\x1bP1000pwall tail", b"\x1bP1000p");
    }

    #[test]
    fn bare_introducer_and_response_terminator_match_upstream_framing() {
        assert_every_split(
            b"\x1bP1000p\r\nwall\n%begin 1 2 3\nbody\n\x1b\\prompt\n",
            b"\x1bP1000p\r\n%begin 1 2 3\nbody\n\x1b\\prompt\n",
        );
        assert_every_split(
            b"\x1bP1000pwall\n%output %0 hello\n\x1b\\",
            b"\x1bP1000p%output %0 hello\n\x1b\\",
        );
    }

    #[test]
    fn megabyte_wall_without_newline_uses_constant_carry_and_keeps_split_st() {
        let mut filter = TmuxCcFilter::default();
        assert_eq!(
            filter.apply(b"\x1bP1000p%output %0 hi\n"),
            b"\x1bP1000p%output %0 hi\n"
        );
        let capacity = filter.pending.capacity();
        for _ in 0..64 {
            assert!(filter.apply(&[b'w'; 16 * 1024]).is_empty());
            assert!(filter.pending.len() <= 7);
            assert_eq!(filter.pending.capacity(), capacity);
        }
        assert!(filter.apply(b"\x1b").is_empty());
        assert_eq!(filter.apply(b"\\prompt"), b"\x1b\\prompt");
        assert!(filter.finish().is_empty());
    }

    #[test]
    fn megabyte_opaque_response_without_newline_streams_every_chunk_byte_exact() {
        let body = b"\xff\0%body\x1b\\x".repeat(100_000);
        for size in [1, 3, 16 * 1024] {
            let mut filter = TmuxCcFilter::default();
            let prefix = b"\x1bP1000p%begin 1 2 3\n";
            assert_eq!(filter.apply(prefix), prefix);
            let capacity = filter.pending.capacity();
            for chunk in body.chunks(size) {
                assert_eq!(
                    filter.apply(chunk),
                    chunk,
                    "response delivery waited for newline"
                );
                assert!(filter.pending.is_empty());
                assert_eq!(filter.pending.capacity(), capacity);
            }
            assert_eq!(
                filter.apply(b"\n%end 1 2 3\nwall\n%exit\n"),
                b"\n%end 1 2 3\n%exit\n"
            );
            assert!(filter.finish().is_empty());
        }
    }

    #[test]
    fn long_notifications_and_keyword_lookalikes_stream_without_false_transitions() {
        let body = vec![b'x'; 1024 * 1024];
        for prefix in [
            b"\x1bP1000p%output %0 ".as_slice(),
            b"\x1bP1000p%extended-output %0 0 : ",
            b"\x1bP1000p%begin",
        ] {
            let mut filter = TmuxCcFilter::default();
            let capacity = filter.pending.capacity();
            let mut output = filter.apply(prefix);
            for chunk in body.chunks(16 * 1024) {
                let forwarded = filter.apply(chunk);
                assert!(
                    forwarded.len() >= chunk.len(),
                    "notification delivery waited for newline"
                );
                output.extend(forwarded);
                assert!(filter.pending.len() <= 7);
                assert_eq!(filter.pending.capacity(), capacity);
            }
            assert_eq!(output, [prefix, &body].concat());
            assert_eq!(filter.apply(b"\nwall\n%exit\nprompt"), b"\n%exit\nprompt");
            assert!(filter.finish().is_empty());
        }
        assert_every_split(
            b"\x1bP1000p%begin 1 2 3\n%endless\nopaque\n%errorful\nmore\n%exitmore\nbody\n%error 1 2 3\nwall\n%exit\n",
            b"\x1bP1000p%begin 1 2 3\n%endless\nopaque\n%errorful\nmore\n%exitmore\nbody\n%error 1 2 3\n%exit\n",
        );
    }
}
