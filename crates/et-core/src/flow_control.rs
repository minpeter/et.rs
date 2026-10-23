//! Bounded, fair output lanes used by opt-in flow-control sessions.

use std::collections::VecDeque;

use prost::Message;

use crate::packet::Packet;
use crate::proto::{TerminalBuffer, TerminalPacketType};

const FRAME_BYTES: usize = std::mem::size_of::<u32>();
pub(crate) const MAX_PACKETS_PER_LANE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowControlMode {
    Backpressure,
    Discard,
}

#[derive(Debug, PartialEq, Eq)]
pub enum QueuePushError {
    Full(Packet),
    Oversized(Packet),
}

/// Lane that carries a packet; see [`is_terminal_output`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputLane {
    Terminal,
    Control,
}

pub struct OutputQueue {
    mode: FlowControlMode,
    limit: usize,
    terminal_bytes: usize,
    control_bytes: usize,
    terminal_packets: usize,
    control_packets: usize,
    terminal: VecDeque<Packet>,
    control: VecDeque<Packet>,
    prefer_terminal: bool,
    stream: crate::output_interrupt::TerminalStream,
    before_take: Option<crate::output_interrupt::TerminalStream>,
    skip_until_newline: bool,
    promotion_pending: bool,
}

impl OutputQueue {
    pub fn new(mode: FlowControlMode, limit: usize) -> Self {
        Self {
            mode,
            limit,
            terminal_bytes: 0,
            control_bytes: 0,
            terminal_packets: 0,
            control_packets: 0,
            terminal: VecDeque::new(),
            control: VecDeque::new(),
            prefer_terminal: true,
            stream: crate::output_interrupt::TerminalStream::default(),
            before_take: None,
            skip_until_newline: false,
            promotion_pending: false,
        }
    }

    pub fn push(&mut self, packet: Packet) -> Result<(), QueuePushError> {
        if is_terminal_output(&packet) {
            self.push_terminal(packet)
        } else {
            self.push_control(packet)
        }
    }

    fn push_terminal(&mut self, packet: Packet) -> Result<(), QueuePushError> {
        let Some(mut packet) = self.skip_through_newline(packet) else {
            return Ok(());
        };
        if packet_cost(&packet) > self.limit {
            if self.mode == FlowControlMode::Backpressure {
                return Err(QueuePushError::Oversized(packet));
            }
            packet = truncate_terminal(packet, self.limit).map_err(QueuePushError::Oversized)?;
        }
        let wanted = packet_cost(&packet);
        if self.mode == FlowControlMode::Backpressure
            && (self.terminal_bytes.saturating_add(wanted) > self.limit
                || self.terminal_packets >= MAX_PACKETS_PER_LANE)
        {
            return Err(QueuePushError::Full(packet));
        }
        while self.terminal_bytes.saturating_add(wanted) > self.limit
            || self.terminal_packets >= MAX_PACKETS_PER_LANE
        {
            let Some(removed) = self.terminal.pop_front() else {
                return Err(QueuePushError::Full(packet));
            };
            self.terminal_bytes -= packet_cost(&removed);
            self.terminal_packets -= 1;
        }
        self.append_terminal(packet);
        Ok(())
    }

    /// After an interrupt flush cut a line short, drop terminal output
    /// through the next newline. `None` when nothing of `packet` remains.
    fn skip_through_newline(&mut self, packet: Packet) -> Option<Packet> {
        if !self.skip_until_newline {
            return Some(packet);
        }
        let Ok(mut message) = TerminalBuffer::decode(packet.payload()) else {
            return Some(packet);
        };
        let Some(bytes) = &mut message.buffer else {
            return Some(packet);
        };
        let newline = bytes.iter().position(|byte| *byte == b'\n')?;
        self.skip_until_newline = false;
        bytes.drain(..=newline);
        if bytes.is_empty() {
            return None;
        }
        Some(Packet::new(packet.header(), message.encode_to_vec()))
    }

    /// Admit terminal output without the lane bound.
    fn append_terminal(&mut self, packet: Packet) {
        self.terminal_bytes += packet_cost(&packet);
        self.terminal_packets += 1;
        let may_contain_control =
            if let Some((bytes, _)) = crate::packet::decode_terminal_buffer(packet.payload()) {
                self.stream.may_contain_control(bytes)
            } else if let Ok(message) = TerminalBuffer::decode(packet.payload()) {
                self.stream
                    .may_contain_control(message.buffer.as_deref().unwrap_or_default())
            } else {
                true
            };
        if may_contain_control {
            self.promotion_pending = true;
        }
        self.terminal.push_back(packet);
    }

    fn push_control(&mut self, packet: Packet) -> Result<(), QueuePushError> {
        let wanted = packet_cost(&packet);
        if wanted > self.limit {
            return Err(QueuePushError::Oversized(packet));
        }
        if self.control_bytes.saturating_add(wanted) > self.limit
            || self.control_packets >= MAX_PACKETS_PER_LANE
        {
            return Err(QueuePushError::Full(packet));
        }
        self.control_bytes += wanted;
        self.control_packets += 1;
        self.control.push_back(packet);
        Ok(())
    }

    pub fn take(&mut self) -> Option<Packet> {
        self.promote_terminal_control();
        let packet = if self.prefer_terminal {
            self.terminal
                .pop_front()
                .or_else(|| self.control.pop_front())
        } else {
            self.control
                .pop_front()
                .or_else(|| self.terminal.pop_front())
        }?;
        self.prefer_terminal = !self.prefer_terminal;
        if is_terminal_output(&packet) {
            self.before_take = Some(self.stream.clone());
            if let Some((bytes, _)) = crate::packet::decode_terminal_buffer(packet.payload()) {
                self.stream.observe(bytes);
            } else if let Ok(message) = TerminalBuffer::decode(packet.payload()) {
                self.stream
                    .observe(message.buffer.as_deref().unwrap_or_default());
            }
        }
        Some(packet)
    }

    pub fn complete(&mut self, packet: &Packet) {
        if is_terminal_output(packet) {
            self.terminal_bytes -= packet_cost(packet);
            self.terminal_packets -= 1;
        } else {
            self.control_bytes -= packet_cost(packet);
            self.control_packets -= 1;
        }
    }

    pub fn restore_front(&mut self, packet: Packet) {
        if is_terminal_output(&packet) {
            if let Some(stream) = self.before_take.take() {
                self.stream = stream;
            }
            self.terminal.push_front(packet);
        } else {
            self.control.push_front(packet);
        }
    }

    pub fn pop(&mut self) -> Option<Packet> {
        let packet = self.take()?;
        self.complete(&packet);
        Some(packet)
    }

    pub fn can_accept_terminal(&self, payload_bytes: usize) -> bool {
        let wanted = payload_bytes.saturating_add(crate::packet::HEADER_LEN + FRAME_BYTES);
        match self.mode {
            FlowControlMode::Backpressure => {
                self.terminal_packets < MAX_PACKETS_PER_LANE
                    && self.terminal_bytes.saturating_add(wanted) <= self.limit
            }
            FlowControlMode::Discard => wanted <= self.limit,
        }
    }

    /// Whether a producer refused by `lane` should be woken: the lane has
    /// `free_bytes` of unused byte budget and at most half of its packet slots
    /// occupied. Resuming only at this hysteresis lets a saturated producer
    /// refill a batch instead of one packet per completion, whether the lane
    /// is byte-bound or packet-count-bound. Discard-mode terminal output
    /// evicts instead of refusing, so it resumes whenever `free_bytes` fits.
    pub fn can_resume(&self, lane: OutputLane, free_bytes: usize) -> bool {
        let (bytes, packets) = match lane {
            OutputLane::Terminal if self.mode == FlowControlMode::Discard => {
                return free_bytes <= self.limit;
            }
            OutputLane::Terminal => (self.terminal_bytes, self.terminal_packets),
            OutputLane::Control => (self.control_bytes, self.control_packets),
        };
        packets <= MAX_PACKETS_PER_LANE / 2 && bytes.saturating_add(free_bytes) <= self.limit
    }

    pub fn is_empty(&self) -> bool {
        self.terminal.is_empty() && self.control.is_empty()
    }

    /// Queued terminal-lane bytes, framing included.
    pub fn terminal_bytes(&self) -> usize {
        self.terminal_bytes
    }

    pub fn bytes(&self) -> usize {
        self.terminal_bytes + self.control_bytes
    }

    /// Drop only unsequenced terminal bytes, once at least
    /// [`crate::output_interrupt::FLUSH_THRESHOLD`] of them is queued
    /// (upstream `WriteBuffer::flushIfLarge`). In-flight reservations and the
    /// independent control lane are untouched, so replay stays contiguous.
    pub fn flush_terminal_on_interrupt(&mut self) -> usize {
        self.filter_terminal(crate::output_interrupt::FLUSH_THRESHOLD)
    }

    /// Queue terminal output the producer had already emitted when an
    /// interrupt flush dropped data, then drop every droppable queued
    /// terminal byte regardless of size: upstream `drainDiscardReadableBytes`
    /// enqueues into the `WriteBuffer` and calls `filterDroppable`. The lane
    /// bound is not applied; the filter leaves only bytes a tmux control
    /// client still needs.
    pub fn discard_drained_terminal(&mut self, drained: impl IntoIterator<Item = Packet>) -> usize {
        let mut appended = false;
        for packet in drained {
            debug_assert!(is_terminal_output(&packet));
            appended = true;
            if let Some(packet) = self.skip_through_newline(packet) {
                self.append_terminal(packet);
            }
        }
        if !appended {
            return 0;
        }
        self.filter_terminal(0)
    }

    fn filter_terminal(&mut self, threshold: usize) -> usize {
        let mut bytes = Vec::new();
        let mut lengths = Vec::new();
        let mut stderr_flags = Vec::new();
        for packet in &self.terminal {
            // An opaque/malformed packet is not permission to discard data.
            let Ok(message) = TerminalBuffer::decode(packet.payload()) else {
                return 0;
            };
            let Some(body) = message.buffer else { return 0 };
            lengths.push(body.len());
            stderr_flags.push(message.is_stderr);
            bytes.extend(body);
        }
        if bytes.is_empty() || bytes.len() < threshold {
            return 0;
        }
        let result = self.stream.filter(&bytes);
        self.skip_until_newline |= result.skip_until_newline;
        let mut remaining = result.kept.as_slice();
        let mut retained = VecDeque::new();
        for (index, length) in lengths.into_iter().enumerate() {
            let Some(packet) = self.terminal.pop_front() else {
                break;
            };
            self.terminal_bytes -= packet_cost(&packet);
            self.terminal_packets -= 1;
            let count = remaining.len().min(length);
            if count == 0 {
                continue;
            }
            let body = TerminalBuffer {
                buffer: Some(remaining[..count].to_vec()),
                is_stderr: stderr_flags.get(index).copied().flatten(),
            };
            let packet = Packet::new(packet.header(), body.encode_to_vec());
            self.terminal_bytes += packet_cost(&packet);
            self.terminal_packets += 1;
            retained.push_back(packet);
            remaining = &remaining[count..];
        }
        self.terminal = retained;
        result.dropped
    }

    fn promote_terminal_control(&mut self) {
        if !self.promotion_pending || self.terminal_bytes < crate::output_interrupt::FLUSH_THRESHOLD
        {
            return;
        }
        self.promotion_pending = false;
        let mut bytes = Vec::new();
        let mut lengths = Vec::new();
        let mut stderr_flags = Vec::new();
        for packet in &self.terminal {
            let Ok(message) = TerminalBuffer::decode(packet.payload()) else {
                return;
            };
            let Some(body) = message.buffer else { return };
            lengths.push(body.len());
            stderr_flags.push(message.is_stderr);
            bytes.extend(body);
        }
        let Some(promoted) = self.stream.promote_control(&bytes) else {
            return;
        };
        let mut remaining = promoted.as_slice();
        for (index, (packet, length)) in self.terminal.iter_mut().zip(lengths).enumerate() {
            self.terminal_bytes -= packet_cost(packet);
            let body = TerminalBuffer {
                buffer: Some(remaining[..length].to_vec()),
                is_stderr: stderr_flags.get(index).copied().flatten(),
            };
            *packet = Packet::new(packet.header(), body.encode_to_vec());
            self.terminal_bytes += packet_cost(packet);
            remaining = &remaining[length..];
        }
    }

    /// Adjust admission after a connection state change without evicting data.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

fn packet_cost(packet: &Packet) -> usize {
    packet.wire_len().saturating_add(FRAME_BYTES)
}

fn truncate_terminal(packet: Packet, limit: usize) -> Result<Packet, Packet> {
    let Ok(message) = TerminalBuffer::decode(packet.payload()) else {
        return Err(packet);
    };
    let Some(bytes) = message.buffer else {
        return Err(packet);
    };
    let is_stderr = message.is_stderr;
    let mut low = 0usize;
    let mut high = bytes.len();
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let encoded = TerminalBuffer {
            buffer: Some(bytes[bytes.len() - middle..].to_vec()),
            is_stderr,
        }
        .encode_to_vec();
        if encoded
            .len()
            .saturating_add(crate::packet::HEADER_LEN + FRAME_BYTES)
            <= limit
        {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let encoded = TerminalBuffer {
        buffer: Some(bytes[bytes.len() - low..].to_vec()),
        is_stderr,
    }
    .encode_to_vec();
    Ok(Packet::new(packet.header(), encoded))
}

pub fn is_terminal_output(packet: &Packet) -> bool {
    packet.header() == TerminalPacketType::TerminalBuffer as u8
}
