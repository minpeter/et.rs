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

    fn push_terminal(&mut self, mut packet: Packet) -> Result<(), QueuePushError> {
        if self.skip_until_newline {
            if let Ok(mut message) = TerminalBuffer::decode(packet.payload()) {
                if let Some(bytes) = &mut message.buffer {
                    let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') else {
                        return Ok(());
                    };
                    self.skip_until_newline = false;
                    bytes.drain(..=newline);
                    if bytes.is_empty() {
                        return Ok(());
                    }
                    packet = Packet::new(packet.header(), message.encode_to_vec());
                }
            }
        }
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
        self.terminal_bytes += wanted;
        self.terminal_packets += 1;
        self.terminal.push_back(packet);
        self.promotion_pending = true;
        Ok(())
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
            if let Ok(message) = TerminalBuffer::decode(packet.payload()) {
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

    pub fn is_empty(&self) -> bool {
        self.terminal.is_empty() && self.control.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.terminal_bytes + self.control_bytes
    }

    /// Drop only unsequenced terminal bytes. In-flight reservations and the
    /// independent control lane are untouched, so replay stays contiguous.
    pub fn flush_terminal_on_interrupt(&mut self) -> usize {
        let mut bytes = Vec::new();
        let mut lengths = Vec::new();
        for packet in &self.terminal {
            // An opaque/malformed packet is not permission to discard data.
            let Ok(message) = TerminalBuffer::decode(packet.payload()) else {
                return 0;
            };
            let Some(body) = message.buffer else { return 0 };
            lengths.push(body.len());
            bytes.extend(body);
        }
        if bytes.len() < crate::output_interrupt::FLUSH_THRESHOLD {
            return 0;
        }
        let result = self.stream.filter(&bytes);
        self.skip_until_newline |= result.skip_until_newline;
        let mut remaining = result.kept.as_slice();
        let mut retained = VecDeque::new();
        for length in lengths {
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
        for packet in &self.terminal {
            let Ok(message) = TerminalBuffer::decode(packet.payload()) else {
                return;
            };
            let Some(body) = message.buffer else { return };
            lengths.push(body.len());
            bytes.extend(body);
        }
        let Some(promoted) = self.stream.promote_control(&bytes) else {
            return;
        };
        let mut remaining = promoted.as_slice();
        for (packet, length) in self.terminal.iter_mut().zip(lengths) {
            self.terminal_bytes -= packet_cost(packet);
            let body = TerminalBuffer {
                buffer: Some(remaining[..length].to_vec()),
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
    let mut low = 0usize;
    let mut high = bytes.len();
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let encoded = TerminalBuffer {
            buffer: Some(bytes[bytes.len() - middle..].to_vec()),
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
    }
    .encode_to_vec();
    Ok(Packet::new(packet.header(), encoded))
}

pub fn is_terminal_output(packet: &Packet) -> bool {
    packet.header() == TerminalPacketType::TerminalBuffer as u8
}
