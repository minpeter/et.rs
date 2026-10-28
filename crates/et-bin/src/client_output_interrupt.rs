//! Filtering never touches the chunk already owned by the console writer.

use std::io;

use super::ConsoleOutput;

impl ConsoleOutput {
    pub(crate) fn interrupt(&self) -> io::Result<usize> {
        let Some(shared) = &self.shared else {
            return Ok(0);
        };
        let mut state = shared.lock()?;
        // Upstream `TerminalClient::run` filters `consoleOut` on every
        // interrupt (`filterDroppable`), whatever its size.
        let mut bytes = Vec::with_capacity(state.bytes);
        for entry in &state.queue {
            bytes.extend_from_slice(entry.unsent());
        }
        // The stream has observed exactly the bytes already written, so a
        // partly written direct entry is filtered from its unsent remainder.
        let filtered = state.stream.filter(&bytes);
        state.skip_until_newline |= filtered.skip_until_newline;
        let mut remaining = filtered.kept.as_slice();
        state.queue.retain_mut(|entry| {
            let count = remaining.len().min(entry.unsent().len());
            if count == 0 && entry.sent == 0 {
                return false;
            }
            entry.bytes.truncate(entry.sent);
            entry.bytes.extend_from_slice(&remaining[..count]);
            remaining = &remaining[count..];
            true
        });
        state.bytes = filtered.kept.len();
        // A partly written entry whose remainder was dropped is complete.
        #[cfg(target_os = "linux")]
        state.retire_delivered();
        drop(state);
        shared.wake.notify_all();
        Ok(filtered.dropped)
    }
}

/// Server output that already sat in this client's socket when the user
/// typed an interrupt: the server sent it before it could see the
/// interrupt, so it is filtered like the console queue instead of painted.
///
/// This applies upstream's server-side `drainDiscardReadableBytes`
/// (`TerminalInterruptDrain.hpp`: drain what is readable now, filter its
/// `TERMINAL_BUFFER` bytes with `filterDroppable`, keep every other packet)
/// to the client's socket. Upstream `TerminalClient::run` only filters
/// `consoleOut` and skips one server read; its output loop is slow enough
/// that little else is queued, while a fast session can hold a few hundred
/// KB of flood in the socket receive queue. Like `WriteBuffer::flushIfLarge`
/// this needs a backlog of at least
/// [`et_core::output_interrupt::FLUSH_THRESHOLD`]. It covers no more than
/// the bytes queued at the interrupt, and packets the reader had already
/// buffered count against it first, so nothing the server sends after it
/// handles the interrupt is filtered.
#[cfg(any(unix, test))]
#[derive(Default)]
pub(crate) struct StaleOutput {
    bytes: usize,
}

#[cfg(any(unix, test))]
impl StaleOutput {
    /// An interrupt was typed while `unread` transport bytes were queued.
    pub(crate) fn interrupted(&mut self, unread: usize) {
        self.bytes = if unread >= et_core::output_interrupt::FLUSH_THRESHOLD {
            unread
        } else {
            0
        };
    }

    /// Account one packet read off the transport; whether it is terminal
    /// output that was queued before the interrupt.
    pub(crate) fn read(&mut self, packet: &et_core::packet::Packet) -> bool {
        if self.bytes == 0 {
            return false;
        }
        // Frame length prefix, packet header and payload, and the MAC.
        let wire = 4 + packet.wire_len() + et_core::crypto::MAC_LEN;
        self.bytes = self.bytes.saturating_sub(wire);
        packet.header() == et_core::proto::TerminalPacketType::TerminalBuffer as u8
    }
}
