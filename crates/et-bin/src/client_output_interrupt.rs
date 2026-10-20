//! Filtering never touches the chunk already owned by the console writer.

use std::io;

use super::ConsoleOutput;

impl ConsoleOutput {
    pub(crate) fn interrupt(&self) -> io::Result<usize> {
        let Some(shared) = &self.shared else {
            return Ok(0);
        };
        let mut state = shared.lock()?;
        // The direct console has no writer-owned batch outside its queue, so
        // a packet held back for lack of room also means the backlog reached
        // the threshold.
        if state.bytes < et_core::output_interrupt::FLUSH_THRESHOLD
            && !(self.is_direct() && state.waiting_for_capacity)
        {
            return Ok(0);
        }
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
