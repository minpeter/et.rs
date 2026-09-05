//! Filtering never touches the chunk already owned by the console writer.

use std::io;

use super::ConsoleOutput;

impl ConsoleOutput {
    pub(crate) fn interrupt(&self) -> io::Result<usize> {
        let Some(shared) = &self.shared else {
            return Ok(0);
        };
        let mut state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("console output worker unavailable"))?;
        if state.bytes < et_core::output_interrupt::FLUSH_THRESHOLD {
            return Ok(0);
        }
        let bytes: Vec<u8> = state
            .queue
            .iter()
            .flat_map(|entry| entry.bytes.iter().copied())
            .collect();
        let filtered = state.stream.filter(&bytes);
        state.skip_until_newline |= filtered.skip_until_newline;
        let mut remaining = filtered.kept.as_slice();
        state.queue.retain_mut(|entry| {
            let count = remaining.len().min(entry.bytes.len());
            if count == 0 {
                return false;
            }
            entry.bytes.clear();
            entry.bytes.extend_from_slice(&remaining[..count]);
            remaining = &remaining[count..];
            true
        });
        state.bytes = filtered.kept.len();
        drop(state);
        shared.wake.notify_all();
        Ok(filtered.dropped)
    }
}
