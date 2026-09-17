//! Terminal-owned tmux extended control-mode delimiters (never sent over IPC).
pub const ENTER_HTM_MODE: &[u8] = b"\x1bP1000p";
pub const LEAVE_HTM_MODE: &[u8] = b"\x1b\\";
