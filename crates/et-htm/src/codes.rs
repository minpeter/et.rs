//! HTM protocol header bytes, mirroring upstream `HtmHeaderCodes.hpp`.

/// Client -> server: inject characters into a pane.
pub const INSERT_KEYS: u8 = b'1';
/// Server -> client: sends the serialized multiplexer state.
pub const INIT_STATE: u8 = b'2';
/// Client -> server: requests closing a pane.
pub const CLIENT_CLOSE_PANE: u8 = b'3';
/// Server -> client: streams pane output.
pub const APPEND_TO_PANE: u8 = b'4';
/// Client -> server: opens a new tab/pane.
pub const NEW_TAB: u8 = b'5';
/// Server -> client: tells the UI that a pane was removed.
pub const SERVER_CLOSE_PANE: u8 = b'8';
/// Client -> server: creates a split pane layout.
pub const NEW_SPLIT: u8 = b'9';
/// Client -> server: resizes a pane.
pub const RESIZE_PANE: u8 = b'A';
/// Server -> client: send debug log lines to the terminal.
pub const DEBUG_LOG: u8 = b'B';
/// Client -> server: developer commands (shutdown, disconnect, dump state).
pub const INSERT_DEBUG_KEYS: u8 = b'C';
/// Closes the HTM session (handshake end-of-stream).
pub const SESSION_END: u8 = b'D';

/// Length of the UUID strings used for tabs/panes/splits.
pub const UUID_LENGTH: usize = 36;

/// Escape sequence that switches the client terminal into HTM mode.
pub const ENTER_HTM_MODE: &[u8] = &[0x1b, 0x5b, b'#', b'#', b'#', b'q'];
/// Escape sequence that switches the client terminal out of HTM mode.
pub const LEAVE_HTM_MODE: &[u8] = &[0x1b, 0x5b, b'$', b'$', b'$', b'q'];
