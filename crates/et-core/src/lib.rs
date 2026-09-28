#![forbid(unsafe_code)]

//! Protocol primitives for et.rs: crypto, packet framing, and protobuf codec.
//!
//! Mirrors the EternalTerminal wire contract (protocol version 6) byte-for-byte.
//! The compatibility oracle is `fixtures/wire.json`, generated once from the
//! pinned upstream C++ implementation; the golden test asserts exact parity.

pub mod backed_reader;
pub mod backed_writer;
pub mod crypto;
pub mod flow_control;
pub mod framing;
pub mod keepalive;
pub mod keys;
pub mod output_interrupt;
pub mod packet;
pub mod proto;

pub const PROTOCOL_VERSION: i32 = 6;
/// `--kill` rides in `TERMINAL_INFO` so older peers ignore it.
pub const SESSION_KILL_COMMAND_VERSION: i32 = 1;
pub const SESSION_KILL_ACK: &str = "ET_SESSION_KILLED_V1";
/// Unknown ids get `RETRY_LATER` for this long after etserver starts.
pub const RECOVERY_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(test)]
mod flow_control_tests;
