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
/// `TerminalInfo.commandversion` for `KILL_SESSION`. Matches upstream
/// `SESSION_KILL_COMMAND_VERSION`. Protocol stays 6.
pub const SESSION_KILL_COMMAND_VERSION: i32 = 1;
/// Payload of the `KEEP_ALIVE` etserver sends once a killed terminal exits.
pub const SESSION_KILL_ACK: &str = "ET_SESSION_KILLED_V1";

#[cfg(test)]
mod flow_control_tests;
