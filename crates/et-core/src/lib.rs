//! Protocol primitives for et.rs: crypto, packet framing, and protobuf codec.
//!
//! Mirrors the EternalTerminal wire contract (protocol version 6) byte-for-byte.
//! The compatibility oracle is `fixtures/wire.json`, generated once from the
//! pinned upstream C++ implementation; the golden test asserts exact parity.

pub mod crypto;
pub mod framing;
pub mod packet;

pub const PROTOCOL_VERSION: u32 = 6;
