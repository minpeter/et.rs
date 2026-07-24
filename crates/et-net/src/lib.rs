#![forbid(unsafe_code)]

//! TCP transport for et.rs: SocketHandler framing, Connect handshake, and a
//! blocking [`connection::Connection`] over `TcpStream`.

pub mod connection;
mod connection_error;
mod connection_nonblocking;
pub mod framing_io;
pub mod handshake;
pub mod listener;
pub mod local_packet;
