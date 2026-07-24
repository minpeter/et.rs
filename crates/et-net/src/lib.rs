//! TCP transport for et.rs: SocketHandler framing, Connect handshake, and a
//! blocking [`connection::Connection`] over `TcpStream`.

pub mod connection;
pub mod framing_io;
pub mod handshake;
