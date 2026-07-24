//! Pure state machine mirroring upstream `BackedReader`: reassembles 4-byte
//! big-endian framed packets, decrypts them, and replays catchup packets
//! queued during reconnect before resuming live reads. Owns no socket; bytes
//! arrive via [`BackedReader::feed`] and packets leave via [`BackedReader::pop`],
//! so framing and nonce-synchronised replay are testable without I/O.

use std::collections::VecDeque;

use crate::crypto::{CryptoHandler, DecryptError};
use crate::packet::{Packet, PacketError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadItem {
    Packet(Packet),
    NeedMore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    Frame(crate::framing::FrameError),
    Packet(PacketError),
    Crypto(DecryptError),
    Unencrypted,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "frame: {e}"),
            Self::Packet(e) => write!(f, "packet: {e}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::Unencrypted => write!(f, "unencrypted packet on encrypted stream"),
        }
    }
}

impl std::error::Error for ReadError {}

pub struct BackedReader {
    crypto: CryptoHandler,
    partial: Vec<u8>,
    replay: VecDeque<Vec<u8>>,
    sequence: i64,
    connected: bool,
}

impl BackedReader {
    pub fn new(crypto: CryptoHandler, connected: bool) -> Self {
        Self {
            crypto,
            partial: Vec::new(),
            replay: VecDeque::new(),
            sequence: 0,
            connected,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.partial.extend_from_slice(bytes);
    }

    pub fn pop(&mut self) -> Result<ReadItem, ReadError> {
        if !self.connected {
            return Ok(ReadItem::NeedMore);
        }
        if let Some(serialized) = self.replay.pop_front() {
            let packet = self.decode_packet(&serialized)?;
            return Ok(ReadItem::Packet(packet));
        }
        if self.partial.len() < 4 {
            return Ok(ReadItem::NeedMore);
        }
        let len = crate::framing::parse_be_u32_len(&self.partial).map_err(ReadError::Frame)?;
        if self.partial.len() < 4 + len {
            return Ok(ReadItem::NeedMore);
        }
        let serialized = self.partial[4..4 + len].to_vec();
        self.partial.drain(0..4 + len);
        let packet = self.decode_packet(&serialized)?;
        self.sequence += 1;
        Ok(ReadItem::Packet(packet))
    }

    fn decode_packet(&mut self, serialized: &[u8]) -> Result<Packet, ReadError> {
        let mut packet = Packet::from_serialized(serialized).map_err(ReadError::Packet)?;
        if !packet.is_encrypted() {
            return Err(ReadError::Unencrypted);
        }
        packet
            .decrypt(&mut self.crypto)
            .map_err(ReadError::Crypto)?;
        Ok(packet)
    }

    pub fn revive(&mut self, catchup: Vec<Vec<u8>>) {
        self.partial.clear();
        let n = catchup.len();
        for entry in catchup {
            self.replay.push_back(entry);
        }
        self.sequence += n as i64;
        self.connected = true;
    }

    pub fn invalidate(&mut self) {
        self.connected = false;
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backed_writer::{BackedWriter, WriterOutcome};
    use crate::crypto::{CryptoHandler, DIR_CLIENT_TO_SERVER, KEY_LEN};

    fn pair() -> (BackedWriter, BackedReader) {
        let key = [9u8; KEY_LEN];
        let writer = BackedWriter::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
        let reader = BackedReader::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
        (writer, reader)
    }

    #[test]
    fn reader_parses_writer_frame() {
        let (mut w, mut r) = pair();
        let WriterOutcome::Send(frame) = w.write_packet(7, b"payload").unwrap() else {
            panic!();
        };
        r.feed(&frame);
        match r.pop().unwrap() {
            ReadItem::Packet(p) => {
                assert_eq!(p.header(), 7);
                assert_eq!(p.payload(), b"payload");
            }
            _ => panic!("expected packet"),
        }
    }

    #[test]
    fn partial_frame_needs_more() {
        let (mut w, mut r) = pair();
        let WriterOutcome::Send(frame) = w.write_packet(0, b"ab").unwrap() else {
            panic!();
        };
        r.feed(&frame[..3]);
        assert_eq!(r.pop().unwrap(), ReadItem::NeedMore);
        r.feed(&frame[3..]);
        assert!(matches!(r.pop().unwrap(), ReadItem::Packet(_)));
    }

    #[test]
    fn multiple_packets_in_one_feed() {
        let (mut w, mut r) = pair();
        let mut combined = Vec::new();
        for i in 0..5u8 {
            let WriterOutcome::Send(f) = w.write_packet(i, &[i]).unwrap() else {
                panic!();
            };
            combined.extend_from_slice(&f);
        }
        r.feed(&combined);
        for i in 0..5u8 {
            match r.pop().unwrap() {
                ReadItem::Packet(p) => {
                    assert_eq!(p.header(), i);
                    assert_eq!(p.payload(), &[i]);
                }
                _ => panic!("expected packet {i}"),
            }
        }
        assert_eq!(r.pop().unwrap(), ReadItem::NeedMore);
    }

    #[test]
    fn unencrypted_live_packet_is_rejected() {
        let (_, mut reader) = pair();
        let packet = Packet::raw(false, 0, b"plaintext");
        reader.feed(&crate::framing::frame_be_u32(&packet.serialize()));
        assert_eq!(reader.pop(), Err(ReadError::Unencrypted));
    }

    #[test]
    fn replay_catchup_before_live_reads() {
        let key = [5u8; KEY_LEN];
        let mut w = BackedWriter::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), false);
        let mut r = BackedReader::new(CryptoHandler::new(&key, DIR_CLIENT_TO_SERVER), true);
        for i in 0..3u8 {
            let WriterOutcome::BufferedOnly = w.write_packet(i, &[i]).unwrap() else {
                panic!();
            };
        }
        let catchup = w.recover(0).unwrap();
        r.revive(catchup);
        for i in 0..3u8 {
            match r.pop().unwrap() {
                ReadItem::Packet(p) => {
                    assert_eq!(p.header(), i);
                    assert_eq!(p.payload(), &[i]);
                }
                _ => panic!("expected catchup packet {i}"),
            }
        }
        assert_eq!(r.sequence(), 3);
    }
}
