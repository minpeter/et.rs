use std::io;

use et_core::backed_reader::ReadError;
use et_core::backed_writer::RecoverError;
use et_core::crypto::EncryptError;

use crate::connection::ConnError;

impl From<io::Error> for ConnError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ReadError> for ConnError {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

impl From<RecoverError> for ConnError {
    fn from(error: RecoverError) -> Self {
        Self::Recover(error)
    }
}

impl From<EncryptError> for ConnError {
    fn from(error: EncryptError) -> Self {
        Self::Encrypt(error)
    }
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io: {error}"),
            Self::Read(error) => write!(f, "read: {error}"),
            Self::Recover(error) => write!(f, "recover: {error}"),
            Self::Encrypt(error) => write!(f, "encrypt: {error}"),
            Self::Backpressure => write!(f, "disconnected write buffer is full"),
            Self::PacketTooLarge => write!(f, "packet exceeds the bounded output lane"),
            Self::SequenceOutOfRange(sequence) => {
                write!(f, "sequence number {sequence} exceeds the wire format")
            }
            Self::InvalidRecoverySequence(sequence) => {
                write!(f, "invalid recovery sequence {sequence:?}")
            }
        }
    }
}

impl std::error::Error for ConnError {}
