use std::io;

use et_cli::host::HostError;
use et_net::connection::ConnError;

#[derive(Debug)]
pub enum ClientError {
    Host(HostError),
    Unsupported(&'static str),
    InvalidSshComponent(&'static str),
    SshSpawn(io::Error),
    SshStdout(io::Error),
    SshWait(io::Error),
    SshTerminate(io::Error),
    SshTimeout(&'static str),
    SshNonZero(Option<i32>),
    SshOutputTooLarge(usize),
    SshConfigMalformed(&'static str),
    MissingIdPasskeyMarker,
    MalformedIdPasskeyMarker,
    InvalidSessionId,
    InvalidPasskey,
    DnsTimeout(String),
    DnsWorker(io::Error),
    DnsWorkerPanicked,
    UnreachableEndpoint {
        endpoint: String,
        source: io::Error,
    },
    BootstrapTimeout(&'static str),
    ConnectIo {
        operation: &'static str,
        source: io::Error,
    },
    ServerInvalidKey(Option<String>),
    ProtocolMismatch(Option<String>),
    ReturningSessionRequiresRecovery,
    ServerRejected {
        status: Option<i32>,
        message: Option<String>,
    },
    Transport(ConnError),
    UnexpectedInitialPacket(u8),
    MalformedInitialResponse(prost::DecodeError),
    InitialResponseRejected(String),
    Terminal(String),
}

impl From<HostError> for ClientError {
    fn from(value: HostError) -> Self {
        Self::Host(value)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(error) => write!(f, "{error}"),
            Self::Unsupported(message) => write!(f, "{message}"),
            Self::InvalidSshComponent(component) => {
                write!(f, "SSH {component} must not begin with a hyphen")
            }
            Self::SshSpawn(error) => write!(f, "could not start system ssh: {error}"),
            Self::SshStdout(error) => write!(f, "could not read system ssh stdout: {error}"),
            Self::SshWait(error) => write!(f, "could not wait for system ssh: {error}"),
            Self::SshTerminate(error) => {
                write!(f, "could not terminate timed-out system ssh: {error}")
            }
            Self::SshTimeout(operation) => {
                write!(f, "system ssh timed out while {operation}")
            }
            Self::SshNonZero(Some(code)) => write!(f, "system ssh exited with status {code}"),
            Self::SshNonZero(None) => write!(f, "system ssh terminated without an exit status"),
            Self::SshOutputTooLarge(limit) => {
                write!(f, "system ssh stdout exceeds the {limit}-byte limit")
            }
            Self::SshConfigMalformed(field) => {
                write!(f, "system ssh -G output has no valid {field}")
            }
            Self::MissingIdPasskeyMarker => {
                write!(f, "system ssh output is missing the IDPASSKEY marker")
            }
            Self::MalformedIdPasskeyMarker => write!(f, "malformed IDPASSKEY marker"),
            Self::InvalidSessionId => {
                write!(
                    f,
                    "IDPASSKEY session id must be 16 ASCII alphanumeric bytes"
                )
            }
            Self::InvalidPasskey => {
                write!(f, "IDPASSKEY passkey must be 32 ASCII alphanumeric bytes")
            }
            Self::DnsTimeout(endpoint) => {
                write!(f, "DNS resolution timed out for ET endpoint {endpoint}")
            }
            Self::DnsWorker(error) => write!(f, "could not start DNS resolver: {error}"),
            Self::DnsWorkerPanicked => write!(f, "DNS resolver worker terminated unexpectedly"),
            Self::UnreachableEndpoint { endpoint, source } => {
                write!(f, "could not reach the ET server at {endpoint}: {source}")
            }
            Self::BootstrapTimeout(operation) => {
                write!(f, "ET bootstrap timed out while {operation}")
            }
            Self::ConnectIo { operation, source } => {
                write!(f, "ET connection failed while {operation}: {source}")
            }
            Self::ServerInvalidKey(message) => {
                write!(f, "ET server rejected the session key")?;
                write_message(f, message)
            }
            Self::ProtocolMismatch(message) => {
                write!(f, "ET server rejected protocol version 6")?;
                write_message(f, message)
            }
            Self::ReturningSessionRequiresRecovery => write!(
                f,
                "server reported a returning session; returning recovery belongs to a live reconnect"
            ),
            Self::ServerRejected { status, message } => {
                write!(f, "ET server rejected the connection")?;
                if let Some(status) = status {
                    write!(f, " with status {status}")?;
                }
                write_message(f, message)
            }
            Self::Transport(error) => write!(f, "encrypted ET transport failed: {error}"),
            Self::UnexpectedInitialPacket(header) => {
                write!(
                    f,
                    "expected INITIAL_RESPONSE packet, received header {header}"
                )
            }
            Self::MalformedInitialResponse(error) => {
                write!(f, "malformed INITIAL_RESPONSE: {error}")
            }
            Self::InitialResponseRejected(message) => {
                write!(f, "ET server rejected the initial payload: {message}")
            }
            Self::Terminal(message) => write!(f, "{message}"),
        }
    }
}

fn write_message(f: &mut std::fmt::Formatter<'_>, message: &Option<String>) -> std::fmt::Result {
    if let Some(message) = message.as_deref().filter(|message| !message.is_empty()) {
        write!(f, ": {message}")?;
    }
    Ok(())
}

impl ClientError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Unsupported(_) => 2,
            _ => 1,
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Host(error) => Some(error),
            Self::SshSpawn(error)
            | Self::SshStdout(error)
            | Self::SshWait(error)
            | Self::SshTerminate(error)
            | Self::DnsWorker(error)
            | Self::UnreachableEndpoint { source: error, .. }
            | Self::ConnectIo { source: error, .. } => Some(error),
            Self::Transport(error) => Some(error),
            Self::MalformedInitialResponse(error) => Some(error),
            _ => None,
        }
    }
}
