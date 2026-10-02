use std::io;

use et_cli::host::HostError;
use et_net::connection::ConnError;

use crate::forward_config::ForwardConfigError;

#[derive(Debug)]
pub enum ClientError {
    Host(HostError),
    ForwardConfig(ForwardConfigError),
    Unsupported(&'static str),
    InvalidSshComponent(&'static str),
    InvalidSshConfig(&'static str),
    SshSpawn(io::Error),
    SshStdout(io::Error),
    SshWait(io::Error),
    SshTerminate(io::Error),
    SshTimeout(&'static str),
    SshNonZero(Option<i32>),
    SshOutputTooLarge(usize),
    SshConfigMalformed(&'static str),
    SshConfigMalformedForward {
        directive: &'static str,
        reason: &'static str,
    },
    MissingIdPasskeyMarker,
    MalformedIdPasskeyMarker,
    InvalidSessionId,
    InvalidPasskey,
    DnsTimeout(String),
    DnsResolution {
        endpoint: String,
        source: io::Error,
    },
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
    /// The server asked a challenge-capable client to retry during startup.
    RetryLater,
    /// The initial TCP/handshake attempts failed.
    InitialConnect {
        endpoint: String,
        message: String,
    },
}

impl From<HostError> for ClientError {
    fn from(value: HostError) -> Self {
        Self::Host(value)
    }
}

impl From<ForwardConfigError> for ClientError {
    fn from(value: ForwardConfigError) -> Self {
        Self::ForwardConfig(value)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(error) => write!(f, "{error}"),
            Self::ForwardConfig(error) => write!(f, "{error}"),
            Self::Unsupported(message) => write!(f, "{message}"),
            Self::InvalidSshComponent(component) => {
                write!(f, "SSH {component} must not begin with a hyphen")
            }
            Self::InvalidSshConfig(reason) => write!(f, "--ssh-config {reason}"),
            Self::SshSpawn(error) => write!(f, "could not start system ssh: {error}"),
            Self::SshStdout(error) => write!(f, "could not read system ssh stdout: {error}"),
            Self::SshWait(error) => write!(f, "could not wait for system ssh: {error}"),
            Self::SshTerminate(error) => {
                write!(f, "could not terminate timed-out system ssh: {error}")
            }
            Self::SshTimeout(operation) => {
                write!(f, "Operation timed out: system ssh while {operation}")
            }
            Self::SshNonZero(Some(code)) => write!(f, "system ssh exited with status {code}"),
            Self::SshNonZero(None) => write!(f, "system ssh terminated without an exit status"),
            Self::SshOutputTooLarge(limit) => {
                write!(f, "system ssh stdout exceeds the {limit}-byte limit")
            }
            Self::SshConfigMalformed(field) => {
                write!(f, "system ssh -G output has no valid {field}")
            }
            Self::SshConfigMalformedForward { directive, reason } => {
                write!(f, "system ssh -G output has a malformed {directive} record: {reason}")
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
                write!(f, "Could not resolve hostname {endpoint}: Operation timed out")
            }
            Self::DnsResolution { endpoint, source } => {
                write!(f, "Could not resolve hostname {endpoint}: ")?;
                write_connect_reason(f, source)
            }
            Self::DnsWorker(error) => write!(f, "could not start DNS resolver: {error}"),
            Self::DnsWorkerPanicked => write!(f, "DNS resolver worker terminated unexpectedly"),
            Self::UnreachableEndpoint { endpoint, source } => {
                write!(f, "Could not reach the ET server: {endpoint}: ")?;
                write_connect_reason(f, source)
            }
            Self::BootstrapTimeout(operation) => {
                write!(f, "Operation timed out: ET bootstrap while {operation}")
            }
            Self::ConnectIo { operation, source } => {
                write!(f, "ET connection failed while {operation}: ")?;
                write_connect_reason(f, source)
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
            Self::RetryLater => write!(f, "ET server asked the client to retry"),
            Self::InitialConnect { endpoint, message } => {
                write!(f, "Could not make initial connection to {endpoint}: {message}")
            }
        }
    }
}

// Remote-SSH recognizes these OpenSSH/upstream ET phrases, not Rust's
// platform-dependent descriptions (in particular Windows Winsock text).
// Preserve the original diagnostic, including its OS error code.
fn write_connect_reason(f: &mut std::fmt::Formatter<'_>, source: &io::Error) -> std::fmt::Result {
    let reason = match source.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Some("Operation timed out"),
        io::ErrorKind::NetworkUnreachable => Some("Network is unreachable"),
        io::ErrorKind::HostUnreachable => Some("No route to host"),
        io::ErrorKind::ConnectionRefused => Some("Connection refused"),
        // Rust leaves WSAEHOSTDOWN unclassified; upstream maps it to
        // EHOSTUNREACH along with WSAEHOSTUNREACH.
        #[cfg(windows)]
        _ if source.raw_os_error() == Some(10064) => Some("No route to host"),
        _ => None,
    };
    if let Some(reason) = reason {
        if !source.to_string().contains(reason) {
            write!(f, "{reason}: ")?;
        }
    }
    write!(f, "{source}")
}

fn write_message(f: &mut std::fmt::Formatter<'_>, message: &Option<String>) -> std::fmt::Result {
    if let Some(message) = message.as_deref().filter(|message| !message.is_empty()) {
        write!(f, ": {message}")?;
    }
    Ok(())
}

impl ClientError {
    /// Errors that mean the network is temporarily unreachable (e.g. a
    /// laptop waking from sleep before Wi-Fi is back, a DNS outage, a
    /// half-restored link). A live session should retry the reconnect
    /// instead of exiting, mirroring upstream ET.
    /// Failures of the TCP connect or the pre-payload handshake. A socket that
    /// already carried `INITIAL_PAYLOAD` is not in this set.
    pub fn is_retryable_initial_connect(&self) -> bool {
        matches!(
            self,
            Self::DnsTimeout(_)
                | Self::DnsResolution { .. }
                | Self::DnsWorker(_)
                | Self::DnsWorkerPanicked
                | Self::UnreachableEndpoint { .. }
                | Self::BootstrapTimeout(_)
                | Self::ConnectIo { .. }
                | Self::RetryLater
        )
    }

    pub fn is_transient_reconnect(&self) -> bool {
        matches!(
            self,
            Self::DnsTimeout(_)
                | Self::DnsResolution { .. }
                | Self::DnsWorker(_)
                | Self::DnsWorkerPanicked
                | Self::UnreachableEndpoint { .. }
                | Self::BootstrapTimeout(_)
                | Self::ConnectIo { .. }
                | Self::Transport(ConnError::Io(_))
                | Self::RetryLater
        )
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Unsupported(_)
            | Self::ForwardConfig(_)
            | Self::InvalidSshConfig(_)
            | Self::SshConfigMalformedForward { .. } => 2,
            _ => 1,
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Host(error) => Some(error),
            Self::ForwardConfig(error) => Some(error),
            Self::SshSpawn(error)
            | Self::SshStdout(error)
            | Self::SshWait(error)
            | Self::SshTerminate(error)
            | Self::DnsWorker(error)
            | Self::DnsResolution { source: error, .. }
            | Self::UnreachableEndpoint { source: error, .. }
            | Self::ConnectIo { source: error, .. } => Some(error),
            Self::Transport(error) => Some(error),
            Self::MalformedInitialResponse(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn network_reasons_use_ssh_retry_phrases_and_keep_platform_details() {
        for (kind, phrase) in [
            (io::ErrorKind::TimedOut, "Operation timed out"),
            (io::ErrorKind::WouldBlock, "Operation timed out"),
            (io::ErrorKind::NetworkUnreachable, "Network is unreachable"),
            (io::ErrorKind::HostUnreachable, "No route to host"),
            (io::ErrorKind::ConnectionRefused, "Connection refused"),
        ] {
            // Deliberately unlike Unix strerror: Windows/localized messages
            // still need the recognized English prefix without losing detail.
            let detail = "platform-specific diagnostic (os error 12345)";
            let error = ClientError::UnreachableEndpoint {
                endpoint: "[::1]:2022".to_owned(),
                source: io::Error::new(kind, detail),
            };
            assert_eq!(
                error.to_string(),
                format!("Could not reach the ET server: [::1]:2022: {phrase}: {detail}")
            );
            assert_eq!(error.source().unwrap().to_string(), detail);
            assert!(error.is_retryable_initial_connect());
            assert!(error.is_transient_reconnect());
            let handshake = ClientError::ConnectIo {
                operation: "completing the ET handshake",
                source: io::Error::new(kind, detail),
            };
            assert!(handshake
                .to_string()
                .contains(&format!("{phrase}: {detail}")));
        }
    }

    #[test]
    fn unclassified_errors_are_not_mislabeled_as_network_outages() {
        let error = ClientError::UnreachableEndpoint {
            endpoint: "localhost:2022".to_owned(),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "access denied"),
        };
        assert_eq!(
            error.to_string(),
            "Could not reach the ET server: localhost:2022: access denied"
        );
        let rejected = ClientError::ServerInvalidKey(None);
        assert!(!rejected.is_retryable_initial_connect());
        assert!(!rejected.is_transient_reconnect());
    }

    #[test]
    fn deadline_errors_are_recognized_by_ssh_clients() {
        for error in [
            ClientError::DnsTimeout("dns.invalid:2022".to_owned()),
            ClientError::BootstrapTimeout("connecting"),
            ClientError::SshTimeout("bootstrapping"),
        ] {
            assert!(error.to_string().contains("Operation timed out"));
        }
        let resolution = ClientError::DnsResolution {
            endpoint: "dns.invalid:2022".to_owned(),
            source: io::Error::new(io::ErrorKind::TimedOut, "localized resolver timeout"),
        };
        assert_eq!(
            resolution.to_string(),
            "Could not resolve hostname dns.invalid:2022: Operation timed out: localized resolver timeout"
        );
    }

    #[cfg(windows)]
    #[test]
    fn winsock_host_down_uses_upstream_host_unreachable_wording() {
        let source = io::Error::from_raw_os_error(10064);
        let detail = source.to_string();
        let error = ClientError::UnreachableEndpoint {
            endpoint: "host:2022".to_owned(),
            source,
        };
        assert_eq!(
            error.to_string(),
            format!("Could not reach the ET server: host:2022: No route to host: {detail}")
        );
    }
}
