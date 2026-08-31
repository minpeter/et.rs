use std::collections::BTreeSet;

use et_cli::client::ClientArgs;
use et_cli::tunnel::parse_tunnels;
use et_core::proto::{InitialPayload, PortForwardSourceRequest, SocketEndpoint};
use et_net::forward::ForwardSource;

use crate::ssh_config::ResolvedSshConfig;
use crate::terminal_protocol::{valid_environment_name, MAX_ENVIRONMENT};

#[derive(Debug)]
pub enum ForwardConfigError {
    MissingAgentSocket,
    Tunnel(et_cli::tunnel::TunnelError),
    InvalidEnvironmentName(String),
    TooManyEnvironmentNames(usize),
    EnvironmentPacketTooLarge(usize),
    JumphostPacketTooLarge(usize),
}

impl std::fmt::Display for ForwardConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAgentSocket => write!(
                formatter,
                "Missing environment variable SSH_AUTH_SOCK.  Are you sure you ran ssh-agent first?"
            ),
            Self::Tunnel(error) => error.fmt(formatter),
            Self::InvalidEnvironmentName(name) => {
                write!(
                    formatter,
                    "invalid reverse-tunnel environment variable name: {name}"
                )
            }
            Self::TooManyEnvironmentNames(count) => write!(
                formatter,
                "terminal environment has {count} reserved names; maximum is {MAX_ENVIRONMENT}"
            ),
            Self::EnvironmentPacketTooLarge(length) => write!(
                formatter,
                "terminal environment packet needs at least {length} bytes; maximum is {}",
                et_net::local_packet::MAX_LOCAL_PACKET_LEN
            ),
            Self::JumphostPacketTooLarge(length) => write!(
                formatter,
                "jumphost initialization packet needs at least {length} bytes; maximum is {}",
                et_net::local_packet::MAX_LOCAL_PACKET_LEN
            ),
        }
    }
}

impl std::error::Error for ForwardConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tunnel(error) => Some(error),
            Self::MissingAgentSocket
            | Self::InvalidEnvironmentName(_)
            | Self::TooManyEnvironmentNames(_)
            | Self::EnvironmentPacketTooLarge(_)
            | Self::JumphostPacketTooLarge(_) => None,
        }
    }
}

impl From<et_cli::tunnel::TunnelError> for ForwardConfigError {
    fn from(error: et_cli::tunnel::TunnelError) -> Self {
        Self::Tunnel(error)
    }
}

pub struct ForwardConfig {
    pub local_sources: Vec<ForwardSource>,
    pub initial_payload: InitialPayload,
}

impl ForwardConfig {
    pub fn apply_ssh_config(
        &mut self,
        resolved: &ResolvedSshConfig,
    ) -> Result<(), ForwardConfigError> {
        let mut local_requests = Vec::new();
        self.local_sources.retain(|source| {
            if local_requests.contains(&source.request) {
                false
            } else {
                local_requests.push(source.request.clone());
                true
            }
        });
        for request in &resolved.local_forwards {
            if !local_requests.contains(request) {
                local_requests.push(request.clone());
                self.local_sources
                    .push(ForwardSource::ssh_config(request.clone()));
            }
        }

        let mut remote_requests = Vec::new();
        self.initial_payload.reversetunnels.retain(|request| {
            let is_agent_forward = request.source.is_none()
                && request.environmentvariable.as_deref() == Some("SSH_AUTH_SOCK");
            if is_agent_forward {
                true
            } else if remote_requests.contains(request) {
                false
            } else {
                remote_requests.push(request.clone());
                true
            }
        });
        for request in &resolved.remote_forwards {
            if !remote_requests.contains(request) {
                remote_requests.push(request.clone());
                self.initial_payload.reversetunnels.push(request.clone());
            }
        }
        validate_environment_names(&self.initial_payload.reversetunnels)
    }
}

pub fn build(
    args: &ClientArgs,
    environment_agent: Option<&str>,
) -> Result<ForwardConfig, ForwardConfigError> {
    let local_sources = parse_tunnels(&args.tunnel)?
        .into_iter()
        .map(ForwardSource::explicit)
        .collect();
    let mut reverse_tunnels = parse_tunnels(&args.reverse_tunnel)?;
    if args.forward_ssh_agent {
        // Upstream sends a reverse tunnel with no source: the server creates
        // a private socket, exports it as SSH_AUTH_SOCK, and connections are
        // forwarded back to the local agent socket.
        let destination = args
            .ssh_socket
            .as_deref()
            .or(environment_agent)
            .filter(|value| !value.is_empty())
            .ok_or(ForwardConfigError::MissingAgentSocket)?;
        reverse_tunnels.push(PortForwardSourceRequest {
            source: None,
            destination: Some(SocketEndpoint {
                name: Some(destination.to_owned()),
                port: None,
            }),
            environmentvariable: Some("SSH_AUTH_SOCK".to_owned()),
        });
    }
    validate_environment_names(&reverse_tunnels)?;
    Ok(ForwardConfig {
        local_sources,
        initial_payload: InitialPayload {
            jumphost: Some(false),
            reversetunnels: reverse_tunnels,
            environmentvariables: std::collections::HashMap::new(),
        },
    })
}

fn validate_environment_names(
    reverse_tunnels: &[PortForwardSourceRequest],
) -> Result<(), ForwardConfigError> {
    let mut names = BTreeSet::new();
    for name in reverse_tunnels
        .iter()
        .filter_map(|request| request.environmentvariable.as_deref())
    {
        if !valid_environment_name(name) {
            return Err(ForwardConfigError::InvalidEnvironmentName(name.to_owned()));
        }
        names.insert(name);
    }
    if names.len() > MAX_ENVIRONMENT {
        return Err(ForwardConfigError::TooManyEnvironmentNames(names.len()));
    }
    Ok(())
}

#[cfg(test)]
#[path = "forward_config_tests.rs"]
mod tests;
