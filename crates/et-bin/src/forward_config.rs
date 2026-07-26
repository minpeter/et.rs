use et_cli::client::ClientArgs;
use et_cli::tunnel::parse_tunnels;
use et_core::proto::{InitialPayload, PortForwardSourceRequest, SocketEndpoint};

#[derive(Debug)]
pub enum ForwardConfigError {
    MissingAgentSocket,
    Tunnel(et_cli::tunnel::TunnelError),
}

impl std::fmt::Display for ForwardConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAgentSocket => write!(
                formatter,
                "Missing environment variable SSH_AUTH_SOCK.  Are you sure you ran ssh-agent first?"
            ),
            Self::Tunnel(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ForwardConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tunnel(error) => Some(error),
            Self::MissingAgentSocket => None,
        }
    }
}

impl From<et_cli::tunnel::TunnelError> for ForwardConfigError {
    fn from(error: et_cli::tunnel::TunnelError) -> Self {
        Self::Tunnel(error)
    }
}

pub struct ForwardConfig {
    pub local_sources: Vec<PortForwardSourceRequest>,
    pub initial_payload: InitialPayload,
}

pub fn build(
    args: &ClientArgs,
    environment_agent: Option<&str>,
) -> Result<ForwardConfig, ForwardConfigError> {
    let local_sources = parse_tunnels(&args.tunnel)?;
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
    Ok(ForwardConfig {
        local_sources,
        initial_payload: InitialPayload {
            jumphost: Some(false),
            reversetunnels: reverse_tunnels,
            environmentvariables: std::collections::HashMap::new(),
        },
    })
}

#[cfg(test)]
#[path = "forward_config_tests.rs"]
mod tests;
