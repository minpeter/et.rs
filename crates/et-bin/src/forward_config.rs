use et_cli::client::ClientArgs;
use et_cli::tunnel::parse_tunnels;
use et_core::proto::{InitialPayload, PortForwardSourceRequest};

#[derive(Debug)]
pub enum ForwardConfigError {
    MissingAgentSocket,
    InvalidSessionId,
    Tunnel(et_cli::tunnel::TunnelError),
}

impl std::fmt::Display for ForwardConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAgentSocket => write!(
                formatter,
                "SSH-agent forwarding requires --ssh-socket or SSH_AUTH_SOCK"
            ),
            Self::InvalidSessionId => write!(formatter, "invalid session id for SSH-agent socket"),
            Self::Tunnel(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ForwardConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tunnel(error) => Some(error),
            Self::MissingAgentSocket | Self::InvalidSessionId => None,
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
    session_id: &str,
    environment_agent: Option<&str>,
) -> Result<ForwardConfig, ForwardConfigError> {
    let local_sources = parse_tunnels(&args.tunnel)?;
    let mut reverse_tunnels = parse_tunnels(&args.reverse_tunnel)?;
    let mut environmentvariables = std::collections::HashMap::new();
    if args.forward_ssh_agent {
        if session_id.len() != 16 || !session_id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(ForwardConfigError::InvalidSessionId);
        }
        let destination = args
            .ssh_socket
            .as_deref()
            .or(environment_agent)
            .ok_or(ForwardConfigError::MissingAgentSocket)?;
        let source = format!("/tmp/et-agent-{session_id}/agent.sock");
        let mut agent = parse_tunnels(&[format!("{source}:{destination}")])?
            .pop()
            .ok_or(ForwardConfigError::MissingAgentSocket)?;
        agent.environmentvariable = Some("SSH_AUTH_SOCK".to_owned());
        environmentvariables.insert("SSH_AUTH_SOCK".to_owned(), source);
        reverse_tunnels.push(agent);
    }
    Ok(ForwardConfig {
        local_sources,
        initial_payload: InitialPayload {
            jumphost: Some(false),
            reversetunnels: reverse_tunnels,
            environmentvariables,
        },
    })
}

#[cfg(test)]
#[path = "forward_config_tests.rs"]
mod tests;
