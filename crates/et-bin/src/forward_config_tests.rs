use clap::Parser;
use et_cli::client::ClientArgs;

use super::*;

#[test]
fn builds_local_reverse_and_agent_forwarding_configuration() {
    let args = ClientArgs::try_parse_from([
        "et",
        "host",
        "-t",
        "1000:2000",
        "-r",
        "3000:4000",
        "--forward-ssh-agent",
        "--ssh-socket",
        "/tmp/local-agent.sock",
    ])
    .unwrap();
    let config = build(&args, None).unwrap();
    assert_eq!(config.local_sources.len(), 1);
    assert_eq!(config.initial_payload.reversetunnels.len(), 2);
    let agent = &config.initial_payload.reversetunnels[1];
    // Upstream leaves the source unset: the server picks a private socket
    // path and exports it through SSH_AUTH_SOCK.
    assert_eq!(agent.source, None);
    assert_eq!(
        agent.destination.as_ref().unwrap().name.as_deref(),
        Some("/tmp/local-agent.sock")
    );
    assert_eq!(agent.environmentvariable.as_deref(), Some("SSH_AUTH_SOCK"));
    assert!(config.initial_payload.environmentvariables.is_empty());
}

#[test]
fn agent_forwarding_falls_back_to_environment_and_requires_a_socket() {
    let args = ClientArgs::try_parse_from(["et", "host", "--forward-ssh-agent"]).unwrap();
    let config = build(&args, Some("/run/agent.sock")).unwrap();
    assert_eq!(
        config.initial_payload.reversetunnels[0]
            .destination
            .as_ref()
            .unwrap()
            .name
            .as_deref(),
        Some("/run/agent.sock")
    );
    assert!(matches!(
        build(&args, None),
        Err(ForwardConfigError::MissingAgentSocket)
    ));
}
