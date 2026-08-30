use clap::Parser;
use et_cli::client::ClientArgs;

use crate::ssh_config::ResolvedSshConfig;

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

#[test]
fn ssh_config_reverse_forwards_preserve_agent_forwarding() {
    let args = ClientArgs::try_parse_from(["et", "host", "--forward-ssh-agent"]).unwrap();
    let mut config = build(&args, Some("/run/agent.sock")).unwrap();
    let resolved = ResolvedSshConfig {
        hostname: "host".to_owned(),
        user: None,
        local_forwards: Vec::new(),
        remote_forwards: vec!["localhost:1492:[127.0.0.1]:1492".to_owned()],
    };

    config.apply_ssh_config(&args, &resolved).unwrap();

    assert_eq!(config.initial_payload.reversetunnels.len(), 2);
    assert_eq!(
        config.initial_payload.reversetunnels[0]
            .source
            .as_ref()
            .and_then(|source| source.port),
        Some(1492)
    );
    assert_eq!(
        config.initial_payload.reversetunnels[1]
            .environmentvariable
            .as_deref(),
        Some("SSH_AUTH_SOCK")
    );
}
