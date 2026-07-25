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
    let config = build(&args, "abcdefghijklmnop", None).unwrap();
    assert_eq!(config.local_sources.len(), 1);
    assert_eq!(config.initial_payload.reversetunnels.len(), 2);
    let agent = &config.initial_payload.reversetunnels[1];
    assert_eq!(
        agent.source.as_ref().unwrap().name.as_deref(),
        Some("/tmp/et-agent-abcdefghijklmnop/agent.sock")
    );
    assert_eq!(
        agent.destination.as_ref().unwrap().name.as_deref(),
        Some("/tmp/local-agent.sock")
    );
    assert_eq!(agent.environmentvariable.as_deref(), Some("SSH_AUTH_SOCK"));
    assert_eq!(
        config
            .initial_payload
            .environmentvariables
            .get("SSH_AUTH_SOCK")
            .map(String::as_str),
        Some("/tmp/et-agent-abcdefghijklmnop/agent.sock")
    );
}

#[test]
fn agent_forwarding_requires_an_absolute_socket() {
    let args = ClientArgs::try_parse_from(["et", "host", "--forward-ssh-agent"]).unwrap();
    assert!(matches!(
        build(&args, "abcdefghijklmnop", None),
        Err(ForwardConfigError::MissingAgentSocket)
    ));
}
