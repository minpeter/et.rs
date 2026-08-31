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
fn ssh_config_reverse_forwards_follow_cli_agent_forwarding() {
    let args = ClientArgs::try_parse_from(["et", "host", "--forward-ssh-agent"]).unwrap();
    let mut config = build(&args, Some("/run/agent.sock")).unwrap();
    let resolved = ResolvedSshConfig {
        hostname: "host".to_owned(),
        user: None,
        local_forwards: Vec::new(),
        remote_forwards: vec![PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some("localhost".to_owned()),
                port: Some(1492),
            }),
            destination: Some(SocketEndpoint {
                name: Some("127.0.0.1".to_owned()),
                port: Some(1492),
            }),
            environmentvariable: None,
        }],
    };

    // When
    config.apply_ssh_config(&resolved).unwrap();

    // Then
    assert_eq!(config.initial_payload.reversetunnels.len(), 2);
    assert_eq!(
        config.initial_payload.reversetunnels[0]
            .environmentvariable
            .as_deref(),
        Some("SSH_AUTH_SOCK")
    );
    assert_eq!(
        config.initial_payload.reversetunnels[1]
            .source
            .as_ref()
            .and_then(|source| source.port),
        Some(1492)
    );
}

#[test]
fn ssh_config_forwards_are_cumulative_stable_and_exactly_deduplicated() {
    // Given
    let args = ClientArgs::try_parse_from([
        "et",
        "host",
        "-t",
        "localhost:1000:127.0.0.1:2000",
        "-t",
        "localhost:1000:127.0.0.1:2000",
        "-t",
        "localhost:1000:127.0.0.1:2001",
        "-r",
        "localhost:3000:127.0.0.1:4000",
        "-r",
        "localhost:3000:127.0.0.1:4000",
    ])
    .unwrap();
    let mut config = build(&args, None).unwrap();
    let local_duplicate = config.local_sources[0].request.clone();
    let local_distinct = config.local_sources[2].request.clone();
    let remote_duplicate = config.initial_payload.reversetunnels[0].clone();
    let resolved = ResolvedSshConfig {
        hostname: "host".to_owned(),
        user: None,
        local_forwards: vec![
            local_duplicate.clone(),
            local_duplicate,
            PortForwardSourceRequest {
                source: Some(SocketEndpoint {
                    name: Some("localhost".to_owned()),
                    port: Some(1001),
                }),
                destination: Some(SocketEndpoint {
                    name: Some("127.0.0.1".to_owned()),
                    port: Some(2002),
                }),
                environmentvariable: None,
            },
        ],
        remote_forwards: vec![
            remote_duplicate.clone(),
            remote_duplicate,
            PortForwardSourceRequest {
                source: Some(SocketEndpoint {
                    name: Some("localhost".to_owned()),
                    port: Some(3001),
                }),
                destination: Some(SocketEndpoint {
                    name: Some("127.0.0.1".to_owned()),
                    port: Some(4001),
                }),
                environmentvariable: None,
            },
        ],
    };

    // When
    config.apply_ssh_config(&resolved).unwrap();

    // Then
    assert_eq!(config.local_sources.len(), 3);
    assert_eq!(
        config.local_sources[0].request.source,
        local_distinct.source
    );
    assert_eq!(
        config.local_sources[0]
            .request
            .destination
            .as_ref()
            .and_then(|value| value.port),
        Some(2000)
    );
    assert_eq!(config.local_sources[1].request, local_distinct);
    assert_eq!(config.local_sources[2].request, resolved.local_forwards[2]);
    assert_eq!(
        config.local_sources[0].origin,
        et_net::forward::ForwardOrigin::Explicit
    );
    assert_eq!(
        config.local_sources[2].origin,
        et_net::forward::ForwardOrigin::SshConfig
    );
    assert_eq!(config.initial_payload.reversetunnels.len(), 2);
    assert_eq!(
        config.remote_origins,
        [
            et_net::forward::ForwardOrigin::Explicit,
            et_net::forward::ForwardOrigin::SshConfig,
        ]
    );
    assert_eq!(
        config.initial_payload.reversetunnels[0],
        resolved.remote_forwards[0]
    );
    assert_eq!(
        config.initial_payload.reversetunnels[1],
        resolved.remote_forwards[2]
    );
}
