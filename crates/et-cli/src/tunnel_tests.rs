use super::*;

#[test]
fn parses_upstream_two_port_and_range_syntax() {
    let requests = parse_tunnels(&["1000:2000,8000-8002:9000-9002".to_owned()]).unwrap();
    assert_eq!(requests.len(), 4);
    let first = &requests[0];
    assert_eq!(
        first.source.as_ref().unwrap().name.as_deref(),
        Some("localhost")
    );
    assert_eq!(first.source.as_ref().unwrap().port, Some(1000));
    // Upstream leaves the destination name unset for plain TCP tunnels.
    assert_eq!(first.destination.as_ref().unwrap().name, None);
    assert_eq!(first.destination.as_ref().unwrap().port, Some(2000));
    assert_eq!(requests[3].source.as_ref().unwrap().port, Some(8002));
    assert_eq!(requests[3].destination.as_ref().unwrap().port, Some(9002));
}

#[test]
fn parses_ssh_style_and_unix_socket_endpoints() {
    let requests = parse_tunnels(&[
        "127.0.0.1:8080:db.internal:80".to_owned(),
        "/tmp/local.sock:/tmp/remote.sock".to_owned(),
    ])
    .unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].source.as_ref().unwrap().name.as_deref(),
        Some("127.0.0.1")
    );
    assert_eq!(
        requests[0].destination.as_ref().unwrap().name.as_deref(),
        Some("db.internal")
    );
    assert_eq!(
        requests[1].source.as_ref().unwrap().name.as_deref(),
        Some("/tmp/local.sock")
    );
    assert_eq!(requests[1].source.as_ref().unwrap().port, None);
    assert_eq!(
        requests[1].destination.as_ref().unwrap().name.as_deref(),
        Some("/tmp/remote.sock")
    );
}

#[test]
fn parses_mixed_socket_and_port_forms_like_upstream() {
    let requests = parse_tunnels(&[
        "8080:/tmp/remote.sock".to_owned(),
        "/tmp/l.sock:9090".to_owned(),
    ])
    .unwrap();
    assert_eq!(requests[0].source.as_ref().unwrap().port, Some(8080));
    assert_eq!(
        requests[0].destination.as_ref().unwrap().name.as_deref(),
        Some("/tmp/remote.sock")
    );
    assert_eq!(requests[0].destination.as_ref().unwrap().port, None);
    assert_eq!(
        requests[1].source.as_ref().unwrap().name.as_deref(),
        Some("/tmp/l.sock")
    );
    assert_eq!(requests[1].destination.as_ref().unwrap().name, None);
    assert_eq!(requests[1].destination.as_ref().unwrap().port, Some(9090));
}

#[test]
fn parses_environment_variable_named_pipe_form() {
    let requests = parse_tunnels(&["SSH_AUTH_SOCK:/tmp/agent.sock".to_owned()]).unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].source, None);
    assert_eq!(
        requests[0].environmentvariable.as_deref(),
        Some("SSH_AUTH_SOCK")
    );
    assert_eq!(
        requests[0].destination.as_ref().unwrap().name.as_deref(),
        Some("/tmp/agent.sock")
    );
}

#[test]
fn parses_ssh_style_with_empty_bind_and_bracketed_ipv6() {
    let requests = parse_tunnels(&[":8080:localhost:80".to_owned()]).unwrap();
    assert_eq!(
        requests[0].source.as_ref().unwrap().name.as_deref(),
        Some("")
    );
    assert_eq!(requests[0].source.as_ref().unwrap().port, Some(8080));

    let requests = parse_tunnels(&["[::1]:8080:[::1]:9090".to_owned()]).unwrap();
    assert_eq!(
        requests[0].source.as_ref().unwrap().name.as_deref(),
        Some("::1")
    );
    assert_eq!(
        requests[0].destination.as_ref().unwrap().name.as_deref(),
        Some("::1")
    );
    assert_eq!(requests[0].destination.as_ref().unwrap().port, Some(9090));

    // Five or more parts means an unbracketed IPv6 address: rejected upstream.
    assert!(parse_tunnels(&["::1:8080:localhost:80".to_owned()]).is_err());
}

#[test]
fn rejects_malformed_mismatched_and_excessive_expansions() {
    assert!(matches!(
        parse_tunnels(&["1000-1002:2000-2001".to_owned()]),
        Err(TunnelError::MismatchedRanges)
    ));
    assert!(matches!(
        parse_tunnels(&["0:80".to_owned()]),
        Err(TunnelError::InvalidEndpoint(_))
    ));
    // A range paired with a non-range is rejected, mirroring upstream.
    assert!(parse_tunnels(&["1000-1002:2000".to_owned()]).is_err());
    assert!(matches!(
        parse_tunnels(&["1-40000:1-40000".to_owned(), "2-40001:2-40001".to_owned()]),
        Err(TunnelError::TooManyRequests)
    ));
}
