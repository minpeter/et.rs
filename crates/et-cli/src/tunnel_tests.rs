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
    assert_eq!(
        first.destination.as_ref().unwrap().name.as_deref(),
        Some("localhost")
    );
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
fn rejects_malformed_mismatched_and_excessive_expansions() {
    assert!(matches!(
        parse_tunnels(&["1000-1002:2000-2001".to_owned()]),
        Err(TunnelError::MismatchedRanges)
    ));
    assert!(matches!(
        parse_tunnels(&["0:80".to_owned()]),
        Err(TunnelError::InvalidEndpoint(_))
    ));
    assert!(matches!(
        parse_tunnels(&[format!(
            "1-{}:1-{}",
            MAX_TUNNEL_REQUESTS + 1,
            MAX_TUNNEL_REQUESTS + 1
        )]),
        Err(TunnelError::TooManyRequests)
    ));
}
