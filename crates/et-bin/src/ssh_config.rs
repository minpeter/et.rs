use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bootstrap::{validate_ssh_destination, InvocationCompletion, SshInvocation};
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::ssh_process::{run_checked, SshRunner};
use et_core::proto::{PortForwardSourceRequest, SocketEndpoint};

#[derive(Clone, Copy)]
enum GatewayPorts {
    No,
    Yes,
    ClientSpecified,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedSshConfig {
    pub hostname: String,
    pub user: Option<String>,
    pub local_forwards: Vec<PortForwardSourceRequest>,
    pub remote_forwards: Vec<PortForwardSourceRequest>,
}

pub fn resolve_ssh_config(
    runner: &dyn SshRunner,
    host_alias: &str,
    requested_user: Option<&str>,
    ssh_options: &[String],
    parse_local_forwards: bool,
    parse_remote_forwards: bool,
    deadline: Deadline,
) -> Result<ResolvedSshConfig, ClientError> {
    validate_ssh_destination(host_alias, requested_user)?;
    // Config expansion never opens a remote session. Disable PTY allocation
    // so Windows OpenSSH completes reliably when stdout is a pipe, preserving
    // the bounded SystemSsh capture path.
    let mut args = vec!["-G".to_string(), "-T".to_string()];
    args.extend(ssh_options.iter().map(|option| format!("-o{option}")));
    let destination = match requested_user {
        Some(user) => format!("{user}@{host_alias}"),
        None => host_alias.to_string(),
    };
    args.push(destination);
    let invocation = SshInvocation {
        program: "ssh".to_string(),
        args,
        operation: "resolving SSH configuration",
        completion: InvocationCompletion::Exit,
    };
    parse_ssh_config(
        &run_checked(runner, &invocation, deadline)?,
        parse_local_forwards,
        parse_remote_forwards,
    )
}

fn parse_ssh_config(
    stdout: &[u8],
    parse_local_forwards: bool,
    parse_remote_forwards: bool,
) -> Result<ResolvedSshConfig, ClientError> {
    let text =
        std::str::from_utf8(stdout).map_err(|_| ClientError::SshConfigMalformed("UTF-8 output"))?;
    let gateway_ports = text
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            fields
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case("gatewayports"))
                .then(|| fields.next())
                .flatten()
        })
        .map(GatewayPorts::parse)
        .transpose()?
        .unwrap_or(GatewayPorts::No);
    let mut hostname = None;
    let mut user = None;
    let mut local_forwards = Vec::new();
    let mut remote_forwards = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some(key) if key.eq_ignore_ascii_case("hostname") => {
                hostname = fields.next().map(str::to_string);
            }
            Some(key) if key.eq_ignore_ascii_case("user") => {
                user = fields.next().map(str::to_string);
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("localforward") => {
                if let Some(forward) = parse_forward(fields, "localforward", gateway_ports)? {
                    local_forwards.push(forward);
                }
            }
            Some(key) if parse_remote_forwards && key.eq_ignore_ascii_case("remoteforward") => {
                if let Some(forward) = parse_forward(fields, "remoteforward", gateway_ports)? {
                    remote_forwards.push(forward);
                }
            }
            _ => {}
        }
    }
    let hostname = hostname
        .filter(|hostname| !hostname.is_empty())
        .ok_or(ClientError::SshConfigMalformed("hostname"))?;
    let user = user.filter(|user| !user.is_empty());
    validate_ssh_destination(&hostname, user.as_deref())?;
    Ok(ResolvedSshConfig {
        hostname,
        user,
        local_forwards,
        remote_forwards,
    })
}

fn parse_forward<'a>(
    fields: impl Iterator<Item = &'a str>,
    directive: &'static str,
    gateway_ports: GatewayPorts,
) -> Result<Option<PortForwardSourceRequest>, ClientError> {
    let fields: Vec<&str> = fields.collect();
    let [source, destination] = fields.as_slice() else {
        return Err(ClientError::SshConfigMalformedForward {
            directive,
            reason: "expected exactly two fields",
        });
    };
    let source = parse_source_endpoint(
        source,
        gateway_ports,
        directive.eq_ignore_ascii_case("localforward"),
    )
    .ok_or(ClientError::SshConfigMalformedForward {
        directive,
        reason: "invalid source endpoint",
    })?;
    let destination =
        parse_destination_endpoint(destination).ok_or(ClientError::SshConfigMalformedForward {
            directive,
            reason: "invalid destination endpoint",
        })?;
    if let (Some(host), Some(_)) = (destination.name.as_deref(), destination.port) {
        if !is_representable_tcp_destination(host) {
            et_cli::logging::warn(format!(
                "SSH {directive} destination host '{host}' is unsupported by ET protocol v6; skipping forwarding row"
            ));
            return Ok(None);
        }
    }
    Ok(Some(PortForwardSourceRequest {
        source: Some(source),
        destination: Some(destination),
        environmentvariable: None,
    }))
}

fn is_representable_tcp_destination(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback())
        || host
            .parse::<Ipv6Addr>()
            .is_ok_and(|address| address == Ipv6Addr::LOCALHOST)
}

impl GatewayPorts {
    fn parse(value: &str) -> Result<Self, ClientError> {
        match value {
            "no" => Ok(Self::No),
            "yes" => Ok(Self::Yes),
            "clientspecified" => Ok(Self::ClientSpecified),
            _ => Err(ClientError::SshConfigMalformed("gatewayports")),
        }
    }
}

fn parse_source_endpoint(
    value: &str,
    gateway_ports: GatewayPorts,
    is_local_forward: bool,
) -> Option<SocketEndpoint> {
    if let Some(endpoint) = parse_unix_endpoint(value) {
        return Some(endpoint);
    }
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(normalize_tcp_source(
            SocketEndpoint {
                name: Some("localhost".to_owned()),
                port: Some(parse_port(value)?),
            },
            gateway_ports,
            is_local_forward,
        ));
    }
    parse_tcp_endpoint(value, true)
        .map(|endpoint| normalize_tcp_source(endpoint, gateway_ports, is_local_forward))
}

fn normalize_tcp_source(
    mut endpoint: SocketEndpoint,
    gateway_ports: GatewayPorts,
    is_local_forward: bool,
) -> SocketEndpoint {
    let requested = endpoint.name.take().unwrap_or_default();
    let normalized = match (is_local_forward, gateway_ports) {
        (false, _) if requested == "*" || requested == "[*]" => String::new(),
        (false, _) if requested.is_empty() => "localhost".to_owned(),
        (false, _) => requested,
        (true, GatewayPorts::No) => "localhost".to_owned(),
        (true, GatewayPorts::Yes) => String::new(),
        (true, GatewayPorts::ClientSpecified) if requested == "*" || requested == "[*]" => {
            String::new()
        }
        (true, GatewayPorts::ClientSpecified) if requested.is_empty() => "localhost".to_owned(),
        (true, GatewayPorts::ClientSpecified) => requested,
    };
    endpoint.name = Some(normalized);
    endpoint
}

fn parse_destination_endpoint(value: &str) -> Option<SocketEndpoint> {
    parse_unix_endpoint(value).or_else(|| parse_tcp_endpoint(value, false))
}

fn parse_unix_endpoint(value: &str) -> Option<SocketEndpoint> {
    if !value.starts_with('/') || value == "/" || value.len() > 107 || value.contains('\0') {
        return None;
    }
    Some(SocketEndpoint {
        name: Some(value.to_owned()),
        port: None,
    })
}

fn parse_tcp_endpoint(value: &str, allow_empty_host: bool) -> Option<SocketEndpoint> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, port) = bracketed.split_once("]:")?;
        if (!allow_empty_host && host.is_empty()) || port.contains(':') {
            return None;
        }
        (host, port)
    } else {
        let (host, port) = value.rsplit_once(':')?;
        if host.is_empty() || host.contains(':') {
            return None;
        }
        (host, port)
    };
    Some(SocketEndpoint {
        name: Some(host.to_owned()),
        port: Some(parse_port(port)?),
    })
}

fn parse_port(value: &str) -> Option<i32> {
    let port = value.parse::<u16>().ok()?;
    (port != 0).then(|| i32::from(port))
}

#[cfg(test)]
mod tests {
    use std::process::{Command, ExitStatus};
    use std::time::Duration;

    use crate::ssh_process::SshOutput;

    use super::*;

    struct FakeRunner {
        stdout: Vec<u8>,
    }

    impl SshRunner for FakeRunner {
        fn run(&self, invocation: &SshInvocation, _: Deadline) -> Result<SshOutput, ClientError> {
            assert_eq!(
                invocation.args,
                ["-G", "-T", "-oPort=2222", "requested@server-alias"]
            );
            Ok(SshOutput {
                status: Some(success_status()),
                stdout: self.stdout.clone(),
            })
        }
    }

    fn success_status() -> ExitStatus {
        Command::new("true").status().unwrap()
    }

    #[test]
    fn ssh_config_hardening_query_does_not_suppress_forwardings() {
        let runner = FakeRunner {
            stdout: b"host server-alias\nuser config-user\nhostname 127.0.0.1\nport 22\n".to_vec(),
        };
        let resolved = resolve_ssh_config(
            &runner,
            "server-alias",
            Some("requested"),
            &["Port=2222".to_string()],
            true,
            true,
            Deadline::after(Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(
            resolved,
            ResolvedSshConfig {
                hostname: "127.0.0.1".to_string(),
                user: Some("config-user".to_string()),
                local_forwards: Vec::new(),
                remote_forwards: Vec::new(),
            }
        );
    }

    #[test]
    fn malformed_and_option_like_values_are_rejected() {
        assert!(matches!(
            parse_ssh_config(b"user somebody\n", true, true),
            Err(ClientError::SshConfigMalformed("hostname"))
        ));
        assert!(matches!(
            parse_ssh_config(b"hostname host\nuser -oProxyCommand=bad\n", true, true),
            Err(ClientError::InvalidSshComponent("user"))
        ));
    }

    #[test]
    fn parses_ordered_tcp_ipv6_unix_and_mixed_forwards() {
        let resolved = parse_ssh_config(
            b"hostname host\n\
              localforward 10022 [127.0.0.1]:22\n\
              localforward [::1]:18080 [::1]:80\n\
              localforward /tmp/local.sock /tmp/remote.sock\n\
              localforward /tmp/mixed.sock [127.0.0.1]:8080\n\
              localforward [127.0.0.1]:9090 /tmp/destination.sock\n\
              remoteforward 1492 [127.0.0.1]:1492\n",
            true,
            true,
        )
        .unwrap();

        assert_eq!(
            resolved.local_forwards,
            [
                request("localhost", Some(10022), "127.0.0.1", Some(22)),
                request("localhost", Some(18080), "::1", Some(80)),
                request("/tmp/local.sock", None, "/tmp/remote.sock", None),
                request("/tmp/mixed.sock", None, "127.0.0.1", Some(8080)),
                request("localhost", Some(9090), "/tmp/destination.sock", None,),
            ]
        );
        assert_eq!(
            resolved.remote_forwards,
            [request("localhost", Some(1492), "127.0.0.1", Some(1492))]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_config_hardening_normalizes_real_openssh_bind_shapes() {
        struct RemoveFile(std::path::PathBuf);
        impl Drop for RemoveFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "et-ssh-g-oracle-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("bind-policy")
        ));
        let _cleanup = RemoveFile(path.clone());
        let config = |gatewayports: &str| {
            format!(
                "Host oracle\n HostName localhost\n GatewayPorts {gatewayports}\n\
                 LocalForward *:15432 localhost:5432\n\
                 LocalForward :15433 localhost:5432\n\
                 LocalForward 127.0.0.2:15434 localhost:5432\n\
                 RemoteForward *:25432 localhost:5432\n\
                 RemoteForward :25433 localhost:5432\n\
                 RemoteForward 127.0.0.2:25434 localhost:5432\n"
            )
        };
        let query = |gatewayports: &str| {
            std::fs::write(&path, config(gatewayports)).unwrap();
            std::process::Command::new("ssh")
                .args(["-G", "-F"])
                .arg(&path)
                .arg("oracle")
                .output()
                .unwrap()
        };
        let parse_oracle = |gatewayports: &str| {
            let output = query(gatewayports);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            parse_ssh_config(&output.stdout, true, true).unwrap()
        };

        let no = parse_oracle("no");
        assert_eq!(
            no.local_forwards
                .iter()
                .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["localhost", "localhost", "localhost"]
        );
        assert_eq!(
            no.remote_forwards
                .iter()
                .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["", "localhost", "127.0.0.2"]
        );

        let yes = parse_oracle("yes");
        assert_eq!(
            yes.local_forwards
                .iter()
                .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["", "", ""]
        );
        assert_eq!(
            yes.remote_forwards
                .iter()
                .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["", "localhost", "127.0.0.2"]
        );

        let clientspecified = query("clientspecified");
        if clientspecified.status.success() {
            let resolved = parse_ssh_config(&clientspecified.stdout, true, true).unwrap();
            assert_eq!(
                resolved
                    .local_forwards
                    .iter()
                    .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                    .collect::<Vec<_>>(),
                ["", "localhost", "127.0.0.2"]
            );
        } else {
            assert!(
                String::from_utf8_lossy(&clientspecified.stderr).contains("unsupported option")
                    && String::from_utf8_lossy(&clientspecified.stderr).contains("clientspecified")
            );
        }
    }

    #[test]
    fn ssh_config_hardening_nonlocal_tcp_destinations_are_skipped_per_row() {
        let resolved = parse_ssh_config(
            b"hostname host\n\
              localforward 15432 db.internal:5432\n\
              localforward 15433 127.0.0.2:5432\n\
              localforward 15434 LocalHost:5432\n\
              remoteforward 25432 db.internal:5432\n\
              remoteforward 25433 [::1]:5432\n",
            true,
            true,
        )
        .unwrap();

        assert_eq!(
            resolved.local_forwards,
            [
                request("localhost", Some(15433), "127.0.0.2", Some(5432)),
                request("localhost", Some(15434), "LocalHost", Some(5432)),
            ]
        );
        assert_eq!(
            resolved.remote_forwards,
            [request("localhost", Some(25433), "::1", Some(5432))]
        );
    }

    #[test]
    fn rejects_forward_records_without_exactly_two_fields() {
        for (config, directive) in [
            ("hostname host\nlocalforward only-one\n", "localforward"),
            (
                "hostname host\nremoteforward 1000 host:2000 extra\n",
                "remoteforward",
            ),
        ] {
            assert!(matches!(
                parse_ssh_config(config.as_bytes(), true, true),
                Err(ClientError::SshConfigMalformedForward {
                    directive: found,
                    reason: "expected exactly two fields",
                }) if found == directive
            ));
        }
    }

    fn request(
        source_name: &str,
        source_port: Option<i32>,
        destination_name: &str,
        destination_port: Option<i32>,
    ) -> PortForwardSourceRequest {
        PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some(source_name.to_owned()),
                port: source_port,
            }),
            destination: Some(SocketEndpoint {
                name: Some(destination_name.to_owned()),
                port: destination_port,
            }),
            environmentvariable: None,
        }
    }
}
