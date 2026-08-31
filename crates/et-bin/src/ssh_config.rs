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

#[derive(Clone, Copy)]
enum StreamLocalBindPolicy {
    Default,
    Unsupported,
}

#[derive(Clone, Copy)]
struct ForwardPolicies {
    gateway_ports: GatewayPorts,
    stream_local_bind: StreamLocalBindPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedSshConfig {
    pub hostname: String,
    pub user: Option<String>,
    pub local_forwards: Vec<PortForwardSourceRequest>,
    pub remote_forwards: Vec<PortForwardSourceRequest>,
}

enum ForwardRecord {
    Supported(PortForwardSourceRequest),
    Unsupported(String),
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
    let policies = ForwardPolicies {
        gateway_ports,
        stream_local_bind: StreamLocalBindPolicy::parse(text),
    };
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
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("dynamicforward") => {
                et_cli::logging::warn(
                    "SSH dynamicforward is unsupported by ET protocol v6; skipping forwarding row",
                );
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("localforward") => {
                match parse_forward(fields, "localforward", policies)? {
                    ForwardRecord::Supported(forward) => local_forwards.push(forward),
                    ForwardRecord::Unsupported(reason) => warn_unsupported("localforward", &reason),
                }
            }
            Some(key) if parse_remote_forwards && key.eq_ignore_ascii_case("remoteforward") => {
                match parse_forward(fields, "remoteforward", policies)? {
                    ForwardRecord::Supported(forward) => remote_forwards.push(forward),
                    ForwardRecord::Unsupported(reason) => {
                        warn_unsupported("remoteforward", &reason)
                    }
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

fn warn_unsupported(directive: &str, reason: &str) {
    et_cli::logging::warn(format!("SSH {directive} {reason}; skipping forwarding row"));
}

fn parse_forward<'a>(
    fields: impl Iterator<Item = &'a str>,
    directive: &'static str,
    policies: ForwardPolicies,
) -> Result<ForwardRecord, ClientError> {
    let fields: Vec<&str> = fields.collect();
    if fields.len() != 2 && fields.iter().any(|field| field.contains('/')) {
        return Ok(ForwardRecord::Unsupported(
            "ambiguous stream-local path is unsupported".to_owned(),
        ));
    }
    let [source, destination] = fields.as_slice() else {
        return Err(ClientError::SshConfigMalformedForward {
            directive,
            reason: "expected exactly two fields",
        });
    };
    if directive.eq_ignore_ascii_case("remoteforward") && *destination == "[socks]:0" {
        return Ok(ForwardRecord::Unsupported(
            "dynamic forwarding is unsupported".to_owned(),
        ));
    }
    if directive.eq_ignore_ascii_case("remoteforward") && endpoint_has_zero_port(source) {
        return Ok(ForwardRecord::Unsupported(
            "allocated remote port 0 is unsupported".to_owned(),
        ));
    }
    if is_relative_stream_path(source) || is_relative_stream_path(destination) {
        return Ok(ForwardRecord::Unsupported(
            "relative stream-local path is unsupported".to_owned(),
        ));
    }
    if source.starts_with('/') {
        match policies.stream_local_bind {
            StreamLocalBindPolicy::Default => {}
            StreamLocalBindPolicy::Unsupported => {
                return Ok(ForwardRecord::Unsupported(
                    "stream-local bind policy is unsupported".to_owned(),
                ));
            }
        }
        #[cfg(not(unix))]
        return Ok(ForwardRecord::Unsupported(
            "stream-local forwarding is unsupported on this platform".to_owned(),
        ));
    }
    #[cfg(not(unix))]
    if destination.starts_with('/') {
        return Ok(ForwardRecord::Unsupported(
            "stream-local forwarding is unsupported on this platform".to_owned(),
        ));
    }
    let source = parse_source_endpoint(
        source,
        policies.gateway_ports,
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
            return Ok(ForwardRecord::Unsupported(format!(
                "destination host '{host}' is unsupported by ET protocol v6"
            )));
        }
    }
    Ok(ForwardRecord::Supported(PortForwardSourceRequest {
        source: Some(source),
        destination: Some(destination),
        environmentvariable: None,
    }))
}

fn endpoint_has_zero_port(value: &str) -> bool {
    value == "0"
        || value
            .strip_suffix(":0")
            .is_some_and(|host| !host.is_empty())
}

fn is_relative_stream_path(value: &str) -> bool {
    !value.starts_with('/') && value.contains('/')
}

fn is_representable_tcp_destination(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<Ipv4Addr>()
            .is_ok_and(|address| address == Ipv4Addr::LOCALHOST)
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

impl StreamLocalBindPolicy {
    fn parse(text: &str) -> Self {
        let mut policy = Self::Default;
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next()) {
                (Some(key), Some(value))
                    if key.eq_ignore_ascii_case("streamlocalbindunlink")
                        && !value.eq_ignore_ascii_case("no") =>
                {
                    policy = Self::Unsupported;
                }
                (Some(key), Some(value))
                    if key.eq_ignore_ascii_case("streamlocalbindmask")
                        && value != "0177"
                        && value != "177" =>
                {
                    policy = Self::Unsupported;
                }
                _ => {}
            }
        }
        policy
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
    fn parses_supported_tcp_and_unix_destination_forwards() {
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
            [request("localhost", Some(15434), "LocalHost", Some(5432))]
        );
        assert_eq!(
            resolved.remote_forwards,
            [request("localhost", Some(25433), "::1", Some(5432))]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_config_hardening_real_openssh_defaults_preserve_absolute_unix_forwards() {
        // Given
        struct RemoveFile(std::path::PathBuf);
        impl Drop for RemoveFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "et-ssh-streamlocal-oracle-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("defaults")
        ));
        let _cleanup = RemoveFile(path.clone());
        std::fs::write(
            &path,
            "Host oracle\n HostName localhost\n\
             LocalForward /tmp/local.sock /tmp/local-destination.sock\n\
             RemoteForward /tmp/remote.sock /tmp/remote-destination.sock\n",
        )
        .unwrap();

        // When
        let output = std::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&path)
            .arg("oracle")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let resolved = parse_ssh_config(&output.stdout, true, true).unwrap();

        // Then
        assert_eq!(
            resolved.local_forwards,
            [request(
                "/tmp/local.sock",
                None,
                "/tmp/local-destination.sock",
                None,
            )]
        );
        assert_eq!(
            resolved.remote_forwards,
            [request(
                "/tmp/remote.sock",
                None,
                "/tmp/remote-destination.sock",
                None,
            )]
        );
    }

    #[test]
    fn ssh_config_hardening_emitted_nondefault_streamlocal_policy_skips_unix_sources() {
        // Given / When
        let unlink = parse_ssh_config(
            b"hostname host\nstreamlocalbindunlink yes\n\
              localforward /tmp/source.sock /tmp/destination.sock\n\
              localforward 15433 localhost:5432\n",
            true,
            true,
        )
        .unwrap();
        let mask = parse_ssh_config(
            b"hostname host\nstreamlocalbindmask 0077\n\
              remoteforward /tmp/source.sock /tmp/destination.sock\n\
              remoteforward 25433 localhost:5432\n",
            true,
            true,
        )
        .unwrap();

        // Then
        assert_eq!(
            unlink.local_forwards,
            [request("localhost", Some(15433), "localhost", Some(5432))]
        );
        assert_eq!(
            mask.remote_forwards,
            [request("localhost", Some(25433), "localhost", Some(5432))]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_config_hardening_real_openssh_unsupported_records_skip_per_row() {
        struct RemoveFile(std::path::PathBuf);
        impl Drop for RemoveFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "et-ssh-unsupported-oracle-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("records")
        ));
        let _cleanup = RemoveFile(path.clone());
        std::fs::write(
            &path,
            r#"Host oracle
 HostName localhost
 DynamicForward *:1080
 RemoteForward 2080
 RemoteForward 0 localhost:22
 LocalForward relative/source.sock /tmp/destination.sock
 LocalForward "/tmp/source path" "/tmp/destination path"
 LocalForward /tmp/source.sock /tmp/destination.sock
 LocalForward 15433 localhost:5432
 RemoteForward 25433 localhost:5432
"#,
        )
        .unwrap();
        let output = std::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&path)
            .arg("oracle")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let resolved = parse_ssh_config(&output.stdout, true, true).unwrap();

        assert_eq!(
            resolved.local_forwards,
            [
                request("/tmp/source.sock", None, "/tmp/destination.sock", None,),
                request("localhost", Some(15433), "localhost", Some(5432)),
            ]
        );
        assert_eq!(
            resolved.remote_forwards,
            [request("localhost", Some(25433), "localhost", Some(5432))]
        );
    }

    #[test]
    fn ssh_config_hardening_malformed_record_remains_typed() {
        assert!(matches!(
            parse_ssh_config(
                b"hostname host\nlocalforward 1000 localhost:22 unexpected\n",
                true,
                true,
            ),
            Err(ClientError::SshConfigMalformedForward {
                directive: "localforward",
                reason: "expected exactly two fields",
            })
        ));
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
