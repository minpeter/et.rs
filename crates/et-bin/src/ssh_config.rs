use crate::bootstrap::{validate_ssh_destination, InvocationCompletion, SshInvocation};
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::ssh_process::{run_checked, SshRunner};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSshConfig {
    pub hostname: String,
    pub user: Option<String>,
    pub local_forwards: Vec<String>,
    pub remote_forwards: Vec<String>,
}

pub fn resolve_ssh_config(
    runner: &dyn SshRunner,
    host_alias: &str,
    requested_user: Option<&str>,
    ssh_options: &[String],
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
    parse_ssh_config(&run_checked(runner, &invocation, deadline)?)
}

fn parse_ssh_config(stdout: &[u8]) -> Result<ResolvedSshConfig, ClientError> {
    let text =
        std::str::from_utf8(stdout).map_err(|_| ClientError::SshConfigMalformed("UTF-8 output"))?;
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
            Some(key) if key.eq_ignore_ascii_case("localforward") => {
                local_forwards.push(parse_forward(fields));
            }
            Some(key) if key.eq_ignore_ascii_case("remoteforward") => {
                remote_forwards.push(parse_forward(fields));
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

fn parse_forward<'a>(fields: impl Iterator<Item = &'a str>) -> String {
    let fields: Vec<&str> = fields.collect();
    let [source, destination] = fields.as_slice() else {
        return fields.join(" ");
    };
    if source.starts_with('/') || destination.starts_with('/') || source.contains(':') {
        format!("{source}:{destination}")
    } else {
        format!("localhost:{source}:{destination}")
    }
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
    fn query_preserves_alias_and_parses_effective_values() {
        let runner = FakeRunner {
            stdout: b"host server-alias\nuser config-user\nhostname 127.0.0.1\nport 22\n".to_vec(),
        };
        let resolved = resolve_ssh_config(
            &runner,
            "server-alias",
            Some("requested"),
            &["Port=2222".to_string()],
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
            parse_ssh_config(b"user somebody\n"),
            Err(ClientError::SshConfigMalformed("hostname"))
        ));
        assert!(matches!(
            parse_ssh_config(b"hostname host\nuser -oProxyCommand=bad\n"),
            Err(ClientError::InvalidSshComponent("user"))
        ));
    }

    #[test]
    fn parses_ordered_tcp_ipv6_and_unix_forwards() {
        let resolved = parse_ssh_config(
            b"hostname host\n\
              localforward 10022 [127.0.0.1]:22\n\
              localforward [::1]:18080 [::1]:80\n\
              localforward /tmp/local.sock /tmp/remote.sock\n\
              remoteforward 1492 [127.0.0.1]:1492\n",
        )
        .unwrap();

        assert_eq!(
            resolved.local_forwards,
            [
                "localhost:10022:[127.0.0.1]:22",
                "[::1]:18080:[::1]:80",
                "/tmp/local.sock:/tmp/remote.sock",
            ]
        );
        assert_eq!(
            resolved.remote_forwards,
            ["localhost:1492:[127.0.0.1]:1492"]
        );
    }
}
