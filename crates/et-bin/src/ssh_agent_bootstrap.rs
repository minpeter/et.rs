//! Upstream #879: give the bootstrap ssh a temporary agent proxy so the
//! session-bind it sends can be replayed on forwarded agent connections.

use std::path::{Path, PathBuf};

use crate::bootstrap::Credentials;
use crate::bootstrap::SshInvocation;
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::ssh_process::{run_bootstrap, SshRunner};

/// Resolve the agent socket from an `ssh -G` dump, following OpenSSH
/// `IdentityAgent` rules (`none`, `SSH_AUTH_SOCK`, `$VAR`, or a path).
pub fn identity_agent_socket(dump: &str) -> Option<PathBuf> {
    let configured = dump.lines().find_map(|line| {
        let line = line.trim_end_matches('\r');
        line.strip_prefix("identityagent ").map(str::to_owned)
    });
    match configured.as_deref() {
        None | Some("SSH_AUTH_SOCK") => std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from),
        Some("none") | Some("") => None,
        Some(value) if value.starts_with('$') => {
            let name = &value[1..];
            if name.is_empty() {
                None
            } else {
                std::env::var_os(name).map(PathBuf::from)
            }
        }
        Some(value) => Some(PathBuf::from(value)),
    }
}

/// Prepend the recorder socket. OpenSSH keeps the first value of an option,
/// so these override config and `--ssh-option`. `ControlMaster=no` stops a
/// persisting master from inheriting the temporary proxy.
pub fn with_agent_recorder(invocation: &SshInvocation, socket: &Path) -> SshInvocation {
    let mut invocation = invocation.clone();
    invocation.args.splice(
        0..0,
        [
            format!("-oIdentityAgent={}", socket.display()),
            "-oControlMaster=no".to_owned(),
        ],
    );
    invocation
}

/// Run bootstrap ssh in front of a session-bind recorder when `capture` is
/// set. The jumphost binding, when present, belongs ahead of the destination
/// binding because that etserver relays the session.
pub fn run_capturing(
    runner: &dyn SshRunner,
    invocation: &SshInvocation,
    dump: &str,
    hop: &str,
    deadline: Deadline,
) -> Result<(Credentials, Option<Vec<u8>>), ClientError> {
    #[cfg(unix)]
    {
        capture_unix(runner, invocation, dump, hop, deadline)
    }
    #[cfg(not(unix))]
    {
        let _ = (dump, hop);
        Ok((run_bootstrap(runner, invocation, deadline)?, None))
    }
}

#[cfg(unix)]
fn capture_unix(
    runner: &dyn SshRunner,
    invocation: &SshInvocation,
    dump: &str,
    hop: &str,
    deadline: Deadline,
) -> Result<(Credentials, Option<Vec<u8>>), ClientError> {
    if dump.trim().is_empty() {
        et_cli::logging::warn(format!(
            "ssh -G failed; not recording ssh agent session binding for {hop}"
        ));
        return Ok((run_bootstrap(runner, invocation, deadline)?, None));
    }
    let upstream = identity_agent_socket(dump).unwrap_or_default();
    let recorder =
        match et_net::ssh_agent_session_bind::SshAgentSessionBindRecorder::start(&upstream) {
            Ok(recorder) => recorder,
            Err(error) => {
                et_cli::logging::warn(format!(
                    "Not recording ssh agent session binding for {hop}: {error}"
                ));
                return Ok((run_bootstrap(runner, invocation, deadline)?, None));
            }
        };
    let invocation = with_agent_recorder(invocation, recorder.socket_path());
    let credentials = run_bootstrap(runner, &invocation, deadline)?;
    let bind = recorder.last_forwarded_bind();
    if let Some(bind) = bind.as_deref() {
        let fingerprint = et_net::ssh_agent_session_bind::session_bind_host_key_fingerprint(bind)
            .unwrap_or_else(|| "?".to_owned());
        et_cli::logging::info(format!(
            "Recorded ssh agent session binding for {hop} host key {fingerprint}"
        ));
    } else {
        et_cli::logging::warn(format!(
            "ssh made no agent session binding for {hop} (it needs OpenSSH 8.9+ and a new connection rather than an existing ControlMaster); forwarded agent connections will not be bound to this hop"
        ));
    }
    Ok((credentials, bind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_agent_follows_openssh_rules() {
        let saved = std::env::var_os("SSH_AUTH_SOCK");
        std::env::set_var("SSH_AUTH_SOCK", "/tmp/env-agent");
        std::env::set_var("ET_TEST_AGENT", "/tmp/var-agent");
        assert_eq!(
            identity_agent_socket("hostname host\n").as_deref(),
            Some(Path::new("/tmp/env-agent"))
        );
        assert_eq!(
            identity_agent_socket("identityagent SSH_AUTH_SOCK\n").as_deref(),
            Some(Path::new("/tmp/env-agent"))
        );
        assert!(identity_agent_socket("identityagent none\n").is_none());
        assert_eq!(
            identity_agent_socket("identityagent /tmp/agent space\n").as_deref(),
            Some(Path::new("/tmp/agent space"))
        );
        assert_eq!(
            identity_agent_socket("identityagent $ET_TEST_AGENT\n").as_deref(),
            Some(Path::new("/tmp/var-agent"))
        );
        match saved {
            Some(value) => std::env::set_var("SSH_AUTH_SOCK", value),
            None => std::env::remove_var("SSH_AUTH_SOCK"),
        }
        std::env::remove_var("ET_TEST_AGENT");
    }

    #[test]
    fn recorder_options_are_prepended_so_they_win() {
        let invocation = SshInvocation {
            program: "ssh".to_owned(),
            args: vec!["-oControlMaster=yes".to_owned(), "host".to_owned()],
            operation: "testing bootstrap",
            completion: crate::bootstrap::InvocationCompletion::Credentials,
            control_path: None,
        };
        let updated = with_agent_recorder(&invocation, Path::new("/tmp/recorder.sock"));
        assert_eq!(
            updated.args[..2],
            [
                "-oIdentityAgent=/tmp/recorder.sock".to_owned(),
                "-oControlMaster=no".to_owned(),
            ]
        );
        assert_eq!(updated.args[2], "-oControlMaster=yes");
    }
}
