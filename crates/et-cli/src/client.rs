//! `et` client argument surface, matching upstream `TerminalClientMain.cpp`.
//!
//! The `--telemetry` flag is accepted for script compatibility but is a no-op:
//! et.rs never collects telemetry regardless of its value.

use clap::Parser;

pub const DEFAULT_PORT: u16 = 2022;
pub const MAX_KEEPALIVE: u32 = 5;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "et",
    version = concat!("version ", env!("CARGO_PKG_VERSION")),
    about = "Remote shell for the busy and impatient",
    long_about = "Connect to a remote shell over a persistent, reconnectable session."
)]
pub struct ClientArgs {
    #[arg(help = "[user@]host[:port] destination")]
    pub host: String,

    #[arg(short = 'u', long = "username")]
    pub username: Option<String>,

    #[arg(short = 'p', long = "port", default_value_t = DEFAULT_PORT)]
    pub port: u16,

    #[arg(short = 'c', long = "command")]
    pub command: Option<String>,

    #[arg(short = 'e', long = "noexit", alias = "no-exit")]
    pub no_exit: bool,

    #[arg(long = "terminal-path")]
    pub terminal_path: Option<String>,

    #[arg(short = 't', long = "tunnel", value_name = "SPEC")]
    pub tunnel: Vec<String>,

    #[arg(
        short = 'r',
        long = "reversetunnel",
        alias = "reverse-tunnel",
        value_name = "SPEC"
    )]
    pub reverse_tunnel: Vec<String>,

    #[arg(long = "jumphost")]
    pub jumphost: Option<String>,

    #[arg(long = "jport", default_value_t = DEFAULT_PORT)]
    pub jport: u16,

    #[arg(long = "jserverfifo")]
    pub jserverfifo: Option<String>,

    #[arg(short = 'x', long = "kill-other-sessions")]
    pub kill_other_sessions: bool,

    #[arg(
        long = "macserver",
        help = "Set when connecting to an macOS server.  Sets --terminal-path=/usr/local/bin/etterminal"
    )]
    pub macserver: bool,

    /// Bootstrap a Windows server, whose default shell is `cmd.exe` and has no
    /// `printf`. Also defaults `--terminal-path` to `et.exe`.
    #[arg(
        long = "winserver",
        help = "Set when connecting to a Windows server. Uses a cmd.exe-compatible bootstrap and sets --terminal-path=et.exe"
    )]
    pub winserver: bool,

    /// Grammar of the remote login shell, used for `--command` injection.
    /// Defaults to `posix`, or to `cmd` when `--winserver` is given.
    #[arg(long = "remote-shell", value_enum)]
    pub remote_shell: Option<RemoteShellKind>,

    #[arg(
        short = 'v',
        long = "verbose",
        value_name = "LEVEL",
        default_value_t = 0
    )]
    pub verbose: u8,

    #[arg(short = 'k', long = "keepalive", default_value_t = MAX_KEEPALIVE, value_parser = validate_keepalive)]
    pub keepalive: u32,

    #[arg(short = 'l', long = "logdir")]
    pub logdir: Option<String>,

    #[arg(long = "logtostdout")]
    pub logtostdout: bool,

    #[arg(long = "silent")]
    pub silent: bool,

    #[arg(short = 'N', long = "no-terminal")]
    pub no_terminal: bool,

    #[arg(short = 'f', long = "forward-ssh-agent")]
    pub forward_ssh_agent: bool,

    #[arg(long = "ssh-socket")]
    pub ssh_socket: Option<String>,

    #[arg(long = "serverfifo")]
    pub serverfifo: Option<String>,

    #[arg(long = "ssh-option", value_name = "OPT")]
    pub ssh_option: Vec<String>,

    /// Accepted for upstream compatibility; et.rs never collects telemetry.
    #[arg(
        long = "telemetry",
        num_args = 0..=1,
        default_value_t = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        hide = true
    )]
    pub telemetry: bool,
}

/// Remote login-shell grammar.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteShellKind {
    /// `sh`-family: `<cmd>; exit` terminated with LF.
    Posix,
    /// `cmd.exe`: `<cmd> & exit` terminated with CRLF.
    Cmd,
    /// PowerShell: `<cmd>; exit` terminated with CRLF.
    Powershell,
}

impl ClientArgs {
    /// Effective remote shell grammar.
    pub fn effective_remote_shell(&self) -> RemoteShellKind {
        self.remote_shell.unwrap_or({
            if self.winserver {
                RemoteShellKind::Cmd
            } else {
                RemoteShellKind::Posix
            }
        })
    }

    /// Whether the remote is a Windows host (cmd or PowerShell).
    pub fn remote_is_windows(&self) -> bool {
        matches!(
            self.effective_remote_shell(),
            RemoteShellKind::Cmd | RemoteShellKind::Powershell
        )
    }
    /// Effective etterminal path: `--terminal-path` wins over the platform
    /// shortcuts.
    pub fn effective_terminal_path(&self) -> Option<String> {
        if let Some(path) = &self.terminal_path {
            return Some(path.clone());
        }
        if self.macserver {
            return Some("/usr/local/bin/etterminal".to_owned());
        }
        if self.remote_is_windows() {
            return Some("et.exe".to_owned());
        }
        None
    }
}

fn validate_keepalive(s: &str) -> Result<u32, String> {
    let n: u32 = s.parse().map_err(|_| format!("`{s}` is not a number"))?;
    if !(1..=MAX_KEEPALIVE).contains(&n) {
        return Err(format!("keepalive must be between 1 and {MAX_KEEPALIVE}"));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_only_uses_default_port() {
        let a = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(a.host, "host");
        assert_eq!(a.port, DEFAULT_PORT);
    }

    #[test]
    fn port_override() {
        let a = ClientArgs::try_parse_from(["et", "host", "-p", "9999"]).unwrap();
        assert_eq!(a.port, 9999);
    }

    #[test]
    fn verbose_takes_an_integer_level_like_upstream() {
        let a = ClientArgs::try_parse_from(["et", "host", "-v", "3"]).unwrap();
        assert_eq!(a.verbose, 3);
        let a = ClientArgs::try_parse_from(["et", "host", "--verbose=2"]).unwrap();
        assert_eq!(a.verbose, 2);
        let a = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(a.verbose, 0);
    }

    #[test]
    fn keepalive_defaults_to_upstream_maximum() {
        let a = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(a.keepalive, MAX_KEEPALIVE);
    }

    #[test]
    fn upstream_long_flag_spellings_parse() {
        let a = ClientArgs::try_parse_from([
            "et",
            "host",
            "-c",
            "true",
            "--noexit",
            "--reversetunnel",
            "8080:80",
        ])
        .unwrap();
        assert!(a.no_exit);
        assert_eq!(a.reverse_tunnel.len(), 1);
    }

    #[test]
    fn remote_shell_overrides_and_defaults() {
        let a = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(a.effective_remote_shell(), RemoteShellKind::Posix);
        assert!(!a.remote_is_windows());
        let a = ClientArgs::try_parse_from(["et", "host", "--winserver"]).unwrap();
        assert_eq!(a.effective_remote_shell(), RemoteShellKind::Cmd);
        let a = ClientArgs::try_parse_from(["et", "host", "--remote-shell", "powershell"]).unwrap();
        assert_eq!(a.effective_remote_shell(), RemoteShellKind::Powershell);
        assert!(a.remote_is_windows());
        assert_eq!(a.effective_terminal_path().as_deref(), Some("et.exe"));
    }

    #[test]
    fn winserver_sets_the_default_terminal_path() {
        let a = ClientArgs::try_parse_from(["et", "host", "--winserver"]).unwrap();
        assert_eq!(a.effective_terminal_path().as_deref(), Some("et.exe"));
        let a = ClientArgs::try_parse_from([
            "et",
            "host",
            "--winserver",
            "--terminal-path",
            "C:/tools/et.exe",
        ])
        .unwrap();
        assert_eq!(
            a.effective_terminal_path().as_deref(),
            Some("C:/tools/et.exe")
        );
    }

    #[test]
    fn macserver_sets_the_default_terminal_path() {
        let a = ClientArgs::try_parse_from(["et", "host", "--macserver"]).unwrap();
        assert_eq!(
            a.effective_terminal_path().as_deref(),
            Some("/usr/local/bin/etterminal")
        );
        let a = ClientArgs::try_parse_from([
            "et",
            "host",
            "--macserver",
            "--terminal-path",
            "/opt/etterminal",
        ])
        .unwrap();
        assert_eq!(
            a.effective_terminal_path().as_deref(),
            Some("/opt/etterminal")
        );
    }

    #[test]
    fn keepalive_rejects_zero() {
        assert!(ClientArgs::try_parse_from(["et", "host", "-k", "0"]).is_err());
    }

    #[test]
    fn keepalive_rejects_above_max() {
        assert!(ClientArgs::try_parse_from(["et", "host", "-k", "6"]).is_err());
    }

    #[test]
    fn keepalive_accepts_bounds() {
        assert!(ClientArgs::try_parse_from(["et", "host", "-k", "1"]).is_ok());
        assert!(ClientArgs::try_parse_from(["et", "host", "-k", "5"]).is_ok());
    }

    #[test]
    fn no_terminal_flag() {
        let a = ClientArgs::try_parse_from(["et", "host", "-N"]).unwrap();
        assert!(a.no_terminal);
    }

    #[test]
    fn multiple_tunnels() {
        let a = ClientArgs::try_parse_from([
            "et",
            "host",
            "-t",
            "8080:remote:80",
            "-t",
            "9090:remote:90",
        ])
        .unwrap();
        assert_eq!(a.tunnel.len(), 2);
    }

    #[test]
    fn telemetry_flag_accepted_as_noop() {
        let a = ClientArgs::try_parse_from(["et", "host", "--telemetry"]).unwrap();
        assert!(a.telemetry);
        let a = ClientArgs::try_parse_from(["et", "host", "--telemetry", "false"]).unwrap();
        assert!(!a.telemetry);
    }

    #[test]
    fn requires_host_without_explicit_mode() {
        assert!(ClientArgs::try_parse_from(["et"]).is_err());
    }
}
