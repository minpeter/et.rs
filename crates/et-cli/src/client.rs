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
    version,
    about = "EternalTerminal client (Rust port)",
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

    #[arg(short = 'e', long = "no-exit")]
    pub no_exit: bool,

    #[arg(long = "terminal-path")]
    pub terminal_path: Option<String>,

    #[arg(short = 't', long = "tunnel", value_name = "SPEC")]
    pub tunnel: Vec<String>,

    #[arg(short = 'r', long = "reverse-tunnel", value_name = "SPEC")]
    pub reverse_tunnel: Vec<String>,

    #[arg(long = "jumphost")]
    pub jumphost: Option<String>,

    #[arg(long = "jport", default_value_t = DEFAULT_PORT)]
    pub jport: u16,

    #[arg(long = "jserverfifo")]
    pub jserverfifo: Option<String>,

    #[arg(short = 'x', long = "kill-other-sessions")]
    pub kill_other_sessions: bool,

    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(short = 'k', long = "keepalive", default_value_t = 1, value_parser = validate_keepalive)]
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

    #[arg(long = "telemetry", default_value_t = false, hide = true)]
    pub telemetry: bool,
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
    fn verbose_count_accumulates() {
        let a = ClientArgs::try_parse_from(["et", "host", "-vvv"]).unwrap();
        assert_eq!(a.verbose, 3);
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
    }

    #[test]
    fn requires_host_without_explicit_mode() {
        assert!(ClientArgs::try_parse_from(["et"]).is_err());
    }
}
