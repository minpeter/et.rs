//! `et` client argument surface, matching upstream `TerminalClientMain.cpp`.
//!
//! The `--telemetry` flag is accepted for script compatibility but is a no-op:
//! et.rs never collects telemetry regardless of its value.

use clap::{CommandFactory, Parser};

pub const DEFAULT_PORT: u16 = 2022;
pub const MAX_KEEPALIVE: u32 = 5;

#[derive(clap::Args, Debug, Clone)]
#[command(
    name = "et",
    disable_version_flag = true,
    args_override_self = true,
    version = crate::VERSION,
    long_version = crate::LONG_VERSION,
    about = "Remote shell for the busy and impatient",
    long_about = "Connect to a remote shell over a persistent, reconnectable session."
)]
pub struct ClientArgs {
    #[arg(
        help = "[user@]host[:port] destination",
        required_unless_present_any = ["list_sessions", "attach", "kill_named", "ssh_version", "version", "control_command"]
    )]
    pub host: Option<String>,

    #[arg(hide = true, allow_hyphen_values = true)]
    pub command_operands: Vec<String>,

    #[arg(long, action = clap::ArgAction::Version)]
    pub version: Option<bool>,

    #[arg(short = 'V', help = "Print an OpenSSH-compatible version and exit")]
    pub ssh_version: bool,

    #[arg(
        short = 'G',
        help = "Print resolved SSH configuration without connecting"
    )]
    pub print_config: bool,

    #[arg(short = 'p', value_parser = clap::value_parser!(u16).range(1..))]
    pub ssh_port: Option<u16>,

    #[arg(short = 'l')]
    pub login_name: Option<String>,

    #[arg(short = 'c')]
    pub cipher: Option<String>,

    #[arg(short = 'e')]
    pub escape_char: Option<String>,

    #[arg(short = 'i')]
    pub identity_files: Vec<String>,

    #[arg(short = 'x')]
    pub disable_x11: bool,

    #[arg(short = 'f')]
    pub background: bool,

    #[arg(short = 't', overrides_with = "no_pty")]
    pub force_pty: bool,

    #[arg(short = 'N')]
    pub no_remote_command: bool,

    #[arg(short = 'v', action = clap::ArgAction::Count)]
    pub verbose_count: u8,

    #[arg(short = 'o', value_name = "OPTION")]
    pub session_options: Vec<String>,

    #[arg(short = 'M')]
    pub master: bool,

    #[arg(short = 'S')]
    pub control_path: Option<String>,

    #[arg(short = 'O')]
    pub control_command: Option<String>,

    #[arg(skip)]
    pub control_master: Option<ControlMasterMode>,

    #[arg(skip)]
    pub control_persist: Option<ControlPersist>,

    #[arg(long)]
    pub ctl: bool,

    #[arg(long)]
    pub ctl_socket: Option<String>,

    #[arg(long)]
    pub no_persist: bool,

    #[arg(skip)]
    pub keepalive_explicit: bool,

    #[arg(short = 'u', long = "username")]
    pub username: Option<String>,

    #[arg(long = "port", default_value_t = DEFAULT_PORT)]
    pub port: u16,

    #[arg(long = "command")]
    pub command: Option<String>,

    #[arg(long = "noexit", alias = "no-exit")]
    pub no_exit: bool,

    #[arg(long = "terminal-path")]
    pub terminal_path: Option<String>,

    #[arg(short = 'L', long = "tunnel", value_name = "SPEC")]
    pub tunnel: Vec<String>,

    #[arg(
        short = 'r',
        short_alias = 'R',
        long = "reversetunnel",
        alias = "reverse-tunnel",
        value_name = "SPEC"
    )]
    pub reverse_tunnel: Vec<String>,

    /// Listen for SOCKS4/SOCKS5 clients and open the destination they choose
    /// after connect (ssh -D). May be repeated.
    #[arg(
        short = 'D',
        long = "dynamic",
        value_name = "[BIND:]PORT",
        help = "Dynamic SOCKS port forward, chosen after connect (ssh -D)"
    )]
    pub dynamic: Vec<String>,

    /// Tie stdin/stdout to a remote destination with no pty and no shell (ssh -W).
    #[arg(
        short = 'W',
        long = "stdio-forward",
        value_name = "HOST:PORT",
        help = "Forward stdio to host:port without a remote shell (ssh -W)"
    )]
    pub stdio_forward: Option<String>,

    #[arg(short = 'j', short_alias = 'J', long = "jumphost")]
    pub jumphost: Option<String>,

    #[arg(long = "jport", default_value_t = DEFAULT_PORT)]
    pub jport: u16,

    #[arg(long = "jserverfifo")]
    pub jserverfifo: Option<String>,

    #[arg(long = "kill-other-sessions")]
    pub kill_other_sessions: bool,

    /// Save this direct session under `~/.et/sessions/<name>`.
    #[arg(long = "name", value_name = "NAME")]
    pub session_name: Option<String>,

    /// Reattach a saved session without SSH bootstrap.
    #[arg(
        long = "attach",
        value_name = "NAME",
        conflicts_with_all = ["session_name", "list_sessions", "kill_named"]
    )]
    pub attach: Option<String>,

    /// List saved sessions. The passkey is not printed.
    #[arg(
        long = "list",
        conflicts_with_all = ["session_name", "attach", "kill_named"]
    )]
    pub list_sessions: bool,

    /// Ask etterminal to end a saved session.
    #[arg(
        long = "kill",
        value_name = "NAME",
        conflicts_with_all = ["session_name", "attach", "list_sessions"]
    )]
    pub kill_named: Option<String>,

    /// Per-session disconnect timeout in minutes. 0 disables the timeout.
    #[arg(
        long = "disconnect-timeout",
        value_name = "MINUTES",
        value_parser = parse_disconnect_minutes
    )]
    pub disconnect_timeout: Option<i64>,

    /// Terminate the remote session when this terminal receives SIGHUP or closes.
    ///
    /// Off by default: a local hangup leaves the remote session running.
    #[arg(
        long = "close-on-hangup",
        help = "terminate the remote session when this terminal receives SIGHUP or closes"
    )]
    pub close_on_hangup: bool,

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

    #[arg(long = "verbose", value_name = "LEVEL", default_value_t = 0)]
    pub verbose: u8,

    #[arg(short = 'k', long = "keepalive", default_value_t = MAX_KEEPALIVE, value_parser = validate_keepalive)]
    pub keepalive: u32,

    #[arg(long = "logdir")]
    pub logdir: Option<String>,

    #[arg(
        long = "flow-control",
        value_enum,
        default_value_t = FlowControlMode::None,
        help = "Bound terminal output when it outruns the network",
        long_help = "Choose how terminal output behaves when it outruns the network.\n\n\
                     none preserves the existing replay behavior. backpressure pauses the remote \
                     producer at a bounded queue without losing output. discard drops the oldest \
                     terminal output while preserving control traffic so the display stays current."
    )]
    pub flow_control: FlowControlMode,

    #[arg(long = "logtostdout")]
    pub logtostdout: bool,

    #[arg(long = "silent")]
    pub silent: bool,

    #[arg(long = "no-terminal")]
    pub no_terminal: bool,

    /// Run a command on pipes instead of a pty: binary stdio, separate stderr, no
    /// shell injection. Matches EternalTerminal `-T` / `--no-pty`.
    #[arg(
        short = 'T',
        long = "no-pty",
        overrides_with = "force_pty",
        help = "Run command on pipes instead of a pty (binary stdio, separate stderr, no shell injection)"
    )]
    pub no_pty: bool,

    #[arg(long = "forward-ssh-agent")]
    pub forward_ssh_agent: bool,

    #[arg(long = "ssh-socket")]
    pub ssh_socket: Option<String>,

    #[arg(long = "serverfifo")]
    pub serverfifo: Option<String>,

    #[arg(long = "ssh-option", value_name = "OPT")]
    pub ssh_option: Vec<String>,

    /// Read only this absolute SSH configuration file (or `none`).
    #[arg(
        short = 'F',
        long = "ssh-config",
        value_name = "PATH",
        conflicts_with = "no_ssh_config"
    )]
    pub ssh_config: Option<String>,

    /// Do not read user or system SSH configuration for the destination or jumphost.
    #[arg(long = "no-ssh-config", conflicts_with = "ssh_config")]
    pub no_ssh_config: bool,

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

fn parse_disconnect_minutes(raw: &str) -> Result<i64, String> {
    let minutes: i64 = raw
        .parse()
        .map_err(|_| "disconnect timeout must be a number of minutes".to_owned())?;
    if minutes < 0 {
        return Err("disconnect timeout cannot be negative".to_owned());
    }
    let seconds = minutes
        .checked_mul(60)
        .ok_or_else(|| "disconnect timeout overflows".to_owned())?;
    i32::try_from(seconds).map_err(|_| "disconnect timeout overflows".to_owned())?;
    Ok(minutes)
}

impl ClientArgs {
    /// Stop option parsing at the destination, just like OpenSSH. In particular,
    /// `host echo -v` must not change local verbosity.
    pub fn try_parse_from<I, T>(values: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let values: Vec<std::ffi::OsString> = values.into_iter().map(Into::into).collect();
        let mut command = Self::command();
        command.build();
        let mut normalized = values.first().cloned().into_iter().collect::<Vec<_>>();
        let mut index = 1;
        while index < values.len() {
            let token = values[index].to_string_lossy();
            if token == "--" {
                normalized.extend_from_slice(&values[index..]);
                break;
            }
            if !token.starts_with('-') || token == "-" {
                normalized.push("--".into());
                normalized.extend_from_slice(&values[index..]);
                break;
            }
            if let Some(long) = token.strip_prefix("--") {
                let name = long.split('=').next().unwrap_or(long);
                if let Some(arg) = command.get_arguments().find(|arg| {
                    arg.get_long() == Some(name)
                        || arg
                            .get_all_aliases()
                            .is_some_and(|aliases| aliases.contains(&name))
                }) {
                    normalized.push(values[index].clone());
                    if !long.contains('=')
                        && arg.get_action().takes_values()
                        && index + 1 < values.len()
                    {
                        index += 1;
                        normalized.push(values[index].clone());
                    }
                }
            } else {
                let mut chars = token[1..].char_indices().peekable();
                while let Some((offset, short)) = chars.next() {
                    let arg = command.get_arguments().find(|arg| {
                        arg.get_short() == Some(short)
                            || arg
                                .get_all_short_aliases()
                                .is_some_and(|aliases| aliases.contains(&short))
                    });
                    // The canonical upstream pre-pass consumes unsupported SSH
                    // value options too, so their operands never become a host.
                    let takes_value = arg.is_some_and(|arg| arg.get_action().takes_values())
                        || "BbEImPQw".contains(short);
                    if arg.is_some() {
                        normalized.push(format!("-{short}").into());
                    }
                    if takes_value {
                        let value = if chars.peek().is_some() {
                            Some(std::ffi::OsString::from(
                                &token[1 + offset + short.len_utf8()..],
                            ))
                        } else {
                            index += 1;
                            values.get(index).cloned()
                        };
                        let value = value.ok_or_else(|| {
                            clap::Error::raw(
                                clap::error::ErrorKind::InvalidValue,
                                format!("-{short} requires an argument"),
                            )
                        })?;
                        if arg.is_some() {
                            normalized.push(value);
                        }
                        break;
                    }
                }
            }
            index += 1;
        }
        let matches = command.try_get_matches_from(normalized)?;
        let mut parsed = <Self as clap::FromArgMatches>::from_arg_matches(&matches)?;
        if !parsed.command_operands.is_empty() {
            parsed.command = Some(parsed.command_operands.join(" "));
        }
        if matches.value_source("verbose") != Some(clap::parser::ValueSource::CommandLine) {
            parsed.verbose = parsed.verbose_count;
        }
        parsed.keepalive_explicit =
            matches.value_source("keepalive") == Some(clap::parser::ValueSource::CommandLine);
        if let Some(login) = &parsed.login_name {
            parsed.username = Some(login.clone());
        }
        let mut controls = Vec::new();
        if parsed.master {
            controls.push((matches.index_of("master").unwrap(), "ControlMaster", "yes"));
        }
        if let Some(path) = parsed.control_path.as_deref() {
            controls.push((
                matches.index_of("control_path").unwrap(),
                "ControlPath",
                path,
            ));
        }
        if let Some(indices) = matches.indices_of("session_options") {
            for (index, option) in indices.zip(&parsed.session_options) {
                let (key, value) = split_ssh_option(option);
                controls.push((index, key, value));
            }
        }
        controls.sort_by_key(|(index, _, _)| *index);
        let mut path = parsed.control_path.clone();
        for (_, key, value) in controls {
            let invalid =
                |message| clap::Error::raw(clap::error::ErrorKind::ValueValidation, message);
            if key.eq_ignore_ascii_case("ControlMaster") {
                parsed.control_master = Some(value.parse().map_err(invalid)?);
            } else if key.eq_ignore_ascii_case("ControlPersist") {
                parsed.control_persist = Some(value.parse().map_err(invalid)?);
            } else if key.eq_ignore_ascii_case("ControlPath") {
                path = Some(value.to_owned());
            }
        }
        parsed.control_path = path;
        if let Some(command) = &mut parsed.control_command {
            command.make_ascii_lowercase();
        }
        parsed.no_pty &= !parsed.no_remote_command;
        if parsed.no_pty && parsed.stdio_forward.is_some() {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                "-W/--stdio-forward cannot be combined with -T/--no-pty",
            ));
        }
        Ok(parsed)
    }

    /// Seconds to put in `InitialPayload.disconnect_timeout_seconds`.
    ///
    /// `None` leaves the field unset. `Some(0)` is an explicit "no timeout".
    pub fn disconnect_timeout_seconds(&self) -> Option<i32> {
        self.disconnect_timeout
            .map(|minutes| i32::try_from(minutes * 60).expect("parser rejected overflow"))
    }
}

impl CommandFactory for ClientArgs {
    fn command() -> clap::Command {
        <Self as clap::Args>::augment_args(clap::Command::new("et"))
    }

    fn command_for_update() -> clap::Command {
        <Self as clap::Args>::augment_args_for_update(clap::Command::new("et"))
    }
}

impl Parser for ClientArgs {
    fn try_parse_from<I, T>(values: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::try_parse_from(values)
    }

    fn parse_from<I, T>(values: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::try_parse_from(values).unwrap_or_else(|error| error.exit())
    }

    fn try_parse() -> Result<Self, clap::Error> {
        Self::try_parse_from(std::env::args_os())
    }

    fn parse() -> Self {
        Self::parse_from(std::env::args_os())
    }
}

/// Split an OpenSSH option, accepting both `Key=value` and `Key value`.
pub fn split_ssh_option(option: &str) -> (&str, &str) {
    let option = option.trim();
    let end = option
        .find(|c: char| c == '=' || c.is_whitespace())
        .unwrap_or(option.len());
    let (key, rest) = option.split_at(end);
    (key, rest.trim_start().trim_start_matches('=').trim_start())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlMasterMode {
    No,
    Yes,
    Auto,
}

impl std::str::FromStr for ControlMasterMode {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "no" | "false" => Ok(Self::No),
            "yes" | "true" => Ok(Self::Yes),
            "auto" => Ok(Self::Auto),
            _ => Err(format!("invalid ControlMaster: {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlPersist {
    pub enabled: bool,
    /// Zero means indefinitely when enabled.
    pub seconds: u64,
}

impl std::str::FromStr for ControlPersist {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "no" | "false" => Ok(Self {
                enabled: false,
                seconds: 0,
            }),
            "yes" | "true" => Ok(Self {
                enabled: true,
                seconds: 0,
            }),
            _ => value
                .parse()
                .map(|seconds| Self {
                    enabled: true,
                    seconds,
                })
                .map_err(|_| format!("invalid ControlPersist: {value}")),
        }
    }
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

/// Terminal-output behavior when the producer outruns the network.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FlowControlMode {
    /// Preserve the existing unbounded replay behavior.
    #[default]
    None,
    /// Pause the terminal producer while the bounded output queue is full.
    Backpressure,
    /// Drop the oldest queued terminal output to keep the display current.
    Discard,
}

impl FlowControlMode {
    /// Optional protobuf value; `none` stays absent for legacy wire parity.
    pub const fn protocol_value(self) -> Option<i32> {
        match self {
            Self::None => None,
            Self::Backpressure => Some(et_core::proto::FlowControlMode::Backpressure as i32),
            Self::Discard => Some(et_core::proto::FlowControlMode::Discard as i32),
        }
    }
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
    fn ignored_ssh_options_never_turn_their_operands_into_hosts() {
        let args = <ClientArgs as Parser>::try_parse_from([
            "et",
            "-4q",
            "-B",
            "interface",
            "-Elogfile",
            "-m",
            "hmac",
            "--unknown=ignored",
            "host",
            "-B",
            "remote",
        ])
        .unwrap();
        assert_eq!(args.host.as_deref(), Some("host"));
        assert_eq!(args.command.as_deref(), Some("-B remote"));
        assert!(ClientArgs::try_parse_from(["et", "-B"]).is_err());
        assert_eq!(
            ClientArgs::try_parse_from(["et", "--help"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::DisplayHelp
        );
        let forward =
            ClientArgs::try_parse_from(["et", "-NT", "-W", "localhost:80", "host"]).unwrap();
        assert!(!forward.no_pty);
    }

    #[test]
    fn host_boundary_preserves_remote_operands_and_overrides_command_flag() {
        let args = ClientArgs::try_parse_from([
            "et",
            "--command",
            "ignored",
            "-v",
            "host",
            "printf",
            "a b",
            "--port",
            "7",
            "-v",
            "--",
        ])
        .unwrap();
        assert_eq!(args.command.as_deref(), Some("printf a b --port 7 -v --"));
        assert_eq!(args.port, DEFAULT_PORT);
        assert_eq!(args.verbose, 1);
        let escaped = ClientArgs::try_parse_from(["et", "--", "-host", "-V"]).unwrap();
        assert_eq!(escaped.host.as_deref(), Some("-host"));
        assert!(!escaped.ssh_version);
        assert_eq!(escaped.command.as_deref(), Some("-V"));
    }

    #[test]
    fn short_flags_have_openssh_meanings_and_last_pty_override_wins() {
        let args = ClientArgs::try_parse_from([
            "et",
            "-fx",
            "-luser",
            "-c",
            "aes256-ctr",
            "-e",
            "none",
            "-i",
            "/tmp/key",
            "-Tt",
            "-Jfirst",
            "--jumphost",
            "second",
            "-N",
            "host",
        ])
        .unwrap();
        assert!(args.background && args.disable_x11 && args.force_pty && args.no_remote_command);
        assert!(
            !args.forward_ssh_agent && !args.kill_other_sessions && !args.no_exit && !args.no_pty
        );
        assert_eq!(args.username.as_deref(), Some("user"));
        assert_eq!(args.cipher.as_deref(), Some("aes256-ctr"));
        assert_eq!(args.identity_files, ["/tmp/key"]);
        assert_eq!(args.jumphost.as_deref(), Some("second"));
        assert!(
            ClientArgs::try_parse_from(["et", "-tT", "host", "true"])
                .unwrap()
                .no_pty
        );
    }

    #[test]
    fn mux_controls_are_ordered_and_queries_do_not_require_a_host() {
        let args = ClientArgs::try_parse_from([
            "et",
            "-M",
            "-oControlMaster=auto",
            "-S/tmp/first",
            "-o",
            "ControlPath = /tmp/second",
            "-oControlPersist=37",
            "-O",
            "CHECK",
        ])
        .unwrap();
        assert_eq!(args.control_master, Some(ControlMasterMode::Auto));
        assert_eq!(args.control_path.as_deref(), Some("/tmp/second"));
        assert_eq!(
            args.control_persist,
            Some(ControlPersist {
                enabled: true,
                seconds: 37
            })
        );
        assert_eq!(args.control_command.as_deref(), Some("check"));
        let later =
            ClientArgs::try_parse_from(["et", "-oControlMaster=no", "-M", "-Ocheck"]).unwrap();
        assert_eq!(later.control_master, Some(ControlMasterMode::Yes));
        assert!(
            ClientArgs::try_parse_from(["et", "-V"])
                .unwrap()
                .ssh_version
        );
        assert_eq!(
            ClientArgs::try_parse_from(["et", "--version"])
                .unwrap_err()
                .kind(),
            clap::error::ErrorKind::DisplayVersion
        );
        assert!(ClientArgs::try_parse_from(["et", "-oControlPersist=-1", "host"]).is_err());
        assert!(ClientArgs::try_parse_from(["et", "-G"]).is_err());
    }

    #[test]
    fn host_only_uses_default_port() {
        let a = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(a.host.as_deref(), Some("host"));
        assert_eq!(a.port, DEFAULT_PORT);
    }

    #[test]
    fn port_override() {
        let a = ClientArgs::try_parse_from(["et", "--port", "9999", "-p2200", "host"]).unwrap();
        assert_eq!(a.port, 9999);
        assert_eq!(a.ssh_port, Some(2200));
    }

    #[test]
    fn verbose_takes_an_integer_level_like_upstream() {
        let a = ClientArgs::try_parse_from(["et", "-vvv", "host"]).unwrap();
        assert_eq!(a.verbose, 3);
        let a = ClientArgs::try_parse_from(["et", "--verbose=2", "-vvv", "host"]).unwrap();
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
    fn flow_control_defaults_to_none() {
        let a = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert_eq!(a.flow_control, FlowControlMode::None);
    }

    #[test]
    fn flow_control_parses_opt_in_modes() {
        let backpressure =
            ClientArgs::try_parse_from(["et", "--flow-control", "backpressure", "host"]).unwrap();
        assert_eq!(backpressure.flow_control, FlowControlMode::Backpressure);

        let discard =
            ClientArgs::try_parse_from(["et", "--flow-control", "discard", "host"]).unwrap();
        assert_eq!(discard.flow_control, FlowControlMode::Discard);
    }

    #[test]
    fn no_pty_flag_parses_with_command() {
        let raw = ClientArgs::try_parse_from(["et", "-T", "host", "printf", "ok"]).unwrap();
        assert!(raw.no_pty);
        assert_eq!(raw.command.as_deref(), Some("printf ok"));
        let long =
            ClientArgs::try_parse_from(["et", "--no-pty", "--command", "true", "host"]).unwrap();
        assert!(long.no_pty);
    }

    #[test]
    fn upstream_long_flag_spellings_parse() {
        let a = ClientArgs::try_parse_from([
            "et",
            "--command",
            "true",
            "--noexit",
            "--reversetunnel",
            "8080:80",
            "host",
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
        let a = ClientArgs::try_parse_from(["et", "--winserver", "host"]).unwrap();
        assert_eq!(a.effective_remote_shell(), RemoteShellKind::Cmd);
        let a = ClientArgs::try_parse_from(["et", "--remote-shell", "powershell", "host"]).unwrap();
        assert_eq!(a.effective_remote_shell(), RemoteShellKind::Powershell);
        assert!(a.remote_is_windows());
        assert_eq!(a.effective_terminal_path().as_deref(), Some("et.exe"));
    }

    #[test]
    fn winserver_sets_the_default_terminal_path() {
        let a = ClientArgs::try_parse_from(["et", "--winserver", "host"]).unwrap();
        assert_eq!(a.effective_terminal_path().as_deref(), Some("et.exe"));
        let a = ClientArgs::try_parse_from([
            "et",
            "--winserver",
            "--terminal-path",
            "C:/tools/et.exe",
            "host",
        ])
        .unwrap();
        assert_eq!(
            a.effective_terminal_path().as_deref(),
            Some("C:/tools/et.exe")
        );
    }

    #[test]
    fn macserver_sets_the_default_terminal_path() {
        let a = ClientArgs::try_parse_from(["et", "--macserver", "host"]).unwrap();
        assert_eq!(
            a.effective_terminal_path().as_deref(),
            Some("/usr/local/bin/etterminal")
        );
        let a = ClientArgs::try_parse_from([
            "et",
            "--macserver",
            "--terminal-path",
            "/opt/etterminal",
            "host",
        ])
        .unwrap();
        assert_eq!(
            a.effective_terminal_path().as_deref(),
            Some("/opt/etterminal")
        );
    }

    #[test]
    fn keepalive_rejects_zero() {
        assert!(ClientArgs::try_parse_from(["et", "-k", "0", "host"]).is_err());
    }

    #[test]
    fn keepalive_rejects_above_max() {
        assert!(ClientArgs::try_parse_from(["et", "-k", "6", "host"]).is_err());
    }

    #[test]
    fn keepalive_accepts_bounds() {
        assert!(ClientArgs::try_parse_from(["et", "-k", "1", "host"]).is_ok());
        assert!(ClientArgs::try_parse_from(["et", "-k", "5", "host"]).is_ok());
    }

    #[test]
    fn no_terminal_flag() {
        let a = ClientArgs::try_parse_from(["et", "--no-terminal", "host"]).unwrap();
        assert!(a.no_terminal);
    }

    #[test]
    fn close_on_hangup_defaults_off_and_parses() {
        let off = ClientArgs::try_parse_from(["et", "host"]).unwrap();
        assert!(!off.close_on_hangup);
        let on = ClientArgs::try_parse_from(["et", "--close-on-hangup", "host"]).unwrap();
        assert!(on.close_on_hangup);
    }

    #[test]
    fn dynamic_and_stdio_forwards_parse_and_w_conflicts_with_no_pty() {
        let dynamic =
            ClientArgs::try_parse_from(["et", "-D", "1080", "-D", "[::1]:1081", "host"]).unwrap();
        assert_eq!(dynamic.dynamic, ["1080", "[::1]:1081"]);
        assert!(dynamic.stdio_forward.is_none());
        let stdio = ClientArgs::try_parse_from(["et", "-W", "127.0.0.1:9", "host"]).unwrap();
        assert_eq!(stdio.stdio_forward.as_deref(), Some("127.0.0.1:9"));
        assert!(ClientArgs::try_parse_from(["et", "-W", "h:1", "-T", "host", "id"]).is_err());
    }

    #[test]
    fn multiple_tunnels() {
        let a = ClientArgs::try_parse_from([
            "et",
            "-L",
            "8080:remote:80",
            "--tunnel",
            "9090:remote:90",
            "host",
        ])
        .unwrap();
        assert_eq!(a.tunnel.len(), 2);
    }

    #[test]
    fn telemetry_flag_accepted_as_noop() {
        let a = ClientArgs::try_parse_from(["et", "--telemetry=true", "host"]).unwrap();
        assert!(a.telemetry);
        let a = ClientArgs::try_parse_from(["et", "--telemetry", "false", "host"]).unwrap();
        assert!(!a.telemetry);
    }

    #[test]
    fn requires_host_without_explicit_mode() {
        assert!(ClientArgs::try_parse_from(["et"]).is_err());
        assert!(ClientArgs::try_parse_from(["et", "--list"]).is_ok());
        let named = ClientArgs::try_parse_from(["et", "--kill", "work"]).unwrap();
        assert_eq!(named.kill_named.as_deref(), Some("work"));
        assert!(!named.kill_other_sessions);
        let timeout =
            ClientArgs::try_parse_from(["et", "--disconnect-timeout", "2", "host"]).unwrap();
        assert_eq!(timeout.disconnect_timeout_seconds(), Some(120));
        assert!(ClientArgs::try_parse_from(["et", "--disconnect-timeout", "-1", "host"]).is_err());
    }

    #[test]
    fn ssh_config_and_no_ssh_config_parse() {
        let selected =
            ClientArgs::try_parse_from(["et", "--ssh-config", "/etc/et/ssh_config", "host"])
                .unwrap();
        assert_eq!(selected.ssh_config.as_deref(), Some("/etc/et/ssh_config"));
        assert!(!selected.no_ssh_config);

        let none = ClientArgs::try_parse_from(["et", "-F", "none", "host"]).unwrap();
        assert_eq!(none.ssh_config.as_deref(), Some("none"));
        assert!(!none.no_ssh_config);

        let windows =
            ClientArgs::try_parse_from(["et", "--ssh-config", r"C:\Users\me\.ssh\config", "host"])
                .unwrap();
        assert_eq!(
            windows.ssh_config.as_deref(),
            Some(r"C:\Users\me\.ssh\config")
        );

        let disabled = ClientArgs::try_parse_from(["et", "--no-ssh-config", "host"]).unwrap();
        assert!(disabled.ssh_config.is_none());
        assert!(disabled.no_ssh_config);
    }

    #[test]
    fn ssh_config_conflicts_with_no_ssh_config() {
        assert!(ClientArgs::try_parse_from([
            "et",
            "--ssh-config",
            "/etc/et/ssh_config",
            "--no-ssh-config",
            "host",
        ])
        .is_err());
        assert!(ClientArgs::try_parse_from([
            "et",
            "--no-ssh-config",
            "--ssh-config",
            "none",
            "host",
        ])
        .is_err());
    }
}
