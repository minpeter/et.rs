//! `etserver` argument surface and INI configuration, matching upstream
//! `TerminalServerMain.cpp` + the `[Networking]`/`[Debug]` INI schema.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::Parser;

pub const DEFAULT_PORT: u16 = 2022;
pub const DEFAULT_CONFIG_PATH: &str = "/etc/et/config";

#[derive(Parser, Debug, Clone)]
#[command(
    name = "etserver",
    version = crate::VERSION,
    long_version = crate::LONG_VERSION,
    about = "Remote shell for the busy and impatient",
    long_about = "Listen for ET client connections and spawn terminal sessions."
)]
pub struct ServerArgs {
    #[arg(short = 'p', long = "port", value_parser = parse_port)]
    pub port: Option<u16>,

    #[arg(long = "bindip", value_parser = parse_bind_ip)]
    pub bindip: Option<IpAddr>,

    #[arg(long = "serverfifo")]
    pub serverfifo: Option<PathBuf>,

    #[arg(long = "daemon", help = "Daemonize the server")]
    pub daemon: bool,

    /// Internal marker: this process is the re-executed daemon child.
    #[arg(long = "daemon-child", hide = true)]
    pub daemon_child: bool,

    #[arg(long = "cfgfile", default_value = DEFAULT_CONFIG_PATH)]
    pub cfgfile: PathBuf,

    #[arg(short = 'l', long = "logdir")]
    pub logdir: Option<PathBuf>,

    #[arg(long = "logtostdout")]
    pub logtostdout: bool,

    #[arg(long = "pidfile", help = "Location of the pid file")]
    pub pidfile: Option<PathBuf>,

    #[arg(
        short = 'v',
        long = "verbose",
        value_name = "LEVEL",
        default_value_t = 0
    )]
    pub verbose: u8,

    /// Accepted for upstream compatibility; et.rs never collects telemetry.
    #[arg(
        long = "telemetry",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        hide = true
    )]
    pub telemetry: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub port: u16,
    pub bind_ip: IpAddr,
    pub server_fifo: Option<PathBuf>,
    pub verbose: u8,
    pub log_directory: PathBuf,
    pub silent: bool,
    pub log_size: u64,
    /// Parsed for upstream compatibility only; et.rs never sends telemetry.
    pub telemetry: bool,
}

/// Upstream default max log size for `etserver` (20 MiB).
pub const DEFAULT_LOG_SIZE: u64 = 20_971_520;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidPort(String),
    InvalidBindIp(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPort(value) => write!(f, "invalid server port: {value}"),
            Self::InvalidBindIp(value) => write!(f, "invalid server bind IP: {value}"),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn resolve_config(
    args: &ServerArgs,
    ini_text: Option<&str>,
) -> Result<ServerConfig, ConfigError> {
    let mut config = ServerConfig {
        port: DEFAULT_PORT,
        bind_ip: IpAddr::from([0, 0, 0, 0]),
        server_fifo: None,
        verbose: 0,
        log_directory: std::env::temp_dir(),
        silent: false,
        log_size: DEFAULT_LOG_SIZE,
        telemetry: false,
    };
    let ini_log_directory_set = if let Some(text) = ini_text {
        apply_ini(&mut config, args, text)?
    } else {
        false
    };
    if let Some(port) = args.port {
        config.port = port;
    }
    if let Some(bind_ip) = args.bindip {
        config.bind_ip = bind_ip;
    }
    if let Some(path) = &args.serverfifo {
        config.server_fifo = Some(path.clone());
    }
    if args.verbose > 0 {
        config.verbose = args.verbose;
    }
    if let Some(directory) = &args.logdir {
        config.log_directory = directory.clone();
    }
    // Machine-local env overrides (`ET_DEBUG` / `ET_LOGDIR` / `ET_VERBOSE`)
    // apply only when CLI (and, for logdir, INI) left the field at defaults.
    // CLI always wins; INI wins over env for values it set.
    apply_env_debug_overrides(&mut config, args, ini_log_directory_set);
    Ok(config)
}

/// Apply `ET_*` debug env vars after CLI/INI resolution.
///
/// - `verbose`: raised only when still 0 (CLI `-v` / INI `verbose` win).
/// - `log_directory`: replaced only when neither CLI `--logdir` nor INI
///   `logdirectory` set a path (detected via args + whether the directory is
///   still the process temp default from construction). Callers that set
///   `logdir` on args already overwrote `log_directory` above.
/// - `silent`: forced off under `ET_DEBUG`.
fn apply_env_debug_overrides(
    config: &mut ServerConfig,
    args: &ServerArgs,
    ini_log_directory_set: bool,
) {
    config.verbose = crate::logging::effective_verbose(config.verbose);
    config.log_directory = resolve_server_log_directory(
        config.log_directory.clone(),
        args.logdir.is_some(),
        ini_log_directory_set,
        crate::logging::effective_log_directory(None),
    );
    config.silent = crate::logging::effective_silent(config.silent);
}

fn resolve_server_log_directory(
    configured: PathBuf,
    cli_log_directory_set: bool,
    ini_log_directory_set: bool,
    environment_default: PathBuf,
) -> PathBuf {
    if cli_log_directory_set || ini_log_directory_set {
        configured
    } else {
        environment_default
    }
}

fn apply_ini(
    config: &mut ServerConfig,
    args: &ServerArgs,
    text: &str,
) -> Result<bool, ConfigError> {
    let mut section = String::new();
    let mut log_directory_set = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match (section.as_str(), key.as_str()) {
            ("networking", "port") if args.port.is_none() => {
                config.port = parse_port(value).map_err(ConfigError::InvalidPort)?;
            }
            ("networking", "bind_ip") if args.bindip.is_none() => {
                config.bind_ip = parse_bind_ip(value).map_err(ConfigError::InvalidBindIp)?;
            }
            ("debug", "serverfifo") if args.serverfifo.is_none() && !value.is_empty() => {
                config.server_fifo = Some(PathBuf::from(value));
            }
            ("debug", "verbose") if args.verbose == 0 => {
                if let Ok(level) = value.parse::<u8>() {
                    config.verbose = level;
                }
            }
            ("debug", "logdirectory") if args.logdir.is_none() => {
                config.log_directory = PathBuf::from(value);
                log_directory_set = true;
            }
            ("debug", "silent") => {
                config.silent = value.parse::<i64>().is_ok_and(|value| value != 0);
            }
            ("debug", "logsize") => {
                if let Ok(size) = value.parse::<u64>() {
                    if size != 0 {
                        config.log_size = size;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(log_directory_set)
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value.parse::<u16>().map_err(|_| value.to_owned())?;
    if port == 0 {
        return Err(value.to_owned());
    }
    Ok(port)
}

fn parse_bind_ip(value: &str) -> Result<IpAddr, String> {
    value.parse::<IpAddr>().map_err(|_| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_unknown_sections_are_ignored() {
        let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
        let ini = "# comment\n[Other]\nfoo=bar\n[Networking]\n; comment\nport=4022\n";
        assert_eq!(resolve_config(&args, Some(ini)).unwrap().port, 4022);
    }

    #[test]
    fn verbose_and_logdir_cli_values_override_ini() {
        let args = ServerArgs::try_parse_from(["etserver", "-v", "2", "--logdir", "/tmp/cli-logs"])
            .unwrap();
        let ini = "[Debug]\nverbose=1\nlogdirectory=/tmp/ini-logs\n";
        let config = resolve_config(&args, Some(ini)).unwrap();
        assert_eq!(config.verbose, 2);
        assert_eq!(config.log_directory, PathBuf::from("/tmp/cli-logs"));
    }

    #[test]
    fn verbose_takes_an_integer_level_like_upstream() {
        let args = ServerArgs::try_parse_from(["etserver", "--verbose=3"]).unwrap();
        assert_eq!(args.verbose, 3);
    }

    #[test]
    fn silent_and_logsize_ini_keys_are_honored() {
        let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
        let ini = "[Debug]\nsilent=1\nlogsize=1048576\n";
        let config = resolve_config(&args, Some(ini)).unwrap();
        assert!(config.silent);
        assert_eq!(config.log_size, 1_048_576);
    }

    #[test]
    fn telemetry_ini_and_flag_are_parsed_without_effect() {
        let args = ServerArgs::try_parse_from(["etserver", "--telemetry", "false"]).unwrap();
        assert_eq!(args.telemetry, Some(false));
        let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
        let ini = "[Debug]\ntelemetry=true\n";
        // Parsed for compatibility; et.rs never reports telemetry.
        assert!(!resolve_config(&args, Some(ini)).unwrap().telemetry);
    }

    #[test]
    fn daemon_defaults_to_the_upstream_pid_file() {
        let args = ServerArgs::try_parse_from(["etserver", "--daemon"]).unwrap();
        assert!(args.daemon);
        assert!(!args.daemon_child);
        assert_eq!(args.pidfile, None);
    }

    #[test]
    fn apply_env_debug_overrides_leaves_cli_logdir_alone() {
        // Without mutating process env: CLI logdir is sticky because
        // `args.logdir` is Some, so `apply_env_debug_overrides` skips the dir.
        let args = ServerArgs::try_parse_from(["etserver", "-v", "3", "--logdir", "/tmp/cli-wins"])
            .unwrap();
        let config = resolve_config(&args, None).unwrap();
        assert_eq!(config.verbose, 3);
        assert_eq!(config.log_directory, PathBuf::from("/tmp/cli-wins"));
    }

    #[test]
    fn explicit_ini_temp_logdir_wins_over_environment() {
        assert_eq!(
            resolve_server_log_directory(
                PathBuf::from("/tmp"),
                false,
                true,
                PathBuf::from("/environment"),
            ),
            PathBuf::from("/tmp")
        );
    }
}
