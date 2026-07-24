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
    version,
    about = "EternalTerminal server (Rust port)",
    long_about = "Listen for ET client connections and spawn terminal sessions."
)]
pub struct ServerArgs {
    #[arg(short = 'p', long = "port", value_parser = parse_port)]
    pub port: Option<u16>,

    #[arg(long = "bindip", value_parser = parse_bind_ip)]
    pub bindip: Option<IpAddr>,

    #[arg(long = "serverfifo")]
    pub serverfifo: Option<PathBuf>,

    #[arg(long = "daemon")]
    pub daemon: bool,

    #[arg(long = "cfgfile", default_value = DEFAULT_CONFIG_PATH)]
    pub cfgfile: PathBuf,

    #[arg(short = 'l', long = "logdir")]
    pub logdir: Option<PathBuf>,

    #[arg(long = "logtostdout")]
    pub logtostdout: bool,

    #[arg(long = "pidfile")]
    pub pidfile: Option<PathBuf>,

    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(long = "telemetry", default_value_t = false, hide = true)]
    pub telemetry: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub port: u16,
    pub bind_ip: IpAddr,
    pub server_fifo: Option<PathBuf>,
    pub verbose: u8,
    pub log_directory: PathBuf,
}

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
    };
    if let Some(text) = ini_text {
        apply_ini(&mut config, args, text)?;
    }
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
    Ok(config)
}

fn apply_ini(config: &mut ServerConfig, args: &ServerArgs, text: &str) -> Result<(), ConfigError> {
    let mut section = String::new();
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
            }
            _ => {}
        }
    }
    Ok(())
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
        let args =
            ServerArgs::try_parse_from(["etserver", "-vv", "--logdir", "/tmp/cli-logs"]).unwrap();
        let ini = "[Debug]\nverbose=1\nlogdirectory=/tmp/ini-logs\n";
        let config = resolve_config(&args, Some(ini)).unwrap();
        assert_eq!(config.verbose, 2);
        assert_eq!(config.log_directory, PathBuf::from("/tmp/cli-logs"));
    }
}
