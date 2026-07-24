//! `etserver` argument surface and INI configuration, matching upstream
//! `TerminalServerMain.cpp` + the `[Networking]`/`[Debug]` INI schema.

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
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    #[arg(long = "bindip")]
    pub bindip: Option<String>,

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerConfig {
    pub port: u16,
    pub bind_ip: String,
    pub server_fifo: String,
    pub verbose: u8,
    pub log_directory: PathBuf,
}

pub fn resolve_config(args: &ServerArgs, ini_text: Option<&str>) -> ServerConfig {
    let mut cfg = ServerConfig {
        port: DEFAULT_PORT,
        bind_ip: "0.0.0.0".to_string(),
        server_fifo: "/tmp/etserver.cfg".to_string(),
        verbose: 0,
        log_directory: std::env::temp_dir(),
    };
    if let Some(text) = ini_text {
        apply_ini(&mut cfg, text);
    }
    if let Some(p) = args.port {
        cfg.port = p;
    }
    if let Some(ref ip) = args.bindip {
        cfg.bind_ip = ip.clone();
    }
    if args.verbose > 0 {
        cfg.verbose = args.verbose;
    }
    if let Some(ref d) = args.logdir {
        cfg.log_directory = d.clone();
    }
    cfg
}

fn apply_ini(cfg: &mut ServerConfig, text: &str) {
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_lowercase();
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let (k, v) = (key.trim().to_lowercase(), val.trim());
            match (section.as_str(), k.as_str()) {
                ("networking", "port") => {
                    if let Ok(p) = v.parse::<u16>() {
                        cfg.port = p;
                    }
                }
                ("networking", "bind_ip") => cfg.bind_ip = v.to_string(),
                ("networking", "serverfifo") => cfg.server_fifo = v.to_string(),
                ("debug", "verbose") => {
                    if let Ok(n) = v.parse::<u8>() {
                        cfg.verbose = n;
                    }
                }
                ("debug", "logdirectory") => cfg.log_directory = PathBuf::from(v),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_no_config() {
        let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
        let cfg = resolve_config(&args, None);
        assert_eq!(cfg.port, DEFAULT_PORT);
        assert_eq!(cfg.bind_ip, "0.0.0.0");
    }

    #[test]
    fn cli_overrides_ini() {
        let args = ServerArgs::try_parse_from(["etserver", "-p", "8888"]).unwrap();
        let ini = "[Networking]\nport = 2022\nbind_ip = 127.0.0.1\n";
        let cfg = resolve_config(&args, Some(ini));
        assert_eq!(cfg.port, 8888);
        assert_eq!(cfg.bind_ip, "127.0.0.1");
    }

    #[test]
    fn ini_parses_all_fields() {
        let ini = "[Networking]\nport = 3022\nbind_ip = ::1\nserverfifo = /run/et.fifo\n[Debug]\nverbose = 2\nlogdirectory = /var/log/et\n";
        let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
        let cfg = resolve_config(&args, Some(ini));
        assert_eq!(cfg.port, 3022);
        assert_eq!(cfg.bind_ip, "::1");
        assert_eq!(cfg.server_fifo, "/run/et.fifo");
        assert_eq!(cfg.verbose, 2);
        assert_eq!(cfg.log_directory, PathBuf::from("/var/log/et"));
    }

    #[test]
    fn ini_ignores_comments_and_unknown_sections() {
        let ini = "# comment\n[Other]\nfoo = bar\n[Networking]\n; inline\nport = 4022\n";
        let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
        let cfg = resolve_config(&args, Some(ini));
        assert_eq!(cfg.port, 4022);
    }

    #[test]
    fn bad_ini_port_falls_back_to_default() {
        let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
        let cfg = resolve_config(&args, Some("[Networking]\nport = notanumber\n"));
        assert_eq!(cfg.port, DEFAULT_PORT);
    }
}
