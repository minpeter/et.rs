#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use clap::Parser;
use et_cli::server::{resolve_config, ConfigError, ServerArgs, DEFAULT_PORT};

#[test]
fn defaults_are_typed_and_do_not_force_an_insecure_router_path() {
    let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
    let cfg = resolve_config(&args, None).unwrap();
    assert_eq!(cfg.port, DEFAULT_PORT);
    assert_eq!(cfg.bind_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(cfg.server_fifo, None);
    assert_eq!(cfg.listen_backlog, et_cli::server::DEFAULT_LISTEN_BACKLOG);
}

#[test]
fn cli_precedence_skips_shadowed_invalid_ini_values() {
    let args = ServerArgs::try_parse_from([
        "etserver",
        "--port",
        "8888",
        "--bindip",
        "127.0.0.1",
        "--serverfifo",
        "/run/cli.sock",
    ])
    .unwrap();
    let ini = "[Networking]\nport=invalid\nbind_ip=invalid\n[Debug]\nserverfifo=/run/ini.sock\n";
    let cfg = resolve_config(&args, Some(ini)).unwrap();
    assert_eq!(cfg.port, 8888);
    assert_eq!(cfg.bind_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(cfg.server_fifo, Some(PathBuf::from("/run/cli.sock")));
}

#[test]
fn debug_serverfifo_and_networking_values_are_read() {
    let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
    let ini =
        "[Networking]\nport=3022\nbind_ip=::1\nbacklog=256\n[Debug]\nserverfifo=/run/et.sock\n";
    let cfg = resolve_config(&args, Some(ini)).unwrap();
    assert_eq!(cfg.port, 3022);
    assert_eq!(cfg.bind_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(cfg.server_fifo, Some(PathBuf::from("/run/et.sock")));
    assert_eq!(cfg.listen_backlog, 256);
}

#[test]
fn invalid_ini_port_and_bind_are_typed_errors() {
    let args = ServerArgs::try_parse_from(["etserver"]).unwrap();
    assert!(matches!(
        resolve_config(&args, Some("[Networking]\nport=0\n")),
        Err(ConfigError::InvalidPort(_))
    ));
    assert!(matches!(
        resolve_config(&args, Some("[Networking]\nbind_ip=localhost\n")),
        Err(ConfigError::InvalidBindIp(_))
    ));
}

#[test]
fn cli_rejects_zero_port_and_non_literal_bind() {
    assert!(ServerArgs::try_parse_from(["etserver", "--port", "0"]).is_err());
    assert!(ServerArgs::try_parse_from(["etserver", "--bindip", "localhost"]).is_err());
}
