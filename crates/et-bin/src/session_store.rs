//! Named-session files under `~/.et/sessions`.
//!
//! The file format matches EternalTerminal `SessionStore`: one owner-only
//! record per name. Errors never include the passkey or file contents.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use et_cli::client::ClientArgs;
use et_core::proto::{TerminalInfo, TerminalPacketType};
use prost::Message;

use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::initial_connect::{connect_initial_with_intent, Endpoint};
use crate::resolver::EndpointResolver;

const VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedSession {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub id: String,
    pub passkey: String,
    pub saved_at: i64,
    pub title: String,
}

pub fn print_sessions() -> Result<i32, ClientError> {
    let sessions = list().map_err(ClientError::Terminal)?;
    for session in sessions {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            session.name, session.host, session.port, session.title, session.saved_at
        );
    }
    Ok(0)
}

pub fn save_direct(
    name: &str,
    host: &str,
    port: u16,
    id: &str,
    passkey: &str,
) -> Result<(), ClientError> {
    if !valid_name(name) {
        return Err(ClientError::Terminal(
            "session name must be 1-63 characters of [A-Za-z0-9._-] and start alphanumeric"
                .to_owned(),
        ));
    }
    let saved_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(0))
        .unwrap_or(0);
    let session = SavedSession {
        name: name.to_owned(),
        host: host.to_owned(),
        port,
        id: id.to_owned(),
        passkey: passkey.to_owned(),
        saved_at,
        title: String::new(),
    };
    save(&session).map_err(ClientError::Terminal)
}

pub fn attach(
    name: &str,
    args: &ClientArgs,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<i32, ClientError> {
    let saved = load(name).map_err(ClientError::Terminal)?;
    let endpoint = Endpoint {
        host: saved.host.clone(),
        port: saved.port,
    };
    let credentials = crate::bootstrap::Credentials {
        id: saved.id.clone(),
        passkey: saved.passkey.clone(),
    };
    let mut payload = et_core::proto::InitialPayload {
        supports_exit_status: Some(true),
        disconnect_timeout_seconds: args.disconnect_timeout_seconds(),
        ..Default::default()
    };
    payload.jumphost = Some(false);
    let connection =
        connect_initial_with_intent(&endpoint, &credentials, &payload, resolver, deadline, true)?;
    let agent_forward = crate::agent_forward::AgentForward::attach(&credentials.id)?;
    let (forwarder, _) = et_net::forward::Forwarder::start_with_origins_deadline(
        Vec::new(),
        deadline.expires_at(),
        std::sync::Arc::new(et_net::forward::SystemForwardResolver),
    )
    .map_err(|error| ClientError::Terminal(error.to_string()))?;
    crate::client_terminal::run(
        connection,
        crate::client_terminal::TerminalOptions {
            command: None,
            no_exit: args.no_exit,
            keepalive: args.keepalive,
            flow_control: args.flow_control,
            terminal_enabled: !args.no_terminal,
            lines: crate::client_terminal::RemoteLines::Posix,
            connection_name: &saved.name,
            close_on_hangup: args.close_on_hangup,
            no_pty: false,
            stdio_forward: false,
        },
        forwarder,
        |connection| {
            let outcome = crate::initial_connect::reconnect(
                connection,
                &endpoint,
                &credentials,
                resolver,
                crate::deadline::Deadline::after(std::time::Duration::from_secs(10)),
            )?;
            agent_forward.reconnected(outcome)
        },
    )
}

pub fn kill(
    name: &str,
    resolver: &dyn EndpointResolver,
    deadline: Deadline,
) -> Result<i32, ClientError> {
    let saved = load(name).map_err(ClientError::Terminal)?;
    let endpoint = Endpoint {
        host: saved.host.clone(),
        port: saved.port,
    };
    let credentials = crate::bootstrap::Credentials {
        id: saved.id,
        passkey: saved.passkey,
    };
    let payload = et_core::proto::InitialPayload {
        supports_exit_status: Some(true),
        ..Default::default()
    };
    let mut connection = match connect_initial_with_intent(
        &endpoint,
        &credentials,
        &payload,
        resolver,
        deadline,
        true,
    ) {
        Ok(connection) => connection,
        Err(ClientError::ServerInvalidKey(_)) => return Ok(0),
        Err(error) => return Err(error),
    };
    let info = TerminalInfo {
        id: Some(credentials.id.clone()),
        command: Some(et_core::proto::terminal_info::Command::KillSession as i32),
        commandversion: Some(et_core::SESSION_KILL_COMMAND_VERSION),
        ..Default::default()
    };
    connection
        .write_packet_live(
            TerminalPacketType::TerminalInfo as u8,
            &info.encode_to_vec(),
        )
        .map_err(ClientError::Transport)?;
    loop {
        if deadline.remaining().is_none() {
            return Err(ClientError::BootstrapTimeout(
                "waiting for the session kill acknowledgement",
            ));
        }
        let packet = connection.read_packet().map_err(ClientError::Transport)?;
        if packet.header() == TerminalPacketType::KeepAlive as u8
            && packet.payload() == et_core::SESSION_KILL_ACK.as_bytes()
        {
            return Ok(0);
        }
    }
}

fn list() -> Result<Vec<SavedSession>, String> {
    let directory = sessions_dir()?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    verify_dir(directory.parent().unwrap_or(directory.as_path()), true)?;
    verify_dir(&directory, true)?;
    let mut sessions = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|_| "could not list sessions".to_owned())? {
        let entry = entry.map_err(|_| "could not list sessions".to_owned())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !valid_name(&name) {
            continue;
        }
        if let Ok(session) = load(&name) {
            sessions.push(session);
        }
    }
    sessions.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(sessions)
}

fn save(session: &SavedSession) -> Result<(), String> {
    if !valid_name(&session.name) {
        return Err("session name is invalid".to_owned());
    }
    let directory = sessions_dir()?;
    let home = home_dir()?;
    if !home.exists() {
        fs::create_dir_all(&home)
            .map_err(|_| "could not create the session directory".to_owned())?;
    }
    ensure_private_dir(
        directory
            .parent()
            .ok_or_else(|| "session directory is invalid".to_owned())?,
    )?;
    ensure_private_dir(&directory)?;
    if !printable_field(&session.host)
        || !printable_field(&session.id)
        || !printable_field(&session.passkey)
        || session.title.contains(['\r', '\n'])
    {
        return Err("session file is invalid".to_owned());
    }
    let path = directory.join(&session.name);
    if path.exists() && !private_file(&path).unwrap_or(false) {
        return Err("could not store the session file".to_owned());
    }
    let nonce = et_core::crypto::random_bytes::<4>();
    let temporary = directory.join(format!(
        ".{}.{:02x}{:02x}{:02x}{:02x}.tmp",
        session.name, nonce[0], nonce[1], nonce[2], nonce[3]
    ));
    let body = format!(
        "version={VERSION}\nname={}\nhost={}\nport={}\nid={}\npasskey={}\nsavedat={}\ntitle={}\n",
        session.name,
        session.host,
        session.port,
        session.id,
        session.passkey,
        session.saved_at,
        session.title
    );
    if let Err(error) = write_private(&temporary, body.as_bytes()) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if fs::rename(&temporary, &path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("could not store the session file".to_owned());
    }
    set_private_file(&path)?;
    Ok(())
}

fn printable_field(value: &str) -> bool {
    !value.is_empty() && !value.contains(['\r', '\n'])
}

fn load(name: &str) -> Result<SavedSession, String> {
    if !valid_name(name) {
        return Err("session name is invalid".to_owned());
    }
    let path = sessions_dir()?.join(name);
    let contents = read_private(&path)?;
    parse_session(name, &contents)
}

fn parse_session(name: &str, contents: &str) -> Result<SavedSession, String> {
    let mut fields = std::collections::BTreeMap::new();
    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err("session file is invalid".to_owned());
        };
        if value.contains(['\r', '\n']) {
            return Err("session file is invalid".to_owned());
        }
        fields.insert(key.to_owned(), value.to_owned());
    }
    if fields.get("version").map(String::as_str) != Some(VERSION) {
        return Err("session file is invalid".to_owned());
    }
    if fields.get("name").map(String::as_str) != Some(name) {
        return Err("session file is invalid".to_owned());
    }
    let host = fields
        .get("host")
        .cloned()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "session file is invalid".to_owned())?;
    let port = fields
        .get("port")
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| "session file is invalid".to_owned())?;
    let id = fields
        .get("id")
        .cloned()
        .ok_or_else(|| "session file is invalid".to_owned())?;
    let passkey = fields
        .get("passkey")
        .cloned()
        .ok_or_else(|| "session file is invalid".to_owned())?;
    let saved_at = fields
        .get("savedat")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let title = fields.get("title").cloned().unwrap_or_default();
    Ok(SavedSession {
        name: name.to_owned(),
        host,
        port,
        id,
        passkey,
        saved_at,
        title,
    })
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && name.len() <= 63
}

fn home_dir() -> Result<PathBuf, String> {
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    if let Some(home) = std::env::var_os("USERPROFILE").filter(|home| !home.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    Err("could not determine the user home directory".to_owned())
}

fn sessions_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".et").join("sessions"))
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir(path).map_err(|_| "could not create the session directory".to_owned())?;
    }
    set_private_dir(path)?;
    verify_dir(path, false)
}

fn verify_dir(path: &Path, allow_missing: bool) -> Result<(), String> {
    if !path.exists() {
        if allow_missing {
            return Ok(());
        }
        return Err("session directory is missing".to_owned());
    }
    if !path.is_dir() {
        return Err("session directory has unsafe owner or permissions".to_owned());
    }
    if !private_dir(path)? {
        return Err("session directory has unsafe owner or permissions".to_owned());
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        write_private_unix(path, bytes)
    }
    #[cfg(windows)]
    {
        write_private_windows(path, bytes)
    }
}

#[cfg(unix)]
fn write_private_unix(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use rustix::fs::{open, Mode, OFlags};
    let descriptor = open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "could not create the session file".to_owned())?;
    let mut file = fs::File::from(descriptor);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "could not write the session file".to_owned())
}

#[cfg(windows)]
fn write_private_windows(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "could not create the session file".to_owned())?;
    file.write_all(bytes)
        .map_err(|_| "could not write the session file".to_owned())
}

fn read_private(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        read_private_unix(path)
    }
    #[cfg(windows)]
    {
        read_private_windows(path)
    }
}

#[cfg(unix)]
fn read_private_unix(path: &Path) -> Result<String, String> {
    use rustix::fs::{fstat, open, FileType, Mode, OFlags};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| "could not open the session file".to_owned())?;
    let stat = fstat(&descriptor).map_err(|_| "could not inspect the session file".to_owned())?;
    let regular = FileType::from_raw_mode(stat.st_mode).is_file();
    if !regular
        || stat.st_uid != rustix::process::getuid().as_raw()
        || stat.st_mode & 0o077 != 0
        || stat.st_nlink != 1
    {
        return Err("session file has unsafe owner or permissions".to_owned());
    }
    let mut file = fs::File::from(descriptor);
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|_| "could not read the session file".to_owned())?;
    if contents.len() > 64 * 1024 {
        return Err("session file is invalid".to_owned());
    }
    Ok(contents)
}

#[cfg(windows)]
fn read_private_windows(path: &Path) -> Result<String, String> {
    if !private_file(path)? {
        return Err("session file has unsafe owner or permissions".to_owned());
    }
    let mut file =
        fs::File::open(path).map_err(|_| "could not open the session file".to_owned())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|_| "could not read the session file".to_owned())?;
    if contents.len() > 64 * 1024 {
        return Err("session file is invalid".to_owned());
    }
    Ok(contents)
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "could not set session directory permissions".to_owned())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "could not set session file permissions".to_owned())
}

#[cfg(unix)]
fn private_dir(path: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "could not inspect the session directory".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(false);
    }
    Ok(metadata.uid() == rustix::process::getuid().as_raw() && metadata.mode() & 0o077 == 0)
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "could not inspect the session file".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    Ok(metadata.uid() == rustix::process::getuid().as_raw()
        && metadata.mode() & 0o077 == 0
        && metadata.nlink() == 1)
}

#[cfg(windows)]
fn set_private_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn set_private_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn private_dir(path: &Path) -> Result<bool, String> {
    Ok(path.is_dir())
}

#[cfg(windows)]
fn private_file(path: &Path) -> Result<bool, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "could not inspect the session file".to_owned())?;
    Ok(metadata.is_file() && !metadata.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hides_the_passkey_from_errors() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "et-sessions-{}-{}",
            std::process::id(),
            saved_nonce()
        ));
        let _ = fs::remove_dir_all(&directory);
        let previous = std::env::var_os("HOME");
        std::env::set_var("HOME", &directory);
        let session = SavedSession {
            name: "work".to_owned(),
            host: "example.test".to_owned(),
            port: 2022,
            id: "abcdefghijklmnop".to_owned(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".to_owned(),
            saved_at: 10,
            title: "desk".to_owned(),
        };
        save(&session).unwrap();
        let loaded = load("work").unwrap();
        assert_eq!(loaded.host, "example.test");
        assert_eq!(loaded.passkey, session.passkey);
        let _ = fs::write(
            directory.join(".et").join("sessions").join("work"),
            b"not a session\nSECRETKEY",
        );
        let error = load("work").unwrap_err();
        assert!(!error.contains("SECRETKEY"));
        assert!(!error.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"));
        match previous {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
        let _ = fs::remove_dir_all(&directory);
    }

    fn saved_nonce() -> u128 {
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
