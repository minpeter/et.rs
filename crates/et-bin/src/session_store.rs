//! Named-session files, matching upstream `~/.et/sessions` version 1.
//!
//! Direct sessions (`--name`) persist id and passkey so `--attach`, `--list`,
//! and `--kill` can find them after the client exits. Jumphost, `-T`, and
//! `-W` sessions are not stored.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub id: String,
    pub passkey: String,
    pub saved_at: String,
    pub title: String,
}

pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub fn save(record: &SessionRecord) -> Result<(), String> {
    if !valid_name(&record.name) {
        return Err("session name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$".to_owned());
    }
    let dir = sessions_dir()?;
    ensure_dir(&dir)?;
    let path = dir.join(&record.name);
    reject_linked(&path, true)?;
    let body = format!(
        "version=1\nname={}\nhost={}\nport={}\nid={}\npasskey={}\nsavedat={}\ntitle={}\n",
        record.name,
        record.host,
        record.port,
        record.id,
        record.passkey,
        record.saved_at,
        record.title
    );
    let temp = dir.join(format!(".{}.tmp", record.name));
    {
        let mut file = open_owner(&temp)?;
        file.write_all(body.as_bytes())
            .map_err(|error| format!("could not write session file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("could not flush session file: {error}"))?;
    }
    fs::rename(&temp, &path).map_err(|error| format!("could not commit session file: {error}"))?;
    owner_only_file(&path)?;
    Ok(())
}

pub fn load(name: &str) -> Result<SessionRecord, String> {
    if !valid_name(name) {
        return Err("invalid session name".to_owned());
    }
    let path = sessions_dir()?.join(name);
    reject_linked(&path, false)?;
    let mut text = String::new();
    OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|error| format!("could not open session {name}: {error}"))?
        .read_to_string(&mut text)
        .map_err(|error| format!("could not read session {name}: {error}"))?;
    parse(&text)
}

pub fn list() -> Result<Vec<SessionRecord>, String> {
    let dir = sessions_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    ensure_dir(&dir)?;
    let mut records = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|error| format!("could not list sessions: {error}"))? {
        let entry = entry.map_err(|error| format!("could not list sessions: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.') || !valid_name(name) {
            continue;
        }
        if reject_linked(&entry.path(), false).is_err() {
            continue;
        }
        if let Ok(record) = load(name) {
            records.push(record);
        }
    }
    records.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(records)
}

pub fn delete(name: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err("invalid session name".to_owned());
    }
    let path = sessions_dir()?.join(name);
    if !path.exists() {
        return Ok(());
    }
    reject_linked(&path, false)?;
    fs::remove_file(&path).map_err(|error| format!("could not remove session {name}: {error}"))
}

pub fn now_saved_at() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

fn parse(text: &str) -> Result<SessionRecord, String> {
    let mut version = None;
    let mut name = None;
    let mut host = None;
    let mut port = None;
    let mut id = None;
    let mut passkey = None;
    let mut saved_at = None;
    let mut title = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "version" => version = Some(value.to_owned()),
            "name" => name = Some(value.to_owned()),
            "host" => host = Some(value.to_owned()),
            "port" => port = value.parse::<u16>().ok(),
            "id" => id = Some(value.to_owned()),
            "passkey" => passkey = Some(value.to_owned()),
            "savedat" => saved_at = Some(value.to_owned()),
            "title" => title = Some(value.to_owned()),
            _ => {}
        }
    }
    if version.as_deref() != Some("1") {
        return Err("unsupported session file version".to_owned());
    }
    Ok(SessionRecord {
        name: name.ok_or_else(|| "session file is missing name".to_owned())?,
        host: host.ok_or_else(|| "session file is missing host".to_owned())?,
        port: port.ok_or_else(|| "session file is missing port".to_owned())?,
        id: id.ok_or_else(|| "session file is missing id".to_owned())?,
        passkey: passkey.ok_or_else(|| "session file is missing passkey".to_owned())?,
        saved_at: saved_at.unwrap_or_default(),
        title: title.unwrap_or_default(),
    })
}

fn sessions_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "could not locate the home directory for session files".to_owned())?;
    Ok(PathBuf::from(home).join(".et").join("sessions"))
}

fn ensure_dir(dir: &Path) -> Result<(), String> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create session directory: {error}"))?;
        owner_only_dir(parent)?;
    }
    fs::create_dir_all(dir)
        .map_err(|error| format!("could not create session directory: {error}"))?;
    owner_only_dir(dir)?;
    reject_linked(dir, false)
}

fn reject_linked(path: &Path, allow_missing: bool) -> Result<(), String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(())
        }
        Err(error) => return Err(format!("could not inspect {}: {error}", path.display())),
    };
    if meta.file_type().is_symlink() {
        return Err(format!("{} is a symlink", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(format!("{} has extra hard links", path.display()));
        }
    }
    Ok(())
}

fn open_owner(path: &Path) -> Result<std::fs::File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("could not create session file: {error}"))
}

fn owner_only_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not restrict {}: {error}", path.display()))?;
    }
    let _ = path;
    Ok(())
}

fn owner_only_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("could not restrict {}: {error}", path.display()))?;
    }
    let _ = path;
    Ok(())
}
