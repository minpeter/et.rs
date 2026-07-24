use et_core::keys::{gen_id_passkey, passkey_to_key};

use crate::error::ClientError;

const MARKER: &[u8] = b"IDPASSKEY:";
const CREDENTIAL_LEN: usize = 16 + 1 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub id: String,
    pub passkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRequest {
    pub user: Option<String>,
    pub host_alias: String,
    pub jumphost: Option<String>,
    pub terminal_path: Option<String>,
    pub server_fifo: Option<String>,
    pub kill_other_sessions: bool,
    pub verbose: u8,
    pub ssh_options: Vec<String>,
    pub term: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub operation: &'static str,
}

pub fn provisional_credentials() -> Result<Credentials, ClientError> {
    let (id, passkey) = gen_id_passkey();
    let tail = id.get(3..).ok_or(ClientError::InvalidSessionId)?;
    validate_credentials(Credentials {
        id: format!("XXX{tail}"),
        passkey,
    })
}

pub fn build_invocation(request: &BootstrapRequest, credentials: &Credentials) -> SshInvocation {
    let mut args = Vec::new();
    if let Some(jumphost) = request.jumphost.as_deref() {
        args.push("-J".to_string());
        args.push(jumphost.to_string());
    }

    let destination = match request.user.as_deref() {
        Some(user) => format!("{user}@{}", request.host_alias),
        None => request.host_alias.clone(),
    };
    args.push(destination);
    args.extend(
        request
            .ssh_options
            .iter()
            .map(|option| format!("-o{option}")),
    );
    args.push(remote_command(request, credentials));

    SshInvocation {
        program: "ssh".to_string(),
        args,
        operation: "starting the remote etterminal",
    }
}

pub fn validate_ssh_destination(host: &str, user: Option<&str>) -> Result<(), ClientError> {
    if host.starts_with('-') {
        return Err(ClientError::InvalidSshComponent("host"));
    }
    if user.is_some_and(|user| user.starts_with('-')) {
        return Err(ClientError::InvalidSshComponent("user"));
    }
    Ok(())
}

pub fn parse_id_passkey(stdout: &[u8]) -> Result<Credentials, ClientError> {
    let marker = stdout
        .windows(MARKER.len())
        .position(|window| window == MARKER)
        .ok_or(ClientError::MissingIdPasskeyMarker)?;
    let value = stdout
        .get(marker + MARKER.len()..)
        .and_then(|tail| tail.get(..CREDENTIAL_LEN))
        .ok_or(ClientError::MalformedIdPasskeyMarker)?;
    if value.get(16) != Some(&b'/') {
        return Err(ClientError::MalformedIdPasskeyMarker);
    }

    let id = value
        .get(..16)
        .ok_or(ClientError::MalformedIdPasskeyMarker)?;
    let passkey = value
        .get(17..CREDENTIAL_LEN)
        .ok_or(ClientError::MalformedIdPasskeyMarker)?;
    if !id.iter().all(u8::is_ascii_alphanumeric) {
        return Err(ClientError::InvalidSessionId);
    }
    if !passkey.iter().all(u8::is_ascii_alphanumeric) {
        return Err(ClientError::InvalidPasskey);
    }

    let id = std::str::from_utf8(id).map_err(|_| ClientError::InvalidSessionId)?;
    let passkey = std::str::from_utf8(passkey).map_err(|_| ClientError::InvalidPasskey)?;
    validate_credentials(Credentials {
        id: id.to_string(),
        passkey: passkey.to_string(),
    })
}

pub fn validate_credentials(credentials: Credentials) -> Result<Credentials, ClientError> {
    if credentials.id.len() != 16
        || !credentials
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(ClientError::InvalidSessionId);
    }
    if !credentials
        .passkey
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric())
        || passkey_to_key(&credentials.passkey).is_none()
    {
        return Err(ClientError::InvalidPasskey);
    }
    Ok(credentials)
}

fn remote_command(request: &BootstrapRequest, credentials: &Credentials) -> String {
    let terminal = request
        .terminal_path
        .as_deref()
        .filter(|path| !path.is_empty())
        .unwrap_or("etterminal");
    let input = format!(
        "{}/{}_{}",
        credentials.id, credentials.passkey, request.term
    );
    let mut command = String::new();
    if request.kill_other_sessions {
        let user = request
            .user
            .as_deref()
            .map(shell_quote)
            .unwrap_or_else(|| "\"$(id -un)\"".to_string());
        command.push_str(&format!("pkill -u {user} 'etterminal'; sleep 0.5; "));
    }
    command.push_str(&format!(
        "printf '%s\\n' {} | {} {}",
        shell_quote(&input),
        shell_quote(terminal),
        shell_quote(&format!("--verbose={}", request.verbose))
    ));
    if let Some(fifo) = request.server_fifo.as_deref() {
        command.push(' ');
        command.push_str(&shell_quote(&format!("--serverfifo={fifo}")));
    }
    command
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BootstrapRequest {
        BootstrapRequest {
            user: Some("alice".into()),
            host_alias: "server".into(),
            jumphost: None,
            terminal_path: None,
            server_fifo: None,
            kill_other_sessions: false,
            verbose: 2,
            ssh_options: vec!["Port=2222".into()],
            term: "xterm-256color".into(),
        }
    }

    #[test]
    fn builds_upstream_ssh_shape() {
        let credentials = Credentials {
            id: "XXXdefghijklmnop".into(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".into(),
        };
        let invocation = build_invocation(&request(), &credentials);
        assert_eq!(invocation.program, "ssh");
        assert_eq!(invocation.args[0..2], ["alice@server", "-oPort=2222"]);
        assert_eq!(
            invocation.args[2],
            "printf '%s\\n' 'XXXdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_xterm-256color' | 'etterminal' '--verbose=2'"
        );
    }

    #[test]
    fn quotes_every_remote_shell_input() {
        let mut request = request();
        request.user = Some("a'; touch user; echo '".into());
        request.term = "x'; touch term; echo '".into();
        request.terminal_path = Some("/bin/e'; touch path; echo '".into());
        request.server_fifo = Some("/tmp/f'; touch fifo; echo '".into());
        request.kill_other_sessions = true;
        let credentials = provisional_credentials().unwrap();
        let command = build_invocation(&request, &credentials).args.pop().unwrap();
        for injected in ["user", "term", "path", "fifo"] {
            assert!(command.contains(&format!("touch {injected}")));
        }
        assert_eq!(command.matches("'\"'\"'").count(), 8);
    }

    #[test]
    fn parses_marker_after_banner_and_validates_material() {
        let stdout = b"banner\nIDPASSKEY:abcdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef\n";
        let credentials = parse_id_passkey(stdout).unwrap();
        assert_eq!(credentials.id, "abcdefghijklmnop");
        assert_eq!(credentials.passkey, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef");
    }

    #[test]
    fn classifies_marker_and_credential_errors() {
        assert!(matches!(
            parse_id_passkey(b"banner"),
            Err(ClientError::MissingIdPasskeyMarker)
        ));
        assert!(matches!(
            parse_id_passkey(b"IDPASSKEY:short"),
            Err(ClientError::MalformedIdPasskeyMarker)
        ));
        assert!(matches!(
            parse_id_passkey(b"IDPASSKEY:abcdefghijklmno!/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"),
            Err(ClientError::InvalidSessionId)
        ));
        assert!(matches!(
            parse_id_passkey(b"IDPASSKEY:abcdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcde!"),
            Err(ClientError::InvalidPasskey)
        ));
    }

    #[test]
    fn provisional_id_has_exact_legacy_prefix() {
        let credentials = provisional_credentials().unwrap();
        assert_eq!(credentials.id.len(), 16);
        assert!(credentials.id.starts_with("XXX"));
        assert_eq!(credentials.passkey.len(), 32);
    }

    #[test]
    fn leading_hyphen_cannot_become_an_ssh_option() {
        assert!(matches!(
            validate_ssh_destination("-oProxyCommand=bad", None),
            Err(ClientError::InvalidSshComponent("host"))
        ));
        assert!(matches!(
            validate_ssh_destination("host", Some("-oProxyCommand=bad")),
            Err(ClientError::InvalidSshComponent("user"))
        ));
    }
}
