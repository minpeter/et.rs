use et_core::keys::{gen_id_passkey, passkey_to_key};

use crate::error::ClientError;

const MARKER: &[u8] = b"IDPASSKEY:";
const CREDENTIAL_LEN: usize = 16 + 1 + 32;
pub const WINDOWS_SHELL_PROBE_SENTINEL: &str = "__ET_COMSPEC__";
const CLEAR_ALL_FORWARDINGS: &str = "ClearAllForwardings=yes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub id: String,
    pub passkey: String,
}

/// Shell grammar used for the remote bootstrap command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RemoteShell {
    /// POSIX shell, as upstream assumes: `printf '%s\n' '<cred>' | 'etterminal'`.
    #[default]
    Posix,
    /// Windows `cmd.exe`, which has no `printf` and no single-quote quoting:
    /// `echo <cred>| "et.exe" "--verbose=0"`.
    Cmd,
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
    pub remote_shell: RemoteShell,
    pub session_shell: Option<String>,
}

/// Second bootstrap hop for ET-native jumphosts, mirroring the
/// `if (!jumphost.empty())` branch of upstream `SshSetupHandler::SetupSsh`:
/// `ssh [-p sshport] [user@]jumphost '<etterminal --jump ...>'`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpBootstrapRequest {
    /// `[user@]host[:sshport]` jumphost as given on the command line.
    pub jumphost: String,
    /// Final destination host passed to `--dsthost`.
    pub destination_host: String,
    /// Final destination ET port passed to `--dstport`.
    pub destination_port: u16,
    /// `--jserverfifo` value, forwarded as the jump terminal's `--serverfifo`.
    pub jump_server_fifo: Option<String>,
    pub terminal_path: Option<String>,
    pub kill_other_sessions: bool,
    pub verbose: u8,
    pub ssh_options: Vec<String>,
    pub term: String,
}

pub fn build_jump_invocation(
    request: &JumpBootstrapRequest,
    credentials: &Credentials,
) -> SshInvocation {
    let parsed = et_cli::host::parse_host_string(&request.jumphost);
    // ssh destinations do not accept user@host:port, so the ssh port from the
    // jumphost string becomes an explicit `-p` flag.
    let mut args = Vec::new();
    if let Some(port) = parsed.port_suffix.strip_prefix(':') {
        args.push("-p".to_string());
        args.push(port.to_string());
    }
    append_operational_options(&mut args, &request.ssh_options);
    let host = parsed.host.trim_matches(|c| c == '[' || c == ']');
    args.push(if parsed.user.is_empty() {
        host.to_string()
    } else {
        format!("{}@{host}", parsed.user)
    });
    args.push(jump_remote_command(request, credentials));
    SshInvocation {
        program: "ssh".to_string(),
        args,
        operation: "starting the jumphost etterminal",
        completion: InvocationCompletion::Credentials,
    }
}

fn jump_remote_command(request: &JumpBootstrapRequest, credentials: &Credentials) -> String {
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
        command.push_str("pkill -u \"$(id -un)\" 'etterminal'; sleep 0.5; ");
    }
    command.push_str(&format!(
        "printf '%s\\n' {} | {} {}",
        shell_quote(&input),
        shell_quote(terminal),
        shell_quote(&format!("--verbose={}", request.verbose))
    ));
    if let Some(fifo) = request.jump_server_fifo.as_deref() {
        command.push(' ');
        command.push_str(&shell_quote(&format!("--serverfifo={fifo}")));
    }
    command.push_str(" '--jump'");
    command.push(' ');
    command.push_str(&shell_quote(&format!(
        "--dsthost={}",
        request.destination_host
    )));
    command.push(' ');
    command.push_str(&shell_quote(&format!(
        "--dstport={}",
        request.destination_port
    )));
    command
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationCompletion {
    Exit,
    Credentials,
    ShellProbe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub operation: &'static str,
    pub completion: InvocationCompletion,
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
    append_operational_options(&mut args, &request.ssh_options);
    args.push(destination);
    args.push(remote_command(request, credentials));

    SshInvocation {
        program: "ssh".to_string(),
        args,
        operation: "starting the remote etterminal",
        completion: InvocationCompletion::Credentials,
    }
}

pub fn build_shell_probe(request: &BootstrapRequest) -> SshInvocation {
    let mut args = Vec::new();
    if let Some(jumphost) = request.jumphost.as_deref() {
        args.push("-J".to_string());
        args.push(jumphost.to_string());
    }
    let destination = match request.user.as_deref() {
        Some(user) => format!("{user}@{}", request.host_alias),
        None => request.host_alias.clone(),
    };
    append_operational_options(&mut args, &request.ssh_options);
    args.push("-oLogLevel=ERROR".to_owned());
    args.push(destination);
    args.push(format!("echo {WINDOWS_SHELL_PROBE_SENTINEL}%ComSpec%"));
    SshInvocation {
        program: "ssh".to_owned(),
        args,
        operation: "detecting the remote login shell",
        completion: InvocationCompletion::ShellProbe,
    }
}

fn append_operational_options(args: &mut Vec<String>, options: &[String]) {
    args.push(format!("-o{CLEAR_ALL_FORWARDINGS}"));
    args.extend(
        options
            .iter()
            .filter(|option| {
                !option
                    .trim_start()
                    .split(|character: char| character == '=' || character.is_ascii_whitespace())
                    .next()
                    .is_some_and(|key| key.eq_ignore_ascii_case("ClearAllForwardings"))
            })
            .map(|option| format!("-o{option}")),
    );
}

pub fn parse_shell_probe(stdout: &[u8]) -> Result<RemoteShell, ClientError> {
    let stdout = String::from_utf8_lossy(stdout);
    for line in stdout.split_inclusive('\n') {
        if !line.ends_with('\n') {
            continue;
        }
        let Some(value) = line.trim().strip_prefix(WINDOWS_SHELL_PROBE_SENTINEL) else {
            continue;
        };
        if value.eq_ignore_ascii_case("%ComSpec%") {
            return Ok(RemoteShell::Posix);
        }
        if value.to_ascii_lowercase().ends_with("cmd.exe") {
            return Ok(RemoteShell::Cmd);
        }
        break;
    }
    Err(ClientError::Unsupported(
        "remote shell probe returned unexpected output",
    ))
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
        .unwrap_or(match request.remote_shell {
            RemoteShell::Posix => "etterminal",
            RemoteShell::Cmd => "et.exe",
        });
    let input = format!(
        "{}/{}_{}",
        credentials.id, credentials.passkey, request.term
    );
    if request.remote_shell == RemoteShell::Cmd {
        return cmd_remote_command(request, terminal, &input);
    }
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

/// Build the bootstrap command for a Windows `cmd.exe` remote.
///
/// `cmd` has no `printf`, does not understand single quotes, and would treat
/// `& | < > ^ %` as syntax, so the credential line is validated instead of
/// escaped: everything in it is ASCII-alphanumeric plus `/`, `_`, `-`, and `.`.
fn cmd_remote_command(request: &BootstrapRequest, terminal: &str, input: &str) -> String {
    let mut command = String::new();
    if let Some(shell) = request.session_shell.as_deref() {
        command.push_str(&format!("set \"ET_SHELL={shell}\" & "));
    }
    if request.kill_other_sessions {
        // Best-effort equivalent of `pkill etterminal -u <user>`.
        command.push_str("taskkill /F /FI \"USERNAME eq %USERNAME%\" /IM et.exe >nul 2>&1 & ");
    }
    // `echo x| y` avoids the trailing space cmd would otherwise include.
    command.push_str(&format!("echo {input}| {}", cmd_quote(terminal)));
    // The Windows binary is the single `et.exe`, so the role has to be named
    // explicitly instead of relying on an `etterminal` argv[0].
    if !terminal_is_etterminal(terminal) {
        command.push_str(" terminal");
    }
    command.push_str(&format!(
        " {}",
        cmd_quote(&format!("--verbose={}", request.verbose))
    ));
    if let Some(fifo) = request.server_fifo.as_deref() {
        command.push_str(&format!(" {}", cmd_quote(&format!("--serverfifo={fifo}"))));
    }
    command
}

/// Whether the remote path already dispatches to the terminal role by name.
fn terminal_is_etterminal(path: &str) -> bool {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    name == "etterminal" || name == "etterminal.exe"
}

/// Quote one argument for `cmd.exe`.
fn cmd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// Reject credential material that would not survive a `cmd.exe` `echo`.
pub fn cmd_safe(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.' | b'+')
        })
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
            remote_shell: RemoteShell::Posix,
            session_shell: None,
        }
    }

    fn assert_clear_all_forwardings_once(invocation: &SshInvocation) {
        assert_eq!(
            invocation
                .args
                .iter()
                .filter(|argument| argument.as_str() == "-oClearAllForwardings=yes")
                .count(),
            1,
            "operational SSH argv must suppress configured forwarding exactly once: {:?}",
            invocation.args
        );
    }

    #[test]
    fn ssh_config_hardening_destination_bootstrap_suppresses_forwardings() {
        let mut request = request();
        request.ssh_options.extend([
            "ClearAllForwardings=no".to_owned(),
            "clearallforwardings NO".to_owned(),
            "CLEARALLFORWARDINGS = no".to_owned(),
        ]);
        let invocation = build_invocation(&request, &provisional_credentials().unwrap());

        assert_clear_all_forwardings_once(&invocation);
        let suppression = invocation
            .args
            .iter()
            .position(|argument| argument == "-oClearAllForwardings=yes")
            .unwrap();
        let destination = invocation
            .args
            .iter()
            .position(|argument| argument == "alice@server")
            .unwrap();
        assert!(suppression < destination);
        assert!(!invocation.args.iter().any(|argument| {
            argument
                .trim_start_matches("-o")
                .split(['=', ' ', '\t'])
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case("ClearAllForwardings"))
                && argument != "-oClearAllForwardings=yes"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn ssh_config_hardening_real_openssh_observes_operational_precedence() {
        struct RemoveFile(std::path::PathBuf);
        impl Drop for RemoveFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }

        let path = std::env::temp_dir().join(format!(
            "et-clear-forwarding-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("openssh")
        ));
        let _cleanup = RemoveFile(path.clone());
        std::fs::write(
            &path,
            "Host oracle\n HostName localhost\n LocalForward 15432 localhost:5432\n",
        )
        .unwrap();
        let mut request = request();
        request.ssh_options.extend([
            "clearallforwardings no".to_owned(),
            "CLEARALLFORWARDINGS=no".to_owned(),
        ]);
        let invocation = build_invocation(&request, &provisional_credentials().unwrap());
        let destination = invocation
            .args
            .iter()
            .position(|argument| argument == "alice@server")
            .unwrap();

        let output = std::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&path)
            .args(&invocation.args[..destination])
            .arg("oracle")
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let effective = String::from_utf8(output.stdout).unwrap();
        assert!(effective
            .lines()
            .any(|line| line == "clearallforwardings yes"));
        assert!(!effective
            .lines()
            .any(|line| line.starts_with("localforward ")));
    }

    #[test]
    fn ssh_config_hardening_shell_probe_suppresses_forwardings() {
        let invocation = build_shell_probe(&request());

        assert_clear_all_forwardings_once(&invocation);
    }

    #[test]
    fn ssh_config_hardening_direct_jumphost_suppresses_forwardings() {
        let request = JumpBootstrapRequest {
            jumphost: "jump.example".to_owned(),
            destination_host: "destination.example".to_owned(),
            destination_port: 2022,
            jump_server_fifo: None,
            terminal_path: None,
            kill_other_sessions: false,
            verbose: 0,
            ssh_options: Vec::new(),
            term: "xterm-256color".to_owned(),
        };
        let invocation = build_jump_invocation(&request, &provisional_credentials().unwrap());

        assert_clear_all_forwardings_once(&invocation);
    }

    #[test]
    fn builds_upstream_ssh_shape() {
        let credentials = Credentials {
            id: "XXXdefghijklmnop".into(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".into(),
        };
        let invocation = build_invocation(&request(), &credentials);
        assert_eq!(invocation.program, "ssh");
        assert_eq!(
            invocation.args[0..3],
            ["-oClearAllForwardings=yes", "-oPort=2222", "alice@server"]
        );
        assert_eq!(
            invocation.args[3],
            "printf '%s\\n' 'XXXdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_xterm-256color' | 'etterminal' '--verbose=2'"
        );
    }

    #[test]
    fn jumphost_uses_ssh_proxyjump_flag() {
        let credentials = Credentials {
            id: "XXXdefghijklmnop".into(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".into(),
        };
        let mut req = request();
        req.jumphost = Some("jump.example,user@hop2".into());
        let invocation = build_invocation(&req, &credentials);
        assert_eq!(
            invocation.args[0..5],
            [
                "-J",
                "jump.example,user@hop2",
                "-oClearAllForwardings=yes",
                "-oPort=2222",
                "alice@server",
            ]
        );
    }

    #[test]
    fn shell_probe_has_no_credentials_and_uses_cmd_sentinel() {
        let credentials = Credentials {
            id: "XXXdefghijklmnop".into(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".into(),
        };
        let invocation = build_shell_probe(&request());
        let command = invocation.args.last().unwrap();
        assert_eq!(command, "echo __ET_COMSPEC__%ComSpec%");
        assert!(!command.contains(&credentials.id));
        assert!(!command.contains(&credentials.passkey));
        assert!(invocation.args.iter().any(|arg| arg == "-oLogLevel=ERROR"));
        assert_eq!(invocation.operation, "detecting the remote login shell");
    }

    #[test]
    fn shell_probe_parser_requires_exact_sentinel_line() {
        assert_eq!(
            parse_shell_probe(b"banner\r\n__ET_COMSPEC__C:\\Windows\\System32\\cmd.exe\r\n")
                .unwrap(),
            RemoteShell::Cmd
        );
        assert_eq!(
            parse_shell_probe(b"__ET_COMSPEC__%ComSpec%\n").unwrap(),
            RemoteShell::Posix
        );
        assert!(matches!(
            parse_shell_probe(b"__ET_COMSPEC__powershell\n"),
            Err(ClientError::Unsupported(_))
        ));
        assert!(matches!(
            parse_shell_probe(b"__ET_COMSPEC__C:\\Windows\\System32\\cmd.exe"),
            Err(ClientError::Unsupported(_))
        ));
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
    fn cmd_bootstrap_uses_echo_and_double_quotes() {
        let credentials = Credentials {
            id: "XXXdefghijklmnop".into(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".into(),
        };
        let mut request = request();
        request.remote_shell = RemoteShell::Cmd;
        request.terminal_path = None;
        request.server_fifo = Some("C:\\Users\\me\\router".into());
        let command = build_invocation(&request, &credentials).args.pop().unwrap();
        assert_eq!(
            command,
            "echo XXXdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_xterm-256color| \"et.exe\" terminal \"--verbose=2\" \"--serverfifo=C:\\Users\\me\\router\""
        );
        assert!(!command.contains('\''));

        // A path already named etterminal keeps upstream's argv[0] dispatch.
        request.terminal_path = Some("C:\\tools\\etterminal.exe".into());
        let command = build_invocation(&request, &credentials).args.pop().unwrap();
        assert!(!command.contains(" terminal \""), "{command}");
    }

    #[test]
    fn cmd_bootstrap_exports_requested_session_shell() {
        let credentials = Credentials {
            id: "XXXdefghijklmnop".into(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".into(),
        };
        let mut request = request();
        request.remote_shell = RemoteShell::Cmd;
        request.session_shell = Some("powershell.exe".to_owned());
        let command = build_invocation(&request, &credentials).args.pop().unwrap();
        assert_eq!(
            command,
            "set \"ET_SHELL=powershell.exe\" & echo XXXdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef_xterm-256color| \"et.exe\" terminal \"--verbose=2\""
        );
    }

    #[test]
    fn cmd_safe_rejects_shell_metacharacters() {
        assert!(cmd_safe("XXXabc/DEF_xterm-256color"));
        assert!(!cmd_safe("bad&echo"));
        assert!(!cmd_safe("bad|echo"));
        assert!(!cmd_safe("bad>file"));
        assert!(!cmd_safe(""));
    }

    #[test]
    fn jump_bootstrap_matches_upstream_command_shape() {
        let credentials = Credentials {
            id: "XXXdefghijklmnop".into(),
            passkey: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".into(),
        };
        let request = JumpBootstrapRequest {
            jumphost: "user@jump.example:2200".into(),
            destination_host: "dst.internal".into(),
            destination_port: 9901,
            jump_server_fifo: Some("/tmp/jump.fifo".into()),
            terminal_path: None,
            kill_other_sessions: false,
            verbose: 1,
            ssh_options: vec!["StrictHostKeyChecking=no".into()],
            term: "xterm-256color".into(),
        };
        let invocation = build_jump_invocation(&request, &credentials);
        assert_eq!(
            invocation.args[0..5],
            [
                "-p",
                "2200",
                "-oClearAllForwardings=yes",
                "-oStrictHostKeyChecking=no",
                "user@jump.example"
            ]
        );
        let command = &invocation.args[5];
        assert!(command.contains("'--serverfifo=/tmp/jump.fifo'"));
        assert!(command.contains("'--jump'"));
        assert!(command.contains("'--dsthost=dst.internal'"));
        assert!(command.contains("'--dstport=9901'"));
    }

    #[test]
    fn jump_bootstrap_quotes_injection_attempts() {
        let credentials = provisional_credentials().unwrap();
        let request = JumpBootstrapRequest {
            jumphost: "jump".into(),
            destination_host: "d'; touch dst; echo '".into(),
            destination_port: 2022,
            jump_server_fifo: Some("/tmp/f'; touch fifo; echo '".into()),
            terminal_path: None,
            kill_other_sessions: false,
            verbose: 0,
            ssh_options: Vec::new(),
            term: "xterm".into(),
        };
        let command = build_jump_invocation(&request, &credentials)
            .args
            .pop()
            .unwrap();
        assert!(command.contains("touch dst"));
        assert!(command.contains("touch fifo"));
        assert_eq!(command.matches("'\"'\"'").count(), 4);
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
