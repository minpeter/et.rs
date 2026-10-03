use crate::bootstrap::{
    append_ssh_config_flag, validate_ssh_destination, InvocationCompletion, SshInvocation,
};
use crate::deadline::Deadline;
use crate::error::ClientError;
use crate::ssh_process::{run_checked, SshRunner};
use et_core::proto::{PortForwardSourceRequest, SocketEndpoint};

#[derive(Clone, Copy)]
enum GatewayPorts {
    No,
    Yes,
    ClientSpecified,
}

#[derive(Clone, Copy)]
enum StreamLocalBindPolicy {
    Default,
    Unsupported,
}

#[derive(Clone, Copy)]
struct ForwardPolicies {
    gateway_ports: GatewayPorts,
    stream_local_bind: StreamLocalBindPolicy,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResolvedSshConfig {
    pub hostname: String,
    pub user: Option<String>,
    pub port: u16,
    pub exit_on_forward_failure: bool,
    pub local_forwards: Vec<PortForwardSourceRequest>,
    pub set_env: Vec<(String, String)>,
    pub proxy_jump: Option<String>,
    pub forward_agent: bool,
    pub identity_agent: Option<String>,
    pub remote_forwards: Vec<PortForwardSourceRequest>,
    pub dynamic_forwards: Vec<SocketEndpoint>,
    pub send_env: Vec<String>,
    pub remote_command: Option<String>,
    pub clear_all_forwardings: bool,
    pub batch_mode: bool,
    pub server_alive_interval: u32,
    pub control_master: Option<et_cli::client::ControlMasterMode>,
    pub control_path: Option<String>,
    pub control_persist: Option<et_cli::client::ControlPersist>,
    /// Original local query output, used by `et -G` without a connection.
    pub dump: String,
}

impl ResolvedSshConfig {
    /// Additive ET session options are applied after file resolution. They must
    /// never accidentally create forwards or commands on the bootstrap SSH link.
    pub fn apply_session_options(&mut self, options: &[String]) -> Result<(), ClientError> {
        let mut changed = std::collections::BTreeSet::new();
        for option in options {
            let (key, value) = et_cli::client::split_ssh_option(option);
            let key = key.to_ascii_lowercase();
            if key.is_empty() || value.is_empty() || value.contains(['\0', '\n', '\r']) {
                return Err(ClientError::SshConfigMalformed("-o option"));
            }
            match key.as_str() {
                "localforward" | "remoteforward" => {
                    let requests = if value.split_whitespace().count() == 1 {
                        et_cli::tunnel::parse_tunnels(&[value.to_owned()])
                            .map_err(crate::forward_config::ForwardConfigError::Tunnel)?
                    } else {
                        let record = parse_forward(
                            value.split_whitespace(),
                            ForwardPolicies {
                                gateway_ports: if key == "localforward" {
                                    GatewayPorts::No
                                } else {
                                    GatewayPorts::ClientSpecified
                                },
                                stream_local_bind: StreamLocalBindPolicy::Default,
                            },
                            if key == "localforward" {
                                "localforward"
                            } else {
                                "remoteforward"
                            },
                        )?;
                        match record {
                            ForwardRecord::Supported(request) => vec![request],
                            ForwardRecord::Unsupported(reason) => {
                                warn_unsupported(&key, &reason);
                                Vec::new()
                            }
                        }
                    };
                    if !self.clear_all_forwardings {
                        if key == "localforward" {
                            self.local_forwards.extend(requests);
                        } else {
                            self.remote_forwards.extend(requests);
                        }
                    }
                }
                "dynamicforward" => {
                    let endpoint = et_cli::tunnel::parse_dynamic_forward(value)
                        .map_err(crate::forward_config::ForwardConfigError::Tunnel)?;
                    if !self.clear_all_forwardings {
                        self.dynamic_forwards.push(endpoint);
                    }
                }
                "sendenv" => {
                    for pattern in value.split_whitespace() {
                        if let Some(remove) = pattern.strip_prefix('-') {
                            self.send_env.retain(|existing| {
                                !crate::client_environment::environment_pattern_matches(
                                    remove.as_bytes(),
                                    existing.as_bytes(),
                                )
                            });
                        } else {
                            self.send_env.push(pattern.to_owned());
                        }
                    }
                }
                "setenv" => {
                    for assignment in split_quoted_words(value)? {
                        let (name, value) = assignment
                            .split_once('=')
                            .ok_or(ClientError::SshConfigMalformed("setenv"))?;
                        if !crate::terminal_protocol::valid_environment_name(name)
                            || value.len() > crate::terminal_protocol::MAX_ENV_VALUE
                        {
                            return Err(ClientError::SshConfigMalformed("setenv"));
                        }
                        self.set_env.retain(|(existing, _)| existing != name);
                        self.set_env.push((name.to_owned(), value.to_owned()));
                    }
                }
                _ => continue,
            }
            changed.insert(key);
        }
        if changed.is_empty() {
            return Ok(());
        }
        self.dump = self
            .dump
            .lines()
            .filter(|line| !changed.contains(line.split_whitespace().next().unwrap_or("")))
            .map(|line| format!("{line}\n"))
            .collect();
        for key in changed {
            match key.as_str() {
                "sendenv" => {
                    for pattern in &self.send_env {
                        self.dump.push_str(&format!("sendenv {pattern}\n"));
                    }
                }
                "setenv" => {
                    for (name, value) in &self.set_env {
                        self.dump.push_str(&format!("setenv {name}={value}\n"));
                    }
                }
                "dynamicforward" => {
                    for endpoint in &self.dynamic_forwards {
                        self.dump
                            .push_str(&format!("dynamicforward {}\n", format_endpoint(endpoint)));
                    }
                }
                _ => {
                    let requests = if key == "localforward" {
                        &self.local_forwards
                    } else {
                        &self.remote_forwards
                    };
                    for request in requests {
                        if let (Some(source), Some(destination)) =
                            (&request.source, &request.destination)
                        {
                            self.dump.push_str(&format!(
                                "{key} {} {}\n",
                                format_endpoint(source),
                                format_endpoint(destination)
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn format_endpoint(endpoint: &SocketEndpoint) -> String {
    match (endpoint.name.as_deref(), endpoint.port) {
        (Some(name), Some(port)) if name.contains(':') => format!("[{name}]:{port}"),
        (Some(name), Some(port)) => format!("{name}:{port}"),
        (None, Some(port)) => format!("localhost:{port}"),
        (Some(name), None) => name.to_owned(),
        (None, None) => String::new(),
    }
}

/// Inputs for `ssh -G` configuration expansion.
#[derive(Clone, Copy)]
pub struct SshConfigQuery<'a> {
    pub host_alias: &'a str,
    pub requested_user: Option<&'a str>,
    /// Port given explicitly on the command line (`host:port`). It must reach
    /// `ssh -G`, because the resolved port becomes part of the control-master
    /// identity: resolving without it yields the config/default port and would
    /// multiplex a session for `host:2200` through a master established for
    /// `host:22`.
    pub explicit_port: Option<u16>,
    pub ssh_options: &'a [String],
    pub ssh_config: Option<&'a str>,
    /// When false, jumphost-only lookups resolve address/user/port and do not
    /// import or reject session options belonging to the relay host.
    pub parse_local_forwards: bool,
}

enum ForwardRecord {
    Supported(PortForwardSourceRequest),
    Unsupported(String),
}

#[cfg(test)]
pub fn resolve_ssh_config(
    runner: &dyn SshRunner,
    host_alias: &str,
    requested_user: Option<&str>,
    ssh_options: &[String],
    ssh_config: Option<&str>,
    parse_local_forwards: bool,
    deadline: Deadline,
) -> Result<ResolvedSshConfig, ClientError> {
    resolve_ssh_config_on_port(
        runner,
        SshConfigQuery {
            host_alias,
            requested_user,
            explicit_port: None,
            ssh_options,
            ssh_config,
            parse_local_forwards,
        },
        deadline,
    )
}

/// Resolve SSH configuration, honouring an explicit command-line port.
pub fn resolve_ssh_config_on_port(
    runner: &dyn SshRunner,
    query: SshConfigQuery<'_>,
    deadline: Deadline,
) -> Result<ResolvedSshConfig, ClientError> {
    validate_ssh_destination(query.host_alias, query.requested_user)?;
    // Config expansion never opens a remote session. Disable PTY allocation
    // so Windows OpenSSH completes reliably when stdout is a pipe, preserving
    // the bounded SystemSsh capture path.
    let mut args = vec!["-G".to_string(), "-T".to_string()];
    append_ssh_config_flag(&mut args, query.ssh_config);
    if let Some(port) = query.explicit_port {
        args.extend(["-p".to_string(), port.to_string()]);
    }
    args.extend(query.ssh_options.iter().map(|option| format!("-o{option}")));
    let destination = match query.requested_user {
        Some(user) => format!("{user}@{}", query.host_alias),
        None => query.host_alias.to_string(),
    };
    args.push(destination);
    let invocation = SshInvocation {
        program: "ssh".to_string(),
        args,
        operation: "resolving SSH configuration",
        completion: InvocationCompletion::Exit,
        control_path: None,
    };
    let stdout = run_checked(runner, &invocation, deadline)?;
    if stdout
        .split(|byte| *byte == b'\n')
        .any(|line| line.starts_with(b"setenv "))
    {
        // ssh -G emits SetEnv values unescaped. A newline in a value must
        // never become a hostname, ProxyJump, or forwarding directive. The
        // first nonempty SetEnv option suppresses the entire configured list.
        let mut baseline = invocation.clone();
        baseline
            .args
            .insert(2, "-oSetEnv=ET_RS_CONFIG_SENTINEL=1".to_owned());
        verify_setenv_block(&stdout, &run_checked(runner, &baseline, deadline)?)?;
    }
    if stdout
        .split(|byte| *byte == b'\n')
        .any(|line| line.starts_with(b"remotecommand "))
    {
        let mut baseline = invocation.clone();
        baseline
            .args
            .insert(2, "-oRemoteCommand=ET_RS_CONFIG_SENTINEL".to_owned());
        let baseline = run_checked(runner, &baseline, deadline)?;
        let malformed = || ClientError::SshConfigMalformed("ambiguous RemoteCommand output");
        let baseline = std::str::from_utf8(&baseline).map_err(|_| malformed())?;
        let original = std::str::from_utf8(&stdout).map_err(|_| malformed())?;
        let (before, after) = baseline
            .split_once("remotecommand ET_RS_CONFIG_SENTINEL")
            .ok_or_else(malformed)?;
        let (newline, after) = if let Some(after) = after.strip_prefix("\r\n") {
            ("\r\n", after)
        } else {
            ("\n", after.strip_prefix('\n').ok_or_else(malformed)?)
        };
        let command = original
            .strip_prefix(before)
            .and_then(|rest| rest.strip_suffix(after))
            .ok_or_else(malformed)?;
        let command = command
            .strip_prefix("remotecommand ")
            .and_then(|rest| rest.strip_suffix(newline))
            .ok_or_else(malformed)?;
        if command.contains(['\n', '\r', '\0']) {
            return Err(malformed());
        }
    }
    parse_ssh_config(&stdout, query.parse_local_forwards)
}

fn verify_setenv_block(original: &[u8], baseline: &[u8]) -> Result<(), ClientError> {
    let malformed = || ClientError::SshConfigMalformed("ambiguous or changed SetEnv output");
    let original = std::str::from_utf8(original).map_err(|_| malformed())?;
    let baseline = std::str::from_utf8(baseline).map_err(|_| malformed())?;
    let mut offset = 0;
    let mut block = None;
    for line in baseline.split_inclusive('\n') {
        if line.starts_with("setenv ") {
            if block.is_some()
                || !matches!(
                    line,
                    "setenv ET_RS_CONFIG_SENTINEL=1\n" | "setenv ET_RS_CONFIG_SENTINEL=1\r\n"
                )
            {
                return Err(malformed());
            }
            block = Some(offset..offset + line.len());
        }
        offset += line.len();
    }
    let block = block.ok_or_else(malformed)?;
    let environment = original
        .strip_prefix(&baseline[..block.start])
        .and_then(|rest| rest.strip_suffix(&baseline[block.end..]))
        .ok_or_else(malformed)?;
    if !environment.ends_with('\n')
        || !environment
            .lines()
            .all(|line| line.starts_with("setenv ") && !line.contains('\r'))
    {
        return Err(malformed());
    }
    Ok(())
}

fn parse_ssh_config(
    stdout: &[u8],
    parse_local_forwards: bool,
) -> Result<ResolvedSshConfig, ClientError> {
    let text =
        std::str::from_utf8(stdout).map_err(|_| ClientError::SshConfigMalformed("UTF-8 output"))?;
    let gateway_ports = text
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            fields
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case("gatewayports"))
                .then(|| fields.next())
                .flatten()
        })
        .map(GatewayPorts::parse)
        .transpose()?
        .unwrap_or(GatewayPorts::No);
    let policies = ForwardPolicies {
        gateway_ports,
        stream_local_bind: StreamLocalBindPolicy::parse(text),
    };
    let exit_on_forward_failure = text
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            fields
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case("exitonforwardfailure"))
                .then(|| fields.next())
                .flatten()
        })
        .map(|value| parse_yes_no("exitonforwardfailure", value))
        .transpose()?
        .unwrap_or(false);
    let mut hostname = None;
    let mut user = None;
    let mut port = None;
    let mut local_forwards = Vec::new();
    let mut extra = ResolvedSshConfig {
        dump: text.to_owned(),
        ..Default::default()
    };
    let mut environment_names = std::collections::BTreeSet::new();
    let unsupported_dynamic = unsupported_dynamic_forwards(text);
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        // OpenSSH prints the value verbatim, without shell quoting. In
        // particular, SetEnv is one assignment per output line.
        let value = line
            .trim_start()
            .split_once(char::is_whitespace)
            .map(|(_, value)| value)
            .unwrap_or("");
        match fields.next() {
            // Jumphost-only lookups resolve address/user/port; they must not
            // import or reject session options belonging to the relay host.
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("setenv") => {
                let (name, value) = value
                    .split_once('=')
                    .ok_or(ClientError::SshConfigMalformed("setenv"))?;
                if !crate::terminal_protocol::valid_environment_name(name)
                    || value.len() > crate::terminal_protocol::MAX_ENV_VALUE
                    || value.contains(['\0', '\r'])
                {
                    return Err(ClientError::SshConfigMalformed("setenv"));
                }
                if environment_names.insert(name) {
                    extra.set_env.push((name.to_owned(), value.to_owned()));
                }
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("proxyjump") => {
                extra.proxy_jump = (value != "none").then(|| value.to_owned());
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("forwardagent") => {
                extra.forward_agent = parse_yes_no("forwardagent", value)?;
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("identityagent") => {
                extra.identity_agent = Some(value.to_owned());
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("sendenv") => {
                extra
                    .send_env
                    .extend(value.split_whitespace().map(str::to_owned));
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("remotecommand") => {
                extra.remote_command = (!value.eq_ignore_ascii_case("none") && !value.is_empty())
                    .then(|| value.to_owned());
            }
            Some(key)
                if parse_local_forwards && key.eq_ignore_ascii_case("clearallforwardings") =>
            {
                extra.clear_all_forwardings = parse_yes_no("clearallforwardings", value)?;
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("batchmode") => {
                extra.batch_mode = parse_yes_no("batchmode", value)?;
            }
            Some(key)
                if parse_local_forwards && key.eq_ignore_ascii_case("serveraliveinterval") =>
            {
                extra.server_alive_interval = value
                    .parse()
                    .map_err(|_| ClientError::SshConfigMalformed("serveraliveinterval"))?;
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("controlmaster") => {
                extra.control_master = Some(
                    value
                        .parse()
                        .map_err(|_| ClientError::SshConfigMalformed("controlmaster"))?,
                );
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("controlpath") => {
                extra.control_path = (value != "none").then(|| value.to_owned());
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("controlpersist") => {
                extra.control_persist = Some(
                    value
                        .parse()
                        .map_err(|_| ClientError::SshConfigMalformed("controlpersist"))?,
                );
            }
            Some(key) if key.eq_ignore_ascii_case("hostname") => {
                hostname = fields.next().map(str::to_string);
            }
            Some(key) if key.eq_ignore_ascii_case("user") => {
                user = fields.next().map(str::to_string);
            }
            Some(key) if key.eq_ignore_ascii_case("port") => {
                port = fields.next().and_then(|port| port.parse::<u16>().ok());
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("dynamicforward") => {
                // Some OpenSSH versions print an additional dynamicforward for
                // a LocalForward whose destination is a Unix socket.
                if unsupported_dynamic.contains(&value) {
                    let source = parse_source_endpoint(value, policies.gateway_ports, true)
                        .ok_or(ClientError::SshConfigMalformed("dynamicforward"))?;
                    extra.dynamic_forwards.push(source);
                }
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("remoteforward") => {
                let fields: Vec<_> = fields.collect();
                if fields.get(1) == Some(&"[socks]:0")
                    || fields
                        .first()
                        .is_some_and(|source| *source == "0" || source.ends_with(":0"))
                {
                    warn_unsupported(
                        "remoteforward",
                        "reverse SOCKS and server-allocated ports are unsupported",
                    );
                    continue;
                }
                match parse_forward(
                    fields.into_iter(),
                    ForwardPolicies {
                        gateway_ports: GatewayPorts::ClientSpecified,
                        ..policies
                    },
                    "remoteforward",
                )? {
                    ForwardRecord::Supported(forward) => extra.remote_forwards.push(forward),
                    ForwardRecord::Unsupported(reason) => {
                        warn_unsupported("remoteforward", &reason)
                    }
                }
            }
            Some(key) if parse_local_forwards && key.eq_ignore_ascii_case("localforward") => {
                match parse_forward(fields, policies, "localforward")? {
                    ForwardRecord::Supported(forward) => local_forwards.push(forward),
                    ForwardRecord::Unsupported(reason) => {
                        warn_unsupported("localforward", &reason);
                    }
                }
            }
            _ => {}
        }
    }
    let hostname = hostname
        .filter(|hostname| !hostname.is_empty())
        .ok_or(ClientError::SshConfigMalformed("hostname"))?;
    let user = user.filter(|user| !user.is_empty());
    validate_ssh_destination(&hostname, user.as_deref())?;
    if extra.clear_all_forwardings {
        local_forwards.clear();
        extra.remote_forwards.clear();
        extra.dynamic_forwards.clear();
    }
    Ok(ResolvedSshConfig {
        hostname,
        user,
        port: port.unwrap_or(22),
        exit_on_forward_failure,
        local_forwards,
        ..extra
    })
}

fn unsupported_dynamic_forwards(text: &str) -> Vec<&str> {
    let mut dynamic: Vec<&str> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            fields
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case("dynamicforward"))
                .then(|| fields.next())
                .flatten()
        })
        .collect();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let is_local = fields
            .next()
            .is_some_and(|key| key.eq_ignore_ascii_case("localforward"));
        let source = fields.next();
        let destination = fields.next();
        if is_local && destination.is_some_and(|value| value.starts_with('/')) {
            if let Some(index) = dynamic
                .iter()
                .position(|candidate| Some(*candidate) == source)
            {
                dynamic.remove(index);
            }
        }
    }
    dynamic
}

fn warn_unsupported(directive: &str, reason: &str) {
    et_cli::logging::warn(format!("SSH {directive} {reason}; skipping forwarding row"));
}

fn parse_forward<'a>(
    fields: impl Iterator<Item = &'a str>,
    policies: ForwardPolicies,
    directive: &'static str,
) -> Result<ForwardRecord, ClientError> {
    let fields: Vec<&str> = fields.collect();
    if fields.len() != 2 && fields.iter().any(|field| field.contains('/')) {
        return Ok(ForwardRecord::Unsupported(
            "ambiguous stream-local path is unsupported".to_owned(),
        ));
    }
    let [source, destination] = fields.as_slice() else {
        return Err(ClientError::SshConfigMalformedForward {
            directive,
            reason: "expected exactly two fields",
        });
    };
    if is_relative_stream_path(source) || is_relative_stream_path(destination) {
        return Ok(ForwardRecord::Unsupported(
            "relative stream-local path is unsupported".to_owned(),
        ));
    }
    if source.starts_with('/') {
        match policies.stream_local_bind {
            StreamLocalBindPolicy::Default => {}
            StreamLocalBindPolicy::Unsupported => {
                return Ok(ForwardRecord::Unsupported(
                    "stream-local bind policy is unsupported".to_owned(),
                ));
            }
        }
        #[cfg(not(unix))]
        return Ok(ForwardRecord::Unsupported(
            "stream-local forwarding is unsupported on this platform".to_owned(),
        ));
    }
    #[cfg(not(unix))]
    if destination.starts_with('/') {
        return Ok(ForwardRecord::Unsupported(
            "stream-local forwarding is unsupported on this platform".to_owned(),
        ));
    }
    let source = parse_source_endpoint(source, policies.gateway_ports, true).ok_or(
        ClientError::SshConfigMalformedForward {
            directive,
            reason: "invalid source endpoint",
        },
    )?;
    let destination =
        parse_destination_endpoint(destination).ok_or(ClientError::SshConfigMalformedForward {
            directive,
            reason: "invalid destination endpoint",
        })?;
    Ok(ForwardRecord::Supported(PortForwardSourceRequest {
        source: Some(source),
        destination: Some(destination),
        environmentvariable: None,
    }))
}

fn is_relative_stream_path(value: &str) -> bool {
    !value.starts_with('/') && value.contains('/')
}

fn parse_yes_no(directive: &'static str, value: &str) -> Result<bool, ClientError> {
    match value {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(ClientError::SshConfigMalformed(directive)),
    }
}

fn split_quoted_words(value: &str) -> Result<Vec<String>, ClientError> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            word.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if quote == Some(character) {
            quote = None;
        } else if quote.is_none() && matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if quote.is_none() && character.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err(ClientError::SshConfigMalformed("setenv"));
    }
    if !word.is_empty() {
        words.push(word);
    }
    Ok(words)
}

impl GatewayPorts {
    fn parse(value: &str) -> Result<Self, ClientError> {
        match value {
            "no" => Ok(Self::No),
            "yes" => Ok(Self::Yes),
            "clientspecified" => Ok(Self::ClientSpecified),
            _ => Err(ClientError::SshConfigMalformed("gatewayports")),
        }
    }
}

impl StreamLocalBindPolicy {
    fn parse(text: &str) -> Self {
        let mut policy = Self::Default;
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next()) {
                (Some(key), Some(value))
                    if key.eq_ignore_ascii_case("streamlocalbindunlink")
                        && !value.eq_ignore_ascii_case("no") =>
                {
                    policy = Self::Unsupported;
                }
                (Some(key), Some(value))
                    if key.eq_ignore_ascii_case("streamlocalbindmask")
                        && value != "0177"
                        && value != "177" =>
                {
                    policy = Self::Unsupported;
                }
                _ => {}
            }
        }
        policy
    }
}

fn parse_source_endpoint(
    value: &str,
    gateway_ports: GatewayPorts,
    is_local_forward: bool,
) -> Option<SocketEndpoint> {
    if let Some(endpoint) = parse_unix_endpoint(value) {
        return Some(endpoint);
    }
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(normalize_tcp_source(
            SocketEndpoint {
                name: None,
                port: Some(parse_port(value)?),
            },
            gateway_ports,
            is_local_forward,
        ));
    }
    parse_tcp_endpoint(value, true)
        .map(|endpoint| normalize_tcp_source(endpoint, gateway_ports, is_local_forward))
}

fn normalize_tcp_source(
    mut endpoint: SocketEndpoint,
    gateway_ports: GatewayPorts,
    is_local_forward: bool,
) -> SocketEndpoint {
    let requested = endpoint.name.take();
    let normalized = match (is_local_forward, gateway_ports, requested) {
        (false, _, None) => "localhost".to_owned(),
        (false, _, Some(requested)) if requested == "*" || requested == "[*]" => String::new(),
        (false, _, Some(requested)) => requested,
        (true, _, Some(requested))
            if requested.is_empty() || requested == "*" || requested == "[*]" =>
        {
            String::new()
        }
        (true, _, Some(requested)) => requested,
        (true, GatewayPorts::No | GatewayPorts::ClientSpecified, None) => "localhost".to_owned(),
        (true, GatewayPorts::Yes, None) => String::new(),
    };
    endpoint.name = Some(normalized);
    endpoint
}

fn parse_destination_endpoint(value: &str) -> Option<SocketEndpoint> {
    parse_unix_endpoint(value).or_else(|| parse_tcp_endpoint(value, false))
}

fn parse_unix_endpoint(value: &str) -> Option<SocketEndpoint> {
    if !value.starts_with('/') || value == "/" || value.len() > 107 || value.contains('\0') {
        return None;
    }
    Some(SocketEndpoint {
        name: Some(value.to_owned()),
        port: None,
    })
}

fn parse_tcp_endpoint(value: &str, allow_empty_host: bool) -> Option<SocketEndpoint> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, port) = bracketed.split_once("]:")?;
        if (!allow_empty_host && host.is_empty()) || port.contains(':') {
            return None;
        }
        (host, port)
    } else {
        let (host, port) = value.rsplit_once(':')?;
        if host.is_empty() || host.contains(':') {
            return None;
        }
        (host, port)
    };
    Some(SocketEndpoint {
        name: Some(host.to_owned()),
        port: Some(parse_port(port)?),
    })
}

fn parse_port(value: &str) -> Option<i32> {
    let port = value.parse::<u16>().ok()?;
    (port != 0).then(|| i32::from(port))
}

/// Validate `--ssh-config <path>`. `none` is handled by the caller.
///
/// Fail closed on relative, shell-unsafe, missing, non-regular, or symlink
/// paths. Windows drive and UNC shapes are accepted as absolute so the
/// Windows client can select a policy file.
pub fn validate_ssh_config_file(path: &str) -> Result<(), ClientError> {
    if !is_absolute_ssh_config_path(path) {
        return Err(ClientError::InvalidSshConfig(
            "must be an absolute path or 'none'",
        ));
    }
    if !is_ssh_config_path_safe_for_proxy_jump(path) {
        return Err(ClientError::InvalidSshConfig(
            "must contain only ASCII letters, digits, '/', '.', '_', and '-' (Windows also allows ':' and '\\')",
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        ClientError::InvalidSshConfig("must name a readable, non-symlink regular file")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ClientError::InvalidSshConfig(
            "must name a readable, non-symlink regular file",
        ));
    }
    std::fs::File::open(path).map_err(|_| {
        ClientError::InvalidSshConfig("must name a readable, non-symlink regular file")
    })?;
    Ok(())
}

pub(crate) fn is_absolute_ssh_config_path(path: &str) -> bool {
    if std::path::Path::new(path).is_absolute() {
        return true;
    }
    is_windows_absolute_ssh_config_path(path)
}

fn is_windows_absolute_ssh_config_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[0] == b'\\' && bytes[1] == b'\\' {
        return true;
    }
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

pub(crate) fn is_ssh_config_path_safe_for_proxy_jump(path: &str) -> bool {
    if !is_absolute_ssh_config_path(path) {
        return false;
    }
    let windows_path = is_windows_absolute_ssh_config_path(path);
    path.chars()
        .all(|character| is_ssh_config_path_char_safe(character, windows_path))
}

fn is_ssh_config_path_char_safe(character: char, windows_path: bool) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(character, '/' | '.' | '_' | '-')
        || (windows_path && matches!(character, ':' | '\\'))
}

#[cfg(test)]
mod tests {
    use std::process::{Command, ExitStatus};
    use std::time::Duration;

    use crate::ssh_process::SshOutput;

    use super::*;

    #[test]
    fn session_rows_preserve_remote_dynamic_and_additive_overrides() {
        let mut config = parse_ssh_config(b"hostname host\nremoteforward [::1]:9000 [db.internal]:5432\ndynamicforward [127.0.0.1]:1080\nremotecommand echo configured\nserveraliveinterval 3\nbatchmode yes\ncontrolmaster auto\ncontrolpath /tmp/master\ncontrolpersist 17\nsendenv APP_* LC_*\nsetenv APP_FIXED=file\n", true).unwrap();
        assert_eq!(
            config.remote_forwards,
            [request("::1", Some(9000), "db.internal", Some(5432))]
        );
        assert_eq!(
            config.dynamic_forwards,
            [SocketEndpoint {
                name: Some("127.0.0.1".into()),
                port: Some(1080)
            }]
        );
        assert_eq!(config.remote_command.as_deref(), Some("echo configured"));
        assert_eq!(config.server_alive_interval, 3);
        assert!(config.batch_mode);
        assert_eq!(
            config.control_master,
            Some(et_cli::client::ControlMasterMode::Auto)
        );
        assert_eq!(config.control_persist.unwrap().seconds, 17);
        config
            .apply_session_options(&[
                "RemoteForward=9001:db.other:5433".into(),
                "LocalForward=8000-8001:80-81".into(),
                "DynamicForward=[::1]:1081".into(),
                "SendEnv=-LC_* CUSTOM_?".into(),
                "SetEnv=APP_FIXED=cli EMPTY=".into(),
            ])
            .unwrap();
        assert_eq!(config.remote_forwards.len(), 2);
        assert_eq!(config.local_forwards.len(), 2);
        assert_eq!(config.dynamic_forwards.len(), 2);
        assert_eq!(config.send_env, ["APP_*", "CUSTOM_?"]);
        assert_eq!(
            config.set_env,
            [
                ("APP_FIXED".into(), "cli".into()),
                ("EMPTY".into(), "".into())
            ]
        );
        assert!(config.dump.contains("setenv APP_FIXED=cli\n"));
        assert!(!config.dump.contains("setenv APP_FIXED=file\n"));
        let mut cleared = parse_ssh_config(b"hostname host\nclearallforwardings yes\nlocalforward 8000 localhost:80\nremoteforward 9000 localhost:90\ndynamicforward 1080\n", true).unwrap();
        cleared
            .apply_session_options(&[
                "LocalForward=8001:81".into(),
                "RemoteForward=9001:91".into(),
                "DynamicForward=1081".into(),
            ])
            .unwrap();
        assert!(
            cleared.local_forwards.is_empty()
                && cleared.remote_forwards.is_empty()
                && cleared.dynamic_forwards.is_empty()
        );
        assert!(
            parse_ssh_config(b"hostname host\nremotecommand none\n", true)
                .unwrap()
                .remote_command
                .is_none()
        );
    }

    #[test]
    fn remote_command_cannot_inject_config_routing() {
        let runner = crate::ssh_process::SystemSsh::default();
        let error = resolve_ssh_config(
            &runner,
            "host.invalid",
            None,
            &["RemoteCommand=echo ok\nhostname attacker.invalid".into()],
            Some("none"),
            true,
            Deadline::after(Duration::from_secs(3)),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ClientError::SshConfigMalformed("ambiguous RemoteCommand output")
        ));
    }

    #[test]
    fn remote_command_verification_accepts_crlf_but_not_embedded_newlines() {
        struct Runner<'a> {
            command: &'a str,
        }
        impl SshRunner for Runner<'_> {
            fn run(
                &self,
                invocation: &SshInvocation,
                _: Deadline,
            ) -> Result<SshOutput, ClientError> {
                let command = if invocation
                    .args
                    .iter()
                    .any(|arg| arg == "-oRemoteCommand=ET_RS_CONFIG_SENTINEL")
                {
                    "ET_RS_CONFIG_SENTINEL"
                } else {
                    self.command
                };
                Ok(SshOutput {
                    status: Some(success_status()),
                    stdout: format!("hostname host\r\nremotecommand {command}\r\nport 22\r\n")
                        .into_bytes(),
                })
            }
        }
        for command in [
            "echo hello",
            "echo ok\nhostname attacker",
            "echo ok\r\nhostname attacker",
        ] {
            let resolved = resolve_ssh_config(
                &Runner { command },
                "host",
                None,
                &[],
                Some("none"),
                true,
                Deadline::after(Duration::from_secs(3)),
            );
            if command == "echo hello" {
                assert_eq!(resolved.unwrap().remote_command.as_deref(), Some(command));
            } else {
                assert!(matches!(
                    resolved,
                    Err(ClientError::SshConfigMalformed(
                        "ambiguous RemoteCommand output"
                    ))
                ));
            }
        }
    }

    struct FakeRunner {
        stdout: Vec<u8>,
    }

    impl SshRunner for FakeRunner {
        fn run(&self, invocation: &SshInvocation, _: Deadline) -> Result<SshOutput, ClientError> {
            assert_eq!(
                invocation.args,
                ["-G", "-T", "-oPort=2222", "requested@server-alias"]
            );
            Ok(SshOutput {
                status: Some(success_status()),
                stdout: self.stdout.clone(),
            })
        }
    }

    fn success_status() -> ExitStatus {
        Command::new("true").status().unwrap()
    }

    #[test]
    fn ssh_config_hardening_query_does_not_suppress_forwardings() {
        let runner = FakeRunner {
            stdout: b"host server-alias\nuser config-user\nhostname 127.0.0.1\nport 22\n".to_vec(),
        };
        let resolved = resolve_ssh_config(
            &runner,
            "server-alias",
            Some("requested"),
            &["Port=2222".to_string()],
            None,
            true,
            Deadline::after(Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(
            resolved,
            ResolvedSshConfig {
                hostname: "127.0.0.1".to_string(),
                user: Some("config-user".to_string()),
                port: 22,
                exit_on_forward_failure: false,
                local_forwards: Vec::new(),
                dump: String::from_utf8(runner.stdout.clone()).unwrap(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn effective_environment_rows_are_not_shell_words() {
        let config = parse_ssh_config(b"hostname host\nsetenv A=two words  \nsetenv B=a=b\nsetenv EMPTY=\nsetenv Q=\"quote\"\\literal\nsetenv A=ignored\nforwardagent yes\nidentityagent /tmp/agent space\nproxyjump user@[::1]:2222\n", true).unwrap();
        assert_eq!(
            config.set_env,
            [
                ("A".into(), "two words  ".into()),
                ("B".into(), "a=b".into()),
                ("EMPTY".into(), "".into()),
                ("Q".into(), "\"quote\"\\literal".into()),
            ]
        );
        assert!(config.forward_agent);
        assert_eq!(config.identity_agent.as_deref(), Some("/tmp/agent space"));
        assert_eq!(config.proxy_jump.as_deref(), Some("user@[::1]:2222"));
        let disabled = parse_ssh_config(
            b"hostname host\nforwardagent no\nidentityagent none\nproxyjump none\n",
            true,
        )
        .unwrap();
        assert!(!disabled.forward_agent);
        assert_eq!(disabled.identity_agent.as_deref(), Some("none"));
        assert_eq!(disabled.proxy_jump, None);
        let spaced = parse_ssh_config(
            b"hostname host\nidentityagent  /tmp/agent \nsetenv A= leading and trailing \n",
            true,
        )
        .unwrap();
        assert_eq!(spaced.identity_agent.as_deref(), Some(" /tmp/agent "));
        assert_eq!(
            spaced.set_env,
            [("A".into(), " leading and trailing ".into())]
        );
    }

    #[test]
    fn effective_environment_rejects_invalid_names_values_and_agent_modes() {
        for row in [
            "setenv NO_EQUALS",
            "setenv =empty",
            "setenv BAD-NAME=x",
            "setenv 1NAME=x",
            "setenv A=nul\0value",
            "forwardagent /tmp/agent",
            "forwardagent yes extra",
        ] {
            assert!(
                parse_ssh_config(format!("hostname host\n{row}\n").as_bytes(), true).is_err(),
                "{row:?}"
            );
        }
        for (length, accepted) in [(4096, true), (4097, false)] {
            let output = format!("hostname host\nsetenv A={}\n", "x".repeat(length));
            assert_eq!(parse_ssh_config(output.as_bytes(), true).is_ok(), accepted);
        }
    }

    #[test]
    fn jump_address_lookup_does_not_import_relay_session_settings() {
        let relay = parse_ssh_config(b"hostname relay\nuser relay-user\nport 2222\nforwardagent /tmp/relay-agent\nidentityagent $RELAY_AGENT\nsetenv BAD-NAME=relay-only\nproxyjump nested\n", false).unwrap();
        assert_eq!(relay.hostname, "relay");
        assert_eq!(relay.port, 2222);
        assert_eq!(relay.user.as_deref(), Some("relay-user"));
        assert!(!relay.forward_agent);
        assert!(relay.set_env.is_empty());
        assert!(relay.proxy_jump.is_none());
        assert!(relay.identity_agent.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn installed_openssh_effective_output_matches_parser_contract() {
        let output = Command::new("ssh")
            .args([
                "-G",
                "-T",
                "-F",
                "/dev/null",
                "-o",
                "SetEnv=A=first A=ignored \"B=two words\" EMPTY= EQ=a=b",
                "-o",
                "ForwardAgent=yes",
                "-o",
                "IdentityAgent=\"/tmp/agent space\"",
                "-o",
                "ProxyJump=ssh://user@jump:2200",
                "example.test",
            ])
            .output()
            .expect("OpenSSH is required for this contract test");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let resolved = parse_ssh_config(&output.stdout, true).unwrap();
        assert_eq!(
            resolved.set_env,
            [
                ("A".into(), "first".into()),
                ("B".into(), "two words".into()),
                ("EMPTY".into(), "".into()),
                ("EQ".into(), "a=b".into()),
            ]
        );
        assert!(resolved.forward_agent);
        assert_eq!(resolved.identity_agent.as_deref(), Some("/tmp/agent space"));
        assert_eq!(resolved.proxy_jump.as_deref(), Some("user@jump:2200"));
    }

    #[test]
    fn setenv_block_cannot_change_other_config_and_preserves_framing() {
        let baseline = b"hostname real\nsetenv ET_RS_CONFIG_SENTINEL=1\nforwardagent no\n";
        for injected in [
            "hostname evil\n",
            "proxyjump evil\n",
            "forwardagent yes\n",
            "unknown value\n",
            "\n",
            "setenv A=x\nforwardagent no\nsetenv B=y\n",
        ] {
            let original = format!("hostname real\nsetenv A=hello\n{injected}forwardagent no\n");
            assert!(
                verify_setenv_block(original.as_bytes(), baseline).is_err(),
                "{injected:?}"
            );
        }
        for newline in ["\n", "\r\n"] {
            let original = format!("hostname real{newline}setenv A= hello ={newline}setenv EMPTY={newline}forwardagent no{newline}");
            let baseline = String::from_utf8(baseline.to_vec())
                .unwrap()
                .replace('\n', newline);
            verify_setenv_block(original.as_bytes(), baseline.as_bytes()).unwrap();
            assert!(verify_setenv_block(
                original
                    .replace("hostname real", "hostname changed")
                    .as_bytes(),
                baseline.as_bytes()
            )
            .is_err());
        }
        assert!(
            verify_setenv_block(b"hostname real\nsetenv A=x\ny\nforwardagent no\n", baseline)
                .is_err()
        );
        // Raw ssh -G cannot distinguish two assignments from a newline that
        // spells another SetEnv row. Such output is confined to environment.
        verify_setenv_block(
            b"hostname real\nsetenv A=x\nsetenv B=y\nforwardagent no\n",
            baseline,
        )
        .unwrap();
        assert!(verify_setenv_block(baseline, b"hostname real\n").is_err());
        assert!(verify_setenv_block(
            baseline,
            b"setenv ET_RS_CONFIG_SENTINEL=1\nsetenv EXTRA=2\n"
        )
        .is_err());
    }

    #[test]
    fn setenv_verification_uses_original_deadline_and_prepends_override() {
        struct Runner {
            calls: std::sync::Mutex<usize>,
            deadline: Deadline,
        }
        impl SshRunner for Runner {
            fn run(
                &self,
                invocation: &SshInvocation,
                deadline: Deadline,
            ) -> Result<SshOutput, ClientError> {
                assert_eq!(deadline.expires_at(), self.deadline.expires_at());
                let mut calls = self.calls.lock().unwrap();
                let output = if *calls == 0 {
                    assert_eq!(invocation.args, ["-G", "-T", "-oSetEnv=A=user", "host"]);
                    "hostname host\nsetenv A=user\n"
                } else {
                    assert_eq!(
                        invocation.args,
                        [
                            "-G",
                            "-T",
                            "-oSetEnv=ET_RS_CONFIG_SENTINEL=1",
                            "-oSetEnv=A=user",
                            "host"
                        ]
                    );
                    "hostname host\nsetenv ET_RS_CONFIG_SENTINEL=1\n"
                };
                *calls += 1;
                Ok(SshOutput {
                    status: Some(success_status()),
                    stdout: output.as_bytes().to_vec(),
                })
            }
        }
        let deadline = Deadline::after(Duration::from_secs(3));
        let runner = Runner {
            calls: std::sync::Mutex::new(0),
            deadline,
        };
        let resolved = resolve_ssh_config(
            &runner,
            "host",
            None,
            &["SetEnv=A=user".into()],
            None,
            true,
            deadline,
        )
        .unwrap();
        assert_eq!(*runner.calls.lock().unwrap(), 2);
        assert_eq!(resolved.set_env, [("A".into(), "user".into())]);
    }

    #[cfg(unix)]
    struct CleanSsh<'a>(&'a str);

    #[cfg(unix)]
    impl SshRunner for CleanSsh<'_> {
        fn run(
            &self,
            invocation: &SshInvocation,
            deadline: Deadline,
        ) -> Result<SshOutput, ClientError> {
            let mut invocation = invocation.clone();
            invocation.args.splice(2..2, ["-F".into(), self.0.into()]);
            crate::ssh_process::SystemSsh::default().run(&invocation, deadline)
        }
    }

    #[cfg(unix)]
    #[test]
    fn real_openssh_multiline_setenv_cannot_inject_routing() {
        for value in [
            "hello\nhostname injected.example",
            "hello\nproxyjump evil",
            "hello\nforwardagent yes",
            "hello\nunknown value",
            "hello\rvalue",
        ] {
            let error = resolve_ssh_config(
                &CleanSsh("/dev/null"),
                "example.test",
                None,
                &[format!("SetEnv=\"A={value}\"")],
                None,
                true,
                Deadline::after(Duration::from_secs(3)),
            )
            .unwrap_err();
            assert!(
                matches!(error, ClientError::SshConfigMalformed(_)),
                "{error}"
            );
        }
        let resolved = resolve_ssh_config(
            &CleanSsh("/dev/null"),
            "example.test",
            None,
            &["SetEnv=A=one ET_RS_CONFIG_SENTINEL=user".into()],
            None,
            true,
            Deadline::after(Duration::from_secs(3)),
        )
        .unwrap();
        assert_eq!(
            resolved.set_env,
            [
                ("A".into(), "one".into()),
                ("ET_RS_CONFIG_SENTINEL".into(), "user".into())
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_openssh_host_include_match_and_cli_precedence() {
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory =
            Directory(std::env::temp_dir().join(format!("et-ssh-match-{}", std::process::id())));
        std::fs::create_dir(&directory.0).unwrap();
        let included = directory.0.join("included");
        let root = directory.0.join("config");
        std::fs::write(&included, "Host alias\n  HostName 127.0.0.8\n  User config-user\n  IdentityAgent /tmp/config-agent\nMatch originalhost alias user cli-user\n  SetEnv SOURCE=matched EMPTY=\n  ForwardAgent yes\nHost *\n").unwrap();
        std::fs::write(&root, format!("Host other\n  SetEnv SOURCE=wrong-host\nHost alias\n  Include {}\nMatch final originalhost alias\n  ProxyJump jump-alias:2200\nHost *\n  SetEnv SOURCE=fallback\n  ForwardAgent no\n", included.display())).unwrap();
        let runner = CleanSsh(root.to_str().unwrap());
        let resolved = resolve_ssh_config(
            &runner,
            "alias",
            Some("cli-user"),
            &[],
            None,
            true,
            Deadline::after(Duration::from_secs(3)),
        )
        .unwrap();
        assert_eq!(resolved.hostname, "127.0.0.8");
        assert_eq!(resolved.user.as_deref(), Some("cli-user"));
        assert!(resolved.forward_agent);
        assert_eq!(
            resolved.identity_agent.as_deref(),
            Some("/tmp/config-agent")
        );
        assert_eq!(resolved.proxy_jump.as_deref(), Some("jump-alias:2200"));
        assert_eq!(
            resolved.set_env,
            [
                ("SOURCE".into(), "matched".into()),
                ("EMPTY".into(), "".into())
            ]
        );
        let overridden = resolve_ssh_config(
            &runner,
            "alias",
            Some("cli-user"),
            &[
                "SetEnv=SOURCE=cli".into(),
                "ForwardAgent=no".into(),
                "IdentityAgent=none".into(),
                "ProxyJump=cli-jump:2300".into(),
            ],
            None,
            true,
            Deadline::after(Duration::from_secs(3)),
        )
        .unwrap();
        assert_eq!(overridden.set_env, [("SOURCE".into(), "cli".into())]);
        assert!(!overridden.forward_agent);
        assert_eq!(overridden.identity_agent.as_deref(), Some("none"));
        assert_eq!(overridden.proxy_jump.as_deref(), Some("cli-jump:2300"));
    }

    struct PortCapturingRunner {
        args: std::sync::Mutex<Vec<String>>,
    }

    impl SshRunner for PortCapturingRunner {
        fn run(&self, invocation: &SshInvocation, _: Deadline) -> Result<SshOutput, ClientError> {
            self.args.lock().unwrap().clone_from(&invocation.args);
            // `ssh -G` echoes the port it actually resolved. When an explicit
            // `-p` is supplied, that is the port it reports.
            let port = invocation
                .args
                .iter()
                .position(|arg| arg == "-p")
                .and_then(|index| invocation.args.get(index + 1))
                .map_or("22", String::as_str);
            Ok(SshOutput {
                status: Some(success_status()),
                stdout: format!(
                    "host jump-alias\nuser config-user\nhostname 127.0.0.1\nport {port}\n"
                )
                .into_bytes(),
            })
        }
    }

    #[test]
    fn explicit_port_reaches_the_config_query_and_the_resolved_port() {
        let runner = PortCapturingRunner {
            args: std::sync::Mutex::new(Vec::new()),
        };
        let resolved = resolve_ssh_config_on_port(
            &runner,
            SshConfigQuery {
                host_alias: "jump-alias",
                requested_user: None,
                explicit_port: Some(2200),
                ssh_options: &[],
                ssh_config: None,
                parse_local_forwards: false,
            },
            Deadline::after(Duration::from_secs(1)),
        )
        .unwrap();
        let args = runner.args.lock().unwrap().clone();
        assert!(
            args.windows(2).any(|pair| pair == ["-p", "2200"]),
            "explicit port must be passed to `ssh -G`: {args:?}"
        );
        assert_eq!(
            resolved.port, 2200,
            "resolved port must honour the explicit port, not the default"
        );
    }

    #[test]
    fn strict_exit_policy_ignores_unix_destination_pseudo_dynamic_row() {
        let resolved = parse_ssh_config(
            b"hostname host\nexitonforwardfailure yes\n\
              dynamicforward 15002\nlocalforward 15002 /tmp/destination.sock\n",
            true,
        )
        .unwrap();

        assert_eq!(resolved.local_forwards.len(), 1);
        assert!(resolved.exit_on_forward_failure);
    }

    #[test]
    fn strict_exit_policy_skips_unsupported_requested_rows() {
        let resolved = parse_ssh_config(
            b"hostname host\nexitonforwardfailure yes\n\
              dynamicforward 1080\n\
              localforward relative/source.sock /tmp/destination.sock\n\
              localforward 10022 localhost:22\n",
            true,
        )
        .unwrap();

        assert!(resolved.exit_on_forward_failure);
        assert_eq!(
            resolved.local_forwards,
            [request("localhost", Some(10022), "localhost", Some(22))]
        );
    }

    #[test]
    fn dynamic_forward_classifier_consumes_unix_destination_pseudo_rows_as_a_multiset() {
        let config = "hostname host\n\
            dynamicforward 15002\n\
            localforward 15002 /tmp/tcp-destination.sock\n\
            dynamicforward /tmp/unix-source.sock\n\
            localforward /tmp/unix-source.sock /tmp/unix-destination.sock\n\
            dynamicforward 1080\n";

        assert_eq!(unsupported_dynamic_forwards(config), ["1080"]);
    }

    #[test]
    fn malformed_and_option_like_values_are_rejected() {
        assert!(matches!(
            parse_ssh_config(b"user somebody\n", true),
            Err(ClientError::SshConfigMalformed("hostname"))
        ));
        assert!(matches!(
            parse_ssh_config(b"hostname host\nuser -oProxyCommand=bad\n", true),
            Err(ClientError::InvalidSshComponent("user"))
        ));
    }

    #[test]
    fn parses_exit_on_forward_failure_policy() {
        let default = parse_ssh_config(b"hostname host\n", true).unwrap();
        let best_effort =
            parse_ssh_config(b"hostname host\nexitonforwardfailure no\n", true).unwrap();
        let strict = parse_ssh_config(b"hostname host\nexitonforwardfailure yes\n", true).unwrap();

        assert!(!default.exit_on_forward_failure);
        assert!(!best_effort.exit_on_forward_failure);
        assert!(strict.exit_on_forward_failure);
    }

    #[test]
    fn parses_supported_tcp_and_unix_destination_forwards() {
        let resolved = parse_ssh_config(
            b"hostname host\n\
          localforward 10022 [127.0.0.1]:22\n\
          localforward [::1]:18080 [::1]:80\n\
          localforward /tmp/local.sock /tmp/remote.sock\n\
          localforward /tmp/mixed.sock [127.0.0.1]:8080\n\
          localforward [127.0.0.1]:9090 /tmp/destination.sock\n\
          remoteforward 1492 [127.0.0.1]:1492\n",
            true,
        )
        .unwrap();

        assert_eq!(
            resolved.local_forwards,
            [
                request("localhost", Some(10022), "127.0.0.1", Some(22)),
                request("::1", Some(18080), "::1", Some(80)),
                request("/tmp/local.sock", None, "/tmp/remote.sock", None),
                request("/tmp/mixed.sock", None, "127.0.0.1", Some(8080)),
                request("127.0.0.1", Some(9090), "/tmp/destination.sock", None,),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_config_hardening_normalizes_real_openssh_bind_shapes() {
        struct RemoveFile(std::path::PathBuf);
        impl Drop for RemoveFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "et-ssh-g-oracle-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("bind-policy")
        ));
        let _cleanup = RemoveFile(path.clone());
        let config = |gatewayports: &str| {
            format!(
                "Host oracle\n HostName localhost\n GatewayPorts {gatewayports}\n\
                 LocalForward *:15432 localhost:5432\n\
                 LocalForward :15433 localhost:5432\n\
                 LocalForward 127.0.0.2:15434 localhost:5432\n\
                 RemoteForward *:25432 localhost:5432\n\
                 RemoteForward :25433 localhost:5432\n\
                 RemoteForward 127.0.0.2:25434 localhost:5432\n"
            )
        };
        let query = |gatewayports: &str| {
            std::fs::write(&path, config(gatewayports)).unwrap();
            std::process::Command::new("ssh")
                .args(["-G", "-F"])
                .arg(&path)
                .arg("oracle")
                .output()
                .unwrap()
        };
        let parse_oracle = |gatewayports: &str| {
            let output = query(gatewayports);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            parse_ssh_config(&output.stdout, true).unwrap()
        };

        let no = parse_oracle("no");
        assert_eq!(
            no.local_forwards
                .iter()
                .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["", "", "127.0.0.2"]
        );
        let yes = parse_oracle("yes");
        assert_eq!(
            yes.local_forwards
                .iter()
                .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["", "", "127.0.0.2"]
        );

        let clientspecified = query("clientspecified");
        if clientspecified.status.success() {
            let resolved = parse_ssh_config(&clientspecified.stdout, true).unwrap();
            assert_eq!(
                resolved
                    .local_forwards
                    .iter()
                    .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                    .collect::<Vec<_>>(),
                ["", "", "127.0.0.2"]
            );
        } else {
            assert!(
                String::from_utf8_lossy(&clientspecified.stderr).contains("unsupported option")
                    && String::from_utf8_lossy(&clientspecified.stderr).contains("clientspecified")
            );
        }
    }

    #[test]
    fn ssh_config_hardening_clientspecified_distinguishes_omitted_and_empty_binds() {
        let resolved = parse_ssh_config(
            b"hostname host\ngatewayports clientspecified\n\
          localforward 15431 localhost:5432\n\
          localforward []:15432 localhost:5432\n\
          remoteforward 25431 localhost:5432\n\
          remoteforward []:25432 localhost:5432\n",
            true,
        )
        .unwrap();

        assert_eq!(
            resolved
                .local_forwards
                .iter()
                .map(|request| request.source.as_ref().unwrap().name.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["localhost", ""]
        );
    }

    #[test]
    fn ssh_config_hardening_preserves_nonlocal_tcp_destinations() {
        let resolved = parse_ssh_config(
            b"hostname host\n\
          localforward 15432 db.internal:5432\n\
          localforward 15433 127.0.0.2:5432\n\
          localforward 15434 LocalHost:5432\n\
          remoteforward 25432 db.internal:5432\n\
          remoteforward 25433 [::1]:5432\n",
            true,
        )
        .unwrap();

        assert_eq!(
            resolved.local_forwards,
            [
                request("localhost", Some(15432), "db.internal", Some(5432)),
                request("localhost", Some(15433), "127.0.0.2", Some(5432)),
                request("localhost", Some(15434), "LocalHost", Some(5432)),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_config_hardening_real_openssh_defaults_preserve_absolute_unix_forwards() {
        // Given
        struct RemoveFile(std::path::PathBuf);
        impl Drop for RemoveFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "et-ssh-streamlocal-oracle-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("defaults")
        ));
        let _cleanup = RemoveFile(path.clone());
        std::fs::write(
            &path,
            "Host oracle\n HostName localhost\n\
             LocalForward /tmp/local.sock /tmp/local-destination.sock\n\
             RemoteForward /tmp/remote.sock /tmp/remote-destination.sock\n",
        )
        .unwrap();

        // When
        let output = std::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&path)
            .arg("oracle")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let resolved = parse_ssh_config(&output.stdout, true).unwrap();

        // Then
        assert_eq!(
            resolved.local_forwards,
            [request(
                "/tmp/local.sock",
                None,
                "/tmp/local-destination.sock",
                None,
            )]
        );
    }

    #[test]
    fn ssh_config_hardening_emitted_nondefault_streamlocal_policy_skips_unix_sources() {
        // Given / When
        let unlink = parse_ssh_config(
            b"hostname host\nstreamlocalbindunlink yes\n\
          localforward /tmp/source.sock /tmp/destination.sock\n\
          localforward 15433 localhost:5432\n",
            true,
        )
        .unwrap();
        // Then
        assert_eq!(
            unlink.local_forwards,
            [request("localhost", Some(15433), "localhost", Some(5432))]
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_config_hardening_real_openssh_unsupported_records_skip_per_row() {
        struct RemoveFile(std::path::PathBuf);
        impl Drop for RemoveFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "et-ssh-unsupported-oracle-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("records")
        ));
        let _cleanup = RemoveFile(path.clone());
        std::fs::write(
            &path,
            r#"Host oracle
 HostName localhost
 DynamicForward *:1080
 RemoteForward 2080
 RemoteForward 0 localhost:22
 LocalForward relative/source.sock /tmp/destination.sock
 LocalForward "/tmp/source path" "/tmp/destination path"
 LocalForward /tmp/source.sock /tmp/destination.sock
 LocalForward 15433 localhost:5432
 RemoteForward 25433 localhost:5432
"#,
        )
        .unwrap();
        let output = std::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&path)
            .arg("oracle")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let resolved = parse_ssh_config(&output.stdout, true).unwrap();

        assert_eq!(
            resolved.local_forwards,
            [
                request("/tmp/source.sock", None, "/tmp/destination.sock", None,),
                request("localhost", Some(15433), "localhost", Some(5432)),
            ]
        );
    }

    #[test]
    fn ssh_config_hardening_malformed_record_remains_typed() {
        assert!(matches!(
            parse_ssh_config(
                b"hostname host\nexitonforwardfailure yes\n\
                  localforward 1000 localhost:22 unexpected\n",
                true,
            ),
            Err(ClientError::SshConfigMalformedForward {
                directive: "localforward",
                reason: "expected exactly two fields",
            })
        ));
    }

    #[test]
    fn rejects_forward_records_without_exactly_two_fields() {
        assert!(matches!(
            parse_ssh_config(b"hostname host\nlocalforward only-one\n", true),
            Err(ClientError::SshConfigMalformedForward {
                directive: "localforward",
                reason: "expected exactly two fields",
            })
        ));
    }

    #[test]
    fn ssh_config_query_emits_selected_file_or_none() {
        struct CapturingRunner {
            args: std::sync::Mutex<Vec<String>>,
        }
        impl SshRunner for CapturingRunner {
            fn run(
                &self,
                invocation: &SshInvocation,
                _: Deadline,
            ) -> Result<SshOutput, ClientError> {
                self.args.lock().unwrap().clone_from(&invocation.args);
                Ok(SshOutput {
                    status: Some(success_status()),
                    stdout: b"host alias\nhostname 127.0.0.1\nport 22\n".to_vec(),
                })
            }
        }

        for selected in [Some("/etc/et/ssh_config"), Some("none")] {
            let runner = CapturingRunner {
                args: std::sync::Mutex::new(Vec::new()),
            };
            resolve_ssh_config(
                &runner,
                "alias",
                None,
                &[],
                selected,
                false,
                Deadline::after(Duration::from_secs(1)),
            )
            .unwrap();
            let args = runner.args.lock().unwrap().clone();
            assert_eq!(
                &args[..4],
                ["-G", "-T", "-F", selected.unwrap()],
                "{args:?}"
            );
        }
    }

    #[test]
    fn ssh_config_path_accepts_unix_and_windows_absolute_shapes() {
        assert!(is_absolute_ssh_config_path("/etc/et/ssh_config"));
        assert!(is_absolute_ssh_config_path(r"C:\Users\me\.ssh\config"));
        assert!(is_absolute_ssh_config_path(r"C:/Users/me/.ssh/config"));
        assert!(is_absolute_ssh_config_path(r"\\server\share\config"));
        assert!(!is_absolute_ssh_config_path("relative/config"));
        assert!(!is_absolute_ssh_config_path("./config"));
        assert!(!is_absolute_ssh_config_path("none"));
    }

    #[test]
    fn ssh_config_path_rejects_shell_unsafe_and_relative_names() {
        assert!(is_ssh_config_path_safe_for_proxy_jump("/etc/et/ssh_config"));
        assert!(is_ssh_config_path_safe_for_proxy_jump(
            r"C:\Users\me\.ssh\config"
        ));
        assert!(!is_ssh_config_path_safe_for_proxy_jump("relative"));
        assert!(!is_ssh_config_path_safe_for_proxy_jump("/tmp/et config"));
        assert!(!is_ssh_config_path_safe_for_proxy_jump("/tmp/et;id"));
        assert!(!is_ssh_config_path_safe_for_proxy_jump("/tmp/et$(id)"));
        assert!(!is_ssh_config_path_safe_for_proxy_jump("/tmp/et`id`"));
        assert!(!is_ssh_config_path_safe_for_proxy_jump("/tmp/et\"quote\""));
    }

    #[cfg(unix)]
    #[test]
    fn ssh_config_file_validation_fails_closed() {
        let directory =
            std::env::temp_dir().join(format!("et-ssh-config-validate-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let regular = directory.join("ssh_config");
        std::fs::write(&regular, "Host *\n").unwrap();
        validate_ssh_config_file(regular.to_str().unwrap()).unwrap();

        assert!(matches!(
            validate_ssh_config_file("relative/config"),
            Err(ClientError::InvalidSshConfig(
                "must be an absolute path or 'none'"
            ))
        ));
        assert!(matches!(
            validate_ssh_config_file("/tmp/et config"),
            Err(ClientError::InvalidSshConfig(_))
        ));
        let missing = directory.join("missing");
        assert!(matches!(
            validate_ssh_config_file(missing.to_str().unwrap()),
            Err(ClientError::InvalidSshConfig(
                "must name a readable, non-symlink regular file"
            ))
        ));
        assert!(matches!(
            validate_ssh_config_file(directory.to_str().unwrap()),
            Err(ClientError::InvalidSshConfig(
                "must name a readable, non-symlink regular file"
            ))
        ));
        let link = directory.join("link");
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        assert!(matches!(
            validate_ssh_config_file(link.to_str().unwrap()),
            Err(ClientError::InvalidSshConfig(
                "must name a readable, non-symlink regular file"
            ))
        ));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn session_option_forwarding_uses_two_endpoints_and_setenv_preserves_quotes() {
        let mut config = ResolvedSshConfig::default();
        config
            .apply_session_options(&[
                "LocalForward=12345 localhost:80".into(),
                "RemoteForward=127.0.0.1:23456 [::1]:443".into(),
                "SetEnv=LABEL=\"two words=a=b\" EMPTY= ESC=one\\ two".into(),
            ])
            .unwrap();
        assert_eq!(
            config.local_forwards[0].source.as_ref().unwrap().port,
            Some(12345)
        );
        assert_eq!(
            config.local_forwards[0].destination.as_ref().unwrap().port,
            Some(80)
        );
        assert_eq!(
            config.remote_forwards[0],
            request("127.0.0.1", Some(23456), "::1", Some(443))
        );
        assert_eq!(
            config.set_env,
            [
                ("LABEL".into(), "two words=a=b".into()),
                ("EMPTY".into(), "".into()),
                ("ESC".into(), "one two".into())
            ]
        );
        assert!(config
            .apply_session_options(&["SetEnv=BROKEN=\"unterminated".into()])
            .is_err());
    }

    fn request(
        source_name: &str,
        source_port: Option<i32>,
        destination_name: &str,
        destination_port: Option<i32>,
    ) -> PortForwardSourceRequest {
        PortForwardSourceRequest {
            source: Some(SocketEndpoint {
                name: Some(source_name.to_owned()),
                port: source_port,
            }),
            destination: Some(SocketEndpoint {
                name: Some(destination_name.to_owned()),
                port: destination_port,
            }),
            environmentvariable: None,
        }
    }
}
