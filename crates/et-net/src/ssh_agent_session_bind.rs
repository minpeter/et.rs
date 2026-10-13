//! OpenSSH agent session binding (`session-bind@openssh.com`, OpenSSH 8.9+).
//!
//! ssh tells its agent which host key and SSH session each agent connection
//! belongs to, which is what makes destination-constrained keys (`ssh-add -h`)
//! enforceable. ET forwards the agent over its own transport, so the client
//! replays the binding ssh made while bootstrapping the session, flagged as
//! forwarded, at the start of every connection to the stable `et-agent-<id>`
//! proxy. This is the same message ssh itself sends on an agent-forwarding
//! channel.
//!
//! [`SshAgentSessionBindRecorder`] records the binding bootstrap ssh sends to
//! its agent (#881). Wiring that recorder into the bootstrap ssh invocation is
//! still upstream #879, which is open, so the client does not supply binds yet.

use std::io::{self, Write};
use std::sync::OnceLock;

/// Largest agent message accepted (OpenSSH's `AGENT_MAX_LEN`).
pub const SSH_AGENT_MAX_MESSAGE_LENGTH: u32 = 256 * 1024;

/// `SSH_AGENTC_EXTENSION` from OpenSSH `PROTOCOL.agent`.
pub const SSH_AGENTC_EXTENSION: u8 = 27;
/// `SSH_AGENT_FAILURE`.
pub const SSH_AGENT_FAILURE: u8 = 5;
/// `SSH_AGENT_SUCCESS`.
pub const SSH_AGENT_SUCCESS: u8 = 6;
/// `SSH_AGENT_EXTENSION_FAILURE`. Agents without `session-bind@openssh.com`
/// answer the extension request with this (or with [`SSH_AGENT_FAILURE`]).
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

/// Extension name carried by [`encode_session_bind`].
pub const SESSION_BIND_EXTENSION: &str = "session-bind@openssh.com";

/// How a session-bind event should be logged. The process logger is installed
/// by the client; library tests leave it unset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionBindLog {
    Warning,
    Info,
    Verbose,
}

static LOGGER: OnceLock<fn(SessionBindLog, &str)> = OnceLock::new();

/// Install the process logger. Later calls are ignored.
pub fn install_logger(logger: fn(SessionBindLog, &str)) {
    let _ = LOGGER.set(logger);
}

fn log(level: SessionBindLog, message: &str) {
    if let Some(logger) = LOGGER.get() {
        logger(level, message);
    }
}

/// A session-bind field does not fit in an SSH string (`uint32` length).
#[derive(Debug)]
pub struct SessionBindEncodeError;

impl std::fmt::Display for SessionBindEncodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ssh agent session bind field does not fit in an SSH string")
    }
}

impl std::error::Error for SessionBindEncodeError {}

/// Body of one `SSH_AGENTC_EXTENSION` / `session-bind@openssh.com` request,
/// without the outer SSH agent length prefix.
///
/// Layout (`PROTOCOL.agent`): type, extension name, host key, session
/// identifier, signature, and `is_forwarding` (one byte, 0 or 1).
pub fn encode_session_bind(
    host_key: &[u8],
    session_id: &[u8],
    signature: &[u8],
    is_forwarding: bool,
) -> Result<Vec<u8>, SessionBindEncodeError> {
    let mut body = Vec::new();
    body.push(SSH_AGENTC_EXTENSION);
    push_ssh_string(&mut body, SESSION_BIND_EXTENSION.as_bytes())?;
    push_ssh_string(&mut body, host_key)?;
    push_ssh_string(&mut body, session_id)?;
    push_ssh_string(&mut body, signature)?;
    body.push(u8::from(is_forwarding));
    Ok(body)
}

fn push_ssh_string(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SessionBindEncodeError> {
    let length = u32::try_from(bytes.len()).map_err(|_| SessionBindEncodeError)?;
    out.extend(length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// SSH agent frame: big-endian `uint32` length plus `body`.
pub(crate) fn frame_agent_message(body: &[u8]) -> io::Result<Vec<u8>> {
    let length = u32::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ssh agent message is too large",
        )
    })?;
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend(length.to_be_bytes());
    framed.extend_from_slice(body);
    Ok(framed)
}

/// Writes every recorded bind on a freshly connected agent socket, ahead of
/// any forwarded data, without waiting for the replies.
pub(crate) fn write_session_binds<W: Write>(
    writer: &mut W,
    agent_socket_path: &str,
    binds: &[Vec<u8>],
) -> io::Result<()> {
    if binds.is_empty() {
        return Ok(());
    }
    let mut requests = Vec::new();
    for bind in binds {
        requests.extend(frame_agent_message(bind)?);
    }
    if let Err(error) = writer.write_all(&requests) {
        log(
            SessionBindLog::Warning,
            &format!(
                "Could not send {} session binding(s) to ssh agent {agent_socket_path}: {error}",
                binds.len()
            ),
        );
        return Err(error);
    }
    Ok(())
}

/// Snapshot of the binds to send on one new destination socket.
pub(crate) struct PendingSessionBinds {
    pub(crate) path: String,
    pub(crate) binds: Vec<Vec<u8>>,
}

/// Binds apply only to a non-TCP destination whose name is the forwarded
/// agent socket, and only when at least one bind was recorded.
pub(crate) fn binds_for_destination(
    recorded_path: &str,
    recorded_binds: &[Vec<u8>],
    is_tcp: bool,
    destination_name: Option<&str>,
) -> Option<PendingSessionBinds> {
    if is_tcp || recorded_binds.is_empty() || recorded_path.is_empty() {
        return None;
    }
    let name = destination_name?;
    if !paths_equal(name, recorded_path) {
        return None;
    }
    Some(PendingSessionBinds {
        path: recorded_path.to_owned(),
        binds: recorded_binds.to_vec(),
    })
}

/// Upstream compares agent paths byte-for-byte, except on Windows where
/// `\` and `/` name the same socket.
pub(crate) fn paths_equal(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        slash_insensitive(left) == slash_insensitive(right)
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

#[cfg(windows)]
fn slash_insensitive(path: &str) -> String {
    path.replace('\\', "/")
}

/// The forwarded form of a well-formed, non-forwarded session-bind request.
///
/// ProxyJump helpers bind before the destination, so callers keep the last
/// value. Already-forwarded binds and every other agent message are rejected.
pub fn forwarded_session_bind(request: &[u8]) -> Option<Vec<u8>> {
    let (_host_key, forwarded) = parse_session_bind(request)?;
    if forwarded {
        return None;
    }
    let mut forwarded_request = request.to_vec();
    *forwarded_request.last_mut()? = 1;
    Some(forwarded_request)
}

/// OpenSSH-style `SHA256:` fingerprint of the host key inside a session-bind.
pub fn session_bind_host_key_fingerprint(bind: &[u8]) -> Option<String> {
    let (host_key, _forwarded) = parse_session_bind(bind)?;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&host_key);
    let mut encoded = base64::engine::general_purpose::STANDARD.encode(digest);
    while encoded.ends_with('=') {
        encoded.pop();
    }
    Some(format!("SHA256:{encoded}"))
}

fn parse_session_bind(request: &[u8]) -> Option<(Vec<u8>, bool)> {
    if request.first().copied() != Some(SSH_AGENTC_EXTENSION) {
        return None;
    }
    let mut pos = 1usize;
    let name = read_ssh_string(request, &mut pos)?;
    if name != SESSION_BIND_EXTENSION.as_bytes() {
        return None;
    }
    let host_key = read_ssh_string(request, &mut pos)?;
    let session_id = read_ssh_string(request, &mut pos)?;
    let signature = read_ssh_string(request, &mut pos)?;
    if host_key.is_empty() || session_id.is_empty() || signature.is_empty() {
        return None;
    }
    if pos + 1 != request.len() {
        return None;
    }
    let flag = *request.get(pos)?;
    if flag > 1 {
        return None;
    }
    Some((host_key, flag == 1))
}

fn read_ssh_string(message: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let rest = message.get(*pos..)?;
    if rest.len() < 4 {
        return None;
    }
    let length = u32::from_be_bytes(rest[..4].try_into().ok()?) as usize;
    *pos += 4;
    let bytes = message.get(*pos..*pos + length)?.to_vec();
    *pos += length;
    Some(bytes)
}

#[path = "ssh_agent_recorder.rs"]
mod recorder;
pub use recorder::SshAgentSessionBindRecorder;

/// Removes the agent's replies to the session binds from the start of its
/// output, so the forwarded client only sees replies to its own requests.
///
/// The agent answers requests in order, so the first replies on the
/// connection belong to the binds. Exactly one reply is consumed per bind.
/// Refusals ([`SSH_AGENT_FAILURE`], [`SSH_AGENT_EXTENSION_FAILURE`], or any
/// other type) are logged and tolerated, as ssh does. A length of 0 or above
/// [`SSH_AGENT_MAX_MESSAGE_LENGTH`] cannot be resynchronized.
pub(crate) struct AgentSessionBindReplies {
    bind_count: usize,
    replies_seen: usize,
    agent_socket_path: String,
    pending: Vec<u8>,
}

impl AgentSessionBindReplies {
    pub(crate) fn new(bind_count: usize, agent_socket_path: impl Into<String>) -> Self {
        Self {
            bind_count,
            replies_seen: 0,
            agent_socket_path: agent_socket_path.into(),
            pending: Vec::new(),
        }
    }

    /// Returns the bytes that follow the last bind reply. An empty `Ok` means
    /// only bind replies have arrived so far.
    pub(crate) fn consume(&mut self, data: &[u8]) -> Result<Vec<u8>, ()> {
        if self.replies_seen == self.bind_count {
            return Ok(data.to_vec());
        }
        self.pending.extend_from_slice(data);
        while self.replies_seen < self.bind_count && self.pending.len() >= 4 {
            let length = u32::from_be_bytes(self.pending[..4].try_into().expect("4 bytes"));
            if length == 0 || length > SSH_AGENT_MAX_MESSAGE_LENGTH {
                log(
                    SessionBindLog::Warning,
                    &format!(
                        "ssh agent {} sent an invalid reply to session binding {}/{} (length {length})",
                        self.agent_socket_path,
                        self.replies_seen + 1,
                        self.bind_count
                    ),
                );
                return Err(());
            }
            let total = 4 + usize::try_from(length).unwrap_or(usize::MAX);
            if self.pending.len() < total {
                break;
            }
            let reply_type = self.pending[4];
            self.replies_seen += 1;
            if reply_type == SSH_AGENT_SUCCESS {
                log(
                    SessionBindLog::Verbose,
                    &format!(
                        "ssh agent {} accepted session binding {}/{}",
                        self.agent_socket_path, self.replies_seen, self.bind_count
                    ),
                );
            } else {
                // Same as ssh: agents without the extension keep working, but
                // destination-constrained keys stay unusable on this connection.
                log(
                    SessionBindLog::Info,
                    &format!(
                        "ssh agent {} refused session binding {}/{} (reply type {reply_type})",
                        self.agent_socket_path, self.replies_seen, self.bind_count
                    ),
                );
            }
            self.pending.drain(..total);
        }
        if self.replies_seen == self.bind_count {
            Ok(std::mem::take(&mut self.pending))
        } else {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use base64::Engine;

    use super::{
        binds_for_destination, encode_session_bind, forwarded_session_bind, frame_agent_message,
        paths_equal, session_bind_host_key_fingerprint, write_session_binds,
        AgentSessionBindReplies, SESSION_BIND_EXTENSION, SSH_AGENTC_EXTENSION,
        SSH_AGENT_EXTENSION_FAILURE, SSH_AGENT_FAILURE, SSH_AGENT_MAX_MESSAGE_LENGTH,
        SSH_AGENT_SUCCESS,
    };

    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn forwarded_session_bind_marks_ssh_own_binding_and_rejects_others() {
        let bind = encode_session_bind(b"host-key", b"session", b"signature", false).unwrap();
        assert_eq!(
            forwarded_session_bind(&bind).as_deref(),
            Some(encode_session_bind(b"host-key", b"session", b"signature", true).unwrap().as_slice())
        );
        let already = encode_session_bind(b"host-key", b"session", b"signature", true).unwrap();
        assert!(forwarded_session_bind(&already).is_none());
        assert!(forwarded_session_bind(&[11]).is_none());
        assert!(forwarded_session_bind(&[]).is_none());
        assert!(forwarded_session_bind(&bind[..bind.len() - 1]).is_none());
        assert!(forwarded_session_bind(&[bind.as_slice(), b"x"].concat()).is_none());
        assert!(forwarded_session_bind(&encode_session_bind(b"", b"session", b"signature", false).unwrap()).is_none());
        let host_key = base64::engine::general_purpose::STANDARD
            .decode("AAAAC3NzaC1lZDI1NTE5AAAAID4NdJ9B1LOS7+li7shEB10b9lQEjdsbe2oNQEW8fZP7")
            .unwrap();
        let recorded = encode_session_bind(&host_key, b"sid", b"sig", true).unwrap();
        assert_eq!(
            session_bind_host_key_fingerprint(&recorded).as_deref(),
            Some("SHA256:1Z8TElQaniPWrBI8ZeIOaUH5BDBpeoK85Bt65Kr7ppY")
        );
        assert!(session_bind_host_key_fingerprint(&[11]).is_none());
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        frame_agent_message(body).unwrap()
    }

    fn success() -> Vec<u8> {
        frame(&[SSH_AGENT_SUCCESS])
    }

    fn failure() -> Vec<u8> {
        frame(&[SSH_AGENT_FAILURE])
    }

    #[test]
    fn session_bind_encoding_matches_protocol_agent() {
        let host_key = b"jump-key";
        let session_id = b"session-id-jump-key";
        let signature = b"signature-jump-key";
        let encoded = encode_session_bind(host_key, session_id, signature, true).unwrap();
        let mut expected = vec![SSH_AGENTC_EXTENSION];
        expected.extend(ssh_string(SESSION_BIND_EXTENSION.as_bytes()));
        expected.extend(ssh_string(host_key));
        expected.extend(ssh_string(session_id));
        expected.extend(ssh_string(signature));
        expected.push(1);
        assert_eq!(encoded, expected);

        let direct = encode_session_bind(host_key, session_id, signature, false).unwrap();
        assert_eq!(*direct.last().unwrap(), 0);
        assert_eq!(&direct[..direct.len() - 1], &expected[..expected.len() - 1]);
    }

    #[test]
    fn framed_binds_are_length_prefixed_and_a_failed_write_is_an_error() {
        let bind = encode_session_bind(b"dest-key", b"sid", b"sig", true).unwrap();
        let mut recorded = Vec::new();
        write_session_binds(
            &mut recorded,
            "/tmp/agent.sock",
            &[bind.clone(), bind.clone()],
        )
        .unwrap();
        let framed = frame(&bind);
        assert_eq!(recorded, [framed.clone(), framed].concat());

        let mut empty = Vec::new();
        write_session_binds(&mut empty, "/tmp/agent.sock", &[]).unwrap();
        assert!(empty.is_empty());

        struct FailWrite;
        impl Write for FailWrite {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let error = write_session_binds(&mut FailWrite, "/tmp/agent.sock", &[bind]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn bind_replies_are_stripped_across_partial_reads() {
        let bind_replies = [success(), failure()].concat();
        let client_reply = frame(&[12, 0, 0, 0, 0]);
        let mut replies = AgentSessionBindReplies::new(2, "/tmp/agent.sock");
        let mut forwarded = Vec::new();
        for byte in bind_replies.iter().chain(client_reply.iter()).copied() {
            forwarded.extend(replies.consume(&[byte]).unwrap());
        }
        assert_eq!(forwarded, client_reply);
    }

    #[test]
    fn client_data_in_the_same_read_as_the_last_bind_reply_is_kept() {
        let bind_replies = [success(), failure()].concat();
        let client_reply = frame(&[12, 0, 0, 0, 0]);
        let mut replies = AgentSessionBindReplies::new(2, "/tmp/agent.sock");
        assert!(replies.consume(&bind_replies[..3]).unwrap().is_empty());
        let mut rest = bind_replies[3..].to_vec();
        rest.extend_from_slice(&client_reply);
        assert_eq!(replies.consume(&rest).unwrap(), client_reply);
        assert_eq!(replies.consume(b"more").unwrap(), b"more");
    }

    #[test]
    fn refusals_are_tolerated_and_one_reply_is_consumed_per_bind() {
        let mut replies = AgentSessionBindReplies::new(3, "/tmp/agent.sock");
        let stream = [
            failure(),
            frame(&[SSH_AGENT_EXTENSION_FAILURE]),
            frame(&[99]),
            b"client".to_vec(),
        ]
        .concat();
        assert_eq!(replies.consume(&stream).unwrap(), b"client");
        assert_eq!(replies.consume(b"next").unwrap(), b"next");
    }

    #[test]
    fn a_malformed_bind_reply_cannot_be_resynchronized() {
        let mut zero = AgentSessionBindReplies::new(1, "/tmp/agent.sock");
        assert!(zero.consume(&frame_length(0)).is_err());

        let mut huge = AgentSessionBindReplies::new(1, "/tmp/agent.sock");
        assert!(huge
            .consume(&frame_length(SSH_AGENT_MAX_MESSAGE_LENGTH + 1))
            .is_err());
    }

    fn frame_length(length: u32) -> Vec<u8> {
        let mut bytes = length.to_be_bytes().to_vec();
        bytes.push(b'x');
        bytes
    }

    #[test]
    fn binds_are_selected_only_for_the_recorded_agent_socket() {
        let binds = vec![vec![SSH_AGENTC_EXTENSION]];
        assert!(
            binds_for_destination("/tmp/agent.sock", &[], false, Some("/tmp/agent.sock")).is_none()
        );
        assert!(
            binds_for_destination("/tmp/agent.sock", &binds, true, Some("/tmp/agent.sock"))
                .is_none()
        );
        assert!(
            binds_for_destination("/tmp/agent.sock", &binds, false, Some("/tmp/other.sock"))
                .is_none()
        );
        assert!(binds_for_destination("", &binds, false, Some("")).is_none());
        let selected =
            binds_for_destination("/tmp/agent.sock", &binds, false, Some("/tmp/agent.sock"))
                .unwrap();
        assert_eq!(selected.path, "/tmp/agent.sock");
        assert_eq!(selected.binds, binds);

        assert!(paths_equal("/tmp/agent.sock", "/tmp/agent.sock"));
        assert!(!paths_equal("/tmp/a", "/tmp/b"));
        #[cfg(windows)]
        {
            assert!(paths_equal(r"C:\et\agent.sock", "C:/et/agent.sock"));
            assert!(binds_for_destination(
                r"C:\et\agent.sock",
                &binds,
                false,
                Some("C:/et/agent.sock")
            )
            .is_some());
        }
        #[cfg(not(windows))]
        {
            assert!(!paths_equal(r"C:\et\agent.sock", "C:/et/agent.sock"));
        }
    }

    #[test]
    fn tcp_destinations_are_not_prefixed_with_session_binds() {
        use std::io::Read;
        use std::net::{Ipv4Addr, TcpListener};
        use std::time::Duration;

        use et_core::packet::Packet;
        use et_core::proto::{
            PortForwardData, PortForwardDestinationRequest, PortForwardDestinationResponse,
            SocketEndpoint, TerminalPacketType,
        };
        use prost::Message;

        use crate::forward::Forwarder;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let forwarder = Forwarder::start(Vec::new()).unwrap();
        let bind = encode_session_bind(b"dest-key", b"sid", b"sig", true).unwrap();
        forwarder
            .set_ssh_agent_session_binds("/tmp/agent.sock", vec![bind])
            .unwrap();
        forwarder
            .receive(Packet::new(
                TerminalPacketType::PortForwardDestinationRequest as u8,
                PortForwardDestinationRequest {
                    destination: Some(SocketEndpoint {
                        name: Some(Ipv4Addr::LOCALHOST.to_string()),
                        port: Some(i32::from(port)),
                    }),
                    fd: Some(1),
                    window: None,
                }
                .encode_to_vec(),
            ))
            .unwrap();
        let response = PortForwardDestinationResponse::decode(
            forwarder
                .wait_outbound(Duration::from_secs(3))
                .unwrap()
                .payload(),
        )
        .unwrap();
        assert!(response.error.is_none(), "{}", response.error.unwrap());
        let socket_id = response.socketid.unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let payload = b"only-client";
        forwarder
            .receive(Packet::new(
                TerminalPacketType::PortForwardData as u8,
                PortForwardData {
                    sourcetodestination: Some(true),
                    socketid: Some(socket_id),
                    buffer: Some(payload.to_vec()),
                    ..Default::default()
                }
                .encode_to_vec(),
            ))
            .unwrap();
        let mut got = vec![0; payload.len()];
        peer.read_exact(&mut got).unwrap();
        assert_eq!(got, payload);
    }
}

#[cfg(all(test, unix))]
mod relay {
    use std::io::{self, Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use et_core::packet::Packet;
    use et_core::proto::{
        PortForwardData, PortForwardDestinationRequest, PortForwardDestinationResponse,
        SocketEndpoint, TerminalPacketType,
    };
    use prost::Message;

    use super::{encode_session_bind, frame_agent_message, SSH_AGENT_FAILURE, SSH_AGENT_SUCCESS};
    use crate::forward::Forwarder;

    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;

    fn temp_socket(label: &str) -> (PathBuf, PathBuf) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "et-session-bind-{}-{}-{}",
            label,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        (directory.clone(), directory.join("agent.sock"))
    }

    struct RemoveDir(PathBuf);
    impl Drop for RemoveDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct FakeAgent {
        path: PathBuf,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        _directory: RemoveDir,
    }

    impl FakeAgent {
        fn new(label: &str, reply: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static) -> Self {
            let (directory, path) = temp_socket(label);
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_requests = requests.clone();
            let thread_stop = stop.clone();
            let reply = Arc::new(reply);
            let thread = thread::spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            serve(stream, &thread_requests, &thread_stop, reply.as_ref());
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                path,
                requests,
                stop,
                thread: Some(thread),
                _directory: RemoveDir(directory),
            }
        }

        fn received(&self) -> Vec<Vec<u8>> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for FakeAgent {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn serve(
        mut stream: UnixStream,
        requests: &Mutex<Vec<Vec<u8>>>,
        stop: &AtomicBool,
        reply: &impl Fn(&[u8]) -> Vec<u8>,
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        while !stop.load(Ordering::Acquire) {
            match read_frame(&mut stream) {
                Ok(body) => {
                    requests.lock().unwrap().push(body.clone());
                    let response = reply(&body);
                    if write_frame(&mut stream, &response).is_err() {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    }

    fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
        let mut length_buf = [0; 4];
        stream.read_exact(&mut length_buf)?;
        let length = usize::try_from(u32::from_be_bytes(length_buf)).unwrap_or(usize::MAX);
        if length > super::SSH_AGENT_MAX_MESSAGE_LENGTH as usize {
            return Err(io::Error::other("agent message too large"));
        }
        let mut body = vec![0; length];
        if length > 0 {
            stream.read_exact(&mut body)?;
        }
        Ok(body)
    }

    fn write_frame(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
        stream.write_all(&frame_agent_message(body)?)
    }

    fn success_body(_: &[u8]) -> Vec<u8> {
        vec![SSH_AGENT_SUCCESS]
    }

    fn open_agent(forwarder: &Forwarder, path: &std::path::Path, fd: i32) -> i32 {
        forwarder
            .receive(Packet::new(
                TerminalPacketType::PortForwardDestinationRequest as u8,
                PortForwardDestinationRequest {
                    destination: Some(SocketEndpoint {
                        name: Some(path.to_string_lossy().into_owned()),
                        port: None,
                    }),
                    fd: Some(fd),
                    window: None,
                }
                .encode_to_vec(),
            ))
            .unwrap();
        let response = PortForwardDestinationResponse::decode(
            forwarder
                .wait_outbound(Duration::from_secs(3))
                .unwrap()
                .payload(),
        )
        .unwrap();
        assert!(
            response.error.is_none(),
            "destination failed: {}",
            response.error.unwrap_or_default()
        );
        response.socketid.unwrap()
    }

    fn send_identities(forwarder: &Forwarder, socket_id: i32) {
        let body = frame_agent_message(&[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        forwarder
            .receive(Packet::new(
                TerminalPacketType::PortForwardData as u8,
                PortForwardData {
                    sourcetodestination: Some(true),
                    socketid: Some(socket_id),
                    buffer: Some(body),
                    ..Default::default()
                }
                .encode_to_vec(),
            ))
            .unwrap();
    }

    fn agent_output(forwarder: &Forwarder, min_bytes: usize, wait: Duration) -> Vec<u8> {
        let deadline = Instant::now() + wait;
        let mut output = Vec::new();
        while output.len() < min_bytes && Instant::now() < deadline {
            match forwarder.try_outbound() {
                Ok(Some(packet)) => {
                    if packet.header() != TerminalPacketType::PortForwardData as u8 {
                        continue;
                    }
                    let data = PortForwardData::decode(packet.payload()).unwrap();
                    assert!(data.error.is_none(), "forward error: {:?}", data.error);
                    assert!(!data.closed.unwrap_or(false));
                    if let Some(buffer) = data.buffer {
                        output.extend(buffer);
                    }
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("forwarder stopped: {error}"),
            }
        }
        output
    }

    fn recorded_binds() -> Vec<Vec<u8>> {
        vec![
            encode_session_bind(
                b"jump-key",
                b"session-id-jump-key",
                b"signature-jump-key",
                true,
            )
            .unwrap(),
            encode_session_bind(
                b"dest-key",
                b"session-id-dest-key",
                b"signature-dest-key",
                true,
            )
            .unwrap(),
        ]
    }

    #[test]
    fn bindings_precede_forwarded_requests_and_their_replies_are_hidden() {
        let agent = FakeAgent::new("order", success_body);
        let forwarder = Forwarder::start(Vec::new()).unwrap();
        let binds = recorded_binds();
        forwarder
            .set_ssh_agent_session_binds(agent.path.to_string_lossy().to_string(), binds.clone())
            .unwrap();
        let socket_id = open_agent(&forwarder, &agent.path, 7);
        send_identities(&forwarder, socket_id);
        let expected = frame_agent_message(&[SSH_AGENT_SUCCESS]).unwrap();
        assert_eq!(
            agent_output(&forwarder, expected.len(), Duration::from_secs(3)),
            expected
        );
        let received = agent.received();
        assert_eq!(received.len(), 3);
        assert_eq!(received[0], binds[0]);
        assert_eq!(received[1], binds[1]);
        assert_eq!(received[2], vec![SSH_AGENTC_REQUEST_IDENTITIES]);
    }

    #[test]
    fn agents_without_the_extension_are_still_forwarded() {
        let agent = FakeAgent::new("refuse", |_| vec![SSH_AGENT_FAILURE]);
        let forwarder = Forwarder::start(Vec::new()).unwrap();
        forwarder
            .set_ssh_agent_session_binds(agent.path.to_string_lossy().to_string(), recorded_binds())
            .unwrap();
        let socket_id = open_agent(&forwarder, &agent.path, 7);
        send_identities(&forwarder, socket_id);
        let expected = frame_agent_message(&[SSH_AGENT_FAILURE]).unwrap();
        assert_eq!(
            agent_output(&forwarder, expected.len(), Duration::from_secs(3)),
            expected
        );
    }

    #[test]
    fn a_slow_agent_does_not_block_the_client_and_bind_replies_stay_hidden() {
        let release = Arc::new(AtomicBool::new(false));
        let gate = release.clone();
        let agent = FakeAgent::new("slow", move |_| {
            while !gate.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(10));
            }
            vec![SSH_AGENT_SUCCESS]
        });
        struct Release(Arc<AtomicBool>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _release = Release(release);
        let forwarder = Forwarder::start(Vec::new()).unwrap();
        forwarder
            .set_ssh_agent_session_binds(agent.path.to_string_lossy().to_string(), recorded_binds())
            .unwrap();
        let started = Instant::now();
        let socket_id = open_agent(&forwarder, &agent.path, 7);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "session bind replay waited for the agent"
        );
        send_identities(&forwarder, socket_id);
        assert!(agent_output(&forwarder, 1, Duration::from_millis(200)).is_empty());
        drop(_release);
        let expected = frame_agent_message(&[SSH_AGENT_SUCCESS]).unwrap();
        assert_eq!(
            agent_output(&forwarder, expected.len(), Duration::from_secs(3)),
            expected
        );
    }

    #[test]
    fn other_unix_sockets_are_not_bound() {
        let agent = FakeAgent::new("agent", success_body);
        let other = FakeAgent::new("other", success_body);
        let forwarder = Forwarder::start(Vec::new()).unwrap();
        forwarder
            .set_ssh_agent_session_binds(agent.path.to_string_lossy().to_string(), recorded_binds())
            .unwrap();
        let _socket_id = open_agent(&forwarder, &other.path, 8);
        thread::sleep(Duration::from_millis(150));
        assert!(other.received().is_empty());
    }

    #[test]
    fn empty_bindings_leave_the_agent_connection_unchanged() {
        let agent = FakeAgent::new("dormant", success_body);
        let forwarder = Forwarder::start(Vec::new()).unwrap();
        forwarder
            .set_ssh_agent_session_binds(agent.path.to_string_lossy().to_string(), Vec::new())
            .unwrap();
        let socket_id = open_agent(&forwarder, &agent.path, 7);
        thread::sleep(Duration::from_millis(100));
        assert!(agent.received().is_empty());
        send_identities(&forwarder, socket_id);
        let expected = frame_agent_message(&[SSH_AGENT_SUCCESS]).unwrap();
        assert_eq!(
            agent_output(&forwarder, expected.len(), Duration::from_secs(3)),
            expected
        );
        assert_eq!(agent.received(), vec![vec![SSH_AGENTC_REQUEST_IDENTITIES]]);
    }

    #[test]
    fn a_malformed_bind_reply_closes_the_forwarded_connection() {
        let (directory, path) = temp_socket("malformed");
        let _directory = RemoveDir(directory);
        let listener = UnixListener::bind(&path).unwrap();
        let accepted = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = read_frame(&mut stream);
            stream.write_all(&0u32.to_be_bytes()).unwrap();
            stream.write_all(b"x").unwrap();
            stream
        });
        let forwarder = Forwarder::start(Vec::new()).unwrap();
        let bind = encode_session_bind(b"dest-key", b"sid", b"sig", true).unwrap();
        forwarder
            .set_ssh_agent_session_binds(path.to_string_lossy().to_string(), vec![bind.clone()])
            .unwrap();
        let socket_id = open_agent(&forwarder, &path, 7);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut error = None;
        while error.is_none() && Instant::now() < deadline {
            match forwarder.try_outbound() {
                Ok(Some(packet))
                    if packet.header() == TerminalPacketType::PortForwardData as u8 =>
                {
                    let data = PortForwardData::decode(packet.payload()).unwrap();
                    if data.socketid == Some(socket_id) && data.error.is_some() {
                        error = data.error;
                        assert!(data.buffer.is_none());
                    }
                }
                Ok(Some(_)) | Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(failure) => panic!("forwarder stopped: {failure}"),
            }
        }
        assert_eq!(
            error.as_deref(),
            Some("invalid ssh agent reply to session binding")
        );
        drop(accepted.join().unwrap());
    }

    #[test]
    fn bind_replies_are_not_forwarded_when_they_arrive_alone() {
        let (directory, path) = temp_socket("alone");
        let _directory = RemoveDir(directory);
        let listener = UnixListener::bind(&path).unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let accepted = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = read_frame(&mut stream);
            write_frame(&mut stream, &[SSH_AGENT_SUCCESS]).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(3));
            let client_reply = frame_agent_message(&[12, 0, 0, 0, 0]).unwrap();
            stream.write_all(&client_reply).unwrap();
            stream
        });
        let forwarder = Forwarder::start(Vec::new()).unwrap();
        let bind = encode_session_bind(b"dest-key", b"sid", b"sig", true).unwrap();
        forwarder
            .set_ssh_agent_session_binds(path.to_string_lossy().to_string(), vec![bind])
            .unwrap();
        let _socket_id = open_agent(&forwarder, &path, 7);
        assert!(agent_output(&forwarder, 1, Duration::from_millis(200)).is_empty());
        release_tx.send(()).unwrap();
        let expected = frame_agent_message(&[12, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            agent_output(&forwarder, expected.len(), Duration::from_secs(3)),
            expected
        );
        drop(accepted.join().unwrap());
    }
}
