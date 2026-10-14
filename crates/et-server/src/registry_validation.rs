use std::io;
use std::sync::Arc;

use et_net::local::LocalStream;

use et_core::keys::passkey_to_key;
use et_core::proto::TerminalUserInfo;

use crate::registry::{Registration, RegistrationError};

const ID_LEN: usize = 16;

#[derive(Clone, Copy)]
pub(crate) enum PeerIdentity {
    #[cfg(unix)]
    Unix { uid: u32, gid: u32 },
    #[cfg(windows)]
    AuthenticatedWindowsToken,
}

impl PeerIdentity {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn from_stream(stream: &LocalStream) -> io::Result<Self> {
        let credentials = rustix::net::sockopt::socket_peercred(stream)?;
        Ok(Self::Unix {
            uid: credentials.uid.as_raw(),
            gid: credentials.gid.as_raw(),
        })
    }

    #[cfg(target_vendor = "apple")]
    pub(crate) fn from_stream(stream: &LocalStream) -> io::Result<Self> {
        let (uid, gid) = nix::unistd::getpeereid(stream)
            .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        Ok(Self::Unix {
            uid: uid.as_raw(),
            gid: gid.as_raw(),
        })
    }

    #[cfg(all(
        unix,
        not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
    ))]
    pub(crate) fn from_stream(_stream: &LocalStream) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "router peer credentials are unavailable on this Unix platform",
        ))
    }

    #[cfg(windows)]
    pub(crate) fn from_stream(_stream: &LocalStream) -> io::Result<Self> {
        Ok(Self::AuthenticatedWindowsToken)
    }
}

pub(crate) fn validate(
    user_info: TerminalUserInfo,
    peer: PeerIdentity,
) -> Result<Registration, RegistrationError> {
    let id = user_info.id.ok_or(RegistrationError::Invalid)?;
    if id.len() != ID_LEN || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(RegistrationError::Invalid);
    }
    let passkey = user_info.passkey.ok_or(RegistrationError::Invalid)?;
    let key = passkey_to_key(&passkey).ok_or(RegistrationError::Invalid)?;
    // Unix socket ownership comes from the kernel, not the peer. A client
    // that claims uid 0 must not be allowed to listen or connect as root
    // (upstream #890 / 7d70aa2). Windows has no AF_UNIX peer credentials;
    // the supplied ids stay, and the router token authenticates the pipe.
    let (uid, gid) = match peer {
        #[cfg(unix)]
        PeerIdentity::Unix { uid, gid } => (uid, gid),
        #[cfg(windows)]
        PeerIdentity::AuthenticatedWindowsToken => {
            let uid = user_info
                .uid
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(RegistrationError::Invalid)?;
            let gid = user_info
                .gid
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(RegistrationError::Invalid)?;
            (uid, gid)
        }
    };
    let startup_ack = user_info.fd == Some(-6);
    Ok(Registration {
        id,
        key,
        uid,
        gid,
        startup_ack,
        pty_active: user_info.ptyactive.unwrap_or(false),
        had_reverse_tunnels: user_info.hadreversetunnels.unwrap_or(false),
        disconnect_timeout_seconds: user_info.disconnect_timeout_seconds,
        identity: Arc::new(()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> TerminalUserInfo {
        TerminalUserInfo {
            id: Some("aaaaaaaaaaaaaaaa".to_owned()),
            passkey: Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".to_owned()),
            uid: Some(501),
            gid: Some(20),
            fd: None,
            ptyactive: None,
            hadreversetunnels: None,
            disconnect_timeout_seconds: None,
        }
    }

    #[test]
    fn identical_material_has_distinct_registration_generations() {
        #[cfg(unix)]
        let peer = PeerIdentity::Unix { uid: 501, gid: 20 };
        #[cfg(windows)]
        let peer = PeerIdentity::AuthenticatedWindowsToken;
        let first = validate(info(), peer).unwrap();
        let second = validate(info(), peer).unwrap();
        assert_eq!(first, second);
        assert!(!first.same_generation(&second));
        assert!(!first.identity().same_generation(&second.identity()));
    }

    #[cfg(unix)]
    #[test]
    fn kernel_credentials_replace_a_forged_uid() {
        let mut supplied = info();
        supplied.uid = Some(0);
        supplied.gid = Some(0);
        let registration = validate(supplied, PeerIdentity::Unix { uid: 501, gid: 20 }).unwrap();
        assert_eq!(registration.uid, 501);
        assert_eq!(registration.gid, 20);

        let mut omitted = info();
        omitted.uid = None;
        omitted.gid = None;
        let registration = validate(omitted, PeerIdentity::Unix { uid: 501, gid: 20 }).unwrap();
        assert_eq!((registration.uid, registration.gid), (501, 20));
    }
}
