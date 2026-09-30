//! Upstream #828: reverse agent tunnels target a stable, session-local symlink.
//! Keep it across client exit: #793 attach reuses the server's original tunnel.
//! Only new agent connections are retargeted; existing streams are not replayed.

use et_cli::client::ClientArgs;
use et_core::proto::InitialPayload;

use crate::error::ClientError;
use crate::initial_connect::ReconnectOutcome;

pub struct AgentForward {
    #[cfg(unix)]
    proxy: Option<unix::Proxy>,
}

impl AgentForward {
    pub fn prepare(
        args: &ClientArgs,
        id: &str,
        payload: &mut InitialPayload,
    ) -> Result<Self, ClientError> {
        #[cfg(unix)]
        {
            let proxy = if args.forward_ssh_agent {
                let proxy = unix::Proxy::open(id, args.ssh_socket.clone(), true)
                    .map_err(agent_error)?
                    .expect("created agent proxy directory");
                proxy
                    .refresh(std::env::var("SSH_AUTH_SOCK").ok().as_deref())
                    .map_err(agent_error)?;
                // build() appends the generated agent request after user tunnels.
                let request = payload.reversetunnels.last_mut().expect("agent request");
                request
                    .destination
                    .as_mut()
                    .expect("agent destination")
                    .name = Some(
                    proxy
                        .path()
                        .to_str()
                        .ok_or_else(|| {
                            agent_error(std::io::Error::other("agent proxy path is not UTF-8"))
                        })?
                        .to_owned(),
                );
                Some(proxy)
            } else {
                None
            };
            Ok(Self { proxy })
        }
        #[cfg(windows)]
        {
            let _ = (id, payload);
            if args.forward_ssh_agent {
                return Err(ClientError::Unsupported(
                    "SSH agent forwarding is not supported on Windows",
                ));
            }
            Ok(Self {})
        }
    }

    /// Attach deliberately uses the attaching process's environment, not the
    /// previous process's --ssh-socket/IdentityAgent (upstream #793/#828).
    /// Call only after authentication has transferred session ownership.
    pub fn attach(id: &str) -> Result<Self, ClientError> {
        #[cfg(unix)]
        {
            let environment = std::env::var("SSH_AUTH_SOCK").ok();
            let proxy = unix::Proxy::open(id, None, environment.is_some()).map_err(agent_error)?;
            if let Some(proxy) = &proxy {
                proxy.refresh(environment.as_deref()).map_err(agent_error)?;
            }
            Ok(Self { proxy })
        }
        #[cfg(windows)]
        {
            let _ = id;
            Ok(Self {})
        }
    }

    pub fn reconnected(&self, outcome: ReconnectOutcome) -> Result<ReconnectOutcome, ClientError> {
        #[cfg(unix)]
        if outcome == ReconnectOutcome::Recovered {
            if let Some(proxy) = &self.proxy {
                proxy
                    .refresh(std::env::var("SSH_AUTH_SOCK").ok().as_deref())
                    .map_err(agent_error)?;
            }
        }
        Ok(outcome)
    }
}

#[cfg(unix)]
fn agent_error(error: std::io::Error) -> ClientError {
    ClientError::Terminal(format!("could not retarget SSH agent forwarding: {error}"))
}

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};

    use rustix::fs::{
        fstat, open, renameat, statat, symlinkat, unlinkat, AtFlags, FileType, Mode, OFlags,
    };

    const LINK: &str = "agent.sock";

    pub(super) struct Proxy {
        path: PathBuf,
        pinned: Option<String>,
    }

    impl Proxy {
        pub(super) fn open(
            id: &str,
            pinned: Option<String>,
            create: bool,
        ) -> io::Result<Option<Self>> {
            if id.len() != 16 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid agent session ID",
                ));
            }
            let directory = std::env::temp_dir().join(format!("et-agent-{id}"));
            Ok(Self::open_directory(&directory, create)?.map(|_| Self {
                path: directory.join(LINK),
                pinned,
            }))
        }

        fn open_directory(path: &Path, create: bool) -> io::Result<Option<OwnedFd>> {
            use std::os::unix::fs::DirBuilderExt;
            if create {
                match std::fs::DirBuilder::new().mode(0o700).create(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            // Never chmod/follow an attacker-precreated symlink or directory.
            // All mutations below are relative to this verified descriptor.
            let directory = match open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let stat = fstat(&directory)?;
            if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o777 != 0o700 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "agent proxy directory must be owned by this user with mode 0700",
                ));
            }
            Ok(Some(directory))
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        fn check_link(directory: &OwnedFd) -> io::Result<bool> {
            match statat(directory, LINK, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat)
                    if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink
                        && stat.st_uid == rustix::process::geteuid().as_raw() =>
                {
                    Ok(true)
                }
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "agent proxy is not an owned symlink",
                )),
                Err(rustix::io::Errno::NOENT) => Ok(false),
                Err(error) => Err(error.into()),
            }
        }

        pub(super) fn refresh(&self, environment: Option<&str>) -> io::Result<()> {
            // A reconnect may follow temporary-directory cleanup. Reopen and
            // verify the directory each time, recreating it when necessary.
            let directory = Self::open_directory(self.path.parent().expect("proxy parent"), true)?
                .expect("created proxy directory");
            let exists = Self::check_link(&directory)?;
            let target = self
                .pinned
                .as_deref()
                .or(environment)
                .filter(|value| !value.is_empty());
            let Some(target) = target else {
                // Fail closed, unlike upstream's stale-target fallback: an
                // attach without an agent must not expose the prior agent.
                if exists {
                    unlinkat(&directory, LINK, AtFlags::empty())?;
                }
                return Ok(());
            };
            if !Path::new(target).is_absolute()
                || target.contains('\0')
                || Path::new(target) == self.path
            {
                if exists {
                    unlinkat(&directory, LINK, AtFlags::empty())?;
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "agent socket must be an absolute path other than the proxy",
                ));
            }
            let temporary = format!("agent.sock.tmp.{}", et_core::keys::gen_id_passkey().0);
            symlinkat(target, &directory, &temporary)?;
            let result = renameat(&directory, &temporary, &directory, LINK);
            if result.is_err() {
                let _ = unlinkat(&directory, &temporary, AtFlags::empty());
            }
            result.map_err(Into::into)
        }
    }
}

#[cfg(all(test, unix))]
#[path = "agent_forward_tests.rs"]
mod tests;
