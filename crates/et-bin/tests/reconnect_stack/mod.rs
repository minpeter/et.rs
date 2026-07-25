use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use wait_timeout::ChildExt;

const TIMEOUT: Duration = Duration::from_secs(10);

pub struct Stack {
    pub directory: std::path::PathBuf,
    pub router: std::path::PathBuf,
    pub terminal: std::path::PathBuf,
    pub ssh_count: std::path::PathBuf,
    pub port: u16,
    server: Option<std::process::Child>,
}

impl Stack {
    pub fn start() -> Self {
        let directory =
            std::env::temp_dir().join(format!("et-rs-reconnect-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let router = directory.join("router.sock");
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let config = directory.join("et.cfg");
        fs::write(
            &config,
            format!(
                "[Networking]\nport={port}\nbind_ip=127.0.0.1\n\
                 [Debug]\nserverfifo={}\n",
                router.display()
            ),
        )
        .unwrap();
        let mut server = Command::new(env!("CARGO_BIN_EXE_et"))
            .args(["server", "--cfgfile"])
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_ready(&mut server, port, &router);
        let ssh_count = directory.join("ssh-count");
        fs::write(&ssh_count, "").unwrap();
        let ssh = directory.join("ssh");
        fs::write(
            &ssh,
            "#!/bin/sh\nif [ \"$1\" = \"-G\" ]; then\n\
             printf 'hostname 127.0.0.1\\nuser tester\\n'; exit 0; fi\n\
             printf x >> \"$ET_SSH_COUNT\"\nfor last do :; done\n\
             exec /bin/sh -c \"$last\"\n",
        )
        .unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
        let terminal = directory.join("etterminal");
        symlink(env!("CARGO_BIN_EXE_et"), &terminal).unwrap();
        Self {
            directory,
            router,
            terminal,
            ssh_count,
            port,
            server: Some(server),
        }
    }

    pub fn shutdown(&mut self) {
        let mut server = self.server.take().unwrap();
        let pid = Pid::from_raw(i32::try_from(server.id()).unwrap());
        kill(pid, Signal::SIGTERM).unwrap();
        assert!(server.wait_timeout(TIMEOUT).unwrap().unwrap().success());
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        if let Some(server) = self.server.as_mut() {
            let pid = Pid::from_raw(i32::try_from(server.id()).unwrap());
            let _ = kill(pid, Signal::SIGTERM);
            let _ = server.wait_timeout(TIMEOUT);
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub fn mkfifo(path: &std::path::Path) {
    assert!(Command::new("mkfifo").arg(path).status().unwrap().success());
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn wait_ready(server: &mut std::process::Child, port: u16, router: &std::path::Path) {
    let stdout = server.stdout.take().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    assert_eq!(
        receiver.recv_timeout(TIMEOUT).unwrap().unwrap(),
        format!(
            "ETSERVER_READY tcp=127.0.0.1:{port} router={}\n",
            router.display()
        )
    );
}
