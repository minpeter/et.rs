use std::io::{self, Read};
use std::process::{Command, ExitStatus, Stdio};

use crate::bootstrap::{parse_id_passkey, Credentials, SshInvocation};
use crate::error::ClientError;

pub const MAX_SSH_STDOUT: usize = 1024 * 1024;

#[derive(Debug)]
pub struct SshOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub truncated: bool,
}

pub trait SshRunner {
    fn run(&self, invocation: &SshInvocation) -> Result<SshOutput, ClientError>;
}

#[derive(Debug, Default)]
pub struct SystemSsh;

impl SshRunner for SystemSsh {
    fn run(&self, invocation: &SshInvocation) -> Result<SshOutput, ClientError> {
        let mut child = Command::new(&invocation.program)
            .args(&invocation.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(ClientError::SshSpawn)?;
        let mut stdout = child.stdout.take().ok_or_else(|| {
            ClientError::SshStdout(io::Error::other("ssh stdout pipe was not created"))
        })?;

        let (stdout, truncated) = match capture_bounded(&mut stdout) {
            Ok(capture) => capture,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ClientError::SshStdout(error));
            }
        };
        let status = child.wait().map_err(ClientError::SshWait)?;
        Ok(SshOutput {
            status,
            stdout,
            truncated,
        })
    }
}

pub fn run_bootstrap<R: SshRunner + ?Sized>(
    runner: &R,
    invocation: &SshInvocation,
) -> Result<Credentials, ClientError> {
    let output = runner.run(invocation)?;
    if output.truncated {
        return Err(ClientError::SshOutputTooLarge(MAX_SSH_STDOUT));
    }
    if !output.status.success() {
        return Err(ClientError::SshNonZero(output.status.code()));
    }
    parse_id_passkey(&output.stdout)
}

fn capture_bounded(reader: &mut impl Read) -> io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::new();
    let mut truncated = false;
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let available = MAX_SSH_STDOUT.saturating_sub(captured.len());
        let keep = count.min(available);
        captured.extend_from_slice(&buffer[..keep]);
        truncated |= keep != count;
    }
    Ok((captured, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRunner(Result<SshOutput, io::Error>);

    impl SshRunner for FakeRunner {
        fn run(&self, _: &SshInvocation) -> Result<SshOutput, ClientError> {
            match &self.0 {
                Ok(output) => Ok(SshOutput {
                    status: output.status,
                    stdout: output.stdout.clone(),
                    truncated: output.truncated,
                }),
                Err(error) => Err(ClientError::SshSpawn(io::Error::new(
                    error.kind(),
                    error.to_string(),
                ))),
            }
        }
    }

    fn invocation() -> SshInvocation {
        SshInvocation {
            program: "ssh".into(),
            args: Vec::new(),
        }
    }

    fn status(program: &str) -> ExitStatus {
        Command::new(program).status().unwrap()
    }

    #[test]
    fn runner_seam_returns_credentials() {
        let runner = FakeRunner(Ok(SshOutput {
            status: status("true"),
            stdout: b"IDPASSKEY:abcdefghijklmnop/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef".to_vec(),
            truncated: false,
        }));
        assert_eq!(
            run_bootstrap(&runner, &invocation()).unwrap().id,
            "abcdefghijklmnop"
        );
    }

    #[test]
    fn nonzero_and_truncated_outputs_are_typed() {
        let nonzero = FakeRunner(Ok(SshOutput {
            status: status("false"),
            stdout: Vec::new(),
            truncated: false,
        }));
        assert!(matches!(
            run_bootstrap(&nonzero, &invocation()),
            Err(ClientError::SshNonZero(_))
        ));
        let truncated = FakeRunner(Ok(SshOutput {
            status: status("true"),
            stdout: Vec::new(),
            truncated: true,
        }));
        assert!(matches!(
            run_bootstrap(&truncated, &invocation()),
            Err(ClientError::SshOutputTooLarge(_))
        ));
    }
}
