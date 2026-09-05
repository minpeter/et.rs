use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};

use wait_timeout::ChildExt;

use super::{observe, Shell, TIMEOUT};

const PROCESS_CLEANUP: &str = include_str!("process_cleanup.ps1");

pub fn powershell() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe")
}

pub struct OwnedChild(pub Child);

impl OwnedChild {
    pub fn spawn(command: &mut Command) -> Self {
        Self(command.spawn().unwrap())
    }

    pub fn wait(&mut self) -> ExitStatus {
        self.0
            .wait_timeout(TIMEOUT)
            .unwrap()
            .expect("owned process exit timed out")
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => eprintln!("process inspection failed: {error}"),
        }
        // Failure-only cleanup targets the exact test-owned root, never an
        // image name, installed service, or machine-wide process list.
        match Command::new("taskkill.exe")
            .args(["/F", "/T", "/PID", &self.0.id().to_string()])
            .output()
        {
            Ok(output) if output.status.success() => {}
            result => eprintln!("fallback tree cleanup: {result:?}"),
        }
        if let Err(error) = self.0.wait() {
            eprintln!("process reaping failed: {error}");
        }
    }
}

pub struct ProcessExitObserver(OwnedChild);

impl ProcessExitObserver {
    pub fn subscribe(shell: &Shell) -> Self {
        // Opening both handles before READY prevents PID reuse races. Native
        // WaitForExit subscribes to process completion without process polling.
        // The observer also owns failure cleanup if a mutant leaves children.
        let script = format!(
            "{PROCESS_CLEANUP}\n$ErrorActionPreference='Stop'; \
             $targets=@({},{}) | ForEach-Object {{ \
               $p=[Diagnostics.Process]::GetProcessById($_); $null=$p.Handle; $p \
             }}; \
             [Console]::WriteLine('READY'); \
             $mode=[Console]::ReadLine(); \
             Complete-ObservedProcesses -Targets $targets -Mode $mode",
            shell.pid, shell.descendant
        );
        let mut command = Command::new(powershell());
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = OwnedChild::spawn(&mut command);
        let stdout = child.0.stdout.take().unwrap();
        assert_eq!(
            observe(move || {
                let mut line = String::new();
                BufReader::new(stdout).read_line(&mut line).unwrap();
                line
            })
            .trim(),
            "READY"
        );
        println!(
            "PROCESS_EXIT_SUBSCRIBED shell={} descendant={}",
            shell.pid, shell.descendant
        );
        Self(child)
    }

    pub fn wait(&mut self) {
        writeln!(self.0 .0.stdin.take().unwrap(), "WAIT").unwrap();
        assert!(self.0.wait().success(), "native shell/descendant leaked");
        println!("SHELL_AND_DESCENDANT_EXITED");
    }
}

impl Drop for ProcessExitObserver {
    fn drop(&mut self) {
        if let Some(stdin) = self.0 .0.stdin.take() {
            // EOF requests cleanup through the already-open process handles,
            // even if the terminal exited and orphaned a descendant on panic.
            drop(stdin);
            match self.0 .0.wait_timeout(TIMEOUT) {
                Ok(Some(status)) if status.success() => {}
                result => eprintln!("process observer fallback failed: {result:?}"),
            }
        }
    }
}

#[path = "process_tests.rs"]
mod tests;
