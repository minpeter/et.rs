---
packages:
  et:
    type: patch
---

## SSH-compatible client options and persistent local sessions

Client arguments now follow SSH's host boundary: all options must precede the
host, and everything after it is the remote command. Short options have changed:
use `--port` for the ET port (`-p` now selects the SSH port), `--command` instead
of `-c`, `--tunnel`/`-L` instead of `-t`, and `--forward-ssh-agent` instead of `-f`
(now background mode). `-N` means no remote command; `--no-terminal` still starts
a shell. See README for the complete migration table.

Adds Unix ControlMaster/ControlPath/ControlPersist multiplexing, `--ctl` sessions,
and runtime local TCP/Unix forwarding. Agent forwarding retargets across reconnect
and saved-session attach. Redirected stdin EOF no longer discards delayed remote
output, including on Windows. SSH configuration supplies session commands,
environment, forwarding, and connection options without leaking those settings
onto the bootstrap SSH connection.

Background authentication retains its controlling terminal until authentication
finishes. Saved control sessions validate the remote user and recover expired
credentials without discarding them on a transient transport error. Mux commands
with comments or syntax errors report completion without wedging the shared shell.

Server disconnect defaults, SSH_TTY, and bounded tmux control filtering are also
included. Protocol v6 is unchanged: EOF-dependent raw terminal commands still need
explicit framing. Local mux/control/background remains unsupported on Windows;
raw `-T` mux sessions (except `-NT` forwarding-only masters), remote/dynamic mux
forwarding, and reverse SOCKS/allocated remote port zero are explicitly unsupported.
