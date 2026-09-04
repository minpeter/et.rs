---
packages:
  et:
    type: patch
---

## Share SSH bootstrap connections under load

Share SSH bootstrap transport connections across ET processes targeting the
same effective destination. ET first runs the configuration-only query, then
checks for a working user-configured ControlMaster without supplying a
ControlPath. A working user master remains preferred and ET's operational
commands use it unchanged.

When no user master exists, ET hashes the effective SSH user, resolved host,
resolved port, and jumphost into a stable 32-hex-character socket name under a
mode-0700 per-user `et-ssh-<uid>` directory. Long Unix temporary-directory
paths fall back to `/tmp`, keeping the complete socket path below a conservative
90-byte `sockaddr_un` limit.

An atomic destination-specific `.lock` directory serializes master startup.
The lock holder checks the socket again before starting OpenSSH; contenders
check that exact socket until the winner publishes it or releases the lock.
This converges concurrent ET processes on one master rather than allowing a
ControlMaster bind race. Master setup failures fall back to ordinary SSH
invocations.

The ET master uses `ControlPersist=15`. Sessions never send `ssh -O exit` and
never unlink the shared socket, so one ET process cannot tear down transport
used by another. OpenSSH removes the socket after the persisted master becomes
idle; the private parent directory is retained for later destination masters.

User `ControlMaster` and `ControlPath` command-line options remain filtered.
Isolation remains forced with `ClearAllForwardings=yes`, `RemoteCommand=none`,
`PermitLocalCommand=no`, and `SessionType=default`.

Local OpenSSH diagnosis against localhost showed configuration and `-O check`
operations open no TCP connections. A master start emitted one `Connecting to`
line and a mux listener; probe and bootstrap operations emitted
`mux_client_request_session` without a new `Connecting to` line.
