## et@0.0.5

### Fix macOS reconnect and PTY end-to-end failures

Fix the remaining macOS portability failures in reconnect, terminal shutdown,
and background process-group cleanup.

The terminal launcher now resolves busybox-style symlinks before re-exec,
client and router loops detect Darwin socket closure reliably, and the PTY
fixtures no longer depend on interactive-shell timing. macOS CI now runs the
affected reconnect and PTY/process integration tests explicitly.

## et@0.0.4

### Fix client dying with "polling terminal streams: Interrupted system call (os error 4)"

The client installs a process-wide SIGWINCH handler for terminal resizes, and
`poll()` is never auto-restarted by `SA_RESTART`: any signal delivered to the
thread blocked in `poll()` (a window resize, `SIGCONT` after job control,
`SIGINFO` from Ctrl-T on macOS) made it fail with `EINTR`, which the client
treated as fatal and tore the session down mid-use.

The terminal loop now retries `poll()` on `EINTR`, recomputing the keepalive
timeout from the absolute deadline so timing stays correct. The same retry was
applied to every other interruptible `poll()` in the workspace: the server
session bridge, the PTY worker, the jump-host bridge, and the port-forward
acceptor (which previously exited silently on `EINTR`).

## et@0.0.3

### Identify the et.rs port in `--version` output

`--version` on every role (`et`, `etserver`, `etterminal`, `htm`, `htmd`) now
prints the et.rs identity and project URL:

```
et version 0.0.3 (et.rs)
A Rust port of Eternal Terminal
https://github.com/minpeter/et.rs
```

`-V` keeps the short upstream-compatible `et version X.Y.Z` line for scripts.
`etterminal` gains `--version`/`-V` support.

## et@0.0.2

### Fix reconnect against upstream C++ peers rejecting the session with "invalid recovery proof"

Reconnecting to an upstream C++ `etserver` (or accepting an upstream C++ `et`
client) failed with `server sent an invalid recovery proof` whenever the peer's
first packet after recovery was regular session traffic, such as terminal
output. et.rs required the first post-recovery packet to be an empty
keep-alive, a convention upstream does not follow.

Recovery authentication now accepts any packet that decrypts with the session
key (which is the actual proof) and requeues it for the session loop instead
of discarding it, so no traffic is lost.

Also fixes a port-forwarding race surfaced by this change: closing a forwarded
socket could drop data still queued for its writer thread. Teardown now drains
queued writes before shutting the socket down.

## et@0.0.1

### Initial release

First automated release of et.rs: a single telemetry-free EternalTerminal binary (Rust port).

One binary serves every role: `et` (client), `etserver`, `etterminal`, `htm`, `htmd`.
