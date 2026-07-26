## et@0.0.6

### Fix a port-forwarding deadlock under bidirectional load

The session loops handed inbound tunnel packets to the forwarding worker with
a blocking send, while the worker hands outbound tunnel packets back through a
bounded queue that only those same session loops drain. Under sustained
bulk transfers in both directions the two bounded queues could fill at the
same time, leaving the session loop and the worker each waiting on the other —
a permanent wedge that also stopped keepalives and made reconnects impossible.

Session loops (client, server bridge, on both Unix and Windows) now hand
packets to the worker without blocking: when the worker is at capacity the
packet is held, no further session packets are read (preserving order), and
the loop keeps draining the worker's outbound queue — which is exactly what
frees the worker — retrying on a 10ms cadence.

### Fix session teardown under local IPC backpressure

`set_nonblocking(true)` applies to the socket, not the handle: every
`try_clone()` of a local stream shares the flag. The readiness-driven session
loops flip their local streams to non-blocking for reads, which silently made
the packet writers on cloned handles non-blocking too. When the kernel socket
buffer filled (a shell that stops reading input during a large paste, or a
bridge pausing terminal output while a client reconnects), `write_all` failed
with `WouldBlock` and tore the whole session down — killing the shell, failing
the server bridge, or silently ending a jump-host relay — and could leave a
truncated frame that corrupted the local packet stream.

`write_local_packet` now treats `WouldBlock` as backpressure: it resumes from
the partial write and retries until the peer drains, matching upstream's
blocking-write semantics on both Unix and Windows.

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
