## et@0.0.17

### Return cleanly to the local prompt after exit

Interactive sessions now finish with an SSH-style `Connection to … closed.`
line and keep the local prompt on the current screen. Graceful shell exits no
longer issue an unmatched alternate-screen restore that could move the cursor
to an old position, while abrupt failures retain the stronger terminal-mode
cleanup needed for crashed full-screen applications.

### Preserve Ghostty truecolor detection

Ghostty clients now forward the standard `COLORTERM=truecolor` hint to POSIX
sessions while continuing to use the compatible `TERM=xterm-256color`
fallback. Applications such as Neovim and tmux can retain automatic 24-bit
color detection on remote hosts without Ghostty's terminfo entry.

### Preserve client locales in POSIX sessions

Clients now forward `LANG` and `LC_*` values to each new POSIX session, matching
the environment behavior users expect from SSH. Locale-sensitive applications
such as btop can detect UTF-8 without changing Windows session environments.

## et@0.0.16

### Restore remote colors for Ghostty clients

ET clients launched from Ghostty now send the widely supported
`TERM=xterm-256color` fallback instead of `xterm-ghostty`. This restores
ordinary remote prompt and application colors on hosts without Ghostty's
terminfo entry. Other terminal types remain unchanged.

## et@0.0.15

### Stabilize remote shell detection

Remote shell probing now ignores sentinel text embedded in banner lines,
finishes as soon as a complete valid sentinel line arrives, and preserves a
nonzero SSH exit status observed before that line.

Explicit `--remote-shell` choices remain authoritative, and Windows
destinations no longer pass their `et.exe` default to POSIX jumphosts.

## et@0.0.14

### Restore colorful shell startup in ET sessions

Unix ET sessions now start the user's shell as a login shell, matching SSH,
upstream EternalTerminal, and ET's own headless terminal multiplexer. This
restores profile-provided prompts, aliases, `dircolors`, and other color setup
that was skipped when ET launched an interactive non-login shell.

Native Windows terminal startup, protocol-v6 bytes, and reconnect behavior are
unchanged.

### Auto-detect Windows OpenSSH bootstrap

Bare `et user@windows-host` connections now probe the login shell without
including session credentials. Expanded `%ComSpec%` selects the existing
Cmd-compatible bootstrap and `et.exe` terminal path automatically, while
POSIX hosts preserve their existing bootstrap.

Explicit `--winserver` and `--remote-shell` overrides remain authoritative.
PowerShell sessions now pass `ET_SHELL=powershell.exe` only to the remote
`etterminal` process.

## et@0.0.13

### Port EternalTerminal #784 pre-auth / LPE fixes

Handshake protos are now capped at 4 KiB (was 64 KiB), matching ET
`MAX_HANDSHAKE_PROTO_LENGTH`. Length-prefixed reads enforce both an idle
gap and an absolute deadline so a slow trickle cannot reset the timer
forever. Failed reconnect recover no longer disconnects the live victim
session before recover succeeds. When `etserver` is root, UNIX listen and
connect on client-chosen paths drop to the session user (helper +
`SCM_RIGHTS`) instead of unlink/bind/chown/connect as root. Reconnect
passkey-before-recover is still omitted: that needs a `PROTOCOL_VERSION`
bump.

## et@0.0.12

### Unblock session recovery after blackholed client writes

`etserver` no longer lets a blackholed client TCP path (peer stops reading
without FIN/RST) hold the session connection mutex inside an unbounded
socket write. Live writes use a two-second deadline loop and soft-disconnect
(with socket shutdown) into the reconnect buffer so partial frames cannot
desync a later recovery on a new stream. Session recovery runs sequence
exchange and peer auth *without* holding the connection mutex (terminal
output is queued and flushed after install), uses a panic-safe single-flight
permit (`RecoverPermit`), and only sends `ReturningClient` after that permit
is held — concurrent recovers are dropped without a handshake so clients
retry instead of burning a sequence-exchange timeout. Returning clients that
previously saw `ReturningClient` then hung with `ET bootstrap timed out while
recovering ET session` can complete recovery again.

## et@0.0.11

### Keep server sessions alive across client transport loss

`etserver` now treats laptop sleep, Wi-Fi changes, and other client transport
loss as a recoverable disconnect instead of terminating the registered
terminal. Output produced while the client is away remains buffered, and a
returning client resumes the same shell without an `InvalidKey` failure.

Recovery handoff now ignores stale events from the replaced socket, drains
packets read during recovery authentication, and preserves port-forwarding
packets when the replay buffer is temporarily full.

## et@0.0.10

### Add debug diagnostics for dropped server sessions

`ET_DEBUG=1` now gives `etserver` a durable machine-local log destination,
non-silent logging, and default verbosity 2. Operators can also use
`ET_LOGDIR` and `ET_VERBOSE` when CLI or INI settings do not override them.

Server diagnostics now record client accept/reject reasons, reconnect and
recovery outcomes, terminal disconnects, and session removal, making long-lived
session drops diagnosable from the server host. Client debug logs omit session
credentials, malformed handshakes are bounded by a five-second deadline and
128-connection pre-auth capacity, and completed connection handlers no longer
accumulate after rapid failed handshakes.

## et@0.0.9

### Recover from macOS post-sleep socket timeouts

Changing networks or waking a MacBook can leave the existing TCP connection in
an unusable state. macOS reports some of those stale connections as
`ETIMEDOUT` (`Operation timed out`, os error 60) rather than EOF or a reset.
The client previously treated that live-transport error as fatal and exited,
which also exposed any terminal mode left by the remote program.

Every socket I/O failure from the live ET transport now enters the normal
reconnect path. Recovery retains the same remote session and keeps retrying
while Wi-Fi or routing returns; protocol, crypto, framing, backpressure, and
local-terminal failures remain fatal. This matches upstream Eternal Terminal's
behavior of reconnecting after any socket read/write error.

## et@0.0.8

### Trim replay backups with delivery acknowledgements on keep-alives

Replay backups previously only shrank at a fixed cap, so a single burst of
output (`cat` a large file) pinned the cap's worth of memory per session for
the rest of the daemon's uptime, and idle sessions slowly accumulated
keep-alive echoes.

Keep-alives now carry the sender's reader sequence as an 8-byte payload.
Every implementation ignores keep-alive payloads on receipt (verified
against upstream C++ `TerminalServer`/`TerminalClient` and released et.rs),
so the extension is invisible to legacy peers. An et.rs receiver uses it to
drop backup packets the peer has already consumed, keeping only the
unacknowledged tail plus a fixed slack — a session's replay backup now
returns to near-empty within one keep-alive interval instead of pinning the
connected cap forever.

Acknowledgements are strictly per-hop. Jumphosts relay packets verbatim
(upstream and et.rs alike), so the jumphost etserver consumes the client's
acknowledgement for its own connection and forwards a payload-less
keep-alive, and `etterminal --jump` attaches its own sequence towards the
destination. A foreign sequence that still arrives through a legacy C++
jumphost is absorbed by the retention slack.

### Stop the daemon from retaining 64 MiB of replay history per live session

Every packet written to a client is kept in a per-session replay backup so a
reconnecting peer can catch up. That backup was only trimmed at upstream's
64 MiB / 262,144-packet cap and never expired otherwise, so a long-lived
`etserver` slowly pinned up to 64 MiB per session — with a couple dozen
sessions the daemon grew towards multiple gigabytes, exactly like the C++
server it replaces.

While the transport is connected, a reconnecting peer can only be missing
data that was in flight, which is bounded by kernel socket buffering
(≤ 4 MiB on default Linux autotuning). The connected backup is now trimmed
to 8 MiB / 32,768 packets and the deque returns its slack capacity after a
reconnect. The disconnected catch-up buffer keeps upstream's full 64 MiB,
and nothing on the wire changes: recovery, the handshake, and the
receive-side catch-up validation limits all stay byte-compatible with
upstream C++ peers.

## et@0.0.7

### Survive network outages during reconnect and restore leaked terminal modes

A laptop waking from sleep has no route to the server for several seconds.
The client attempted exactly one reconnect and treated its failure as fatal,
so a live session died with "could not reach the ET server: connection timed
out" the moment the first attempt raced the returning Wi-Fi. Transient
network failures (unreachable endpoint, DNS outages, connect/transport I/O
errors) are now retried every second until the link returns — matching
upstream ET, which keeps a session alive until the server ends it. The
client announces the retry loop once, and Ctrl-C gives up (raw mode turns
ISIG off, so the byte is read from stdin); protocol mismatches and server
rejections still fail immediately.

Separately, exiting only restored the local termios. Terminal modes a remote
application had enabled in the local emulator — the kitty keyboard protocol,
bracketed paste, mouse and focus reporting, the alternate screen — survived
the client, leaving the shell prompt printing key reports like `2618;9u` as
garbage text. The client now emits the matching reset sequences when it
leaves raw mode; every reset is a no-op when the mode is off or unsupported.

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
