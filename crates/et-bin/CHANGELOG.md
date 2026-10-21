## et@0.0.45

### `etserver` no longer burns a CPU core on a session whose shell exited while the client was away

When the client's connection dropped and the shell then exited with output the server could not deliver yet, such as a full output buffer or the final exit status, the session's thread kept waking without pause, using a whole CPU core until `etserver` stopped. Stopping `etserver` could then hang on that thread. Like ET C++, the server now stops watching a terminal it cannot read from. A session that no client can resume any more now ends.

## et@0.0.44

### `--jumphost` works when the destination runs ET C++

`et --jumphost` now gives the jump terminal the session id and key the destination's `etterminal` answered with, as upstream does. An ET C++ `etterminal` replaces the client's temporary credentials with its own, so the session previously failed against a C++ destination.

### A jumphost session shows its first output without a keypress

When the destination's first output arrived together with its handshake reply, the jump terminal held that output until something else happened on the connection, so the prompt could stay blank until you pressed a key. The jump terminal now forwards it right away.

### Keystrokes typed while `et` reconnects are no longer lost

While the connection was down, `et` read your keystrokes only to watch for Ctrl-C and dropped everything else. It now sends them to the remote shell, in the order you typed them, once the session recovers, as ET C++ does. Ctrl-C still gives up reconnecting.

### `etserver` and `etterminal` accept what ET C++ sends

On the server host, `etserver` and `etterminal` now accept a message of up to 128 MiB, as upstream does (it was 64 KiB). `etterminal` also sets the session environment the way upstream does: any number of variables, of any length, with names such as `MY-VAR`. It skips only entries the system cannot set. A C++ `et` client with a large `SendEnv`/`SetEnv` environment therefore no longer fails to start a session on an et.rs `etserver` or `etterminal`.

The et.rs `et` client still sends only what et.rs 0.0.43 and older accept, so it keeps working with servers that have not been upgraded.

### No lost output when `etserver` restarts as an older et.rs

When `etserver` restarted as et.rs 0.0.43 or older, for example after a downgrade, a running session's first output could go missing, or the client printed `malformed terminal output` and reconnected again. The new `etterminal` now answers that older server's startup check as soon as it reconnects, so the output reaches the client.

### `et -T` passes the end of your input to the remote command

Like `ssh -T`, `et -T host 'wc -c' < file` now finishes: when the client's stdin ends, the remote command sees end of input. On a terminal, Ctrl-D in `et -T` now ends the command's input instead of closing `et`.

This needs an et.rs client and an et.rs `etterminal`. ET C++ has no way to signal it, so with a C++ client or terminal the command keeps waiting as before.

### No lost or garbled output right after `etserver` restarts

When `etserver` restarted under a live session, the new server sometimes read the session's first output itself, waiting for a startup report that a resumed terminal never sends. That output was lost, or the client printed `malformed terminal output` and had to reconnect a second time. The resumed session now gets all of its output.

### `etserver` and `etterminal` now mix with ET C++

On the server host, `etserver` hands keystrokes, resizes and the close request to `etterminal` over a local socket. et.rs now uses upstream's format on that socket, so an et.rs `etserver` serves a C++ `etterminal` and a C++ `etserver` serves an et.rs `etterminal`, in shell, `-T`, `-W` and jumphost sessions. An et.rs `etserver` also handles a C++ jump terminal the way upstream does.

Sessions started by et.rs 0.0.43 or older keep the old format, so they survive restarting `etserver` after the upgrade, and a new `etterminal` still works with an old `etserver` that has not restarted yet. A live session also survives switching `etserver` between et.rs and C++.

## et@0.0.43

### A plain `%exit` line no longer looks like tmux control mode

Ctrl+C output discarding keeps tmux `-CC` control lines (`%begin`, `%output`, …) so a tmux client never sees a broken record. Control mode starts only at tmux's `ESC P 1000 p` introducer or a known control token at the start of a line, so `top` (`%Cpu(s)`) or a csh `%` prompt stays ordinary output, as upstream #900 now does too. A line that happens to read `%exit`, tmux's goodbye, still entered control mode, and later `%` lines then survived a Ctrl+C flush. It is now ordinary output. Inside real control mode the session still leaves at the string terminator that follows `%exit`, so a Ctrl+C between the two cannot drop it.

## et@0.0.42

### One server control thread on Linux and macOS

- **The terminal router runs on the control thread:** `etserver` accepted terminal registrations on an `et-router` thread of its own, next to the `et-runtime` thread that accepts TCP connections and handles terminal lifecycle events. Both waited in `poll(2)`, so the control thread now also polls the router socket, pending registrations and registered terminals, with the same registration timeout, rejection and disconnect handling. Shutdown still closes the router after the sessions and before the registry is cleared. An idle server with one session runs three threads instead of four (OpenSSH's `sshd-session` pair: two; ET-C++: ten).
- Windows keeps the router thread: its router loop cannot wait on the router pipe together with the TCP listeners.

## et@0.0.41

### Fewer server wakeups and per-message system calls

- **Resume sweep only when needed:** the server's control thread checked for expired resumed terminals once a second even when there were none, so an idle server woke every second. It now sweeps only while a terminal that re-registered a live PTY (after a server restart) is registered; the router arms the sweep when one registers. An idle session's server now wakes about twice in 10 s (the client's keep-alive echoes) instead of twelve times.
- **No futex wake per queued packet:** on Linux and macOS the session loop writes its own output, but every packet queued while the queue was empty still notified a condition variable nobody waited on, which costs a `futex` system call each time. The notification now goes only to a parked writer (the Windows writer thread, or the final drain).
- **No `FIONREAD` probe per small forwarded message:** a readable forwarded socket was asked how many bytes it held before every read, to split large messages into pipelined parts. The first read now takes one 16 KiB part and only a full part asks how much is left, so a request or reply that fits in 16 KiB costs one system call fewer at each end. Larger messages are still split into parts of at least 16 KiB.
- With both, a 1-byte tunnel round trip costs 7.3 system calls per side instead of 8.3 on the client and 9.4 on the server.
- `etterminal` checks PTY output for tmux control-mode escapes with a SIMD search.

### One client thread for terminal output on Linux

- **The session loop writes the terminal itself:** when stdout is a terminal or a FIFO, the Linux client no longer starts the `et-console-output` thread. The loop that already reads the server, stdin and forwarded sockets now writes terminal output without blocking and waits for room in the same `poll`, as upstream's `TerminalClient::run` drains its `WriteBuffer` in its select loop. Queued packets go out in one vectored write and their buffers are reused, so a busy terminal no longer costs a copy and an allocation per packet plus a thread wakeup and a socketpair signal per batch. An interactive client now runs one thread, like OpenSSH (two before). Streaming 64 MiB to a terminal, the client's context switches fell from about 10,600 to 6,500 (OpenSSH: 10,400) and its CPU time from 310–330 ms to 280–300 ms (OpenSSH: 260 ms).
- Flow control, Ctrl+C output discarding, cursor-report replies and alternate-screen cleanup still act only on bytes that reached the terminal, and the bounded one-second drain on exit is unchanged. A Ctrl+C now also discards a saturated backlog whose queue is a few bytes short of 64 KiB, since partial terminal writes rarely leave it exactly full.
- Escape-sequence scans for cursor-report requests, alternate-screen switches and the post-interrupt line skip use SIMD searches.
- Regular files, sockets, macOS and Windows keep the output thread.

## et@0.0.40

### Idle sessions stop waking up every 100 ms

- **Event-driven waits on Linux:** the server session loop, the server's terminal registration router and the client loop each polled with a 100 ms cap, although every source they serve already wakes them through a descriptor. An idle tunnel session woke about 31 times per second (OpenSSH: 0, ET-C++: about 220). On Linux these loops now sleep until an event or a real deadline: the next keep-alive, the oldest pending registration's expiry, a disconnected client's timeout, a stalled delivery gate's release, or a forwarding retry. An idle session now wakes about 1.6 times per second (keep-alives and the server's one-second resume sweep).
- **Disconnected sessions no longer poll every 10 ms on Linux:** the session loop sleeps until the disconnect timeout instead, and starts that clock before it first sleeps.
- macOS keeps its 100 ms recheck because Darwin can omit readiness for a closed socket; Windows is unchanged.

## et@0.0.39

### One thread per server session on Unix

- **The terminal bridge writes its own output:** a server session no longer starts a separate output writer thread on Linux and macOS. The bridge loop that already reads the client, the terminal and forwarded sockets now also writes queued output to the client without blocking, waiting for socket room in the same `poll`, as upstream's `TerminalServer::runTerminal` drains its `WriteBuffer` in its select loop. Two threads no longer send and receive on one TCP socket at once, so the kernel socket lock stops forcing context switches, and an idle server session has one thread fewer. Flow control, Ctrl+C output discarding, exit-status ordering, recovery pauses and replay are unchanged; when the terminal ends, the remaining output is delivered on the same thread before the session closes.
- **Wakes never block:** waking the session loop no longer blocks the caller when the wake channel is full.
- Windows keeps its writer thread: its bridge cannot wait on the client socket together with its other sources.

## et@0.0.38

### Server reads no longer wait for the output writer

- **Separate receive lock:** a server session's terminal bridge received and decrypted client packets while holding the connection mutex, which the output writer also takes twice per frame. In a bidirectional transfer most of the server's context switches were the writer blocking on that mutex. The connection's reader state now has its own lock, shared with a receive handle the bridge reads through; recovery swaps the handle together with the connection. A 256 MiB-each-way tunnel in both directions at once (median of 3 interleaved runs): server context switches 1,149 → 335, throughput +27 %, CPU −20 %.
- **No per-frame socket probe on the server writer:** on Unix the output writer no longer peeks the socket (`MSG_PEEK`) before every frame. The session's reader already observes a peer close, and the probe contended with its receives for the kernel socket lock. Windows keeps the probe, which also switches the shared socket to nonblocking mode.

## et@0.0.37

### Cheaper terminal output and pipelined tunnel messages

- **Terminal output scans use SIMD:** the tmux control-mode tracking behind Ctrl+C output filtering (`TerminalStream::observe` and `may_contain_control`) walked every output byte on the server and the client. It now uses `memchr2`/`memrchr`, so plain output costs two SIMD passes; in a PTY output stream those scans were about a fifth of all CPU.
- **Terminal stdout:** the client's console worker waits for room (still cancellable) and then writes a whole queued batch through the inherited blocking terminal description, instead of a poll and a write for every 4 KiB the PTY accepts, and it reuses its batch buffer. A 64 MiB PTY stream: 108 → 132 MiB/s with 29 % less CPU across client, server and terminal.
- **Frame-aligned socket reads:** once a bulk-sized frame has been decoded, a connection asks for the rest of the pending frame plus whole frames of that size, so a uniform bulk stream no longer leaves a partial frame to move to the front of the buffer before every read.
- **Smaller reads on the server:** a server connection reads at most 96 KiB (one aligned 64 KiB-packet frame) instead of 256 KiB, because a server holds one read buffer per session. With 16 concurrent saturated uploads on one server, `etserver` peaks at 17.4 MB RSS instead of 20.4 MB (ET-C++: 18.0 MB) for about 5 % more server CPU (still 40 % below ET-C++); clients keep 256 KiB reads.
- **Pipelined tunnel messages:** a forwarded socket holding up to four packets (about 256 KiB) is read in four parts of at least 16 KiB, so the peer decrypts and forwards the first part while the rest is still encrypted and sent. 64 KiB request/response round trips are 23 % faster (now below OpenSSH) and 32 KiB ones 11 %; bulk transfers keep full 64 KiB packets.

## et@0.0.36

### Bootstrap cleanup spares detached descendants

After the `IDPASSKEY` marker, the client's ssh cleanup sent `SIGKILL` to every local descendant of `ssh`, including processes that had already left ssh's session with `setsid()`. When the bootstrap command runs `etterminal` on the local machine (an `ssh` wrapper, the test and benchmark harnesses), the scan could catch the freshly registered terminal daemon while its launcher was still exiting, and the client then failed with `client is not registered`. Cleanup now stops only descendants still in ssh's session, plus anything holding the captured stdout pipe.

### One poll loop per process and bounded replay memory

- **`etterminal` on Linux runs one `poll(2)` loop** over the router socket, the PTY master (or the `-T` command's stdin/stdout/stderr pipes) and the shell's pidfd, replacing the router pump, blocking PTY reader and `waitpid` waiter threads (and, for `-T`, the per-pipe readers, the 20 ms `try_wait` waiter and the 100 ms pump tick). Idle sessions no longer wake; kernels without `pidfd_open` keep the threaded runtime.
- **Batched PTY output frames:** consecutive full master reads are shaped (motd newline elision and tmux `-CC` filtering unchanged) and sent as one `TERMINAL_BUFFER` of up to 32 KiB instead of one frame per ~4 KiB read; `-T` output frames carry up to 65,472 bytes. Frames are written with resumable vectored writes, so a full router socket never splits one.
- **Forwarding runs on the session thread:** after the session loop first polls forwarding, the forwarding worker hands over its sockets, listeners and timers and exits. Accept, destination request/response, connect, data, credit and close all run in the session's existing poll; per-listener accept threads (and their 100 ms poll / 10 ms retry) are gone on Unix. Forwarded reads pause past a 2 MiB / 256-packet outbound backlog, and the idle window-credit flush moved from 2 ms to 50 ms.
- **`etserver` control plane on one thread:** a single `et-runtime` thread accepts on every TCP listener (IPv4 and IPv6) and services terminal lifecycle events and the 1 s resume-expiry sweep, replacing one accept thread per listener plus the lifecycle thread.
- **Client console output:** an idle console is written straight from the session loop when stdout is a non-blocking FIFO or terminal (terminals are now reopened through `/proc` with `O_NONBLOCK | O_NOCTTY`, like FIFOs), skipping the console worker hand-off; short writes and cursor-report requests still go through the worker. SIGWINCH now wakes the session loop directly instead of a dedicated thread, and `et -W` idles in `poll(2)` instead of a 10 ms sleep loop.
- Forward listeners skip connections that failed before `accept` (`ECONNABORTED`, `EPROTO`, unreachable networks) instead of closing the listener, matching upstream's accept loop.
- **Replay backups trim promptly:** after a delivery acknowledgement, `BackedWriter` keeps the unacknowledged tail plus at most 1024 acknowledged packets bounded to 256 KiB (with a 16-packet floor that absorbs foreign acknowledgements relayed by et.rs ≤ 0.0.7 jumphosts), instead of a flat 1024 packets that pinned the whole 8 MiB connected cap for 64 KiB frames.
- **Acknowledgements by volume:** the client sends an acknowledging keep-alive every 512 KiB read or written, also under continuous inbound and on a saturated link; the server's existing echo carries its own acknowledgement, so one keep-alive trims both sides. No server-initiated keep-alives (upstream `TerminalServer` only echoes and `TerminalClient` never echoes).
- **Client delivery gate:** once the server has acknowledged at least once, stdin and forwarded sockets pause while 4 MiB is unacknowledged, so loopback socket autotuning can no longer push unacknowledged data past the replay cap. Legacy servers never acknowledge and are never gated; an acknowledgement that stops advancing for one keep-alive interval releases the gate until it advances again, so a stalled echo can never wedge forwarding.
- **Server output queue** while connected drops from 16 MiB to 2 MiB in total, 1 MiB each for terminal output and for forwarding/control packets (it feeds a 256 KiB `TCP_NOTSENT_LOWAT` socket), and the flow writer wakes a backpressured bridge once half of the refusing lane's bytes and packet slots are free instead of after every packet; a bridge refused on the forwarding lane no longer waits for terminal output to drain.
- **Socket reads size themselves:** a connection's first read asks for 16 KiB and grows 4x per full read up to 256 KiB, then halves after short reads and releases the drained bulk buffer. Idle and interactive connections no longer zero-fill a 256 KiB read buffer each: with 16 idle sessions on one server, `etserver` drops from 8.4 to 4.6 MB PSS (ET-C++ 5.9 MB) and the 16 clients from 19.2 to 15.2 MB.
- **jemalloc:** builds bake `narenas:1,dirty_decay_ms:1000` via `JEMALLOC_SYS_WITH_MALLOC_CONF` (`.cargo/config.toml`), so freed I/O buffers return to one arena and the kernel within a second; the server keeps muzzy decay at 0. With 8 and 16 saturated sessions on one server, throughput and CPU match `narenas:4` while server RSS stays 5-22% lower.
- Idle threads for a session with one `-L` and one `-R` tunnel: client 6 → 2, server 10 → 5, terminal 3 → 1.

## et@0.0.35

### Preserve strict FIFO packet ordering across concurrent forwarded tunnels

- Avoid worker-side eager reads into `outbound` during `Worker::activate` and prevent the worker from reading sockets owned by the session fast-poll loop, eliminating read reordering between `fast_outbound` and `outbound` under concurrent multi-tunnel bursts.
- Flush `outbound_spill` before emitting new worker packets and drain the oldest spilled packet first when `outbound_spill` reaches capacity.
- Flush queued socket writes before marking a command batch complete in `run_poll`, and only re-enable inline direct writes when both the socket write queue and `held` backlog are empty.

## et@0.0.34

### Optimize tunnel fast-poll path, terminal/pipe zero-copy framing, and memory footprint

- **Direct fast-poll forwarding path (Unix)**: When forwarded routes are eligible, the client and server session loops poll their socket descriptors directly and emit/drain `PortForwardData` frames inline without round-tripping through the forwarding worker thread's wake pipe.
- **Short-read coalescing & 64 KiB bulk chunks**: Break out of the per-turn forwarding read loop immediately after any short read (`<= 4 KiB`) to eliminate extra `EAGAIN` syscalls on interactive/RPC traffic while reading up to `16 x 64 KiB` per turn on the session fast-poll path (`4 x 64 KiB` on initial worker activation).
- **Zero-copy `TerminalBuffer` and local IPC framing**: Encode and decode canonical `TerminalBuffer` payloads without `prost` intermediate allocations, read local packet headers separately in `LocalPacketDecoder` to avoid `Vec::drain(..2)` memmoves, and on Unix send local frames via `write_vectored` (`IoSlice`) in `write_local_terminal_buffer_until_cancelled` and `PendingLocalFrame`.
- **Server inline fast-path send & PTY coalescing**: When the server `OutputQueue` is empty and the TCP socket is immediately writable, encrypt and send packets directly on the bridge thread without waking the flow-control writer thread; coalesce adjacent `2 KiB..=8 KiB` PTY `TerminalBuffer` reads up to `16 KiB` when queued.
- **Raw pipe (`et -T`) & memory footprint optimizations**: Increase `terminal_pipe` output chunks to `65,472` bytes, bypass `std::io::Stdin`'s 8 KiB buffer for binary stdio (`-T`), write directly to `ChildStdin` when no backlog is queued, compact `BackedReader::partial` in L2 cache, and send cumulative 2 MiB `KeepAlive` delivery acknowledgements during binary pipe streams so connected server replay buffers stay trimmed.

## et@0.0.33

### Optimize forwarding and terminal pipeline with zero-hop polling and lock-free crypto

- Eliminate 22-byte frame truncation in `PendingWrite`: raise `WRITE_QUANTUM`
  from 64 KiB to 256 KiB so full 64 KiB forwarding frames (65,558 wire bytes)
  are written in a single system call rather than splitting across an extra
  poll turn.
- Zero-copy framing and backup in `BackedWriter`: share wire frames via
  `Arc<[u8]>` directly between live transport sends and the reconnect backup
  queue, removing per-packet 64 KiB vector clones.
- Direct-buffer crypto in `et-sodium` and `et-core`: link system `libsodium` on
  Unix and add `secretbox_into`, `secretbox_open_into`, and
  `secretbox_open_in_place` to eliminate intermediate ciphertext allocations.
- Decouple 64 KiB XSalsa20-Poly1305 encryption from the session `Connection`
  mutex in `et-server` and `et-net` via `BackedWriter::reserve_write` and
  `commit_reserved`, allowing full-duplex reads and writes to encrypt and
  decrypt concurrently across CPU cores.
- Zero-hop fast poll (`FastPollState`) and wake coalescing in `et-net`,
  `et-bin`, and `et-server`: poll active Unix forwarding routes directly inside
  the client and terminal bridge `poll()` loops, apply window credits inline,
  batch `FlowControl` writer wakeups, and set `TCP_NOTSENT_LOWAT` to a quarter
  of the 256 KiB transport send buffer, cutting context switches by >99% vs
  `v0.0.31` and below upstream C++ ET.
- Cold startup and PTY streaming optimizations in `et-bin`, `et-core`, and
  `et-net`: avoid full-system `/proc` and `sysinfo` scans when SSH bootstrap
  pipes reach EOF normally (cutting cold startup syscalls from 245k to 11.9k),
  add SIMD fast paths to `TmuxCcFilter`, `TerminalStream::observe`, and
  `TerminalModeState`, and reduce local router backpressure retry latency to
  1 ms.
- Enable `TCP_NODELAY` on client, server, and forwarded TCP sockets, and expand
  the per-socket flow-control window to 2 MiB while keeping the 256 KiB socket
  buffer bound so interactive Ctrl-C remains responsive on slow links.

## et@0.0.32

### Switch wire crypto to libsodium and collapse forwarding onto one poll loop

- The wire cipher (XSalsa20-Poly1305, EternalTerminal's `crypto_secretbox`
  scheme) now runs through libsodium via the new `et-sodium` crate, the
  workspace's single FFI boundary. Nonce scheme, packet layout, and the
  `fixtures/wire.json` byte oracles are unchanged. Building now also needs a C
  toolchain, because the bundled libsodium is compiled from source.
- A session reset rekeys from the original passkey on every reset. The first
  libsodium port derived each epoch from the previous epoch's key, so the
  second and later reattach of a named session failed the recovery handshake
  with a poly1305 verification error (`client is ahead of server`).
- On Unix the forwarding worker polls every forwarded socket itself instead of
  running a reader/writer thread pair per socket, matching upstream
  `PortForwardHandler::update`. Reads, writes, half-closes, and window credit
  are handled inline, so a saturated worker no longer pays a context switch per
  packet per hop. Windows keeps the threaded model.
- Coalesce forwarding worker wakeups and outbound notifications under bulk
  transfer, flush queued socket writes and flow-control credits in the same
  poll cycle, and raise the flow-control socket send buffer from 32 KiB to
  256 KiB so full forwarding frames do not block session write batches on
  every packet.

## et@0.0.31

### Fix plain `%` output reordering and pipeline forwarding reads

- Only enter `tmux -CC` control-mode output handling on a real `tmux -CC` DCS
  introducer (`\x1bP1000p`) or a known tmux control notification/block token
  (`%begin`, `%output`, `%extended-output`, `%exit`, etc.), and leave control
  mode on `%exit` (EternalTerminal #899). Plain terminal output starting with
  `%` (such as `top` `%Cpu(s):` or a `%` shell prompt) is no longer reordered
  or retained across an interrupt flush.
- Pipeline windowed port-forwarding socket reads up to the negotiated window
  without blocking after every 16 KiB read chunk, assemble non-blocking
  transport frames with a 64 KiB read buffer, and reuse the server bridge's
  polled client socket handle across iterations.

## et@0.0.30

### Do not inherit client stdin in bootstrap ssh

Redirect the bootstrap `ssh` subprocess's `stdin` from `/dev/null`
(`Stdio::null()`) instead of inheriting the `et` client's `stdin`, matching
upstream `SubprocessToStringInteractive` (EternalTerminal #867). When `et` is
invoked with piped input (such as `printf ... | et -T host ...` or VS Code
Remote-SSH writing its install script to `stdin`), bootstrap `ssh` no longer
consumes the input stream before the ET session starts. Interactive password,
passphrase, and host-key prompts continue to use `/dev/tty` because `ssh`
remains in the client's process group.

## et@0.0.29

### Match upstream TERM forwarding and SetEnv TERM overrides

Forward the local `TERM` value unchanged during SSH bootstrap (defaulting to
`xterm-256color` only when `TERM` is unset or empty) and allow `SetEnv TERM`
and `SendEnv TERM` from SSH configuration or `-o` to override the session
`TERM`, matching upstream EternalTerminal (#679, #725, #870). Remove the
non-upstream `xterm-ghostty` fallback and automatic `COLORTERM` injection.

## et@0.0.28

### Write an explicit foreground pid file

`etserver --pidfile PATH` now records the server process id when the server
stays in the foreground. The file is written with the same hardened pid
writer as `--daemon`: mode 0600, and refused when the path is a symlink, an
extra hard link, a fifo, or has a writable ancestor.

Upstream EternalTerminal writes that file only inside `DaemonCreator::create`
and never unlinks it. A clean foreground shutdown leaves the file in place,
matching the daemon. Protocol v6 is unchanged.

### Reap disconnected forward-only sessions

A `--no-terminal` session that only serves port forwards, and a shell-less
`-N` or `-W` session, now advertises a 5-minute
`disconnect_timeout_seconds` when `--disconnect-timeout` is omitted. etserver
closes the detached terminal after that long with no client attached, instead
of leaving it reparented forever while the server default stays 0.

Interactive sessions, and `--no-terminal` with no forwards, still leave the
field unset so reconnect stays unlimited unless a timeout is configured.
`--disconnect-timeout 0` keeps a forward-only session too. Upstream
EternalTerminal applies one server default to every session and does not
special-case forward-only clients. Protocol v6 is unchanged.

### Drop ended named sessions

When a named session's shell exits, etserver removes that terminal from its
registry and the client deletes the saved session file. `et --list` no longer
shows the session. `et --attach` reports that the session was not found or has
ended when that file is missing, including a name that never existed, instead
of failing to open the file or rejecting the session key. Other failures while
opening the session file are unchanged. Protocol v6 is unchanged.

### Parse et options after the destination

Flags placed after the destination are et options, matching EternalTerminal's
cxxopts parser. `et host --command 'echo hi'` runs `echo hi` on the remote
shell. An explicit `--` ends option parsing, and the following words are the
remote command, including tokens that look like flags. A token that is not an
et option, such as `echo -n`, also stays in that command. Protocol v6 is
unchanged.

### Mark log timestamps as UTC

`et`, `etserver`, and `etterminal` log lines now use an RFC3339 timestamp with
an explicit `Z` UTC marker, for example `2026-10-14T02:48:00.123Z`. The
previous `YYYY-MM-DD HH:MM:SS,mmm` form was UTC with no zone, so a reader
could treat `02:48` as local time. Log file names are unchanged. Protocol v6
is unchanged.

## et@0.0.27

### Replay ssh-agent host-key bindings

Forwarded ssh-agent connections replay the OpenSSH
`session-bind@openssh.com` request recorded during bootstrap ssh, including
the destination host key. A private recorder keeps the last non-forwarded
bind and writes it before client data on each new forwarded connection.
Jumphost binds are included. The agent's replies to those binds are stripped.
A refusal or a missing bind is logged, and forwarding continues. Protocol v6
is unchanged.

### Bound forwarding and harden private daemon paths

Accepted port-forwards waiting on a destination reply are capped at 128 and
expire after 30 seconds. A reply that arrives after its token has expired
closes that destination. Incomplete dynamic-forward SOCKS handshakes are
capped at 64 and closed after 30 seconds.

Daemon pid files refuse symlinks, extra hard links, fifos, and writable
ancestors, and truncate stale contents only after those checks. Creating the
etserver directory checks every ancestor. Root-owned sticky directories such
as `/tmp` stay allowed. Log rotation truncates the open inode. A tmux control
line that was already partly sent is finished from the backlog in one loop,
including a large hostile prelude, so the client receives a complete control
record.

### Harden the daemon, router, and session recovery

Encrypted frames must be at least the 2-byte packet header and at most 128
MiB. Framed bodies grow in 64 KiB chunks. A packet that fails Poly1305
verification leaves the decrypt nonce unchanged, so a retransmission still
matches.

Unix router sessions and HTM control sockets take their identity from kernel
peer credentials. When descriptors or memory are exhausted, the daemon keeps
listening, with at most 64 handshakes in flight.

`et --attach` refuses an unchallenged `NEW_CLIENT` or `RETURNING_CLIENT` and
reports that etserver needs an upgrade. A new session still accepts a legacy
server. Recovery catchup allows 144 MiB. Revive drops the oldest history
above the 64 MiB backup cap and keeps the newest packets for the next
catchup.

### Keep Windows sessions responsive during forwarding writes

Windows client and server transports retain a partial forwarding write and
continue reading while it drains. Terminal input, output, and keepalives stay
live during a large forward, and input and forwarding take turns across those
writes.

## et@0.0.26

### Close forwarded sockets like upstream ET

Port-forward EOF handling now matches upstream EternalTerminal (checked against
master `5b0f17a`). For `-t`, `-r`, and `-D`, EOF closes the forwarded socket in
full. Bytes already sent toward the side that receives `closed` are delivered;
unread local writes and reply packets still in flight in the other direction
are discarded, like upstream C++ `close(fd)`. The earlier et.rs-only behavior
that kept a reply direction open after a local write half-close is removed.

On a peer close, et.rs answers once with `closed` so peers running earlier
et.rs releases free their socket. Mixed old/new et.rs forwarding stays
compatible, and C++ peers harmlessly ignore the extra close.

`-W` keeps upstream's half-close: stdin EOF shuts only the request direction,
and the reply still reaches stdout. When the remote side closes first, `et -W`
now exits as upstream does instead of waiting for stdin EOF, and only after the
final reply bytes are flushed to stdout.

### Keep sessions responsive while a forwarded peer reads slowly

A large port-forward frame sent into a slow TCP window no longer blocks the
client or server transport reader. The partially written frame stays owned by
replay and completes on writable readiness, so inbound terminal output and
keepalives are still read while it drains. Between forwarding frames, the
client gives keystrokes, resize, cursor replies, and keepalives a turn, so a
saturated upload cannot starve them.

A peer that stops reading entirely still hits the live write deadline and
reconnects, as before. On Windows, the client and the server's terminal bridge
still write synchronously, so reads wait for an in-progress forwarding write.

### SSH-compatible client options and persistent local sessions

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

## et@0.0.25

### Interrupt large terminal output without losing session state

Keep unsent terminal output in interruptible queues. Ctrl+C drops large pending
floods while preserving small output, replay-owned frames, and control traffic.
Tmux responses can bypass queued pane floods without splitting incomplete control
records. Default nonterminal packet ordering remains unchanged during recovery.

### Run native Windows HTM sessions

Enable `et.exe htm` and `et.exe htmd` with ConPTY panes, authenticated local IPC,
resize, and retained-state reattachment. Restarting with `-x` replaces only the
selected daemon, including when its UI remains attached.

When Windows forbids job breakaway, HTM reports that its daemon remains inside
the supervising job. It survives the launching UI, not termination of that job.
The existing ET server and terminal breakaway policy remains unchanged.

### Exercise Windows runtime behavior in CI

Run native server, ConPTY, same-session recovery, HTM, and process cleanup tests
on Windows. Downloadable test artifacts run without a compiler on the QA host.
Failure cleanup covers early setup errors and concurrent process exits.

## et@0.0.24

### Match SSH login greeting spacing

Preserve the MOTD's original trailing blank lines without inserting an extra
separator before the previous-login details. Internal SSH control-master
checks no longer print status messages during ET startup.

## et@0.0.23

### Show the previous login before the shell prompt

New Linux terminal sessions now show the authenticated user's previous login
time and remote host after the MOTD, matching SSH's login details. Missing or
unreadable accounting data remains advisory, and `.hushlogin` suppresses the
complete greeting.

## et@0.0.22

### Remove blank lines before the login prompt

Collapse trailing blank lines after assembling the server's complete MOTD so
new ET sessions place the shell prompt directly below the final login message.
Blank lines within a message and between separate MOTD sources remain intact.

## et@0.0.21

### Share SSH bootstrap connections under load

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

### Keep saturated full-duplex forwards moving

Keep a saturated port forward moving in both directions at once. A large
full-duplex transfer through a local tunnel could wedge: each endpoint stopped
reading its transport while it held a forwarding packet for a full worker
queue, so both ends waited for the other, keepalives stopped crossing, and the
session dropped into a recovery loop it could not finish. Both pump loops now
keep draining while a packet is held, so the transfer completes instead of
deadlocking.

### Preserve replies after a forwarding half-close

Preserve forwarded TCP replies after a local client half-closes its write side.
ET now drains the reverse direction before closing the forwarded socket.

### Return finished-session memory to the operating system

On Linux, `etserver` now uses an allocator with immediate dirty-page decay and
reapplies that release policy after terminal session teardown. Bursts of large
finished sessions no longer leave the daemon at its allocator arena
high-water mark while it is idle.

## et@0.0.20

### Add opt-in terminal flow control

Clients can now select lossless backpressure or oldest-output discard when
terminal output outruns the network, keeping Ctrl-C and prompt responses
bounded without changing the default session behavior.

### Align MOTD and shell prompt spacing

Avoid an extra blank line between the MOTD and an interactive shell prompt
when the login shell emits an initial newline.

### Bound flow-control shutdown and recovery admission

Flow-controlled clients now cancel stalled console drains instead of hanging
during shutdown, report closed output streams promptly, and keep client input
moving while terminal output is backpressured. Reconnects are also rejected
when session teardown wins the recovery-admission race.

### Keep terminal startup reliable under heavy load

Terminal startup now uses authenticated, bounded registration and structured
startup acknowledgements before reporting readiness. Initialization remains
responsive under load while forged identities, stalled peers, premature
success, leaked children, and unbounded admission are rejected or cleaned up.

### Port EternalTerminal #798 accept-starvation fix

A stuck client reconnect no longer starves `etserver` accept. Recovery
already ran off the session-table lock and refused a second in-flight
reconnect for the same id; this port also refuses recover after full
session teardown (so a torn-down session cannot be resurrected) while
still allowing recover through terminal HUP so buffered output can
drain. It also raises the TCP `listen(2)` backlog from 32 to 128,
overridable with `backlog` in the `[Networking]` section of the server
config. Non-positive values fall back to 128. `PROTOCOL_VERSION` stays
6. Upstream `#801` / `#803` / `#802` (HTM/Windows/coverage, TIOCGWINSZ,
Windows build) are classified `skip` and not ported.

## et@0.0.19

### Apply SSH configuration port forwarding

The client now reads effective `LocalForward` entries from OpenSSH
configuration and applies them as ET tunnels alongside command-line tunnels.
Configured destination hostnames, explicit bind addresses, `GatewayPorts`, and
`ExitOnForwardFailure` are preserved. `RemoteForward` remains available through
the explicit `-r` option and is not imported from SSH configuration.

### Show the login message of the day

Terminal sessions now display the message of the day before the login shell
starts, matching an interactive `ssh` login. The banner includes Ubuntu's
generated dynamic message followed by `pam_motd`'s default file and directory
sources, honors `.hushlogin`, and never reaches the shell as input.
Reconnecting to the same session does not print it again.

### Harden SSH configuration port forwarding

Operational SSH commands now force isolated forwarding, command, session, and
control socket settings after filtering conflicting user options, while
configuration queries still read supported `LocalForward` rows.
This intentionally overrides user `ClearAllForwardings`, `RemoteCommand`,
`PermitLocalCommand`, `ControlMaster`, `ControlPath`, and `SessionType`
settings for ET's probe and bootstrap commands.

Reverse listeners bind with the authenticated session identity, reject wildcard
or privileged authority escalation, and enforce a transactional per-session
listener limit without capping client-side local listeners. Unix forwarding
helpers clear supplementary groups, authenticate router peers, and roll back
socket paths and created directories on every failed setup or descriptor
transfer. Any explicit reverse bind failure aborts the session and releases
sibling listeners without adding a protocol extension.

Forward initialization now has absolute payload, resolver, helper, and response
deadlines; resolver work and pending router registrations are bounded. Unix
socket teardown stays anchored in the session user's helper so privileged
cleanup cannot follow a replaced parent path. Forwarded TCP destinations are
also resolved and connected as the authenticated session user.

### Complete SSH forwarding compatibility and authority hardening

SSH-config forwarding now preserves explicit bind and destination addresses,
honors `ExitOnForwardFailure`, and keeps setup failures transactional across
direct and native-jumphost sessions.

Reverse listeners remain bound to authenticated loopback authority, helper
processes drop supplementary privileges portably, forwarding listener limits
apply only to server-side reverse tunnels, and failed Unix listener setup no
longer leaves filesystem residue.

## et@0.0.18

### Reject partially unavailable forwarding sources

TCP forwarding now fails when any resolved source address cannot be bound,
instead of silently listening on only one address family.

### Drain terminal output before disconnect

Terminal sessions now drain final terminal output safely when the terminal
exits or disconnects, preserving buffered output for the connected client
before the session closes.

### Fix Windows SSH configuration resolution

SSH configuration expansion now disables PTY allocation, preventing Windows
OpenSSH from stalling before the client bootstrap.

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
