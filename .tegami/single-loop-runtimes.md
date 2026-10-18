---
packages:
  et:
    type: patch
---

### One poll loop per process and bounded replay memory

- **`etterminal` on Linux runs one `poll(2)` loop** over the router socket, the PTY master (or the `-T` command's stdin/stdout/stderr pipes) and the shell's pidfd, replacing the router pump, blocking PTY reader and `waitpid` waiter threads (and, for `-T`, the per-pipe readers, the 20 ms `try_wait` waiter and the 100 ms pump tick). Idle sessions no longer wake; kernels without `pidfd_open` keep the threaded runtime.
- **Batched PTY output frames:** consecutive full master reads are shaped (motd newline elision and tmux `-CC` filtering unchanged) and sent as one `TERMINAL_BUFFER` of up to 32 KiB instead of one frame per ~4 KiB read; `-T` output frames carry up to 65,472 bytes. Frames are written with resumable vectored writes, so a full router socket never splits one.
- **Forwarding runs on the session thread:** after the session loop first polls forwarding, the forwarding worker hands over its sockets, listeners and timers and exits. Accept, destination request/response, connect, data, credit and close all run in the session's existing poll; per-listener accept threads (and their 100 ms poll / 10 ms retry) are gone on Unix. Forwarded reads pause past a 2 MiB / 256-packet outbound backlog, and the idle window-credit flush moved from 2 ms to 50 ms.
- **`etserver` control plane on one thread:** a single `et-runtime` thread accepts on every TCP listener (IPv4 and IPv6) and services terminal lifecycle events and the 1 s resume-expiry sweep, replacing one accept thread per listener plus the lifecycle thread.
- **Client console output:** an idle console is written straight from the session loop when stdout is a non-blocking FIFO or terminal (terminals are now reopened through `/proc` with `O_NONBLOCK | O_NOCTTY`, like FIFOs), skipping the console worker hand-off; short writes and cursor-report requests still go through the worker. SIGWINCH now wakes the session loop directly instead of a dedicated thread, and `et -W` idles in `poll(2)` instead of a 10 ms sleep loop.
- Forward listeners skip connections that failed before `accept` (`ECONNABORTED`, `EPROTO`, unreachable networks) instead of closing the listener, matching upstream's accept loop.
- **Replay backups trim promptly:** after a delivery acknowledgement, `BackedWriter` keeps the unacknowledged tail plus at most 1024 acknowledged packets bounded to 256 KiB (with a 16-packet floor that absorbs foreign acknowledgements relayed by et.rs ≤ 0.0.7 jumphosts), instead of a flat 1024 packets that pinned the whole 8 MiB connected cap for 64 KiB frames.
- **Acknowledgements by volume:** the client sends an acknowledging keep-alive every 512 KiB read or written, also under continuous inbound and on a saturated link; the server's existing echo carries its own acknowledgement, so one keep-alive trims both sides. No server-initiated keep-alives (upstream `TerminalServer` only echoes and `TerminalClient` never echoes).
- **Client delivery gate:** once the server has acknowledged at least once, stdin and forwarded sockets pause while 4 MiB is unacknowledged, so loopback socket autotuning can no longer push unacknowledged data past the replay cap. Legacy servers never acknowledge and are never gated; an acknowledgement that stops advancing for one keep-alive interval disables the gate for the session.
- **Server output queue** while connected drops from 16 MiB to 2 MiB (it feeds a 256 KiB `TCP_NOTSENT_LOWAT` socket), and the flow writer wakes a backpressured bridge once half the queue is free instead of after every packet.
- **jemalloc:** release builds bake `narenas:1,dirty_decay_ms:1000` via `JEMALLOC_SYS_WITH_MALLOC_CONF` (`.cargo/config.toml`), so freed I/O buffers return to one arena and the kernel within a second; the server keeps muzzy decay at 0.
- Idle threads for a session with one `-L` and one `-R` tunnel: client 6 → 2, server 10 → 5, terminal 3 → 1.
