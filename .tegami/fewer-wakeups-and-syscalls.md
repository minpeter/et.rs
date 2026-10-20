---
packages:
  et:
    type: patch
---

### Fewer server wakeups and per-message system calls

- **Resume sweep only when needed:** the server's control thread checked for expired resumed terminals once a second even when there were none, so an idle server woke every second. It now sweeps only while a terminal that re-registered a live PTY (after a server restart) is registered; the router arms the sweep when one registers. An idle session's server now wakes about twice in 10 s (the client's keep-alive echoes) instead of twelve times.
- **No futex wake per queued packet:** on Linux and macOS the session loop writes its own output, but every packet queued while the queue was empty still notified a condition variable nobody waited on, which costs a `futex` system call each time. The notification now goes only to a parked writer (the Windows writer thread, or the final drain).
- **No `FIONREAD` probe per small forwarded message:** a readable forwarded socket was asked how many bytes it held before every read, to split large messages into pipelined parts. The first read now takes one 16 KiB part and only a full part asks how much is left, so a request or reply that fits in 16 KiB costs one system call fewer at each end. Larger messages are still split into parts of at least 16 KiB.
- With both, a 1-byte tunnel round trip costs 7.3 system calls per side instead of 8.3 on the client and 9.4 on the server.
- `etterminal` checks PTY output for tmux control-mode escapes with a SIMD search.
