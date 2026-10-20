---
packages:
  et:
    type: patch
---

### One client thread for terminal output on Linux

- **The session loop writes the terminal itself:** when stdout is a terminal or a FIFO, the Linux client no longer starts the `et-console-output` thread. The loop that already reads the server, stdin and forwarded sockets now writes terminal output without blocking and waits for room in the same `poll`, as upstream's `TerminalClient::run` drains its `WriteBuffer` in its select loop. Queued packets go out in one vectored write and their buffers are reused, so a busy terminal no longer costs a copy and an allocation per packet plus a thread wakeup and a socketpair signal per batch. An interactive client now runs one thread, like OpenSSH (two before). Streaming 64 MiB to a terminal, the client's context switches fell from about 10,600 to 6,500 (OpenSSH: 10,400) and its CPU time from 310–330 ms to 280–300 ms (OpenSSH: 260 ms).
- Flow control, Ctrl+C output discarding, cursor-report replies and alternate-screen cleanup still act only on bytes that reached the terminal, and the bounded one-second drain on exit is unchanged. A Ctrl+C now also discards a saturated backlog whose queue is a few bytes short of 64 KiB, since partial terminal writes rarely leave it exactly full.
- Escape-sequence scans for cursor-report requests, alternate-screen switches and the post-interrupt line skip use SIMD searches.
- Regular files, sockets, macOS and Windows keep the output thread.
