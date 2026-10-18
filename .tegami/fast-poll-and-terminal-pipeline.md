---
packages:
  et:
    type: patch
---

### Optimize tunnel fast-poll path, terminal/pipe zero-copy framing, and memory footprint

- **Direct fast-poll forwarding path (Unix)**: When forwarded routes are eligible, the client and server session loops poll their socket descriptors directly and emit/drain `PortForwardData` frames inline without round-tripping through the forwarding worker thread's wake pipe.
- **Short-read coalescing & 64 KiB bulk chunks**: Break out of the per-turn forwarding read loop immediately after any short read (`<= 4 KiB`) to eliminate extra `EAGAIN` syscalls on interactive/RPC traffic while reading up to `16 x 64 KiB` per turn on the session fast-poll path (`4 x 64 KiB` on initial worker activation).
- **Zero-copy `TerminalBuffer` and local IPC framing**: Encode and decode canonical `TerminalBuffer` payloads without `prost` intermediate allocations, read local packet headers separately in `LocalPacketDecoder` to avoid `Vec::drain(..2)` memmoves, and on Unix send local frames via `write_vectored` (`IoSlice`) in `write_local_terminal_buffer_until_cancelled` and `PendingLocalFrame`.
- **Server inline fast-path send & PTY coalescing**: When the server `OutputQueue` is empty and the TCP socket is immediately writable, encrypt and send packets directly on the bridge thread without waking the flow-control writer thread; coalesce adjacent `2 KiB..=8 KiB` PTY `TerminalBuffer` reads up to `16 KiB` when queued.
- **Raw pipe (`et -T`) & memory footprint optimizations**: Increase `terminal_pipe` output chunks to `65,472` bytes, bypass `std::io::Stdin`'s 8 KiB buffer for binary stdio (`-T`), write directly to `ChildStdin` when no backlog is queued, compact `BackedReader::partial` in L2 cache, and send cumulative 2 MiB `KeepAlive` delivery acknowledgements during binary pipe streams so connected server replay buffers stay trimmed.
