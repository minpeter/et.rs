---
packages:
  et:
    type: patch
---

## Optimize forwarding and terminal pipeline with zero-hop polling and lock-free crypto

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
