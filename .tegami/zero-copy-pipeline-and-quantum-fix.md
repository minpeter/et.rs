---
packages:
  et:
    type: patch
---

## Optimize forwarding pipeline with zero-copy framing and batch queuing

- Eliminate 22-byte frame truncation in `PendingWrite`: raise `WRITE_QUANTUM`
  from 64 KiB to 256 KiB so full 64 KiB forwarding frames (65,558 wire bytes)
  are written in a single system call rather than splitting across an extra
  poll turn.
- Zero-copy framing and backup in `BackedWriter`: share wire frames via
  `Arc<[u8]>` directly between live transport sends and the reconnect backup
  queue, removing per-packet 64 KiB vector clones.
- Direct-buffer crypto in `et-sodium` and `et-core`: add `secretbox_into`,
  `secretbox_open_into`, and `secretbox_open_in_place` to eliminate intermediate
  ciphertext allocations.
- In-place fast-path data serialization in `et-net`: encode forwarding data
  packets in one step and parse incoming data packets directly into queued
  buffer spans, bypassing protobuf intermediate copies.
- Single-lock batch command drain in `CommandReceiver`: drain all pending
  commands per lock acquisition and batch forward packets during session read
  loops, slashing mutex contention and worker wake thrashing.
- Enable `TCP_NODELAY` on the client connection and forward listeners, cutting
  interactive ping-pong latency from 44 ms to ~40–60 µs.
- Expand flow-control window to 2 MiB while keeping the 256 KiB socket buffer
  bound so interactive Ctrl-C remains responsive on slow links.
