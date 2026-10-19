---
packages:
  et:
    type: patch
---

### Server reads no longer wait for the output writer

- **Separate receive lock:** a server session's terminal bridge received and decrypted client packets while holding the connection mutex, which the output writer also takes twice per frame. In a bidirectional transfer most of the server's context switches were the writer blocking on that mutex. The connection's reader state now has its own lock, shared with a receive handle the bridge reads through; recovery swaps the handle together with the connection. A 256 MiB-each-way tunnel in both directions at once (median of 3 interleaved runs): server context switches 1,149 → 335, throughput +27 %, CPU −20 %.
- **No per-frame socket probe on the server writer:** on Unix the output writer no longer peeks the socket (`MSG_PEEK`) before every frame. The session's reader already observes a peer close, and the probe contended with its receives for the kernel socket lock. Windows keeps the probe, which also switches the shared socket to nonblocking mode.
