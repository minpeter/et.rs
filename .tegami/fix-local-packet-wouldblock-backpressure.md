---
packages:
  et: patch
---

## Fix session teardown under local IPC backpressure

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
