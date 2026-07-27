---
packages:
  et: patch
---

## Recover from macOS post-sleep socket timeouts

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
