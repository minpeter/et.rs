---
packages:
  et: patch
---

## Stop the daemon from retaining 64 MiB of replay history per live session

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
