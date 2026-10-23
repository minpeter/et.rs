---
packages:
  et:
    type: patch
---

### `et -N` forwards answer faster, idle `-N` sessions stop waking 200 times a second, and uploads keep replay memory bounded

`et -N` (and `-M`/`--ctl` sessions) passed every forwarded packet between the session thread and a separate forwarding thread, and checked for work every 5 ms even when nothing was happening. Forwarding now runs on the session thread, as it already did in interactive sessions and as it does in ET C++'s client loop. An idle session now sleeps until there is traffic or a timer, such as the keepalive, is due. On loopback, a 64-byte round trip through `-N` went from about 207 to about 163 µs, and an idle `-N` session went from about 195 wakeups per second to under 1. A single bulk upload uses about 5% less client CPU, but it now runs on one core, so on loopback it peaks about 8% lower (about 716 instead of 782 MiB/s).

During uploads these sessions now also send delivery acknowledgements every 512 KiB and pause their forwarded sockets while 4 MiB is still unacknowledged, the same way interactive sessions do. This stops a fast upload from filling the client's replay buffer.
