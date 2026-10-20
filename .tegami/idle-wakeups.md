---
packages:
  et:
    type: patch
---

### Idle sessions stop waking up every 100 ms

- **Event-driven waits on Linux:** the server session loop, the server's terminal registration router and the client loop each polled with a 100 ms cap, although every source they serve already wakes them through a descriptor. An idle tunnel session woke about 31 times per second (OpenSSH: 0, ET-C++: about 220). On Linux these loops now sleep until an event or a real deadline: the next keep-alive, the oldest pending registration's expiry, a disconnected client's timeout, a stalled delivery gate's release, or a forwarding retry. An idle session now wakes about 1.6 times per second (keep-alives and the server's one-second resume sweep).
- **Disconnected sessions no longer poll every 10 ms on Linux:** the session loop sleeps until the disconnect timeout instead, and starts that clock before it first sleeps.
- macOS keeps its 100 ms recheck because Darwin can omit readiness for a closed socket; Windows is unchanged.
