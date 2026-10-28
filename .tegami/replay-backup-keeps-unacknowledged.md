---
packages:
  et:
    type: patch
---

### A client that stops reading for a while no longer loses its session

While connected, `etserver` and `et` kept only the newest 8 MiB of replay history, even when the other side had not received it yet. A client whose output was blocked (for example a paused terminal) while a command kept printing could fall more than 8 MiB behind; on reconnect the server reported "client is too far behind server" and the session was lost. Data the other side has not acknowledged is now kept up to 64 MiB, as in ET C++. History the other side has already acknowledged is still trimmed to 8 MiB, so idle and well-behaved sessions use no more memory than before.
