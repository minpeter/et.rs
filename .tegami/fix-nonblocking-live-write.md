---
packages:
  et:
    type: patch
---

## Keep sessions responsive while a forwarded peer stops reading

A large port-forward frame sent into a slow or stalled TCP window no longer
blocks the client or server transport reader. The partially written frame stays
owned by replay and completes on writable readiness, so keystrokes, terminal
output, keepalives, and recovery keep flowing instead of waiting for a write
timeout and reconnect.
