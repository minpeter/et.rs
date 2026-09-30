---
packages:
  et:
    type: patch
---

## Keep sessions responsive while a forwarded peer reads slowly

A large port-forward frame sent into a slow TCP window no longer blocks the
client or server transport reader. The partially written frame stays owned by
replay and completes on writable readiness, so inbound terminal output and
keepalives are still read while it drains. Between forwarding frames, the
client gives keystrokes, resize, cursor replies, and keepalives a turn, so a
saturated upload cannot starve them.

A peer that stops reading entirely still hits the live write deadline and
reconnects, as before. On Windows, the client and the server's terminal bridge
still write synchronously, so reads wait for an in-progress forwarding write.
