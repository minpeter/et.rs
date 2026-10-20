---
packages:
  et:
    type: patch
---

### A jumphost session shows its first output without a keypress

When the destination's first output arrived together with its handshake reply, the jump terminal held that output until something else happened on the connection, so the prompt could stay blank until you pressed a key. The jump terminal now forwards it right away.
