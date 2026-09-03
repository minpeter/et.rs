---
packages:
  et:
    type: patch
---

## Add opt-in terminal flow control

Clients can now select lossless backpressure or oldest-output discard when
terminal output outruns the network, keeping Ctrl-C and prompt responses
bounded without changing the default session behavior.
