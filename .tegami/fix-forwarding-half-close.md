---
et: patch
---

Preserve forwarded TCP replies after a local client half-closes its write side.
ET now drains the reverse direction before closing the forwarded socket.
