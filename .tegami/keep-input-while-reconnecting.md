---
packages:
  et:
    type: patch
---

### Keystrokes typed while `et` reconnects are no longer lost

While the connection was down, `et` read your keystrokes only to watch for Ctrl-C and dropped everything else. It now sends them to the remote shell, in the order you typed them, once the session recovers, as ET C++ does. Ctrl-C still gives up reconnecting.
