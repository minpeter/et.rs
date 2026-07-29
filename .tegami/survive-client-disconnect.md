---
packages:
  et:
    type: patch
---

## Keep server sessions alive across client transport loss

`etserver` now treats laptop sleep, Wi-Fi changes, and other client transport
loss as a recoverable disconnect instead of terminating the registered
terminal. Output produced while the client is away remains buffered, and a
returning client resumes the same shell without an `InvalidKey` failure.

Recovery handoff now ignores stale events from the replaced socket, drains
packets read during recovery authentication, and preserves port-forwarding
packets when the replay buffer is temporarily full.
