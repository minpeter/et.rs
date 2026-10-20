---
packages:
  et:
    type: patch
---

### `--jumphost` works when the destination runs ET C++

`et --jumphost` now gives the jump terminal the session id and key the destination's `etterminal` answered with, as upstream does. An ET C++ `etterminal` replaces the client's temporary credentials with its own, so the session previously failed against a C++ destination.
