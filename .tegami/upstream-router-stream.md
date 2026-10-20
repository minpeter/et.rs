---
packages:
  et:
    type: patch
---

### `etserver` and `etterminal` now mix with ET C++

On the server host, `etserver` hands keystrokes, resizes and the close request to `etterminal` over a local socket. et.rs now uses upstream's format on that socket, so an et.rs `etserver` serves a C++ `etterminal` and a C++ `etserver` serves an et.rs `etterminal`, in shell, `-T`, `-W` and jumphost sessions. An et.rs `etserver` also handles a C++ jump terminal the way upstream does.

Sessions started by et.rs 0.0.43 or older keep the old format, so they survive restarting `etserver` after the upgrade, and a new `etterminal` still works with an old `etserver` that has not restarted yet. A live session also survives switching `etserver` between et.rs and C++.
