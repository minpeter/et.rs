---
packages:
  et: patch
---

## Return cleanly to the local prompt after exit

Interactive sessions now finish with an SSH-style `Connection to … closed.`
line and keep the local prompt on the current screen. Graceful shell exits no
longer issue an unmatched alternate-screen restore that could move the cursor
to an old position, while abrupt failures retain the stronger terminal-mode
cleanup needed for crashed full-screen applications.
