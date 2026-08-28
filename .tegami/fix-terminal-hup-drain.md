---
packages:
  et:
    type: patch
---

## Drain terminal output before disconnect

Terminal sessions now drain final terminal output safely when the terminal
exits or disconnects, preserving buffered output for the connected client
before the session closes.
