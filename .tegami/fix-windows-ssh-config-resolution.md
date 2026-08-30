---
packages:
  et:
    type: patch
---

## Fix Windows SSH configuration resolution

SSH configuration expansion now disables PTY allocation, preventing Windows
OpenSSH from stalling before the client bootstrap.
