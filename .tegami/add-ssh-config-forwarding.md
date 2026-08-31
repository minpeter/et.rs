---
packages:
  et:
    type: patch
---

## Apply SSH configuration port forwarding

The client now reads effective `LocalForward` and `RemoteForward` entries from
OpenSSH configuration and applies them as ET tunnels when matching command-line
tunnel options are not provided.
