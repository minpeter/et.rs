---
packages:
  et:
    type: patch
---

### No lost or garbled output right after `etserver` restarts

When `etserver` restarted under a live session, the new server sometimes read the session's first output itself, waiting for a startup report that a resumed terminal never sends. That output was lost, or the client printed `malformed terminal output` and had to reconnect a second time. The resumed session now gets all of its output.
