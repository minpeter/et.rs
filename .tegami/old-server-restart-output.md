---
packages:
  et:
    type: patch
---

### No lost output when `etserver` restarts as an older et.rs

When `etserver` restarted as et.rs 0.0.43 or older, for example after a downgrade, a running session's first output could go missing, or the client printed `malformed terminal output` and reconnected again. The new `etterminal` now answers that older server's startup check as soon as it reconnects, so the output reaches the client.
