---
packages:
  et:
    type: patch
---

## Drop ended named sessions

When a named session's shell exits, etserver removes that terminal from its
registry. `et --list` no longer shows the session. Attaching to a session that
has already ended reports that the session was not found or has ended, instead
of rejecting the session key. Protocol v6 is unchanged.
