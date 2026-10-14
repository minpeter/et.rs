---
packages:
  et:
    type: patch
---

## Drop ended named sessions

When a named session's shell exits, etserver removes that terminal from its
registry and the client deletes the saved session file. `et --list` no longer
shows the session. `et --attach` reports that the session was not found or has
ended when that file is missing, including a name that never existed, instead
of failing to open the file or rejecting the session key. Other failures while
opening the session file are unchanged. Protocol v6 is unchanged.
