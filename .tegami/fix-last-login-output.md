---
packages:
  et:
    type: patch
---

## Show the previous login before the shell prompt

New Linux terminal sessions now show the authenticated user's previous login
time and remote host after the MOTD, matching SSH's login details. Missing or
unreadable accounting data remains advisory, and `.hushlogin` suppresses the
complete greeting.
