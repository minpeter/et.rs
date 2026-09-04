---
packages:
  et:
    type: patch
---

## Remove blank lines before the login prompt

Collapse trailing blank lines after assembling the server's complete MOTD so
new ET sessions place the shell prompt directly below the final login message.
Blank lines within a message and between separate MOTD sources remain intact.
