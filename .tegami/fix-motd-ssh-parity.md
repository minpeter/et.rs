---
packages:
  et:
    type: patch
---

## Match SSH login greeting spacing

Preserve the MOTD's original trailing blank lines without inserting an extra
separator before the previous-login details. Internal SSH control-master
checks no longer print status messages during ET startup.
