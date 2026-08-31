---
packages:
  et:
    type: patch
---

## Show the login message of the day

Terminal sessions now display the message of the day before the login shell
starts, matching an interactive `ssh` login. The banner includes Ubuntu's
generated dynamic message followed by `pam_motd`'s default file and directory
sources, honors `.hushlogin`, and never reaches the shell as input.
Reconnecting to the same session does not print it again.
