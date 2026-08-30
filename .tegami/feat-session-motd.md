---
packages:
  et:
    type: patch
---

## Show the login message of the day

Terminal sessions now display the message of the day before the login shell
starts, matching an interactive `ssh` login. The banner follows `pam_motd`'s
default file and directory precedence, honors `.hushlogin`, and never reaches
the shell as input. Reconnecting to the same session does not print it again.
