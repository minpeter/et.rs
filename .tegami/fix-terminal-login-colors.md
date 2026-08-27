---
packages:
  et: patch
---

## Restore colorful shell startup in ET sessions

Unix ET sessions now start the user's shell as a login shell, matching SSH,
upstream EternalTerminal, and ET's own headless terminal multiplexer. This
restores profile-provided prompts, aliases, `dircolors`, and other color setup
that was skipped when ET launched an interactive non-login shell.

Native Windows terminal startup, protocol-v6 bytes, and reconnect behavior are
unchanged.
