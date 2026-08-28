---
packages:
  et: patch
---

## Preserve client locales in POSIX sessions

Clients now forward `LANG` and `LC_*` values to each new POSIX session, matching
the environment behavior users expect from SSH. Locale-sensitive applications
such as btop can detect UTF-8 without changing Windows session environments.
