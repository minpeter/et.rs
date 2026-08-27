---
packages:
  et: patch
---

## Auto-detect Windows OpenSSH bootstrap

Bare `et user@windows-host` connections now probe the login shell without
including session credentials. Expanded `%ComSpec%` selects the existing
Cmd-compatible bootstrap and `et.exe` terminal path automatically, while
POSIX hosts preserve their existing bootstrap.

Explicit `--winserver` and `--remote-shell` overrides remain authoritative.
PowerShell sessions now pass `ET_SHELL=powershell.exe` only to the remote
`etterminal` process.
