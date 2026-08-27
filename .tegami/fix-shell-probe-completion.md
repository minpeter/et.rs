---
packages:
  et: patch
---

## Stabilize remote shell detection

Remote shell probing now ignores sentinel text embedded in banner lines,
finishes as soon as a complete valid sentinel line arrives, and preserves a
nonzero SSH exit status observed before that line.

Explicit `--remote-shell` choices remain authoritative, and Windows
destinations no longer pass their `et.exe` default to POSIX jumphosts.
