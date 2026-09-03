---
packages:
  et:
    type: patch
---

## Return finished-session memory to the operating system

On Linux, `etserver` now uses an allocator with immediate dirty-page decay and
reapplies that release policy after terminal session teardown. Bursts of large
finished sessions no longer leave the daemon at its allocator arena
high-water mark while it is idle.
