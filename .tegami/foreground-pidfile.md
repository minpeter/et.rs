---
packages:
  et:
    type: patch
---

## Write an explicit foreground pid file

`etserver --pidfile PATH` now records the server process id when the server
stays in the foreground. The file is written with the same hardened pid
writer as `--daemon`: mode 0600, and refused when the path is a symlink, an
extra hard link, a fifo, or has a writable ancestor.

Upstream EternalTerminal writes that file only inside `DaemonCreator::create`
and never unlinks it. A clean foreground shutdown leaves the file in place,
matching the daemon. Protocol v6 is unchanged.
