---
packages:
  et:
    type: patch
---

## Port EternalTerminal #798 accept-starvation fix

A stuck client reconnect no longer starves `etserver` accept. Recovery
already ran off the session-table lock and refused a second in-flight
reconnect for the same id; this port also refuses recover after full
session teardown (so a torn-down session cannot be resurrected) while
still allowing recover through terminal HUP so buffered output can
drain. It also raises the TCP `listen(2)` backlog from 32 to 128,
overridable with `backlog` in the `[Networking]` section of the server
config. Non-positive values fall back to 128. `PROTOCOL_VERSION` stays
6. Upstream `#801` / `#803` / `#802` (HTM/Windows/coverage, TIOCGWINSZ,
Windows build) are classified `skip` and not ported.
