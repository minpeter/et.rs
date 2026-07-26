---
packages:
  et: patch
---

## Trim replay backups with delivery acknowledgements on keep-alives

Replay backups previously only shrank at a fixed cap, so a single burst of
output (`cat` a large file) pinned the cap's worth of memory per session for
the rest of the daemon's uptime, and idle sessions slowly accumulated
keep-alive echoes.

Keep-alives now carry the sender's reader sequence as an 8-byte payload.
Every implementation ignores keep-alive payloads on receipt (verified
against upstream C++ `TerminalServer`/`TerminalClient` and released et.rs),
so the extension is invisible to legacy peers. An et.rs receiver uses it to
drop backup packets the peer has already consumed, keeping only the
unacknowledged tail plus a fixed slack — a session's replay backup now
returns to near-empty within one keep-alive interval instead of pinning the
connected cap forever.

Acknowledgements are strictly per-hop. Jumphosts relay packets verbatim
(upstream and et.rs alike), so the jumphost etserver consumes the client's
acknowledgement for its own connection and forwards a payload-less
keep-alive, and `etterminal --jump` attaches its own sequence towards the
destination. A foreign sequence that still arrives through a legacy C++
jumphost is absorbed by the retention slack.
