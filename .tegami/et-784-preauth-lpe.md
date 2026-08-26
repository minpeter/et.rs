---
packages:
  et:
    type: patch
---

## Port EternalTerminal #784 pre-auth / LPE fixes

Handshake protos are now capped at 4 KiB (was 64 KiB), matching ET
`MAX_HANDSHAKE_PROTO_LENGTH`. Length-prefixed reads enforce both an idle
gap and an absolute deadline so a slow trickle cannot reset the timer
forever. Failed reconnect recover no longer disconnects the live victim
session before recover succeeds. When `etserver` is root, UNIX listen and
connect on client-chosen paths drop to the session user (helper +
`SCM_RIGHTS`) instead of unlink/bind/chown/connect as root. Reconnect
passkey-before-recover is still omitted: that needs a `PROTOCOL_VERSION`
bump.
