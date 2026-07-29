---
packages:
  et:
    type: patch
---

## Add debug diagnostics for dropped server sessions

`ET_DEBUG=1` now gives `etserver` a durable machine-local log destination,
non-silent logging, and default verbosity 2. Operators can also use
`ET_LOGDIR` and `ET_VERBOSE` when CLI or INI settings do not override them.

Server diagnostics now record client accept/reject reasons, reconnect and
recovery outcomes, terminal disconnects, and session removal, making long-lived
session drops diagnosable from the server host. Client debug logs omit session
credentials, malformed handshakes are bounded by a five-second deadline and
128-connection pre-auth capacity, and completed connection handlers no longer
accumulate after rapid failed handshakes.
