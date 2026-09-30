---
packages:
  et:
    type: patch
---

## Close forwarded sockets like upstream ET

Port-forward EOF handling now matches upstream EternalTerminal (checked against
master `5b0f17a`). For `-t`, `-r`, and `-D`, EOF on either end closes the
forwarded socket in full after bytes already sent are delivered. The earlier
et.rs-only behavior that kept a reply direction open after a local write
half-close is removed, so et.rs and C++ peers behave the same.

`-W` keeps upstream's half-close: stdin EOF shuts only the request direction,
and the reply still reaches stdout. When the remote side closes first, `et -W`
now exits as upstream does instead of waiting for stdin EOF, and only after the
final reply bytes are flushed to stdout.
