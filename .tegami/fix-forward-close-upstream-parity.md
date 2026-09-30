---
packages:
  et:
    type: patch
---

## Close forwarded sockets like upstream ET

Port-forward EOF handling now matches upstream EternalTerminal (checked against
master `5b0f17a`). For `-t`, `-r`, and `-D`, EOF closes the forwarded socket in
full. Bytes already sent toward the side that receives `closed` are delivered;
unread local writes and reply packets still in flight in the other direction
are discarded, like upstream C++ `close(fd)`. The earlier et.rs-only behavior
that kept a reply direction open after a local write half-close is removed.

On a peer close, et.rs answers once with `closed` so peers running earlier
et.rs releases free their socket. Mixed old/new et.rs forwarding stays
compatible, and C++ peers harmlessly ignore the extra close.

`-W` keeps upstream's half-close: stdin EOF shuts only the request direction,
and the reply still reaches stdout. When the remote side closes first, `et -W`
now exits as upstream does instead of waiting for stdin EOF, and only after the
final reply bytes are flushed to stdout.
