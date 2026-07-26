---
packages:
  et: patch
---

## Fix a port-forwarding deadlock under bidirectional load

The session loops handed inbound tunnel packets to the forwarding worker with
a blocking send, while the worker hands outbound tunnel packets back through a
bounded queue that only those same session loops drain. Under sustained
bulk transfers in both directions the two bounded queues could fill at the
same time, leaving the session loop and the worker each waiting on the other —
a permanent wedge that also stopped keepalives and made reconnects impossible.

Session loops (client, server bridge, on both Unix and Windows) now hand
packets to the worker without blocking: when the worker is at capacity the
packet is held, no further session packets are read (preserving order), and
the loop keeps draining the worker's outbound queue — which is exactly what
frees the worker — retrying on a 10ms cadence.
