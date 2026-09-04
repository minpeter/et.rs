---
packages:
  et:
    type: patch
---

## Keep saturated full-duplex forwards moving

Keep a saturated port forward moving in both directions at once. A large
full-duplex transfer through a local tunnel could wedge: each endpoint stopped
reading its transport while it held a forwarding packet for a full worker
queue, so both ends waited for the other, keepalives stopped crossing, and the
session dropped into a recovery loop it could not finish. Both pump loops now
keep draining while a packet is held, so the transfer completes instead of
deadlocking.
