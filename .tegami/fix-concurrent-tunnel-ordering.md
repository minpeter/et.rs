---
packages:
  et:
    type: patch
---

### Preserve strict FIFO packet ordering across concurrent forwarded tunnels

- Avoid worker-side eager reads into `outbound` during `Worker::activate` and prevent the worker from reading sockets owned by the session fast-poll loop, eliminating read reordering between `fast_outbound` and `outbound` under concurrent multi-tunnel bursts.
- Flush `outbound_spill` before emitting new worker packets and drain the oldest spilled packet first when `outbound_spill` reaches capacity.
- Flush queued socket writes before marking a command batch complete in `run_poll`, and only re-enable inline direct writes when both the socket write queue and `held` backlog are empty.
