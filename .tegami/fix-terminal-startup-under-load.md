---
packages:
  et:
    type: patch
---

## Keep terminal startup reliable under heavy load

Terminal startup now uses authenticated, bounded registration and structured
startup acknowledgements before reporting readiness. Initialization remains
responsive under load while forged identities, stalled peers, premature
success, leaked children, and unbounded admission are rejected or cleaned up.
