---
packages:
  et:
    type: patch
---

## Bound flow-control shutdown and recovery admission

Flow-controlled clients now cancel stalled console drains instead of hanging
during shutdown, report closed output streams promptly, and keep client input
moving while terminal output is backpressured. Reconnects are also rejected
when session teardown wins the recovery-admission race.
