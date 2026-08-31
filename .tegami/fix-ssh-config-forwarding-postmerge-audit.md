---
packages:
  et:
    type: patch
---

## Complete SSH forwarding compatibility and authority hardening

SSH-config forwarding now preserves explicit bind and destination addresses,
honors `ExitOnForwardFailure`, and keeps setup failures transactional across
direct and native-jumphost sessions.

Reverse listeners remain bound to authenticated loopback authority, helper
processes drop supplementary privileges portably, forwarding listener limits
apply only to server-side reverse tunnels, and failed Unix listener setup no
longer leaves filesystem residue.
