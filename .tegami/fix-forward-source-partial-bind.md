---
packages:
  et:
    type: patch
---

## Reject partially unavailable forwarding sources

TCP forwarding now fails when any resolved source address cannot be bound,
instead of silently listening on only one address family.
